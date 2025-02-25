import {
  keccak256,
  computeAddress,
  parseUnits,
  hexlify,
  toUtf8Bytes,
  BytesLike,
} from "ethers";
import { Keypair, PublicKey, Connection } from "@solana/web3.js";
import nacl from "tweetnacl";
import {
  createUserPresignSettlementTransactionAndSerializeToString,
  getTradeVaultPda,
} from "bitfi-solana-js";

import { ITypes } from "../typechain-types/contracts/utils/Core";
import { getMPCPubkey } from "../scripts/utils/bitcoin/btc";
import { affiliateInfo, AffiliateInfo, rand, randomTxId } from "./utils";
import { genSolanaKP, getUserEphemeralKeys } from "../scripts/utils/solana/sol";

export function getTradeInfo(
  fromChain: string,
  fromToken: string,
  fromUserAddress: PublicKey,
  decimals: string | number,
): ITypes.TradeInfoStruct {
  const tradeInfo: ITypes.TradeInfoStruct = {
    amountIn: parseUnits((3 * rand(1000)).toString(), decimals),
    fromChain: [
      toUtf8Bytes(fromUserAddress.toString()),
      toUtf8Bytes(fromChain), // fromChain (must register in Management)
      toUtf8Bytes(fromToken), // fromToken (must register in Management)
    ],
    toChain: [
      toUtf8Bytes("tb1q85w8v43nj5gq2elmc57fj0jrk8q900sk3udj8h"), //  toUserAddress
      toUtf8Bytes("bitcoin-testnet"), //  toChain (must register in Management)
      toUtf8Bytes("native"), //  toToken (must register in Management)
    ],
  };

  return tradeInfo;
}

export function getAffiliateInfo(): ITypes.AffiliateStruct {
  //  @dev:
  // - If there are multiple affiliates, `aggregatedFeeRate` is the total sum
  // - The schema is an example. Please re-define for your case.
  //  Note: The L2 contract has an upper limit for the affiliate fee rate
  //  It might be reverted if `aggregatedFeeRate` > `maxAffiliateFeeRate`
  const aggregatedFeeRate: number = 350; //  example 3.5% (bps)
  const affiliates: AffiliateInfo[] = [
    {
      provider: "Provider 1",
      rate: BigInt(350),
      receiver: "DK21qxJuG3VEdh2pSthxRAE9dMXuAf8ph4N3FWxwqi5M",
      network: "solana",
    },
  ];
  const info: ITypes.AffiliateStruct = affiliateInfo(
    aggregatedFeeRate,
    affiliates,
  );

  return info;
}

export function getRFQInfo(): ITypes.RFQInfoStruct {
  const rfqInfo: ITypes.RFQInfoStruct = {
    minAmountOut: parseUnits(rand(1000).toString(), 8),
    tradeTimeout: Math.floor(Date.now() / 1000) + 3600,
    // Temporarily empty, update on test/execution
    rfqInfoSignature: "",
  };

  return rfqInfo;
}

export async function getScriptInfo(
  tradeId: string,
  tradeTimeout: number,
  refundPubkey: BytesLike,
  vault?: BytesLike,
  userL2Address?: string,
): Promise<{
  scriptInfo: ITypes.ScriptInfoStruct;
  ephemeralAssetKey: Keypair;
  ephemeralL2Key: string;
}> {
  const scriptTimeout: number = tradeTimeout + 24 * 3600;

  //  generate:
  //  - `ephemeralAssetKey` and `ephemeralAssetPubkey`
  //  - `ephemeralL2Key` and `ephemeralL2Address`
  const {
    ephemeralAssetKey,
    ephemeralAssetPubkey,
    ephemeralL2Key,
    ephemeralL2Pubkey,
  } = getUserEphemeralKeys(tradeId);
  const ephemeralL2Address: string =
    userL2Address ?? computeAddress(ephemeralL2Pubkey);
  const key: string = getMPCPubkey();
  const mpcAssetKP: Keypair = genSolanaKP(key.slice(0, 64));
  const mpcAssetPubkey: PublicKey = mpcAssetKP.publicKey;

  const vaultAddress: BytesLike =
    vault ?? hexlify(getTradeVaultPda(tradeId).toBytes());
  const scriptInfo: ITypes.ScriptInfoStruct = {
    depositInfo: [
      hexlify(vaultAddress),
      hexlify(randomTxId()), // depositTxId. Note:
      hexlify(ephemeralAssetPubkey), //  ephemeralAssetPubkey
      hexlify(mpcAssetPubkey.toBytes()), //  mpcAssetPubkey (must register in Management)
      hexlify(refundPubkey), // refundAddress (i.e. userKP.publickey.toBytes())
    ],
    userEphemeralL2Address: ephemeralL2Address,
    scriptTimeout: BigInt(scriptTimeout),
  };
  return {
    scriptInfo: scriptInfo,
    ephemeralAssetKey: ephemeralAssetKey,
    ephemeralL2Key: hexlify(ephemeralL2Key),
  };
}

export function getMockPresign(tradeId: string): ITypes.PresignStruct[] {
  const { ephemeralAssetKey } = getUserEphemeralKeys(tradeId);
  const pmmRecvAddress = [
    "DK21qxJuG3VEdh2pSthxRAE9dMXuAf8ph4N3FWxwqi5M",
    "6XHqubPjpxVEh5pnvgtdrSAP3MCsGdwp9YxLh7oYgoeA",
  ];
  let signature: string[] = [];
  for (let i = 0; i < pmmRecvAddress.length; i++) {
    const sig = nacl.sign.detached(
      toUtf8Bytes(pmmRecvAddress[i]),
      ephemeralAssetKey.secretKey,
    );
    signature[i] = Buffer.from(sig).toString("hex");
  }
  const presignSubmission: ITypes.PresignStruct[] = [
    {
      pmmId: keccak256(toUtf8Bytes("PMM Identification 1")),
      pmmRecvAddress: toUtf8Bytes(pmmRecvAddress[0]),
      presigns: [hexlify("0x" + signature[0])],
    },
    {
      pmmId: keccak256(toUtf8Bytes("PMM Identification 2")),
      pmmRecvAddress: toUtf8Bytes(pmmRecvAddress[1]),
      presigns: [hexlify("0x" + signature[1])],
    },
  ];

  return presignSubmission;
}

export async function getPresigns(
  tradeId: string,
  mpcPubkey: PublicKey,
  pmmRecvPubkey: PublicKey,
  connection: Connection,
): Promise<ITypes.PresignStruct[]> {
  const { ephemeralAssetKey } = getUserEphemeralKeys(tradeId);
  const presignature =
    await createUserPresignSettlementTransactionAndSerializeToString({
      connection: connection,
      tradeId: tradeId,
      mpcPubkey: mpcPubkey,
      pmmPubkey: pmmRecvPubkey,
      userEphemeral: ephemeralAssetKey,
    });

  const presignSubmission: ITypes.PresignStruct[] = [
    {
      pmmId: keccak256(toUtf8Bytes("PMM Identification 1")),
      pmmRecvAddress: hexlify(pmmRecvPubkey.toBytes()),
      presigns: [hexlify("0x" + presignature)],
    },
  ];

  return presignSubmission;
}
