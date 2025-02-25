import {
  Wallet,
  keccak256,
  computeAddress,
  parseUnits,
  hexlify,
  toUtf8Bytes,
  BytesLike,
  TypedDataDomain,
  getAddress,
} from "ethers";

import { ITypes } from "../typechain-types/contracts/utils/Core";
import { getMPCPubkey } from "../scripts/utils/bitcoin/btc";
import { affiliateInfo, AffiliateInfo, rand, randomTxId } from "./utils";
import { getUserEphemeralKeys } from "../scripts/utils/evm/evm";
import { getPresignHash } from "../scripts/utils/signatures/getInfoHash";
import { getPresignSignature } from "../scripts/utils/signatures/getSignature";

export function getTradeInfo(
  fromChain: string,
  fromToken: string,
  fromUserAddress: string,
  decimals?: string | number,
): ITypes.TradeInfoStruct {
  const tradeInfo: ITypes.TradeInfoStruct = {
    amountIn: parseUnits((3 * rand(1000)).toString(), decimals ?? "ether"),
    fromChain: [
      hexlify(fromUserAddress), // fromUserAddress
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
  const aggregatedFeeRate: number = 550; //  example 5.5% (bps)
  const affiliates: AffiliateInfo[] = [
    {
      provider: "Provider 1",
      rate: BigInt(350),
      receiver: "0x31003C2D5685c7D28D7174c3255307Eb9a0f3015",
      network: "ethereum",
    },
    {
      provider: "Provider 2",
      rate: BigInt(200),
      receiver: "0xF9F36dC75eAfc38f5e6525fadbA2939FCbC666e0",
      network: "ethereum",
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
  refundAddress: string,
  networkId: BytesLike,
  tokenId: BytesLike,
  vault: string,
  userL2Address?: string,
): Promise<{
  scriptInfo: ITypes.ScriptInfoStruct;
  ephemeralAssetKey: string;
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
  } = await getUserEphemeralKeys(tradeId);
  const ephemeralL2Address: string =
    userL2Address ?? computeAddress(ephemeralL2Pubkey);
  const mpcPubkey: string = getMPCPubkey();

  const scriptInfo: ITypes.ScriptInfoStruct = {
    depositInfo: [
      hexlify(vault),
      hexlify(randomTxId()), // depositTxId
      hexlify(ephemeralAssetPubkey), //  ephemeralAssetPubkey
      hexlify("0x" + mpcPubkey), //  mpcPubkey (must register in Management)
      hexlify(refundAddress), // refundAddress
    ],
    userEphemeralL2Address: ephemeralL2Address,
    scriptTimeout: BigInt(scriptTimeout),
  };
  return {
    scriptInfo: scriptInfo,
    ephemeralAssetKey: hexlify(ephemeralAssetKey),
    ephemeralL2Key: hexlify(ephemeralL2Key),
  };
}

export async function getPresigns(
  tradeId: string,
  amountIn: bigint,
  domain: TypedDataDomain,
): Promise<ITypes.PresignStruct[]> {
  const { ephemeralAssetKey } = await getUserEphemeralKeys(tradeId);
  const wallet = new Wallet(ephemeralAssetKey);

  let pmmRecvAddress: BytesLike[] = [];
  let signature: string[] = [];
  pmmRecvAddress[0] = hexlify("0x31003C2D5685c7D28D7174c3255307Eb9a0f3015");
  pmmRecvAddress[1] = hexlify("0xF9F36dC75eAfc38f5e6525fadbA2939FCbC666e0");

  for (let i = 0; i < pmmRecvAddress.length; i++) {
    const infoHash: string = getPresignHash(
      getAddress(pmmRecvAddress[i].toString()),
      amountIn,
    );
    signature.push(
      await getPresignSignature(wallet, tradeId, infoHash, domain),
    );
  }

  const presignSubmission: ITypes.PresignStruct[] = [
    {
      pmmId: keccak256(toUtf8Bytes("PMM Identification 1")),
      pmmRecvAddress: pmmRecvAddress[0],
      presigns: [hexlify(signature[0])],
    },
    {
      pmmId: keccak256(toUtf8Bytes("PMM Identification 2")),
      pmmRecvAddress: pmmRecvAddress[1],
      presigns: [hexlify(signature[1])],
    },
  ];
  return presignSubmission;
}
