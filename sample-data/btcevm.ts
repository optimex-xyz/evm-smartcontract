import {
  keccak256,
  computeAddress,
  parseUnits,
  hexlify,
  toUtf8Bytes,
  toBeHex,
} from "ethers";

import { ITypes } from "../typechain-types/contracts/utils/Core";
import { testCreatorKP } from "../scripts/utils/bitcoin/btc";
import {
  getMPCPubkey,
  getTaprootScript,
  getUserEphemeralKeys,
} from "../scripts/utils/bitcoin/btc";
import { regtestUtils } from "../scripts/utils/bitcoin/btc";
import { affiliateInfo, AffiliateInfo, rand, randomTxId } from "./utils";

export function getTradeInfo(
  toChain: string,
  toToken: string,
  toUserAddress: string,
): ITypes.TradeInfoStruct {
  const tradeInfo: ITypes.TradeInfoStruct = {
    amountIn: parseUnits(rand(1000).toString(), 8),
    fromChain: [
      toUtf8Bytes("tb1q85w8v43nj5gq2elmc57fj0jrk8q900sk3udj8h"), //  fromUserAddress
      toUtf8Bytes("bitcoin-testnet"), //  fromChain (must register in Management)
      toUtf8Bytes("native"), //  fromToken (must register in Management)
    ],
    toChain: [
      hexlify(toUserAddress), // toUserAddress
      toUtf8Bytes(toChain), // toChain (must register in Management)
      toUtf8Bytes(toToken), // toToken (must register in Management)
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
      rate: BigInt(250),
      receiver: "tb1q85w8v43nj5gq2elmc57fj0jrk8q900sk3udj8h",
      network: "bitcoin",
    },
    {
      provider: "Provider 2",
      rate: BigInt(100),
      receiver:
        "tb1pr00d3pkyhp7aghwk0y8g7mjsau9hkll3m8djdwqw4eukmw79ym2qp97t3v",
      network: "bitcoin",
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
    minAmountOut: parseUnits((3 * rand(1000)).toString(), "ether"),
    tradeTimeout: Math.floor(Date.now() / 1000) + 3600,
    // Temporarily empty, update on test/execution
    rfqInfoSignature: "",
  };

  return rfqInfo;
}

export function getScriptInfo(
  tradeId: string,
  tradeTimeout: number,
  userL2Address?: string,
): {
  scriptInfo: ITypes.ScriptInfoStruct;
  ephemeralAssetKey: string;
  ephemeralL2Key: string;
} {
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
    userL2Address ?? computeAddress(toBeHex("0x" + ephemeralL2Pubkey));

  const mpcPubkey: string = getMPCPubkey();
  const refundPubkey: Uint8Array = testCreatorKP.publicKey;
  const p2tr = getTaprootScript(
    {
      tradeId: tradeId.slice(2),
      ephemeralL2Address: ephemeralL2Address.slice(2),
      scriptTimeout: scriptTimeout,
      creatorPubkey: hexlify(refundPubkey).slice(2), //  remove "0x"
      ephemeralAssetPubkey: ephemeralAssetPubkey,
      network: regtestUtils.network,
    },
    mpcPubkey,
  );
  // const { words } = bech32m.decode(p2tr.p2tr.address as string);
  // const witness: Uint8Array = Buffer.from(bech32m.fromWords(words.slice(1)));
  const scriptInfo: ITypes.ScriptInfoStruct = {
    depositInfo: [
      toUtf8Bytes(p2tr.p2tr.address as string),
      // hexlify(witness),
      hexlify(randomTxId()), // depositTxId
      hexlify("0x" + ephemeralAssetPubkey), //  ephemeralAssetPubkey
      hexlify("0x" + mpcPubkey), //  mpcPubkey (must register in Management)
      hexlify(refundPubkey), // refundPubkey
    ],
    userEphemeralL2Address: ephemeralL2Address,
    scriptTimeout: BigInt(scriptTimeout),
  };
  return {
    scriptInfo: scriptInfo,
    ephemeralAssetKey: hexlify("0x" + ephemeralAssetKey),
    ephemeralL2Key: hexlify("0x" + ephemeralL2Key),
  };
}

export function getPresigns(): ITypes.PresignStruct[] {
  const presignSubmission: ITypes.PresignStruct[] = [
    {
      pmmId: keccak256(toUtf8Bytes("PMM Identification 1")),
      pmmRecvAddress: toUtf8Bytes("tb1q85w8v43nj5gq2elmc57fj0jrk8q900sk3udj8h"),
      presigns: [toUtf8Bytes("presign 1")],
    },
    {
      pmmId: keccak256(toUtf8Bytes("PMM Identification 2")),
      pmmRecvAddress: toUtf8Bytes(
        "tb1pr00d3pkyhp7aghwk0y8g7mjsau9hkll3m8djdwqw4eukmw79ym2qp97t3v",
      ),
      presigns: [toUtf8Bytes("presign 2")],
    },
  ];
  return presignSubmission;
}
