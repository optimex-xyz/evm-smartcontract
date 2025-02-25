import { keccak256, toUtf8Bytes, AbiCoder } from "ethers";

import { ITypes } from "../typechain-types/contracts/BTCEVM";

const abiCoder = AbiCoder.defaultAbiCoder();

export type AffiliateInfo = {
  provider: string;
  rate: BigInt;
  receiver: string;
  network: string;
};

const sampleSchema = {
  format: "json",
  encoding: "abi.encode",
  schema: {
    affiliates: [
      {
        provider: "string",
        rate: "uint256",
        receiver: "string",
        network: "string",
      },
    ],
  },
};

function encodeData(affiliates: AffiliateInfo[]): string {
  const formattedData = affiliates.map(
    ({ provider, rate, receiver, network }) => [
      provider,
      rate.toString(),
      receiver,
      network,
    ],
  );
  const encoded: string = abiCoder.encode(
    ["tuple(string,uint256,string,string)[]"],
    [formattedData],
  );

  return encoded;
}

function decodeData(encodedData: string): AffiliateInfo[] {
  const decoded = abiCoder.decode(
    ["tuple(string,uint256,string,string)[]"],
    encodedData,
  )[0];

  return decoded.map((tuple: any) => ({
    provider: tuple[0],
    rate: BigInt(tuple[1]),
    receiver: tuple[2],
    network: tuple[3],
  }));
}

export const sessionId: bigint = BigInt(
  keccak256(toUtf8Bytes(crypto.randomUUID())),
);

export const randomTxId = (): string => {
  return keccak256(toUtf8Bytes(crypto.randomUUID()));
};

export function rand(maxValue: number): number {
  return Math.floor(Math.random() * maxValue) + 10;
}

export function affiliateInfo(
  aggregatedFeeRate: number | string,
  affiliates: AffiliateInfo[],
): ITypes.AffiliateStruct {
  const value: bigint = BigInt(aggregatedFeeRate);
  if (value > BigInt(10_000))
    throw new Error("Aggregated Fee Rate exceed max limit");

  const schema: string = JSON.stringify(sampleSchema);
  const encodedData: string = encodeData(affiliates);

  const affiliate: ITypes.AffiliateStruct = {
    aggregatedValue: BigInt(aggregatedFeeRate), //  example affiliateFeeRate = 2.5% = 250 / 10_000
    schema: schema,
    data: encodedData,
  };

  return affiliate;
}
