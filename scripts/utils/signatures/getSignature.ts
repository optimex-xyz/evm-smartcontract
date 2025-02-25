import { TypedDataDomain, BytesLike, Wallet, verifyTypedData } from "ethers";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";

import {
  presignType,
  confirmDepositType,
  selectionType,
  rfqAuthenticationTypes,
  makePaymentType,
  confirmPaymentType,
  confirmSettlementType,
  settlementType,
} from "./types";

export enum SignatureType {
  ConfirmDeposit,
  SelectPMM,
  RFQ,
  MakePayment,
  ConfirmPayment,
  ConfirmSettlement,
}

function getSignatureType(type: SignatureType): any {
  if (type === SignatureType.ConfirmDeposit) return confirmDepositType;
  else if (type === SignatureType.SelectPMM) return selectionType;
  else if (type === SignatureType.RFQ) return rfqAuthenticationTypes;
  else if (type === SignatureType.MakePayment) return makePaymentType;
  else if (type === SignatureType.ConfirmPayment) return confirmPaymentType;
  else if (type === SignatureType.ConfirmSettlement)
    return confirmSettlementType;
  else throw new Error("Invalid signature type!");
}

export async function getSigner(
  tradeId: BytesLike,
  infoHash: BytesLike,
  type: SignatureType,
  signature: string,
  domain: TypedDataDomain,
) {
  const values = { tradeId: tradeId, infoHash: infoHash };
  return verifyTypedData(domain, getSignatureType(type), values, signature);
}

export default async function getSignature(
  Signer: HardhatEthersSigner | Wallet,
  tradeId: BytesLike,
  infoHash: BytesLike,
  type: SignatureType,
  domain: TypedDataDomain,
): Promise<string> {
  let values: any;
  if (type === SignatureType.MakePayment) values = { infoHash };
  else values = { tradeId: tradeId, infoHash: infoHash };

  return await Signer.signTypedData(domain, getSignatureType(type), values);
}

export async function getPresignSigner(
  tradeId: BytesLike,
  infoHash: BytesLike,
  signature: string,
  domain: TypedDataDomain,
) {
  const values = { tradeId: tradeId, infoHash: infoHash };
  return verifyTypedData(domain, presignType, values, signature);
}

export async function getPresignSignature(
  Signer: HardhatEthersSigner | Wallet,
  tradeId: BytesLike,
  infoHash: BytesLike,
  domain: TypedDataDomain,
): Promise<string> {
  const values = { tradeId: tradeId, infoHash: infoHash };
  return await Signer.signTypedData(domain, presignType, values);
}

export async function getSettlementSigner(
  totalFee: bigint,
  presign: BytesLike,
  signature: string,
  domain: TypedDataDomain,
) {
  const values = { totalFee: totalFee, presign: presign };
  return verifyTypedData(domain, settlementType, values, signature);
}

export async function getSettlementSignature(
  Signer: HardhatEthersSigner | Wallet,
  totalFee: bigint,
  presign: BytesLike,
  domain: TypedDataDomain,
): Promise<string> {
  const values = { totalFee: totalFee, presign: presign };
  return await Signer.signTypedData(domain, settlementType, values);
}
