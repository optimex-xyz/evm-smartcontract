import { PublicKey } from "@solana/web3.js";

export type PresignTxData = {
  tradeId: string;
  token: string;
  userPubkey: PublicKey;
  mpcPubkey: PublicKey;
  ephemeralAssetPubkey: PublicKey;
  pmmRecvPubkey: PublicKey;
  refundPubkey: PublicKey;
};
