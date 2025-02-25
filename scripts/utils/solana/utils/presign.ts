import {
  AccountMeta,
  Connection,
  Keypair,
  NonceAccount,
  PublicKey,
  SystemProgram,
  Transaction,
} from "@solana/web3.js";
import * as anchor from "@coral-xyz/anchor";
import nacl from "tweetnacl";

import { BitfiSolSmartcontract } from "../types/contract";
import IDL from "../types/idl.json";
import { toBytes32Array } from "./convert";
import { PresignTxData } from "../types/types";
import {
  getAssociatedTokenAddressSync,
  TOKEN_PROGRAM_ID,
} from "@solana/spl-token";

const rpcURL = process.env.SOLANA_RPC_URL as string;

export async function getTransaction(
  params: PresignTxData,
): Promise<Transaction> {
  const {
    tradeId,
    userPubkey,
    mpcPubkey,
    ephemeralAssetPubkey,
    pmmRecvPubkey,
    refundPubkey,
    token,
  } = params;
  const connection = new Connection(rpcURL, "confirmed");
  const program = new anchor.Program(IDL as BitfiSolSmartcontract, {
    connection: connection as any,
  });
  const isToken = token === "native" ? false : true;
  let metaAccounts: AccountMeta[] = [];

  const bTradeId = toBytes32Array(BigInt(tradeId));
  const [tradePDA] = PublicKey.findProgramAddressSync(
    [Buffer.from(bTradeId)],
    program.programId,
  );

  // get nonce account info
  const accountInfo = await connection.getAccountInfo(ephemeralAssetPubkey);
  const nonceAccountData = NonceAccount.fromAccountData(accountInfo!.data);

  if (isToken) {
    const tokenPubkey = new PublicKey(token);
    const [vaultPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("vault")],
      program.programId,
    );
    const [protocolPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("protocol")],
      program.programId,
    );
    const vaultAta = getAssociatedTokenAddressSync(tokenPubkey, vaultPda, true);
    const protocolAta = getAssociatedTokenAddressSync(
      tokenPubkey,
      protocolPda,
      true,
    );
    const pmmAta = getAssociatedTokenAddressSync(
      tokenPubkey,
      pmmRecvPubkey,
      false,
    );
    metaAccounts = [
      {
        pubkey: TOKEN_PROGRAM_ID,
        isSigner: false,
        isWritable: false,
      },
      { pubkey: tokenPubkey, isSigner: false, isWritable: false },
      { pubkey: vaultAta, isSigner: false, isWritable: true },
      { pubkey: pmmAta, isSigner: false, isWritable: true },
      { pubkey: protocolAta, isSigner: false, isWritable: true },
    ];
  }

  const tx = new Transaction()
    .add(
      SystemProgram.nonceAdvance({
        authorizedPubkey: mpcPubkey,
        noncePubkey: ephemeralAssetPubkey,
      }),
    )
    .add(
      await program.methods
        .settlement({
          tradeId: bTradeId,
        })
        .accounts({
          signer: mpcPubkey,
          userEphemeralAccount: ephemeralAssetPubkey,
          userTradeDetail: tradePDA,
          pmm: pmmRecvPubkey,
          refundAccount: refundPubkey,
          userAccount: userPubkey,
        })
        .remainingAccounts(metaAccounts)
        .instruction(),
    );
  // Set the recentBlockhash to the nonce value from the nonce account
  tx.recentBlockhash = nonceAccountData.nonce;
  tx.feePayer = mpcPubkey;

  return tx;
}

export function presign(
  transaction: Transaction,
  ephemeralAssetKey: Keypair,
): string {
  transaction.partialSign(ephemeralAssetKey);
  const serializedTx = transaction.serialize({
    requireAllSignatures: false,
  });

  return Buffer.from(serializedTx).toString("hex");
}

export function isSignedBy(presign: string, signer: PublicKey): boolean {
  const tx = Transaction.from(Buffer.from(presign, "hex"));

  return tx.signatures.some(
    (sig) => sig.publicKey.equals(signer) && sig.signature !== null,
  );
}

export function signatureBy(presign: string, signer: PublicKey): string | null {
  const tx = Transaction.from(Buffer.from(presign, "hex"));
  const sigPair = tx.signatures.find((sig) => sig.publicKey.equals(signer));

  return sigPair?.signature
    ? Buffer.from(sigPair.signature).toString("hex")
    : null;
}

export async function verify(
  presign: string,
  signature: string,
  ephemeralAssetPubkey: PublicKey,
): Promise<boolean> {
  const recoveredTx = Transaction.from(Buffer.from(presign, "hex"));

  return nacl.sign.detached.verify(
    Buffer.from(recoveredTx.serializeMessage()),
    Buffer.from(signature, "hex"),
    ephemeralAssetPubkey.toBytes(),
  );
}
