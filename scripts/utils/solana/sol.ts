import nacl from "tweetnacl";
import bs58 from "bs58";
import { Keypair } from "@solana/web3.js";
import { getBytes, keccak256, toUtf8Bytes, SigningKey, hexlify } from "ethers";

//  User's secret key using in local testing ONLY
export const userSKAsBytes =
  "dfa2a6dc1f2288a895ec832dc2a48876fedd8dc72658f16b2e060c4106f5acf058a9de1a5540d132e957c808fbe1ae110063793ee8030d20e6ac8d54020a4e0f";
export const userSKAsBase58 =
  "5UL5G5HamxwgPtmgeqMFxm84x6cRKKzHMwKbzcGWXQRJsQKZQqHPMHV8kCjispEEfF3BG8cpexPZr8BTAneJJqCz";

export const testUserKP = Keypair.fromSecretKey(getBytes("0x" + userSKAsBytes));

// export const testUserKP = Keypair.fromSecretKey(bs58.decode(userSKAsBase58)); // use this option for base58 secret key

function reverse(key: string): string {
  return key.split("").reverse().join("");
}

export function genSolanaKP(privkey: string) {
  const key: string = privkey.startsWith("0x") ? privkey : "0x" + privkey;
  return Keypair.fromSeed(getBytes(key));
}

export function getEphemeralPrivateKeys(signature: string): {
  ephemeralAssetKey: string;
  ephemeralL2Key: string;
} {
  //  If `signature` has a prefix "0x", then remove it
  const seed: string = signature.startsWith("0x")
    ? signature.slice(2)
    : signature;
  if (seed.length < 64) throw new Error("Invalid signature length");

  const ephemeralAssetKey: string = "0x" + reverse(seed.slice(0, 64));
  const ephemeralL2Key: string = "0x" + seed.slice(-64);

  return { ephemeralAssetKey, ephemeralL2Key };
}

export function getUserEphemeralKeys(tradeId: string): {
  ephemeralAssetKey: Keypair;
  ephemeralAssetPubkey: string;
  ephemeralL2Key: string;
  ephemeralL2Pubkey: string;
} {
  const hash: string = keccak256(tradeId);
  const signature = nacl.sign.detached(toUtf8Bytes(hash), testUserKP.secretKey);
  const { ephemeralAssetKey, ephemeralL2Key } = getEphemeralPrivateKeys(
    Buffer.from(signature).toString("hex"),
  );

  const aSiginingKey = genSolanaKP(ephemeralAssetKey);
  const l2SigningKey: SigningKey = new SigningKey(ephemeralL2Key);

  return {
    ephemeralAssetKey: aSiginingKey,
    ephemeralAssetPubkey: hexlify(aSiginingKey.publicKey.toBytes()),
    ephemeralL2Key: ephemeralL2Key,
    ephemeralL2Pubkey: l2SigningKey.compressedPublicKey,
  };
}
