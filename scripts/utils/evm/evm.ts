import { SigningKey, Wallet, keccak256 } from "ethers";
import * as dotenv from "dotenv";
dotenv.config();

export const testCreatorEVMPrivKey = process.env.TESTNET_DEPLOYER as string;

export function getEphemeralPrivateKeys(signature: string): {
  ephemeralAssetKey: string;
  ephemeralL2Key: string;
} {
  const ephemeralAssetKey: string = signature.slice(0, 66);
  const ephemeralL2Key: string = "0x" + signature.slice(-64);

  return { ephemeralAssetKey, ephemeralL2Key };
}

export async function getUserEphemeralKeys(tradeId: string): Promise<{
  ephemeralAssetKey: string;
  ephemeralAssetPubkey: string;
  ephemeralL2Key: string;
  ephemeralL2Pubkey: string;
}> {
  const wallet = new Wallet(testCreatorEVMPrivKey);
  const hash: string = keccak256(tradeId);
  const userSignature: string = await wallet.signMessage(hash);
  const { ephemeralAssetKey, ephemeralL2Key } =
    getEphemeralPrivateKeys(userSignature);
  const aSiginingKey: SigningKey = new SigningKey(ephemeralAssetKey);
  const l2SigningKey: SigningKey = new SigningKey(ephemeralL2Key);

  return {
    ephemeralAssetKey: ephemeralAssetKey,
    ephemeralAssetPubkey: aSiginingKey.compressedPublicKey,
    ephemeralL2Key: ephemeralL2Key,
    ephemeralL2Pubkey: l2SigningKey.compressedPublicKey,
  };
}
