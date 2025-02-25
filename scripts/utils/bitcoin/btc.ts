import * as tools from "uint8array-tools";
import {
  Network,
  payments,
  script,
  crypto,
  networks,
  initEccLib,
} from "bitcoinjs-lib";
import { SHA256 } from "crypto-js";
import { sha256 } from "@noble/hashes/sha256";
import { RegtestUtils } from "regtest-client";
import ECPairFactory from "ecpair";
import * as ecc from "tiny-secp256k1";
import * as ecp from "@bitcoinerlab/secp256k1";
import * as dotenv from "dotenv";
dotenv.config();

initEccLib(ecc);

const APIPASS = "satoshi";
const APIURL = "https://regtest.bitbank.cc/1";

export const regtestUtils = new RegtestUtils({ APIPASS, APIURL });

export const ECPair = ECPairFactory(ecp);

//  NOTE: Only using for mocking data in test
export const testCreatorKP = ECPair.fromWIF(
  "cScfkGjbzzoeewVWmU2hYPUHeVGJRDdFt7WhmrVVGkxpmPP8BHWe",
  networks.regtest,
);
export const testMPCKP = ECPair.fromWIF(
  "cMkopUXKWsEzAjfa1zApksGRwjVpJRB3831qM9W4gKZsLwjHXA9x",
  networks.regtest,
);

export const testCreatorEVMPrivKey = process.env.TESTNET_DEPLOYER as string;

export const getEcpairFromPrivateKey = (
  privateKey: string,
  network: Network = networks.regtest,
) => {
  return ECPair.fromPrivateKey(Buffer.from(privateKey, "hex"), {
    network,
  });
};

export interface RedemptionScript {
  tradeId: string;
  network: Network;
  creatorPubkey: string; //  refundPubkey (bitcoin)
  ephemeralAssetPubkey: string;
  ephemeralL2Address: string;
  scriptTimeout: number;
}

export interface Tapleaf {
  output: Uint8Array;
  version?: number;
}

const removePrefix = (data: string) => {
  return data.startsWith("0x") ? data.slice(2) : data;
};

const toXCoordinate = (pubKey: Uint8Array) =>
  pubKey.length === 32 ? pubKey : pubKey.slice(1, 33);

/**
 * Ref: https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs
 * @param provableNonce
 */
const makeUnspendableInternalKey = (provableNonce?: Uint8Array): Uint8Array => {
  // This is the generator point of secp256k1. Private key is known (equal to 1)
  const G = Buffer.from(
    "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
    "hex",
  );
  // This is the hash of the uncompressed generator point.
  // It is also a valid X value on the curve, but we don't know what the private key is.
  // Since we know this X value (a fake "public key") is made from a hash of a well known value,
  // We can prove that the internalKey is unspendable.
  const Hx = sha256(G);

  // This "Nothing Up My Sleeve" value is mentioned in BIP341 so we verify it here:
  if (
    tools.toHex(Hx) !==
    "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
  ) {
    throw new Error("Invalid Nothing Up My Sleeve value");
  }

  if (provableNonce) {
    if (provableNonce.length !== 32) {
      throw new Error(
        "provableNonce must be a 32 byte random value shared between script holders",
      );
    }
    // Using a shared random value, we create an unspendable internalKey
    // P = H + int(hash_taptweak(provableNonce))*G
    // Since we don't know H's private key (see explanation above), we can't know P's private key
    const tapHash = crypto.taggedHash("TapTweak", provableNonce);
    const ret = ecc.xOnlyPointAddTweak(Hx, tapHash);
    if (!ret) {
      throw new Error(
        "provableNonce produced an invalid key when tweaking the G hash",
      );
    }
    return Buffer.from(ret.xOnlyPubkey);
  } else {
    // The downside to using no shared provable nonce is that anyone viewing a spend
    // on the blockchain can KNOW that you CAN'T use key spend.
    // Most people would be ok with this being public, but some wallets (exchanges etc)
    // might not want ANY details about how their wallet works public.
    return Hx;
  }
};

export function getMPCPubkey(): string {
  // TODO: Load from MPC insead of hardcoding
  // mocking data
  return "038f0248cc0bebc425eb55af1689a59f88119c69430a860c6a05f340e445c417d7";
}

export function getEphemeralPrivateKeys(signature: string): {
  ephemeralAssetKey: string;
  ephemeralL2Key: string;
} {
  const ephemeralAssetKey: string = Buffer.from(
    tools.fromHex(signature!).slice(0, 32),
  ).toString("hex");
  const ephemeralL2Key: string = Buffer.from(
    tools.fromHex(signature!).slice(-32),
  ).toString("hex");

  return { ephemeralAssetKey, ephemeralL2Key };
}

export function getUserEphemeralKeys(tradeId: string): {
  ephemeralAssetKey: string;
  ephemeralAssetPubkey: string;
  ephemeralL2Key: string;
  ephemeralL2Pubkey: string;
} {
  const hash: string = SHA256(tradeId).toString();
  const userSignature = Buffer.from(
    testCreatorKP.sign(Buffer.from(hash, "hex")),
  ).toString("hex");
  const { ephemeralAssetKey, ephemeralL2Key } =
    getEphemeralPrivateKeys(userSignature);
  const ephemeralAssetKP = getEcpairFromPrivateKey(ephemeralAssetKey);
  const ephemeralL2KP = getEcpairFromPrivateKey(ephemeralL2Key);

  return {
    ephemeralAssetKey: ephemeralAssetKey,
    ephemeralAssetPubkey: tools.toHex(ephemeralAssetKP.publicKey),
    ephemeralL2Key: ephemeralL2Key,
    ephemeralL2Pubkey: tools.toHex(ephemeralL2KP.publicKey),
  };
}

export function getTaprootScriptTree(
  redemption: RedemptionScript,
  mpcPubkey: string,
) {
  //  `scriptTimeout` no longer be the timestamp. Instead, it stores a number of blocks
  const scriptTimeout = redemption.scriptTimeout || 0;

  const mpcScriptPath: Tapleaf = {
    output: (() => {
      const input = [
        tools.toHex(toXCoordinate(tools.fromHex(mpcPubkey))),
        "OP_CHECKSIG",
        tools.toHex(
          toXCoordinate(tools.fromHex(redemption.ephemeralAssetPubkey)),
        ),
        "OP_CHECKSIGADD",
        "OP_2",
        "OP_NUMEQUAL",
      ].join(" ");
      // console.log("MPC script input:", input);
      return script.fromASM(input);
    })(),
  };

  const creatorScriptPath: Tapleaf = {
    output: (() => {
      const input = [
        tools.toHex(script.number.encode(scriptTimeout)),
        "OP_CHECKSEQUENCEVERIFY",
        "OP_DROP",
        tools.toHex(toXCoordinate(tools.fromHex(redemption.creatorPubkey))),
        "OP_CHECKSIG",
      ].join(" ");
      // console.log("Creator script input:", input);
      return script.fromASM(input);
    })(),
  };

  const metadataScriptPath: Tapleaf = {
    output: (() => {
      const input = [
        removePrefix(redemption.tradeId),
        "OP_DROP",
        removePrefix(redemption.ephemeralL2Address!),
        "OP_RETURN",
      ].join(" ");
      // console.log("Metadata script input:", input);
      return script.fromASM(input);
    })(),
  };

  return {
    scriptTree: [mpcScriptPath, [creatorScriptPath, metadataScriptPath]] as [
      Tapleaf,
      [Tapleaf, Tapleaf],
    ],
  };
}

export function getTaprootScript(
  redemption: RedemptionScript,
  mpcPubkey: string,
) {
  const { scriptTree } = getTaprootScriptTree(redemption, mpcPubkey);

  const internalPubkey = makeUnspendableInternalKey(
    tools.fromHex(redemption.tradeId),
  );
  const p2tr = payments.p2tr({
    internalPubkey: toXCoordinate(internalPubkey),
    scriptTree,
    network: redemption.network,
  });

  return {
    p2tr: p2tr,
    scriptTree: scriptTree,
  };
}

//  Old BTC Script
export function getP2SH(redemption: RedemptionScript) {
  const scriptTimeout = redemption.scriptTimeout || 0;

  const p2sh = payments.p2sh({
    network: redemption.network,
    redeem: {
      output: script.fromASM(
        `
        OP_IF
          ${redemption.tradeId}
          OP_DROP
          ${redemption.ephemeralL2Address}
          OP_DROP
          ${tools.toHex(script.number.encode(scriptTimeout))}
          OP_CHECKLOCKTIMEVERIFY
          OP_DROP
          ${redemption.creatorPubkey}
          OP_CHECKSIG
        OP_ELSE
            OP_2
            ${getMPCPubkey()}
            ${redemption.ephemeralAssetPubkey}
            OP_2
            OP_CHECKMULTISIG
        OP_ENDIF
      `
          .trim()
          .replace(/\s+/g, " "),
      ),
    },
  });

  return {
    p2sh,
    scriptTimeout,
  };
}
