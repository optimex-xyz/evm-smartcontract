import { expect } from "chai";
import { ethers, network } from "hardhat";
import {
  BytesLike,
  ZeroAddress,
  Wallet,
  keccak256,
  hexlify,
  toUtf8Bytes,
  parseUnits,
  AbiCoder,
  TypedDataDomain,
  getBytes,
  toBeHex,
  ZeroHash,
} from "ethers";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";
import { Keypair, PublicKey } from "@solana/web3.js";
import { time, takeSnapshot } from "@nomicfoundation/hardhat-network-helpers";
import { HardhatEthersProvider } from "@nomicfoundation/hardhat-ethers/internal/hardhat-ethers-provider";

import {
  Management,
  Management__factory,
  SOLBTC,
  SOLBTC__factory,
  Router,
  Router__factory,
  Signer as SignerHelper,
  Signer__factory as SignerHelperFactory,
} from "../typechain-types";
import { ITypes as CoreTypes } from "../typechain-types/contracts/utils/Core";
import { ITypes as ManagementTypes } from "../typechain-types/contracts/Management";
import { randomTxId } from "../sample-data/utils";
import {
  getAffiliateInfo,
  getMockPresign,
  getRFQInfo,
  getScriptInfo,
  getTradeInfo,
} from "../sample-data/solbtc";
import getTradeId from "../scripts/utils/others/getTradeId";
import { testMPCKP } from "../scripts/utils/bitcoin/btc";
import { getEIP712Domain } from "../scripts/utils/evm/getEIP712Domain";
import { testUserKP } from "../scripts/utils/solana/sol";
import {
  getConfirmPaymentHash,
  getConfirmSettlementHash,
  getDepositConfirmationHash,
  getMakePaymentHash,
  getRFQHash,
  getSelectPMMHash,
} from "../scripts/utils/signatures/getInfoHash";
import getSignature, {
  SignatureType,
} from "../scripts/utils/signatures/getSignature";
import { hex } from "@coral-xyz/anchor/dist/cjs/utils/bytes";

enum STAGE {
  SUBMIT,
  CONFIRM_DEPOSIT,
  SELECT_PMM,
  MAKE_PAYMENT,
  CONFIRM_PAYMENT,
  CONFIRM_SETTLEMENT,
  COMPLETE,
}

const provider = ethers.provider;
const abiCoder = AbiCoder.defaultAbiCoder();
const DENOM: bigint = BigInt(10_000);
const decimals = 9;
const MAX_UINT64 = BigInt("18446744073709551615");
const MAX_AFFILIATE_FEE_RATE = BigInt(1_000); // 10%
const ZERO_VALUE = BigInt(0);

const EMPTY_BYTES = hexlify("0x");
const EMPTY_TRADE_DATA = [
  BigInt(0), // sessionId
  [
    //  tradeInfo
    BigInt(0), //  amountIn
    [EMPTY_BYTES, EMPTY_BYTES, EMPTY_BYTES], //  fromChain
    [EMPTY_BYTES, EMPTY_BYTES, EMPTY_BYTES], //  toChain
  ],
  [
    //  scriptInfo
    [EMPTY_BYTES, EMPTY_BYTES, EMPTY_BYTES, EMPTY_BYTES, EMPTY_BYTES], //  depositInfo
    ZeroAddress, //  userEphemeralL2Address
    BigInt(0), //  scriptTimeout
  ],
];
const EMPTY_PRESIGNS: CoreTypes.PresignStruct[] = [];
const EMPTY_FEE_DETAILS = [
  BigInt(0),
  BigInt(0),
  BigInt(0),
  BigInt(0),
  BigInt(0),
];
const EMPTY_AFFILIATE_INFO = [BigInt(0), "", EMPTY_BYTES];
const EMPTY_DEPOSIT_ADDRESS_LIST: BytesLike[] = [];
const EMPTY_PMM_SELECTION_INFO = [
  [BigInt(0), BigInt(0), EMPTY_BYTES], // RFQInfo
  [BigInt(0), ZeroHash, [EMPTY_BYTES, EMPTY_BYTES], BigInt(0)], // SelectedPMMInfo
];
const EMPTY_SETTLED_PAYMENT = [ZeroHash, EMPTY_BYTES, EMPTY_BYTES, false];

function bundlerHash(tradeIds: BytesLike[]): string {
  return keccak256(abiCoder.encode(["bytes32[]"], [tradeIds]));
}

async function adjustTime(nextTimestamp: number): Promise<void> {
  await time.increaseTo(nextTimestamp);
}

async function getBlockTimestamp(provider: HardhatEthersProvider) {
  const block = await provider.getBlockNumber();
  const timestamp = (await provider.getBlock(block))?.timestamp as number;

  return timestamp;
}

describe("Router-SOLBTC Contract Testing", () => {
  let admin: HardhatEthersSigner, solver: HardhatEthersSigner;
  let mpcL2: Wallet, mpcAssetPubkey: PublicKey;
  let mpcNode1: HardhatEthersSigner, mpcNode2: HardhatEthersSigner;
  let accounts: HardhatEthersSigner[];
  let user: Keypair;

  let management: Management, solbtc: SOLBTC;
  let signerHelper: SignerHelper, router: Router;

  let btcTokenInfo: ManagementTypes.TokenInfoStruct,
    solNativeInfo: ManagementTypes.TokenInfoStruct;

  let tradeInfo: CoreTypes.TradeInfoStruct[] = [];
  let affiliateInfo: CoreTypes.AffiliateStruct[] = [];
  let rfqInfo: CoreTypes.RFQInfoStruct[] = [];
  let scriptInfo: CoreTypes.ScriptInfoStruct[] = [];
  let presigns: CoreTypes.PresignStruct[][] = [];
  let tradeId: string[] = [];
  let amountOut: bigint[] = [];
  let sessionId: bigint[] = [];
  let ephemeralL2Wallet: Wallet[] = [];
  let pFeeAmount: bigint[] = [];
  let aFeeAmount: bigint[] = [];
  let paymentTxId: string[] = [];
  let releaseTxId: string[] = [];
  let domain: TypedDataDomain;
  let savedSignedAt: bigint;

  const pFeeRate: bigint = BigInt(50);
  const fromChain = "solana-devnet";
  const fromToken = "native";

  before(async () => {
    await network.provider.request({
      method: "hardhat_reset",
      params: [],
    });

    [admin, solver, mpcNode1, mpcNode2, ...accounts] =
      await ethers.getSigners();
    user = testUserKP;

    //  Deploy Management contract
    const Management = (await ethers.getContractFactory(
      "Management",
      admin,
    )) as Management__factory;
    management = await Management.deploy(admin.address, pFeeRate);

    //  Deploy Signer contract
    const SignerFactory = (await ethers.getContractFactory(
      "Signer",
      admin,
    )) as SignerHelperFactory;
    // @ts-ignore
    signerHelper = await SignerFactory.deploy();

    //  Deploy Router contract
    const Router = (await ethers.getContractFactory(
      "Router",
      admin,
    )) as Router__factory;
    router = await Router.deploy(
      await management.getAddress(),
      await signerHelper.getAddress(),
    );

    //  Deploy solbtc contract
    const SOLBTC = (await ethers.getContractFactory(
      "SOLBTC",
      admin,
    )) as SOLBTC__factory;
    solbtc = await SOLBTC.deploy(await router.getAddress());

    //  set `maxAffiliateFeeRate`
    await solbtc.connect(admin).setMaxAffiliateFeeRate(MAX_AFFILIATE_FEE_RATE);

    //  generate eip-712 domain
    domain = await getEIP712Domain(await signerHelper.getAddress(), admin);

    //  Whitelist Solver and MPC Node associated accounts
    await management.connect(admin).setSolver(solver.address, true);
    await management.connect(admin).setMPCNode(mpcNode1.address, true);
    await management.connect(admin).setMPCNode(mpcNode2.address, true);

    //  Generate MPC Wallet
    const mpcPrivkey = hexlify(testMPCKP.privateKey as Uint8Array);
    mpcL2 = new Wallet(mpcPrivkey, provider);

    //  Prepare trade data
    for (let i = 0; i < 3; i++) {
      sessionId[i] = BigInt(keccak256(toUtf8Bytes(crypto.randomUUID())));
      tradeInfo[i] = getTradeInfo(
        fromChain,
        fromToken,
        user.publicKey,
        decimals,
      );
      affiliateInfo.push(getAffiliateInfo());
      rfqInfo[i] = getRFQInfo();
      tradeId[i] = getTradeId(
        sessionId[i],
        i % 2 == 0 ? solver.address : admin.address,
        tradeInfo[i],
      );
      const { scriptInfo: info, ephemeralL2Key } = await getScriptInfo(
        tradeId[i],
        Number(rfqInfo[i].tradeTimeout),
        user.publicKey.toBytes(),
      );
      scriptInfo[i] = structuredClone(info);
      ephemeralL2Wallet[i] = new Wallet(ephemeralL2Key, provider);
      presigns[i] = getMockPresign(tradeId[i]);

      paymentTxId[i] = randomTxId();
      releaseTxId[i] = randomTxId();
      pFeeAmount[i] = (BigInt(tradeInfo[i].amountIn) * pFeeRate) / DENOM;
      aFeeAmount.push(
        (BigInt(tradeInfo[i].amountIn) *
          BigInt(affiliateInfo[i].aggregatedValue)) /
          DENOM,
      );
    }

    solNativeInfo = {
      info: [
        tradeInfo[0].fromChain[2], // tokenId
        tradeInfo[0].fromChain[1], // networkId
        toUtf8Bytes("SOL"), // symbol
        toUtf8Bytes("https://explorer.solana.com/?cluster=devnet"),
        toUtf8Bytes("Native SOL (SOL) - Solana Devnet"),
      ],
      decimals: BigInt(decimals),
    };

    btcTokenInfo = {
      info: [
        tradeInfo[0].toChain[2], // tokenId
        tradeInfo[0].toChain[1], // networkId
        toUtf8Bytes("BTC"), // symbol
        toUtf8Bytes("https://example.com"),
        toUtf8Bytes("Bitcoin (BTC) - Bitcoin Testnet Token"),
      ],
      decimals: BigInt(8),
    };

    //  Set `fromNetworkId` and `toNetworkId` in the Management
    //  Note: `networkId` is registered if and only if
    //  there's at least one Token being supported
    await management.connect(admin).setToken(btcTokenInfo);
    await management.connect(admin).setToken(solNativeInfo);
    await router
      .connect(admin)
      .setRoute(
        await solbtc.getAddress(),
        tradeInfo[0].fromChain[1],
        tradeInfo[0].toChain[1],
      );

    // set PMM
    await management
      .connect(admin)
      .setPMM(presigns[0][0].pmmId, accounts[0].address);
    await management
      .connect(admin)
      .setPMM(presigns[0][1].pmmId, accounts[1].address);

    //  set MPC
    mpcAssetPubkey = new PublicKey(getBytes(scriptInfo[0].depositInfo[3]));
    const mpcInfo: ManagementTypes.MPCInfoStruct = {
      mpcL2Address: mpcL2.address,
      expireTime: MAX_UINT64,
      mpcAssetPubkey: scriptInfo[0].depositInfo[3],
      mpcL2Pubkey: mpcL2.signingKey.compressedPublicKey, //  For Solana, `mpcAssetPubkey` != `mpcL2Pubkey`
    };
    const prevExpireTime = BigInt(0);
    await management
      .connect(admin)
      .setMPCInfo(tradeInfo[0].fromChain[1], mpcInfo, prevExpireTime);
  });

  describe("submitTrade() functional testing", async () => {
    it("Should revert when Unauthorized client, an arbitrary account, tries to submit Trade Info", async () => {
      const tradeData: CoreTypes.TradeDataStruct = {
        sessionId: sessionId[0],
        tradeInfo: tradeInfo[0],
        scriptInfo: scriptInfo[0],
      };

      await expect(
        router
          .connect(accounts[0])
          .submitTrade(tradeId[0], tradeData, affiliateInfo[0], presigns[0]),
      ).to.be.revertedWithCustomError(solbtc, "Unauthorized");

      expect(await solbtc.currentStage(tradeId[0])).deep.eq(STAGE.SUBMIT);
      expect(await solbtc.trade(tradeId[0])).deep.eq(EMPTY_TRADE_DATA);
      expect(await solbtc.presign(tradeId[0])).deep.eq(EMPTY_PRESIGNS);
      expect(await solbtc.affiliate(tradeId[0])).deep.eq(EMPTY_AFFILIATE_INFO);
      expect(await solbtc.feeDetails(tradeId[0])).deep.eq(EMPTY_FEE_DETAILS);
    });

    it("Should revert when Unauthorized client, the MPC, tries to submit Trade Info", async () => {
      const tradeData: CoreTypes.TradeDataStruct = {
        sessionId: sessionId[0],
        tradeInfo: tradeInfo[0],
        scriptInfo: scriptInfo[0],
      };

      await expect(
        router
          .connect(mpcNode1)
          .submitTrade(tradeId[0], tradeData, affiliateInfo[0], presigns[0]),
      ).to.be.revertedWithCustomError(solbtc, "Unauthorized");

      expect(await solbtc.currentStage(tradeId[0])).deep.eq(STAGE.SUBMIT);
      expect(await solbtc.trade(tradeId[0])).deep.eq(EMPTY_TRADE_DATA);
      expect(await solbtc.presign(tradeId[0])).deep.eq(EMPTY_PRESIGNS);
      expect(await solbtc.affiliate(tradeId[0])).deep.eq(EMPTY_AFFILIATE_INFO);
      expect(await solbtc.feeDetails(tradeId[0])).deep.eq(EMPTY_FEE_DETAILS);
    });

    it("Should revert when Unauthorized client, the Admin, tries to submit Trade Info", async () => {
      const tradeData: CoreTypes.TradeDataStruct = {
        sessionId: sessionId[0],
        tradeInfo: tradeInfo[0],
        scriptInfo: scriptInfo[0],
      };

      await expect(
        router
          .connect(admin)
          .submitTrade(tradeId[0], tradeData, affiliateInfo[0], presigns[0]),
      ).to.be.revertedWithCustomError(solbtc, "Unauthorized");

      expect(await solbtc.currentStage(tradeId[0])).deep.eq(STAGE.SUBMIT);
      expect(await solbtc.trade(tradeId[0])).deep.eq(EMPTY_TRADE_DATA);
      expect(await solbtc.presign(tradeId[0])).deep.eq(EMPTY_PRESIGNS);
      expect(await solbtc.affiliate(tradeId[0])).deep.eq(EMPTY_AFFILIATE_INFO);
      expect(await solbtc.feeDetails(tradeId[0])).deep.eq(EMPTY_FEE_DETAILS);
    });

    it("Should revert when Solver submits the Trade Info, but the protocol is triggered the Suspension Mode", async () => {
      //  temporarily set the Protocol to the `SUSPEND` State
      await management.connect(admin).suspend();

      const tradeData: CoreTypes.TradeDataStruct = {
        sessionId: sessionId[0],
        tradeInfo: tradeInfo[0],
        scriptInfo: scriptInfo[0],
      };

      await expect(
        router
          .connect(solver)
          .submitTrade(tradeId[0], tradeData, affiliateInfo[0], presigns[0]),
      ).to.be.revertedWithCustomError(solbtc, "InSuspension");

      expect(await solbtc.currentStage(tradeId[0])).deep.eq(STAGE.SUBMIT);
      expect(await solbtc.trade(tradeId[0])).deep.eq(EMPTY_TRADE_DATA);
      expect(await solbtc.presign(tradeId[0])).deep.eq(EMPTY_PRESIGNS);
      expect(await solbtc.affiliate(tradeId[0])).deep.eq(EMPTY_AFFILIATE_INFO);
      expect(await solbtc.feeDetails(tradeId[0])).deep.eq(EMPTY_FEE_DETAILS);

      //  set back to normal
      await management.connect(admin).resume();
    });

    it("Should revert when Solver submits the Trade Info, but the protocol is triggered the Shutdown Mode", async () => {
      //  temporarily set the Protocol to the `SHUTDOWN` State
      await management.connect(admin).shutdown();

      const tradeData: CoreTypes.TradeDataStruct = {
        sessionId: sessionId[0],
        tradeInfo: tradeInfo[0],
        scriptInfo: scriptInfo[0],
      };

      await expect(
        router
          .connect(solver)
          .submitTrade(tradeId[0], tradeData, affiliateInfo[0], presigns[0]),
      ).to.be.revertedWithCustomError(solbtc, "InSuspension");

      expect(await solbtc.currentStage(tradeId[0])).deep.eq(STAGE.SUBMIT);
      expect(await solbtc.trade(tradeId[0])).deep.eq(EMPTY_TRADE_DATA);
      expect(await solbtc.presign(tradeId[0])).deep.eq(EMPTY_PRESIGNS);
      expect(await solbtc.affiliate(tradeId[0])).deep.eq(EMPTY_AFFILIATE_INFO);
      expect(await solbtc.feeDetails(tradeId[0])).deep.eq(EMPTY_FEE_DETAILS);

      //  set back to normal
      await management.connect(admin).resume();
    });

    it("Should revert when Solver submits the Trade Info, but tradeId not match an expected tradeId - Un-matched sessionId", async () => {
      const invalidSessionId: bigint = BigInt(
        keccak256(toUtf8Bytes(crypto.randomUUID())),
      );
      const invalidTradeId: string = getTradeId(
        invalidSessionId,
        solver.address,
        tradeInfo[0],
      );
      const tradeData: CoreTypes.TradeDataStruct = {
        sessionId: sessionId[0],
        tradeInfo: tradeInfo[0],
        scriptInfo: scriptInfo[0],
      };

      await expect(
        router
          .connect(solver)
          .submitTrade(
            invalidTradeId,
            tradeData,
            affiliateInfo[0],
            presigns[0],
          ),
      ).to.be.revertedWithCustomError(solbtc, "InvalidTradeId");

      expect(await solbtc.currentStage(tradeId[0])).deep.eq(STAGE.SUBMIT);
      expect(await solbtc.trade(tradeId[0])).deep.eq(EMPTY_TRADE_DATA);
      expect(await solbtc.presign(tradeId[0])).deep.eq(EMPTY_PRESIGNS);
      expect(await solbtc.affiliate(tradeId[0])).deep.eq(EMPTY_AFFILIATE_INFO);
      expect(await solbtc.feeDetails(tradeId[0])).deep.eq(EMPTY_FEE_DETAILS);
      expect(await solbtc.currentStage(invalidTradeId)).deep.eq(STAGE.SUBMIT);
      expect(await solbtc.trade(invalidTradeId)).deep.eq(EMPTY_TRADE_DATA);
      expect(await solbtc.presign(invalidTradeId)).deep.eq(EMPTY_PRESIGNS);
      expect(await solbtc.affiliate(invalidTradeId)).deep.eq(
        EMPTY_AFFILIATE_INFO,
      );
      expect(await solbtc.feeDetails(invalidTradeId)).deep.eq(
        EMPTY_FEE_DETAILS,
      );
    });

    it("Should revert when Solver submits the Trade Info, but tradeId not match an expected tradeId - Un-matched Solver", async () => {
      const invalidTradeId: string = getTradeId(
        sessionId[0],
        admin.address, //  should be solver.address
        tradeInfo[0],
      );
      const tradeData: CoreTypes.TradeDataStruct = {
        sessionId: sessionId[0],
        tradeInfo: tradeInfo[0],
        scriptInfo: scriptInfo[0],
      };

      await expect(
        router
          .connect(solver)
          .submitTrade(
            invalidTradeId,
            tradeData,
            affiliateInfo[0],
            presigns[0],
          ),
      ).to.be.revertedWithCustomError(solbtc, "InvalidTradeId");

      expect(await solbtc.currentStage(tradeId[0])).deep.eq(STAGE.SUBMIT);
      expect(await solbtc.trade(tradeId[0])).deep.eq(EMPTY_TRADE_DATA);
      expect(await solbtc.presign(tradeId[0])).deep.eq(EMPTY_PRESIGNS);
      expect(await solbtc.affiliate(tradeId[0])).deep.eq(EMPTY_AFFILIATE_INFO);
      expect(await solbtc.feeDetails(tradeId[0])).deep.eq(EMPTY_FEE_DETAILS);
      expect(await solbtc.currentStage(invalidTradeId)).deep.eq(STAGE.SUBMIT);
      expect(await solbtc.trade(invalidTradeId)).deep.eq(EMPTY_TRADE_DATA);
      expect(await solbtc.presign(invalidTradeId)).deep.eq(EMPTY_PRESIGNS);
      expect(await solbtc.affiliate(invalidTradeId)).deep.eq(
        EMPTY_AFFILIATE_INFO,
      );
      expect(await solbtc.feeDetails(invalidTradeId)).deep.eq(
        EMPTY_FEE_DETAILS,
      );
    });

    it("Should revert when Solver submits the Trade Info, but tradeId not match an expected tradeId - Un-matched amountIn", async () => {
      let invalidTradeInfo: CoreTypes.TradeInfoStruct = structuredClone(
        tradeInfo[0],
      );
      invalidTradeInfo.amountIn =
        (tradeInfo[0].amountIn as bigint) + parseUnits("10", decimals);
      const invalidTradeId: string = getTradeId(
        sessionId[0],
        solver.address,
        invalidTradeInfo,
      );
      const tradeData: CoreTypes.TradeDataStruct = {
        sessionId: sessionId[0],
        tradeInfo: tradeInfo[0],
        scriptInfo: scriptInfo[0],
      };

      await expect(
        router
          .connect(solver)
          .submitTrade(
            invalidTradeId,
            tradeData,
            affiliateInfo[0],
            presigns[0],
          ),
      ).to.be.revertedWithCustomError(solbtc, "InvalidTradeId");

      expect(await solbtc.currentStage(tradeId[0])).deep.eq(STAGE.SUBMIT);
      expect(await solbtc.trade(tradeId[0])).deep.eq(EMPTY_TRADE_DATA);
      expect(await solbtc.presign(tradeId[0])).deep.eq(EMPTY_PRESIGNS);
      expect(await solbtc.affiliate(tradeId[0])).deep.eq(EMPTY_AFFILIATE_INFO);
      expect(await solbtc.feeDetails(tradeId[0])).deep.eq(EMPTY_FEE_DETAILS);
      expect(await solbtc.currentStage(invalidTradeId)).deep.eq(STAGE.SUBMIT);
      expect(await solbtc.trade(invalidTradeId)).deep.eq(EMPTY_TRADE_DATA);
      expect(await solbtc.presign(invalidTradeId)).deep.eq(EMPTY_PRESIGNS);
      expect(await solbtc.affiliate(invalidTradeId)).deep.eq(
        EMPTY_AFFILIATE_INFO,
      );
      expect(await solbtc.feeDetails(invalidTradeId)).deep.eq(
        EMPTY_FEE_DETAILS,
      );
    });

    it("Should revert when Solver submits the Trade Info, but tradeId not match an expected tradeId - Un-matched fromUserAddress", async () => {
      let invalidTradeInfo: CoreTypes.TradeInfoStruct = structuredClone(
        tradeInfo[0],
      );
      invalidTradeInfo.fromChain[0] = toUtf8Bytes("AnotherUserAddress");
      const invalidTradeId: string = getTradeId(
        sessionId[0],
        solver.address,
        invalidTradeInfo,
      );
      const tradeData: CoreTypes.TradeDataStruct = {
        sessionId: sessionId[0],
        tradeInfo: tradeInfo[0],
        scriptInfo: scriptInfo[0],
      };

      await expect(
        router
          .connect(solver)
          .submitTrade(
            invalidTradeId,
            tradeData,
            affiliateInfo[0],
            presigns[0],
          ),
      ).to.be.revertedWithCustomError(solbtc, "InvalidTradeId");

      expect(await solbtc.currentStage(tradeId[0])).deep.eq(STAGE.SUBMIT);
      expect(await solbtc.trade(tradeId[0])).deep.eq(EMPTY_TRADE_DATA);
      expect(await solbtc.presign(tradeId[0])).deep.eq(EMPTY_PRESIGNS);
      expect(await solbtc.affiliate(tradeId[0])).deep.eq(EMPTY_AFFILIATE_INFO);
      expect(await solbtc.feeDetails(tradeId[0])).deep.eq(EMPTY_FEE_DETAILS);
      expect(await solbtc.currentStage(invalidTradeId)).deep.eq(STAGE.SUBMIT);
      expect(await solbtc.trade(invalidTradeId)).deep.eq(EMPTY_TRADE_DATA);
      expect(await solbtc.presign(invalidTradeId)).deep.eq(EMPTY_PRESIGNS);
      expect(await solbtc.affiliate(invalidTradeId)).deep.eq(
        EMPTY_AFFILIATE_INFO,
      );
      expect(await solbtc.feeDetails(invalidTradeId)).deep.eq(
        EMPTY_FEE_DETAILS,
      );
    });

    it("Should revert when Solver submits the Trade Info, but tradeId not match an expected tradeId - Un-matched fromChain", async () => {
      //  generate invalidTradeInfo with un-matched `fromChain`
      let invalidTradeInfo: CoreTypes.TradeInfoStruct = structuredClone(
        tradeInfo[0],
      );
      invalidTradeInfo.fromChain[1] = toUtf8Bytes("solana");
      const invalidTradeId: string = getTradeId(
        sessionId[0],
        solver.address,
        invalidTradeInfo,
      );
      const tradeData: CoreTypes.TradeDataStruct = {
        sessionId: sessionId[0],
        tradeInfo: tradeInfo[0],
        scriptInfo: scriptInfo[0],
      };

      await expect(
        router
          .connect(solver)
          .submitTrade(
            invalidTradeId,
            tradeData,
            affiliateInfo[0],
            presigns[0],
          ),
      ).to.be.revertedWithCustomError(solbtc, "InvalidTradeId");

      expect(await solbtc.currentStage(tradeId[0])).deep.eq(STAGE.SUBMIT);
      expect(await solbtc.trade(tradeId[0])).deep.eq(EMPTY_TRADE_DATA);
      expect(await solbtc.presign(tradeId[0])).deep.eq(EMPTY_PRESIGNS);
      expect(await solbtc.affiliate(tradeId[0])).deep.eq(EMPTY_AFFILIATE_INFO);
      expect(await solbtc.feeDetails(tradeId[0])).deep.eq(EMPTY_FEE_DETAILS);
      expect(await solbtc.currentStage(invalidTradeId)).deep.eq(STAGE.SUBMIT);
      expect(await solbtc.trade(invalidTradeId)).deep.eq(EMPTY_TRADE_DATA);
      expect(await solbtc.presign(invalidTradeId)).deep.eq(EMPTY_PRESIGNS);
      expect(await solbtc.affiliate(invalidTradeId)).deep.eq(
        EMPTY_AFFILIATE_INFO,
      );
      expect(await solbtc.feeDetails(invalidTradeId)).deep.eq(
        EMPTY_FEE_DETAILS,
      );
    });

    it("Should revert when Solver submits the Trade Info, but tradeId not match an expected tradeId - Un-matched fromToken", async () => {
      let invalidTradeInfo: CoreTypes.TradeInfoStruct = structuredClone(
        tradeInfo[0],
      );
      invalidTradeInfo.fromChain[2] = toUtf8Bytes("AnotherTokenAddress");
      const invalidTradeId: string = getTradeId(
        sessionId[0],
        solver.address,
        invalidTradeInfo,
      );
      const tradeData: CoreTypes.TradeDataStruct = {
        sessionId: sessionId[0],
        tradeInfo: tradeInfo[0],
        scriptInfo: scriptInfo[0],
      };

      await expect(
        router
          .connect(solver)
          .submitTrade(
            invalidTradeId,
            tradeData,
            affiliateInfo[0],
            presigns[0],
          ),
      ).to.be.revertedWithCustomError(solbtc, "InvalidTradeId");

      expect(await solbtc.currentStage(tradeId[0])).deep.eq(STAGE.SUBMIT);
      expect(await solbtc.trade(tradeId[0])).deep.eq(EMPTY_TRADE_DATA);
      expect(await solbtc.presign(tradeId[0])).deep.eq(EMPTY_PRESIGNS);
      expect(await solbtc.affiliate(tradeId[0])).deep.eq(EMPTY_AFFILIATE_INFO);
      expect(await solbtc.feeDetails(tradeId[0])).deep.eq(EMPTY_FEE_DETAILS);
      expect(await solbtc.currentStage(invalidTradeId)).deep.eq(STAGE.SUBMIT);
      expect(await solbtc.trade(invalidTradeId)).deep.eq(EMPTY_TRADE_DATA);
      expect(await solbtc.presign(invalidTradeId)).deep.eq(EMPTY_PRESIGNS);
      expect(await solbtc.affiliate(invalidTradeId)).deep.eq(
        EMPTY_AFFILIATE_INFO,
      );
      expect(await solbtc.feeDetails(invalidTradeId)).deep.eq(
        EMPTY_FEE_DETAILS,
      );
    });

    it("Should revert when Solver submits the Trade Info, but tradeId not match an expected tradeId - Un-matched toUserAddress", async () => {
      let invalidTradeInfo: CoreTypes.TradeInfoStruct = structuredClone(
        tradeInfo[0],
      );
      invalidTradeInfo.toChain[0] = toUtf8Bytes("AnotherToUserAddress");
      const invalidTradeId: string = getTradeId(
        sessionId[0],
        solver.address,
        invalidTradeInfo,
      );
      const tradeData: CoreTypes.TradeDataStruct = {
        sessionId: sessionId[0],
        tradeInfo: tradeInfo[0],
        scriptInfo: scriptInfo[0],
      };

      await expect(
        router
          .connect(solver)
          .submitTrade(
            invalidTradeId,
            tradeData,
            affiliateInfo[0],
            presigns[0],
          ),
      ).to.be.revertedWithCustomError(solbtc, "InvalidTradeId");

      expect(await solbtc.currentStage(tradeId[0])).deep.eq(STAGE.SUBMIT);
      expect(await solbtc.trade(tradeId[0])).deep.eq(EMPTY_TRADE_DATA);
      expect(await solbtc.presign(tradeId[0])).deep.eq(EMPTY_PRESIGNS);
      expect(await solbtc.affiliate(tradeId[0])).deep.eq(EMPTY_AFFILIATE_INFO);
      expect(await solbtc.feeDetails(tradeId[0])).deep.eq(EMPTY_FEE_DETAILS);
      expect(await solbtc.currentStage(invalidTradeId)).deep.eq(STAGE.SUBMIT);
      expect(await solbtc.trade(invalidTradeId)).deep.eq(EMPTY_TRADE_DATA);
      expect(await solbtc.presign(invalidTradeId)).deep.eq(EMPTY_PRESIGNS);
      expect(await solbtc.affiliate(invalidTradeId)).deep.eq(
        EMPTY_AFFILIATE_INFO,
      );
      expect(await solbtc.feeDetails(invalidTradeId)).deep.eq(
        EMPTY_FEE_DETAILS,
      );
    });

    it("Should revert when Solver submits the Trade Info, but tradeId not match an expected tradeId - Un-matched toChain", async () => {
      //  generate invalidTradeInfo with un-matched `fromChain`
      let invalidTradeInfo: CoreTypes.TradeInfoStruct = structuredClone(
        tradeInfo[0],
      );
      invalidTradeInfo.toChain[1] = toUtf8Bytes("bitcoin");
      const invalidTradeId: string = getTradeId(
        sessionId[0],
        solver.address,
        invalidTradeInfo,
      );
      const tradeData: CoreTypes.TradeDataStruct = {
        sessionId: sessionId[0],
        tradeInfo: tradeInfo[0],
        scriptInfo: scriptInfo[0],
      };

      await expect(
        router
          .connect(solver)
          .submitTrade(
            invalidTradeId,
            tradeData,
            affiliateInfo[0],
            presigns[0],
          ),
      ).to.be.revertedWithCustomError(solbtc, "InvalidTradeId");

      expect(await solbtc.currentStage(tradeId[0])).deep.eq(STAGE.SUBMIT);
      expect(await solbtc.trade(tradeId[0])).deep.eq(EMPTY_TRADE_DATA);
      expect(await solbtc.presign(tradeId[0])).deep.eq(EMPTY_PRESIGNS);
      expect(await solbtc.affiliate(tradeId[0])).deep.eq(EMPTY_AFFILIATE_INFO);
      expect(await solbtc.feeDetails(tradeId[0])).deep.eq(EMPTY_FEE_DETAILS);
      expect(await solbtc.currentStage(invalidTradeId)).deep.eq(STAGE.SUBMIT);
      expect(await solbtc.trade(invalidTradeId)).deep.eq(EMPTY_TRADE_DATA);
      expect(await solbtc.presign(invalidTradeId)).deep.eq(EMPTY_PRESIGNS);
      expect(await solbtc.affiliate(invalidTradeId)).deep.eq(
        EMPTY_AFFILIATE_INFO,
      );
      expect(await solbtc.feeDetails(invalidTradeId)).deep.eq(
        EMPTY_FEE_DETAILS,
      );
    });

    it("Should revert when Solver submits the Trade Info, but tradeId not match an expected tradeId - Un-matched toToken", async () => {
      let invalidTradeInfo: CoreTypes.TradeInfoStruct = structuredClone(
        tradeInfo[0],
      );
      invalidTradeInfo.toChain[2] = toUtf8Bytes("AnotherToTokenAddress");
      const invalidTradeId: string = getTradeId(
        sessionId[0],
        solver.address,
        invalidTradeInfo,
      );
      const tradeData: CoreTypes.TradeDataStruct = {
        sessionId: sessionId[0],
        tradeInfo: tradeInfo[0],
        scriptInfo: scriptInfo[0],
      };

      await expect(
        router
          .connect(solver)
          .submitTrade(
            invalidTradeId,
            tradeData,
            affiliateInfo[0],
            presigns[0],
          ),
      ).to.be.revertedWithCustomError(solbtc, "InvalidTradeId");

      expect(await solbtc.currentStage(tradeId[0])).deep.eq(STAGE.SUBMIT);
      expect(await solbtc.trade(tradeId[0])).deep.eq(EMPTY_TRADE_DATA);
      expect(await solbtc.presign(tradeId[0])).deep.eq(EMPTY_PRESIGNS);
      expect(await solbtc.affiliate(tradeId[0])).deep.eq(EMPTY_AFFILIATE_INFO);
      expect(await solbtc.feeDetails(tradeId[0])).deep.eq(EMPTY_FEE_DETAILS);
      expect(await solbtc.currentStage(invalidTradeId)).deep.eq(STAGE.SUBMIT);
      expect(await solbtc.trade(invalidTradeId)).deep.eq(EMPTY_TRADE_DATA);
      expect(await solbtc.presign(invalidTradeId)).deep.eq(EMPTY_PRESIGNS);
      expect(await solbtc.affiliate(invalidTradeId)).deep.eq(
        EMPTY_AFFILIATE_INFO,
      );
      expect(await solbtc.feeDetails(invalidTradeId)).deep.eq(
        EMPTY_FEE_DETAILS,
      );
    });

    it("Should revert when Solver submits the Trade Info, but provides an invalid script timeout", async () => {
      const timestamp = await getBlockTimestamp(provider);
      const invalidScriptInfo: CoreTypes.ScriptInfoStruct = structuredClone(
        scriptInfo[0],
      );
      invalidScriptInfo.scriptTimeout = BigInt(timestamp - 1);

      const tradeData: CoreTypes.TradeDataStruct = {
        sessionId: sessionId[0],
        tradeInfo: tradeInfo[0],
        scriptInfo: invalidScriptInfo,
      };

      await expect(
        router
          .connect(solver)
          .submitTrade(tradeId[0], tradeData, affiliateInfo[0], presigns[0]),
      ).to.be.revertedWithCustomError(solbtc, "InvalidTimeout");

      expect(await solbtc.currentStage(tradeId[0])).deep.eq(STAGE.SUBMIT);
      expect(await solbtc.trade(tradeId[0])).deep.eq(EMPTY_TRADE_DATA);
      expect(await solbtc.presign(tradeId[0])).deep.eq(EMPTY_PRESIGNS);
      expect(await solbtc.affiliate(tradeId[0])).deep.eq(EMPTY_AFFILIATE_INFO);
      expect(await solbtc.feeDetails(tradeId[0])).deep.eq(EMPTY_FEE_DETAILS);
    });

    it("Should revert when Solver submits the Trade Info, but Token not supported - Source Token", async () => {
      //  temporarily remove source token
      await management
        .connect(admin)
        .removeToken(tradeInfo[0].fromChain[1], tradeInfo[0].fromChain[2]);

      const tradeData: CoreTypes.TradeDataStruct = {
        sessionId: sessionId[0],
        tradeInfo: tradeInfo[0],
        scriptInfo: scriptInfo[0],
      };

      await expect(
        router
          .connect(solver)
          .submitTrade(tradeId[0], tradeData, affiliateInfo[0], presigns[0]),
      ).to.be.revertedWithCustomError(solbtc, "TokenNotSupported");

      expect(await solbtc.currentStage(tradeId[0])).deep.eq(STAGE.SUBMIT);
      expect(await solbtc.trade(tradeId[0])).deep.eq(EMPTY_TRADE_DATA);
      expect(await solbtc.presign(tradeId[0])).deep.eq(EMPTY_PRESIGNS);
      expect(await solbtc.affiliate(tradeId[0])).deep.eq(EMPTY_AFFILIATE_INFO);
      expect(await solbtc.feeDetails(tradeId[0])).deep.eq(EMPTY_FEE_DETAILS);

      //  set back to normal
      await management.connect(admin).setToken(solNativeInfo);
    });

    it("Should revert when Solver submits the Trade Info, but Token not supported - Destination Token", async () => {
      //  temporarily remove destination token
      await management
        .connect(admin)
        .removeToken(tradeInfo[0].toChain[1], tradeInfo[0].toChain[2]);

      const tradeData: CoreTypes.TradeDataStruct = {
        sessionId: sessionId[0],
        tradeInfo: tradeInfo[0],
        scriptInfo: scriptInfo[0],
      };

      await expect(
        router
          .connect(solver)
          .submitTrade(tradeId[0], tradeData, affiliateInfo[0], presigns[0]),
      ).to.be.revertedWithCustomError(solbtc, "TokenNotSupported");

      expect(await solbtc.currentStage(tradeId[0])).deep.eq(STAGE.SUBMIT);
      expect(await solbtc.trade(tradeId[0])).deep.eq(EMPTY_TRADE_DATA);
      expect(await solbtc.presign(tradeId[0])).deep.eq(EMPTY_PRESIGNS);
      expect(await solbtc.affiliate(tradeId[0])).deep.eq(EMPTY_AFFILIATE_INFO);
      expect(await solbtc.feeDetails(tradeId[0])).deep.eq(EMPTY_FEE_DETAILS);

      //  set back to normal
      await management.connect(admin).setToken(btcTokenInfo);
    });

    it("Should revert when Solver submits the Trade Info, but provided mpcAssetPubkey is invalid", async () => {
      //  temporarily revoke MPCPubkey
      await management
        .connect(admin)
        .revokeMPCKey(
          tradeInfo[0].fromChain[1],
          mpcL2.signingKey.compressedPublicKey,
        );

      const tradeData: CoreTypes.TradeDataStruct = {
        sessionId: sessionId[0],
        tradeInfo: tradeInfo[0],
        scriptInfo: scriptInfo[0],
      };

      await expect(
        router
          .connect(solver)
          .submitTrade(tradeId[0], tradeData, affiliateInfo[0], presigns[0]),
      ).to.be.revertedWithCustomError(solbtc, "InvalidMPCAssetPubkey");

      expect(await solbtc.currentStage(tradeId[0])).deep.eq(STAGE.SUBMIT);
      expect(await solbtc.trade(tradeId[0])).deep.eq(EMPTY_TRADE_DATA);
      expect(await solbtc.presign(tradeId[0])).deep.eq(EMPTY_PRESIGNS);
      expect(await solbtc.affiliate(tradeId[0])).deep.eq(EMPTY_AFFILIATE_INFO);
      expect(await solbtc.feeDetails(tradeId[0])).deep.eq(EMPTY_FEE_DETAILS);

      //  set back to normal
      const mpcInfo: ManagementTypes.MPCInfoStruct = {
        mpcL2Address: mpcL2.address,
        expireTime: MAX_UINT64,
        mpcAssetPubkey: scriptInfo[0].depositInfo[3],
        mpcL2Pubkey: mpcL2.signingKey.compressedPublicKey, //  For Solana, `mpcAssetPubkey` != `mpcL2Pubkey`
      };
      const prevExpireTime = BigInt(0);
      await management
        .connect(admin)
        .setMPCInfo(tradeInfo[0].fromChain[1], mpcInfo, prevExpireTime);
    });

    it("Should revert when Solver submits the Trade Info, but the provided PMM is unauthorized", async () => {
      //  temporarily remove one PMM
      await management.connect(admin).removePMM(presigns[0][0].pmmId);

      const tradeData: CoreTypes.TradeDataStruct = {
        sessionId: sessionId[0],
        tradeInfo: tradeInfo[0],
        scriptInfo: scriptInfo[0],
      };

      await expect(
        router
          .connect(solver)
          .submitTrade(tradeId[0], tradeData, affiliateInfo[0], presigns[0]),
      ).to.be.revertedWithCustomError(solbtc, "PMMNotRegistered");

      expect(await solbtc.currentStage(tradeId[0])).deep.eq(STAGE.SUBMIT);
      expect(await solbtc.trade(tradeId[0])).deep.eq(EMPTY_TRADE_DATA);
      expect(await solbtc.presign(tradeId[0])).deep.eq(EMPTY_PRESIGNS);
      expect(await solbtc.affiliate(tradeId[0])).deep.eq(EMPTY_AFFILIATE_INFO);
      expect(await solbtc.feeDetails(tradeId[0])).deep.eq(EMPTY_FEE_DETAILS);

      //  set back to normal
      await management
        .connect(admin)
        .setPMM(presigns[0][0].pmmId, accounts[0].address);
    });

    it("Should revert when Solver submits the Trade Info, but affiliate fee rate exceeds maximum allowance", async () => {
      const invalidAffiliate: CoreTypes.AffiliateStruct = structuredClone(
        affiliateInfo[0],
      );
      invalidAffiliate.aggregatedValue = MAX_AFFILIATE_FEE_RATE + BigInt(1);
      const tradeData: CoreTypes.TradeDataStruct = {
        sessionId: sessionId[0],
        tradeInfo: tradeInfo[0],
        scriptInfo: scriptInfo[0],
      };

      await expect(
        router
          .connect(solver)
          .submitTrade(tradeId[0], tradeData, invalidAffiliate, presigns[0]),
      ).to.be.revertedWithCustomError(solbtc, "ExceededAffiliateFeeLimit");

      expect(await solbtc.currentStage(tradeId[0])).deep.eq(STAGE.SUBMIT);
      expect(await solbtc.trade(tradeId[0])).deep.eq(EMPTY_TRADE_DATA);
      expect(await solbtc.presign(tradeId[0])).deep.eq(EMPTY_PRESIGNS);
      expect(await solbtc.affiliate(tradeId[0])).deep.eq(EMPTY_AFFILIATE_INFO);
      expect(await solbtc.feeDetails(tradeId[0])).deep.eq(EMPTY_FEE_DETAILS);
    });

    it("Should succeed when Solver submits Trade Info", async () => {
      const tradeData: CoreTypes.TradeDataStruct = {
        sessionId: sessionId[0],
        tradeInfo: tradeInfo[0],
        scriptInfo: scriptInfo[0],
      };

      const tx = router
        .connect(solver)
        .submitTrade(tradeId[0], tradeData, affiliateInfo[0], presigns[0]);

      await expect(tx).to.emit(router, "SubmitTradeInfo").withArgs(
        solver.address, // sender
        tradeId[0],
      );
      await expect(tx)
        .to.emit(solbtc, "TradeInfoSubmitted")
        .withArgs(
          await router.getAddress(), // forwarder
          solver.address, // requester
          tradeId[0],
          tradeInfo[0].fromChain[1], //  fromChain
          scriptInfo[0].depositInfo[1], // depositTxId
        );

      const expectedTradeData = [
        sessionId[0],
        //  tradeInfo
        [
          tradeInfo[0].amountIn,
          tradeInfo[0].fromChain.map((data) => hexlify(data)),
          tradeInfo[0].toChain.map((data) => hexlify(data)),
        ],
        //  scriptInfo
        [
          scriptInfo[0].depositInfo.map((data) => hexlify(data)), //  depositInfo
          scriptInfo[0].userEphemeralL2Address, //  userEphemeralL2Address
          scriptInfo[0].scriptTimeout, //  scriptTimeout
        ],
      ];
      const expectedPresigns = [
        [
          presigns[0][0].pmmId,
          hexlify(presigns[0][0].pmmRecvAddress),
          [hexlify(presigns[0][0].presigns[0])],
        ],
        [
          presigns[0][1].pmmId,
          hexlify(presigns[0][1].pmmRecvAddress),
          [hexlify(presigns[0][1].presigns[0])],
        ],
      ];

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.CONFIRM_DEPOSIT,
      );
      expect(await router.getTradeData(tradeId[0])).deep.eq(
        Object.values(expectedTradeData),
      );
      expect(await router.getPresigns(tradeId[0])).deep.eq(
        Object.values(expectedPresigns),
      );
      expect(await router.getAffiliateInfo(tradeId[0])).deep.eq(
        Object.values(affiliateInfo[0]),
      );
      expect(await router.getFeeDetails(tradeId[0])).deep.eq([
        pFeeAmount[0] + aFeeAmount[0],
        pFeeAmount[0], // pFeeAmount
        aFeeAmount[0], // aFeeAmount
        pFeeRate,
        affiliateInfo[0].aggregatedValue, //  aFeeRate
      ]);
    });

    it("Should revert when Solver tries to update the Trade Info data after submission", async () => {
      const tradeData: CoreTypes.TradeDataStruct = {
        sessionId: sessionId[0],
        tradeInfo: tradeInfo[0],
        scriptInfo: scriptInfo[0],
      };

      const currentStage = await router.getCurrentStage(tradeId[0]);
      const lastData = await router.getTradeData(tradeId[0]);
      const lastPresigns = await router.getPresigns(tradeId[0]);
      const lastAffiliateInfo = await router.getAffiliateInfo(tradeId[0]);
      const lastFeeDetails = await router.getFeeDetails(tradeId[0]);

      await expect(
        router
          .connect(solver)
          .submitTrade(tradeId[0], tradeData, affiliateInfo[0], presigns[0]),
      ).to.be.revertedWithCustomError(solbtc, "InvalidProcedureState");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(currentStage);
      expect(await router.getTradeData(tradeId[0])).deep.eq(
        Object.values(lastData),
      );
      expect(await router.getPresigns(tradeId[0])).deep.eq(
        Object.values(lastPresigns),
      );
      expect(await router.getAffiliateInfo(tradeId[0])).deep.eq(
        lastAffiliateInfo,
      );
      expect(await router.getFeeDetails(tradeId[0])).deep.eq(lastFeeDetails);
    });

    it("Should succeed when Solver submits another Trade Info", async () => {
      //  temporarily set `admin` as `Solver`
      await management.connect(admin).setSolver(admin.address, true);

      const tradeData: CoreTypes.TradeDataStruct = {
        sessionId: sessionId[1],
        tradeInfo: tradeInfo[1],
        scriptInfo: scriptInfo[1],
      };

      const tx = router
        .connect(admin)
        .submitTrade(tradeId[1], tradeData, affiliateInfo[1], presigns[1]);

      await expect(tx).to.emit(router, "SubmitTradeInfo").withArgs(
        admin.address, // sender
        tradeId[1],
      );
      await expect(tx)
        .to.emit(solbtc, "TradeInfoSubmitted")
        .withArgs(
          await router.getAddress(), // forwarder
          admin.address, // requester
          tradeId[1],
          tradeInfo[1].fromChain[1], //  fromChain
          scriptInfo[1].depositInfo[1], // depositTxId
        );

      const expectedTradeData = [
        sessionId[1],
        //  tradeInfo
        [
          tradeInfo[1].amountIn,
          tradeInfo[1].fromChain.map((data) => hexlify(data)),
          tradeInfo[1].toChain.map((data) => hexlify(data)),
        ],
        //  scriptInfo
        [
          scriptInfo[1].depositInfo.map((data) => hexlify(data)), //  depositInfo
          scriptInfo[1].userEphemeralL2Address, //  userEphemeralL2Address
          scriptInfo[1].scriptTimeout, //  scriptTimeout
        ],
      ];
      const expectedPresigns = [
        [
          presigns[1][0].pmmId,
          hexlify(presigns[1][0].pmmRecvAddress),
          [hexlify(presigns[1][0].presigns[0])],
        ],
        [
          presigns[1][1].pmmId,
          hexlify(presigns[1][1].pmmRecvAddress),
          [hexlify(presigns[1][1].presigns[0])],
        ],
      ];

      expect(await router.getCurrentStage(tradeId[1])).deep.eq(
        STAGE.CONFIRM_DEPOSIT,
      );
      expect(await router.getTradeData(tradeId[1])).deep.eq(
        Object.values(expectedTradeData),
      );
      expect(await router.getPresigns(tradeId[1])).deep.eq(
        Object.values(expectedPresigns),
      );
      expect(await router.getAffiliateInfo(tradeId[1])).deep.eq(
        Object.values(affiliateInfo[1]),
      );
      expect(await router.getFeeDetails(tradeId[1])).deep.eq([
        pFeeAmount[1] + aFeeAmount[1],
        pFeeAmount[1], // pFeeAmount
        aFeeAmount[1], // aFeeAmount
        pFeeRate,
        affiliateInfo[1].aggregatedValue, //  aFeeRate
      ]);

      //  set back to normal
      await management.connect(admin).setSolver(admin.address, false);
    });

    it("Should succeed when Solver submits another Trade Info", async () => {
      const tradeData: CoreTypes.TradeDataStruct = {
        sessionId: sessionId[2],
        tradeInfo: tradeInfo[2],
        scriptInfo: scriptInfo[2],
      };

      const tx = router
        .connect(solver)
        .submitTrade(tradeId[2], tradeData, affiliateInfo[2], presigns[2]);

      await expect(tx).to.emit(router, "SubmitTradeInfo").withArgs(
        solver.address, // sender
        tradeId[2],
      );
      await expect(tx)
        .to.emit(solbtc, "TradeInfoSubmitted")
        .withArgs(
          await router.getAddress(), // forwarder
          solver.address, // requester
          tradeId[2],
          tradeInfo[2].fromChain[1], //  fromChain
          scriptInfo[2].depositInfo[1], // depositTxId
        );

      const expectedTradeData = [
        sessionId[2],
        //  tradeInfo
        [
          tradeInfo[2].amountIn,
          tradeInfo[2].fromChain.map((data) => hexlify(data)),
          tradeInfo[2].toChain.map((data) => hexlify(data)),
        ],
        //  scriptInfo
        [
          scriptInfo[2].depositInfo.map((data) => hexlify(data)), //  depositInfo
          scriptInfo[2].userEphemeralL2Address, //  userEphemeralL2Address
          scriptInfo[2].scriptTimeout, //  scriptTimeout
        ],
      ];
      const expectedPresigns = [
        [
          presigns[2][0].pmmId,
          hexlify(presigns[2][0].pmmRecvAddress),
          [hexlify(presigns[2][0].presigns[0])],
        ],
        [
          presigns[2][1].pmmId,
          hexlify(presigns[2][1].pmmRecvAddress),
          [hexlify(presigns[2][1].presigns[0])],
        ],
      ];

      expect(await router.getCurrentStage(tradeId[2])).deep.eq(
        STAGE.CONFIRM_DEPOSIT,
      );
      expect(await router.getTradeData(tradeId[2])).deep.eq(
        Object.values(expectedTradeData),
      );
      expect(await router.getPresigns(tradeId[2])).deep.eq(
        Object.values(expectedPresigns),
      );
      expect(await router.getAffiliateInfo(tradeId[2])).deep.eq(
        Object.values(affiliateInfo[2]),
      );
      expect(await router.getFeeDetails(tradeId[2])).deep.eq([
        pFeeAmount[2] + aFeeAmount[2],
        pFeeAmount[2], // pFeeAmount
        aFeeAmount[2], // aFeeAmount
        pFeeRate,
        affiliateInfo[2].aggregatedValue, //  aFeeRate
      ]);
    });
  });

  describe("confirmDeposit() functional testing", async () => {
    it("Should revert when Unauthorized client, an arbitrary account, tries to submit a deposit confirmation", async () => {
      const depositedFromList: BytesLike[] = [
        Keypair.generate().publicKey.toBytes(),
      ];
      const infoHash: string = getDepositConfirmationHash(
        tradeInfo[0].amountIn as bigint,
        tradeInfo[0].fromChain,
        scriptInfo[0].depositInfo[1],
        depositedFromList,
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[0],
        infoHash,
        SignatureType.ConfirmDeposit,
        domain,
      );

      await expect(
        router
          .connect(accounts[0])
          .confirmDeposit(tradeId[0], signature, depositedFromList),
      ).to.be.revertedWithCustomError(solbtc, "Unauthorized");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.CONFIRM_DEPOSIT,
      );
      expect(await router.getDepositAddressList(tradeId[0])).deep.eq(
        EMPTY_DEPOSIT_ADDRESS_LIST,
      );
    });

    it("Should revert when Unauthorized client, the Solver, tries to submit a deposit confirmation", async () => {
      const depositedFromList: BytesLike[] = [
        Keypair.generate().publicKey.toBytes(),
      ];
      const infoHash: string = getDepositConfirmationHash(
        tradeInfo[0].amountIn as bigint,
        tradeInfo[0].fromChain,
        scriptInfo[0].depositInfo[1],
        depositedFromList,
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[0],
        infoHash,
        SignatureType.ConfirmDeposit,
        domain,
      );

      await expect(
        router
          .connect(solver)
          .confirmDeposit(tradeId[0], signature, depositedFromList),
      ).to.be.revertedWithCustomError(solbtc, "Unauthorized");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.CONFIRM_DEPOSIT,
      );
      expect(await router.getDepositAddressList(tradeId[0])).deep.eq(
        EMPTY_DEPOSIT_ADDRESS_LIST,
      );
    });

    it("Should revert when Unauthorized client, the Admin, tries to submit a deposit confirmation", async () => {
      const depositedFromList: BytesLike[] = [
        Keypair.generate().publicKey.toBytes(),
      ];
      const infoHash: string = getDepositConfirmationHash(
        tradeInfo[0].amountIn as bigint,
        tradeInfo[0].fromChain,
        scriptInfo[0].depositInfo[1],
        depositedFromList,
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[0],
        infoHash,
        SignatureType.ConfirmDeposit,
        domain,
      );

      await expect(
        router
          .connect(admin)
          .confirmDeposit(tradeId[0], signature, depositedFromList),
      ).to.be.revertedWithCustomError(solbtc, "Unauthorized");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.CONFIRM_DEPOSIT,
      );
      expect(await router.getDepositAddressList(tradeId[0])).deep.eq(
        EMPTY_DEPOSIT_ADDRESS_LIST,
      );
    });

    it("Should revert when MPC Node submits a deposit confirmation, but the protocol is triggered the Suspension Mode", async () => {
      //  temporarily set the Protocol to the "SUSPEND" state
      await management.connect(admin).suspend();

      const depositedFromList: BytesLike[] = [
        Keypair.generate().publicKey.toBytes(),
      ];
      const infoHash: string = getDepositConfirmationHash(
        tradeInfo[0].amountIn as bigint,
        tradeInfo[0].fromChain,
        scriptInfo[0].depositInfo[1],
        depositedFromList,
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[0],
        infoHash,
        SignatureType.ConfirmDeposit,
        domain,
      );

      await expect(
        router
          .connect(mpcNode1)
          .confirmDeposit(tradeId[0], signature, depositedFromList),
      ).to.be.revertedWithCustomError(solbtc, "InSuspension");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.CONFIRM_DEPOSIT,
      );
      expect(await router.getDepositAddressList(tradeId[0])).deep.eq(
        EMPTY_DEPOSIT_ADDRESS_LIST,
      );

      //  set back to normal
      await management.connect(admin).resume();
    });

    it("Should revert when MPC Node submits a deposit confirmation, but the protocol is triggered the Shutdown Mode", async () => {
      //  temporarily set the Protocol to the "SHUTDOWN" state
      await management.connect(admin).shutdown();

      const depositedFromList: BytesLike[] = [
        Keypair.generate().publicKey.toBytes(),
      ];
      const infoHash: string = getDepositConfirmationHash(
        tradeInfo[0].amountIn as bigint,
        tradeInfo[0].fromChain,
        scriptInfo[0].depositInfo[1],
        depositedFromList,
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[0],
        infoHash,
        SignatureType.ConfirmDeposit,
        domain,
      );

      await expect(
        router
          .connect(mpcNode1)
          .confirmDeposit(tradeId[0], signature, depositedFromList),
      ).to.be.revertedWithCustomError(solbtc, "InSuspension");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.CONFIRM_DEPOSIT,
      );
      expect(await router.getDepositAddressList(tradeId[0])).deep.eq(
        EMPTY_DEPOSIT_ADDRESS_LIST,
      );

      //  set back to normal
      await management.connect(admin).resume();
    });

    it("Should revert when MPC Node submits a deposit confirmation, but tradeId not existed - Router has no record", async () => {
      const depositedFromList: BytesLike[] = [
        Keypair.generate().publicKey.toBytes(),
      ];
      const infoHash: string = getDepositConfirmationHash(
        tradeInfo[0].amountIn as bigint,
        tradeInfo[0].fromChain,
        scriptInfo[0].depositInfo[1],
        depositedFromList,
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[0],
        infoHash,
        SignatureType.ConfirmDeposit,
        domain,
      );
      const invalidTradeId = toBeHex(
        BigInt(tradeId[0].toString()) + BigInt(1),
        32,
      );

      await expect(
        router
          .connect(mpcNode1)
          .confirmDeposit(invalidTradeId, signature, depositedFromList),
      ).to.be.revertedWithoutReason();

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.CONFIRM_DEPOSIT,
      );
      expect(await router.getDepositAddressList(tradeId[0])).deep.eq(
        EMPTY_DEPOSIT_ADDRESS_LIST,
      );
    });

    it("Should revert when MPC Node submits a deposit confirmation, but using another tradeId - Invalid Procedure State", async () => {
      //  take a snapshot before submitting deposit confirmation of `tradeId2`
      const snapshot = await takeSnapshot();

      //  Submit the second trade's deposit confirmation
      let depositedFromList: BytesLike[] = [
        Keypair.generate().publicKey.toBytes(),
      ];
      let infoHash: string = getDepositConfirmationHash(
        tradeInfo[1].amountIn as bigint,
        tradeInfo[1].fromChain,
        scriptInfo[1].depositInfo[1],
        depositedFromList,
      );
      let signature: string = await getSignature(
        mpcL2,
        tradeId[1],
        infoHash,
        SignatureType.ConfirmDeposit,
        domain,
      );
      await router
        .connect(mpcNode1)
        .confirmDeposit(tradeId[1], signature, depositedFromList);

      //  Now, prepare data for the first trade
      depositedFromList = [Keypair.generate().publicKey.toBytes()];
      infoHash = getDepositConfirmationHash(
        tradeInfo[0].amountIn as bigint,
        tradeInfo[0].fromChain,
        scriptInfo[0].depositInfo[1],
        depositedFromList,
      );
      signature = await getSignature(
        mpcL2,
        tradeId[0],
        infoHash,
        SignatureType.ConfirmDeposit,
        domain,
      );

      await expect(
        router
          .connect(mpcNode1)
          .confirmDeposit(tradeId[1], signature, depositedFromList),
      ).to.be.revertedWithCustomError(solbtc, "InvalidProcedureState");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.CONFIRM_DEPOSIT,
      );
      expect(await router.getDepositAddressList(tradeId[0])).deep.eq(
        EMPTY_DEPOSIT_ADDRESS_LIST,
      );

      //  set back to normal
      await snapshot.restore();
    });

    it("Should revert when MPC Node submits a deposit confirmation, but invalid MPC's signature - Invalid Signer", async () => {
      let depositedFromList: BytesLike[] = [
        Keypair.generate().publicKey.toBytes(),
      ];
      const infoHash: string = getDepositConfirmationHash(
        tradeInfo[0].amountIn as bigint,
        tradeInfo[0].fromChain,
        scriptInfo[0].depositInfo[1],
        depositedFromList,
      );
      let signature: string = await getSignature(
        mpcNode1, // should be "mpc"
        tradeId[0],
        infoHash,
        SignatureType.ConfirmDeposit,
        domain,
      );

      await expect(
        router
          .connect(mpcNode1)
          .confirmDeposit(tradeId[0], signature, depositedFromList),
      ).to.be.revertedWithCustomError(solbtc, "InvalidMPCSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.CONFIRM_DEPOSIT,
      );
      expect(await router.getDepositAddressList(tradeId[0])).deep.eq(
        EMPTY_DEPOSIT_ADDRESS_LIST,
      );
    });

    it("Should revert when MPC Node submits a deposit confirmation, but invalid MPC's signature - Un-match amountIn", async () => {
      const depositedFromList: BytesLike[] = [
        Keypair.generate().publicKey.toBytes(),
      ];
      const invalidInfoHash: string = getDepositConfirmationHash(
        (tradeInfo[0].amountIn as bigint) + BigInt(1),
        tradeInfo[0].fromChain,
        scriptInfo[0].depositInfo[1],
        depositedFromList,
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[0],
        invalidInfoHash,
        SignatureType.ConfirmDeposit,
        domain,
      );

      await expect(
        router
          .connect(mpcNode1)
          .confirmDeposit(tradeId[0], signature, depositedFromList),
      ).to.be.revertedWithCustomError(solbtc, "InvalidMPCSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.CONFIRM_DEPOSIT,
      );
      expect(await router.getDepositAddressList(tradeId[0])).deep.eq(
        EMPTY_DEPOSIT_ADDRESS_LIST,
      );
    });

    it("Should revert when MPC Node submits a deposit confirmation, but invalid MPC's signature - Un-match fromUserAddress", async () => {
      const depositedFromList: BytesLike[] = [
        Keypair.generate().publicKey.toBytes(),
      ];
      const invalidInfoHash = getDepositConfirmationHash(
        tradeInfo[0].amountIn as bigint,
        [
          hexlify(ephemeralL2Wallet[0].address),
          tradeInfo[0].fromChain[1],
          tradeInfo[0].fromChain[2],
        ],
        scriptInfo[0].depositInfo[1],
        depositedFromList,
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[0],
        invalidInfoHash,
        SignatureType.ConfirmDeposit,
        domain,
      );

      await expect(
        router
          .connect(mpcNode1)
          .confirmDeposit(tradeId[0], signature, depositedFromList),
      ).to.be.revertedWithCustomError(solbtc, "InvalidMPCSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.CONFIRM_DEPOSIT,
      );
      expect(await router.getDepositAddressList(tradeId[0])).deep.eq(
        EMPTY_DEPOSIT_ADDRESS_LIST,
      );
    });

    it("Should revert when MPC Node submits a deposit confirmation, but invalid MPC's signature - Un-match fromChain", async () => {
      const depositedFromList: BytesLike[] = [
        Keypair.generate().publicKey.toBytes(),
      ];
      const invalidInfoHash = getDepositConfirmationHash(
        tradeInfo[0].amountIn as bigint,
        [
          tradeInfo[0].fromChain[0],
          toUtf8Bytes("Invalid_from_chain"),
          tradeInfo[0].fromChain[2],
        ],
        scriptInfo[0].depositInfo[1],
        depositedFromList,
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[0],
        invalidInfoHash,
        SignatureType.ConfirmDeposit,
        domain,
      );

      await expect(
        router
          .connect(mpcNode1)
          .confirmDeposit(tradeId[0], signature, depositedFromList),
      ).to.be.revertedWithCustomError(solbtc, "InvalidMPCSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.CONFIRM_DEPOSIT,
      );
      expect(await router.getDepositAddressList(tradeId[0])).deep.eq(
        EMPTY_DEPOSIT_ADDRESS_LIST,
      );
    });

    it("Should revert when MPC Node submits a deposit confirmation, but invalid MPC's signature - Un-match fromToken", async () => {
      const depositedFromList: BytesLike[] = [
        Keypair.generate().publicKey.toBytes(),
      ];
      const invalidInfoHash = getDepositConfirmationHash(
        tradeInfo[0].amountIn as bigint,
        [
          tradeInfo[0].fromChain[0],
          tradeInfo[0].fromChain[1],
          Keypair.generate().publicKey.toBytes(),
        ],
        scriptInfo[0].depositInfo[1],
        depositedFromList,
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[0],
        invalidInfoHash,
        SignatureType.ConfirmDeposit,
        domain,
      );

      await expect(
        router
          .connect(mpcNode1)
          .confirmDeposit(tradeId[0], signature, depositedFromList),
      ).to.be.revertedWithCustomError(solbtc, "InvalidMPCSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.CONFIRM_DEPOSIT,
      );
      expect(await router.getDepositAddressList(tradeId[0])).deep.eq(
        EMPTY_DEPOSIT_ADDRESS_LIST,
      );
    });

    it("Should revert when MPC Node submits a deposit confirmation, but invalid MPC's signature - Un-match depositFromList", async () => {
      const depositedFromList: BytesLike[] = [
        Keypair.generate().publicKey.toBytes(),
      ];
      const invalidDepositedFromList: BytesLike[] = [
        Keypair.generate().publicKey.toBytes(), //  generate a random and different pubkey
      ];
      const invalidInfoHash = getDepositConfirmationHash(
        tradeInfo[0].amountIn as bigint,
        tradeInfo[0].fromChain,
        scriptInfo[0].depositInfo[1],
        invalidDepositedFromList,
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[0],
        invalidInfoHash,
        SignatureType.ConfirmDeposit,
        domain,
      );

      await expect(
        router
          .connect(mpcNode1)
          .confirmDeposit(tradeId[0], signature, depositedFromList),
      ).to.be.revertedWithCustomError(solbtc, "InvalidMPCSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.CONFIRM_DEPOSIT,
      );
      expect(await router.getDepositAddressList(tradeId[0])).deep.eq(
        EMPTY_DEPOSIT_ADDRESS_LIST,
      );
    });

    it("Should revert when MPC Node submits a deposit confirmation, but invalid MPC's signature - Un-match depositTxId", async () => {
      const depositedFromList: BytesLike[] = [
        Keypair.generate().publicKey.toBytes(),
      ];
      const invalidInfoHash = getDepositConfirmationHash(
        tradeInfo[0].amountIn as bigint,
        tradeInfo[0].fromChain,
        randomTxId(),
        depositedFromList,
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[0],
        invalidInfoHash,
        SignatureType.ConfirmDeposit,
        domain,
      );

      await expect(
        router
          .connect(mpcNode1)
          .confirmDeposit(tradeId[0], signature, depositedFromList),
      ).to.be.revertedWithCustomError(solbtc, "InvalidMPCSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.CONFIRM_DEPOSIT,
      );
      expect(await router.getDepositAddressList(tradeId[0])).deep.eq(
        EMPTY_DEPOSIT_ADDRESS_LIST,
      );
    });

    it("Should revert when MPC Node submits a deposit confirmation, but invalid MPC's signature - Wrong domain - Wrong contract name", async () => {
      const wrongDomain: TypedDataDomain = {
        ...domain,
        name: "Wrong Contract Name",
      };

      const depositedFromList: BytesLike[] = [
        Keypair.generate().publicKey.toBytes(),
      ];
      const infoHash = getDepositConfirmationHash(
        tradeInfo[0].amountIn as bigint,
        tradeInfo[0].fromChain,
        scriptInfo[0].depositInfo[1],
        depositedFromList,
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[0],
        infoHash,
        SignatureType.ConfirmDeposit,
        wrongDomain,
      );

      await expect(
        router
          .connect(mpcNode1)
          .confirmDeposit(tradeId[0], signature, depositedFromList),
      ).to.be.revertedWithCustomError(solbtc, "InvalidMPCSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.CONFIRM_DEPOSIT,
      );
      expect(await router.getDepositAddressList(tradeId[0])).deep.eq(
        EMPTY_DEPOSIT_ADDRESS_LIST,
      );
    });

    it("Should revert when MPC Node submits a deposit confirmation, but invalid MPC's signature - Wrong domain - Wrong version", async () => {
      const wrongDomain: TypedDataDomain = {
        ...domain,
        version: "Wrong Contract Version",
      };

      const depositedFromList: BytesLike[] = [
        Keypair.generate().publicKey.toBytes(),
      ];
      const infoHash = getDepositConfirmationHash(
        tradeInfo[0].amountIn as bigint,
        tradeInfo[0].fromChain,
        scriptInfo[0].depositInfo[1],
        depositedFromList,
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[0],
        infoHash,
        SignatureType.ConfirmDeposit,
        wrongDomain,
      );

      await expect(
        router
          .connect(mpcNode1)
          .confirmDeposit(tradeId[0], signature, depositedFromList),
      ).to.be.revertedWithCustomError(solbtc, "InvalidMPCSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.CONFIRM_DEPOSIT,
      );
      expect(await router.getDepositAddressList(tradeId[0])).deep.eq(
        EMPTY_DEPOSIT_ADDRESS_LIST,
      );
    });

    it("Should revert when MPC Node submits a deposit confirmation, but invalid MPC's signature - Wrong domain - Wrong chainId", async () => {
      const wrongDomain: TypedDataDomain = {
        ...domain,
        chainId: (domain.chainId as bigint) + BigInt(1),
      };

      const depositedFromList: BytesLike[] = [
        Keypair.generate().publicKey.toBytes(),
      ];
      const infoHash = getDepositConfirmationHash(
        tradeInfo[0].amountIn as bigint,
        tradeInfo[0].fromChain,
        scriptInfo[0].depositInfo[1],
        depositedFromList,
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[0],
        infoHash,
        SignatureType.ConfirmDeposit,
        wrongDomain,
      );

      await expect(
        router
          .connect(mpcNode1)
          .confirmDeposit(tradeId[0], signature, depositedFromList),
      ).to.be.revertedWithCustomError(solbtc, "InvalidMPCSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.CONFIRM_DEPOSIT,
      );
      expect(await router.getDepositAddressList(tradeId[0])).deep.eq(
        EMPTY_DEPOSIT_ADDRESS_LIST,
      );
    });

    it("Should revert when MPC Node submits a deposit confirmation, but invalid MPC's signature - Wrong domain - Wrong contract address", async () => {
      const wrongDomain: TypedDataDomain = {
        ...domain,
        verifyingContract: admin.address,
      };

      const depositedFromList: BytesLike[] = [
        Keypair.generate().publicKey.toBytes(),
      ];
      const infoHash = getDepositConfirmationHash(
        tradeInfo[0].amountIn as bigint,
        tradeInfo[0].fromChain,
        scriptInfo[0].depositInfo[1],
        depositedFromList,
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[0],
        infoHash,
        SignatureType.ConfirmDeposit,
        wrongDomain,
      );

      await expect(
        router
          .connect(mpcNode1)
          .confirmDeposit(tradeId[0], signature, depositedFromList),
      ).to.be.revertedWithCustomError(solbtc, "InvalidMPCSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.CONFIRM_DEPOSIT,
      );
      expect(await router.getDepositAddressList(tradeId[0])).deep.eq(
        EMPTY_DEPOSIT_ADDRESS_LIST,
      );
    });

    it("Should succeed when MPC Node submits a deposit confirmation", async () => {
      const depositedFromList: BytesLike[] = [
        Keypair.generate().publicKey.toBytes(),
      ];
      const infoHash = getDepositConfirmationHash(
        tradeInfo[0].amountIn as bigint,
        tradeInfo[0].fromChain,
        scriptInfo[0].depositInfo[1],
        depositedFromList,
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[0],
        infoHash,
        SignatureType.ConfirmDeposit,
        domain,
      );

      const tx = router
        .connect(mpcNode1)
        .confirmDeposit(tradeId[0], signature, depositedFromList);

      await expect(tx)
        .to.emit(router, "ConfirmDeposit")
        .withArgs(
          mpcNode1.address,
          tradeId[0],
          pFeeRate,
          affiliateInfo[0].aggregatedValue,
          depositedFromList,
        );
      await expect(tx)
        .to.emit(solbtc, "DepositConfirmed")
        .withArgs(
          await router.getAddress(),
          mpcL2.address,
          tradeId[0],
          (affiliateInfo[0].aggregatedValue as bigint) + pFeeRate,
        );

      const expectedList = depositedFromList.map((data) => hexlify(data));
      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.SELECT_PMM,
      );
      expect(await router.getDepositAddressList(tradeId[0])).deep.eq(
        expectedList,
      );
    });

    it("Should revert when MPC Node tries to update deposit confirmation after submission", async () => {
      const newDepositedList: BytesLike[] = [
        Keypair.generate().publicKey.toBytes(),
      ];
      const infoHash = getDepositConfirmationHash(
        tradeInfo[0].amountIn as bigint,
        tradeInfo[0].fromChain,
        scriptInfo[0].depositInfo[1],
        newDepositedList,
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[0],
        infoHash,
        SignatureType.ConfirmDeposit,
        domain,
      );

      const currentStage = await router.getCurrentStage(tradeId[0]);
      const currentList = await router.getDepositAddressList(tradeId[0]);

      await expect(
        router
          .connect(mpcNode2)
          .confirmDeposit(tradeId[0], signature, newDepositedList),
      ).to.be.revertedWithCustomError(solbtc, "InvalidProcedureState");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(currentStage);
      expect(await router.getDepositAddressList(tradeId[0])).deep.eq(
        currentList,
      );
    });

    it("Should succeed when MPC Node submits the second trade's deposit confirmation", async () => {
      const depositedFromList: BytesLike[] = [
        Keypair.generate().publicKey.toBytes(),
      ];
      const infoHash = getDepositConfirmationHash(
        tradeInfo[1].amountIn as bigint,
        tradeInfo[1].fromChain,
        scriptInfo[1].depositInfo[1],
        depositedFromList,
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[1],
        infoHash,
        SignatureType.ConfirmDeposit,
        domain,
      );

      const tx = router
        .connect(mpcNode2)
        .confirmDeposit(tradeId[1], signature, depositedFromList);

      await expect(tx)
        .to.emit(router, "ConfirmDeposit")
        .withArgs(
          mpcNode2.address,
          tradeId[1],
          pFeeRate,
          affiliateInfo[1].aggregatedValue,
          depositedFromList,
        );
      await expect(tx)
        .to.emit(solbtc, "DepositConfirmed")
        .withArgs(
          await router.getAddress(),
          mpcL2.address,
          tradeId[1],
          (affiliateInfo[1].aggregatedValue as bigint) + pFeeRate,
        );

      const expectedList = depositedFromList.map((data) => hexlify(data));
      expect(await router.getCurrentStage(tradeId[1])).deep.eq(
        STAGE.SELECT_PMM,
      );
      expect(await router.getDepositAddressList(tradeId[1])).deep.eq(
        expectedList,
      );
    });

    it("Should succeed when MPC Node submits the third trade's deposit confirmation", async () => {
      const depositedFromList: BytesLike[] = [
        Keypair.generate().publicKey.toBytes(),
      ];
      const infoHash = getDepositConfirmationHash(
        tradeInfo[2].amountIn as bigint,
        tradeInfo[2].fromChain,
        scriptInfo[2].depositInfo[1],
        depositedFromList,
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[2],
        infoHash,
        SignatureType.ConfirmDeposit,
        domain,
      );

      const tx = router
        .connect(mpcNode2)
        .confirmDeposit(tradeId[2], signature, depositedFromList);

      await expect(tx)
        .to.emit(router, "ConfirmDeposit")
        .withArgs(
          mpcNode2.address,
          tradeId[2],
          pFeeRate,
          affiliateInfo[2].aggregatedValue,
          depositedFromList,
        );
      await expect(tx)
        .to.emit(solbtc, "DepositConfirmed")
        .withArgs(
          await router.getAddress(),
          mpcL2.address,
          tradeId[2],
          (affiliateInfo[2].aggregatedValue as bigint) + pFeeRate,
        );

      const expectedList = depositedFromList.map((data) => hexlify(data));
      expect(await router.getCurrentStage(tradeId[2])).deep.eq(
        STAGE.SELECT_PMM,
      );
      expect(await router.getDepositAddressList(tradeId[2])).deep.eq(
        expectedList,
      );
    });
  });

  describe("selectPMM() functional testing", async () => {
    it("Should revert when Unauthorized client, an arbitrary account, tries to submit the PMM selection", async () => {
      //  Selected PMM Info
      const timestamp = await getBlockTimestamp(provider);
      const expiry = BigInt(timestamp + 30 * 60);
      amountOut[0] =
        (rfqInfo[0].minAmountOut as bigint) + parseUnits("1000", 8);
      const selectedPMMId = presigns[0][0].pmmId;
      const pmmRecvAddress = presigns[0][0].pmmRecvAddress;
      const selectedPMMInfoHash: string = getSelectPMMHash(
        selectedPMMId,
        pmmRecvAddress,
        tradeInfo[0].toChain[1],
        tradeInfo[0].toChain[2],
        amountOut[0],
        expiry,
      );
      let signature: string = await getSignature(
        accounts[0],
        tradeId[0],
        selectedPMMInfoHash,
        SignatureType.SelectPMM,
        domain,
      );
      const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
      const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
        amountOut: amountOut[0],
        selectedPMMId: selectedPMMId,
        info: info,
        sigExpiry: expiry,
      };

      //  RFQ Info
      const rfqInfoHash: string = getRFQHash(
        rfqInfo[0].minAmountOut as bigint,
        rfqInfo[0].tradeTimeout as bigint,
        affiliateInfo[0],
      );
      signature = await getSignature(
        ephemeralL2Wallet[0],
        tradeId[0],
        rfqInfoHash,
        SignatureType.RFQ,
        domain,
      );
      rfqInfo[0].rfqInfoSignature = signature;

      //  PMM Selection Info: Selected PMM Info + RFQ Info
      const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
        rfqInfo: rfqInfo[0],
        pmmInfo: pmmInfo,
      };

      await expect(
        router.connect(accounts[0]).selectPMM(tradeId[0], pmmSelectionInfo),
      ).to.be.revertedWithCustomError(solbtc, "Unauthorized");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.SELECT_PMM,
      );
      expect(await router.getPMMSelection(tradeId[0])).deep.eq(
        EMPTY_PMM_SELECTION_INFO,
      );
    });

    it("Should revert when Unauthorized client, the MPC, tries to submit the PMM selection", async () => {
      //  Selected PMM Info
      const timestamp = await getBlockTimestamp(provider);
      const expiry = BigInt(timestamp + 30 * 60);
      amountOut[0] =
        (rfqInfo[0].minAmountOut as bigint) + parseUnits("1000", 8);
      const selectedPMMId = presigns[0][0].pmmId;
      const pmmRecvAddress = presigns[0][0].pmmRecvAddress;
      const selectedPMMInfoHash: string = getSelectPMMHash(
        selectedPMMId,
        pmmRecvAddress,
        tradeInfo[0].toChain[1],
        tradeInfo[0].toChain[2],
        amountOut[0],
        expiry,
      );
      let signature: string = await getSignature(
        accounts[0],
        tradeId[0],
        selectedPMMInfoHash,
        SignatureType.SelectPMM,
        domain,
      );
      const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
      const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
        amountOut: amountOut[0],
        selectedPMMId: selectedPMMId,
        info: info,
        sigExpiry: expiry,
      };

      //  RFQ Info
      const rfqInfoHash: string = getRFQHash(
        rfqInfo[0].minAmountOut as bigint,
        rfqInfo[0].tradeTimeout as bigint,
        affiliateInfo[0],
      );
      signature = await getSignature(
        ephemeralL2Wallet[0],
        tradeId[0],
        rfqInfoHash,
        SignatureType.RFQ,
        domain,
      );
      rfqInfo[0].rfqInfoSignature = signature;

      //  PMM Selection Info: Selected PMM Info + RFQ Info
      const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
        rfqInfo: rfqInfo[0],
        pmmInfo: pmmInfo,
      };

      await expect(
        router.connect(mpcNode1).selectPMM(tradeId[0], pmmSelectionInfo),
      ).to.be.revertedWithCustomError(solbtc, "Unauthorized");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.SELECT_PMM,
      );
      expect(await router.getPMMSelection(tradeId[0])).deep.eq(
        EMPTY_PMM_SELECTION_INFO,
      );
    });

    it("Should revert when Unauthorized client, the Admin, tries to submit the PMM selection", async () => {
      //  Selected PMM Info
      const timestamp = await getBlockTimestamp(provider);
      const expiry = BigInt(timestamp + 30 * 60);
      amountOut[0] =
        (rfqInfo[0].minAmountOut as bigint) + parseUnits("1000", 8);
      const selectedPMMId = presigns[0][0].pmmId;
      const pmmRecvAddress = presigns[0][0].pmmRecvAddress;
      const selectedPMMInfoHash: string = getSelectPMMHash(
        selectedPMMId,
        pmmRecvAddress,
        tradeInfo[0].toChain[1],
        tradeInfo[0].toChain[2],
        amountOut[0],
        expiry,
      );
      let signature: string = await getSignature(
        accounts[0],
        tradeId[0],
        selectedPMMInfoHash,
        SignatureType.SelectPMM,
        domain,
      );
      const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
      const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
        amountOut: amountOut[0],
        selectedPMMId: selectedPMMId,
        info: info,
        sigExpiry: expiry,
      };

      //  RFQ Info
      const rfqInfoHash: string = getRFQHash(
        rfqInfo[0].minAmountOut as bigint,
        rfqInfo[0].tradeTimeout as bigint,
        affiliateInfo[0],
      );
      signature = await getSignature(
        ephemeralL2Wallet[0],
        tradeId[0],
        rfqInfoHash,
        SignatureType.RFQ,
        domain,
      );
      rfqInfo[0].rfqInfoSignature = signature;

      //  PMM Selection Info: Selected PMM Info + RFQ Info
      const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
        rfqInfo: rfqInfo[0],
        pmmInfo: pmmInfo,
      };

      await expect(
        router.connect(admin).selectPMM(tradeId[0], pmmSelectionInfo),
      ).to.be.revertedWithCustomError(solbtc, "Unauthorized");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.SELECT_PMM,
      );
      expect(await router.getPMMSelection(tradeId[0])).deep.eq(
        EMPTY_PMM_SELECTION_INFO,
      );
    });

    it("Should revert when Solver submits the PMM selection, but the protocol is triggered the Suspension Mode", async () => {
      await management.connect(admin).suspend();

      //  Selected PMM Info
      const timestamp = await getBlockTimestamp(provider);
      const expiry = BigInt(timestamp + 30 * 60);
      amountOut[0] =
        (rfqInfo[0].minAmountOut as bigint) + parseUnits("1000", 8);
      const selectedPMMId = presigns[0][0].pmmId;
      const pmmRecvAddress = presigns[0][0].pmmRecvAddress;
      const selectedPMMInfoHash: string = getSelectPMMHash(
        selectedPMMId,
        pmmRecvAddress,
        tradeInfo[0].toChain[1],
        tradeInfo[0].toChain[2],
        amountOut[0],
        expiry,
      );
      let signature: string = await getSignature(
        accounts[0],
        tradeId[0],
        selectedPMMInfoHash,
        SignatureType.SelectPMM,
        domain,
      );
      const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
      const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
        amountOut: amountOut[0],
        selectedPMMId: selectedPMMId,
        info: info,
        sigExpiry: expiry,
      };

      //  RFQ Info
      const rfqInfoHash: string = getRFQHash(
        rfqInfo[0].minAmountOut as bigint,
        rfqInfo[0].tradeTimeout as bigint,
        affiliateInfo[0],
      );
      signature = await getSignature(
        ephemeralL2Wallet[0],
        tradeId[0],
        rfqInfoHash,
        SignatureType.RFQ,
        domain,
      );
      rfqInfo[0].rfqInfoSignature = signature;

      //  PMM Selection Info: Selected PMM Info + RFQ Info
      const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
        rfqInfo: rfqInfo[0],
        pmmInfo: pmmInfo,
      };

      await expect(
        router.connect(solver).selectPMM(tradeId[0], pmmSelectionInfo),
      ).to.be.revertedWithCustomError(solbtc, "InSuspension");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.SELECT_PMM,
      );
      expect(await router.getPMMSelection(tradeId[0])).deep.eq(
        EMPTY_PMM_SELECTION_INFO,
      );

      //  set back to normal
      await management.connect(admin).resume();
    });

    it("Should revert when Solver submits the PMM selection, but the protocol is triggered the Shutdown Mode", async () => {
      await management.connect(admin).shutdown();

      //  Selected PMM Info
      const timestamp = await getBlockTimestamp(provider);
      const expiry = BigInt(timestamp + 30 * 60);
      amountOut[0] =
        (rfqInfo[0].minAmountOut as bigint) + parseUnits("1000", 8);
      const selectedPMMId = presigns[0][0].pmmId;
      const pmmRecvAddress = presigns[0][0].pmmRecvAddress;
      const selectedPMMInfoHash: string = getSelectPMMHash(
        selectedPMMId,
        pmmRecvAddress,
        tradeInfo[0].toChain[1],
        tradeInfo[0].toChain[2],
        amountOut[0],
        expiry,
      );
      let signature: string = await getSignature(
        accounts[0],
        tradeId[0],
        selectedPMMInfoHash,
        SignatureType.SelectPMM,
        domain,
      );
      const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
      const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
        amountOut: amountOut[0],
        selectedPMMId: selectedPMMId,
        info: info,
        sigExpiry: expiry,
      };

      //  RFQ Info
      const rfqInfoHash: string = getRFQHash(
        rfqInfo[0].minAmountOut as bigint,
        rfqInfo[0].tradeTimeout as bigint,
        affiliateInfo[0],
      );
      signature = await getSignature(
        ephemeralL2Wallet[0],
        tradeId[0],
        rfqInfoHash,
        SignatureType.RFQ,
        domain,
      );
      rfqInfo[0].rfqInfoSignature = signature;

      //  PMM Selection Info: Selected PMM Info + RFQ Info
      const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
        rfqInfo: rfqInfo[0],
        pmmInfo: pmmInfo,
      };

      await expect(
        router.connect(solver).selectPMM(tradeId[0], pmmSelectionInfo),
      ).to.be.revertedWithCustomError(solbtc, "InSuspension");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.SELECT_PMM,
      );
      expect(await router.getPMMSelection(tradeId[0])).deep.eq(
        EMPTY_PMM_SELECTION_INFO,
      );

      //  set back to normal
      await management.connect(admin).resume();
    });

    it("Should revert when Solver submits the PMM selection, but tradeTimeout is reached", async () => {
      //  Selected PMM Info
      const timestamp = await getBlockTimestamp(provider);
      const expiry = BigInt(timestamp + 30 * 60);
      amountOut[0] =
        (rfqInfo[0].minAmountOut as bigint) + parseUnits("1000", 8);
      const selectedPMMId = presigns[0][0].pmmId;
      const pmmRecvAddress = presigns[0][0].pmmRecvAddress;
      const selectedPMMInfoHash: string = getSelectPMMHash(
        selectedPMMId,
        pmmRecvAddress,
        tradeInfo[0].toChain[1],
        tradeInfo[0].toChain[2],
        amountOut[0],
        expiry,
      );
      let signature: string = await getSignature(
        accounts[0],
        tradeId[0],
        selectedPMMInfoHash,
        SignatureType.SelectPMM,
        domain,
      );
      const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
      const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
        amountOut: amountOut[0],
        selectedPMMId: selectedPMMId,
        info: info,
        sigExpiry: expiry,
      };

      //  RFQ Info
      const rfqInfoHash: string = getRFQHash(
        rfqInfo[0].minAmountOut as bigint,
        rfqInfo[0].tradeTimeout as bigint,
        affiliateInfo[0],
      );
      signature = await getSignature(
        ephemeralL2Wallet[0],
        tradeId[0],
        rfqInfoHash,
        SignatureType.RFQ,
        domain,
      );
      rfqInfo[0].rfqInfoSignature = signature;

      //  PMM Selection Info: Selected PMM Info + RFQ Info
      const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
        rfqInfo: rfqInfo[0],
        pmmInfo: pmmInfo,
      };

      //  take a snapshot before increasing block.timestamp
      const exceedTradeTimeout = Number(rfqInfo[0].tradeTimeout) + 1;
      const snapshot = await takeSnapshot();
      if (timestamp < exceedTradeTimeout) await adjustTime(exceedTradeTimeout);

      await expect(
        router.connect(solver).selectPMM(tradeId[0], pmmSelectionInfo),
      ).to.be.revertedWithCustomError(solbtc, "DeadlineExceeded");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.SELECT_PMM,
      );
      expect(await router.getPMMSelection(tradeId[0])).deep.eq(
        EMPTY_PMM_SELECTION_INFO,
      );

      //  set back to normal
      await snapshot.restore();
    });

    it("Should revert when Solver submits the PMM selection, but scriptTimeout is less than tradeTimeout", async () => {
      //  Selected PMM Info
      const timestamp = await getBlockTimestamp(provider);
      const expiry = BigInt(timestamp + 30 * 60);
      amountOut[0] =
        (rfqInfo[0].minAmountOut as bigint) + parseUnits("1000", 8);
      const selectedPMMId = presigns[0][0].pmmId;
      const pmmRecvAddress = presigns[0][0].pmmRecvAddress;
      const selectedPMMInfoHash: string = getSelectPMMHash(
        selectedPMMId,
        pmmRecvAddress,
        tradeInfo[0].toChain[1],
        tradeInfo[0].toChain[2],
        amountOut[0],
        expiry,
      );
      let signature: string = await getSignature(
        accounts[0],
        tradeId[0],
        selectedPMMInfoHash,
        SignatureType.SelectPMM,
        domain,
      );
      const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
      const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
        amountOut: amountOut[0],
        selectedPMMId: selectedPMMId,
        info: info,
        sigExpiry: expiry,
      };

      //  RFQ Info
      const invalidRFQInfo = structuredClone(rfqInfo[0]);
      invalidRFQInfo.tradeTimeout =
        (scriptInfo[0].scriptTimeout as bigint) + BigInt(1);
      const rfqInfoHash: string = getRFQHash(
        invalidRFQInfo.minAmountOut as bigint,
        invalidRFQInfo.tradeTimeout as bigint,
        affiliateInfo[0],
      );
      signature = await getSignature(
        ephemeralL2Wallet[0],
        tradeId[0],
        rfqInfoHash,
        SignatureType.RFQ,
        domain,
      );
      invalidRFQInfo.rfqInfoSignature = signature;

      //  PMM Selection Info: Selected PMM Info + RFQ Info
      const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
        rfqInfo: invalidRFQInfo,
        pmmInfo: pmmInfo,
      };

      await expect(
        router.connect(solver).selectPMM(tradeId[0], pmmSelectionInfo),
      ).to.be.revertedWithCustomError(solbtc, "InvalidTimeout");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.SELECT_PMM,
      );
      expect(await router.getPMMSelection(tradeId[0])).deep.eq(
        EMPTY_PMM_SELECTION_INFO,
      );
    });

    it("Should revert when Solver submits the PMM selection, but Solver is not authorized for that tradeId", async () => {
      //  temporarily set `Owner` as Solver role
      await management.connect(admin).setSolver(admin.address, true);

      //  Selected PMM Info
      const timestamp = await getBlockTimestamp(provider);
      const expiry = BigInt(timestamp + 30 * 60);
      amountOut[0] =
        (rfqInfo[0].minAmountOut as bigint) + parseUnits("1000", 8);
      const selectedPMMId = presigns[0][0].pmmId;
      const pmmRecvAddress = presigns[0][0].pmmRecvAddress;
      const selectedPMMInfoHash: string = getSelectPMMHash(
        selectedPMMId,
        pmmRecvAddress,
        tradeInfo[0].toChain[1],
        tradeInfo[0].toChain[2],
        amountOut[0],
        expiry,
      );
      let signature: string = await getSignature(
        accounts[0],
        tradeId[0],
        selectedPMMInfoHash,
        SignatureType.SelectPMM,
        domain,
      );
      const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
      const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
        amountOut: amountOut[0],
        selectedPMMId: selectedPMMId,
        info: info,
        sigExpiry: expiry,
      };

      //  RFQ Info
      const rfqInfoHash: string = getRFQHash(
        rfqInfo[0].minAmountOut as bigint,
        rfqInfo[0].tradeTimeout as bigint,
        affiliateInfo[0],
      );
      signature = await getSignature(
        ephemeralL2Wallet[0],
        tradeId[0],
        rfqInfoHash,
        SignatureType.RFQ,
        domain,
      );
      rfqInfo[0].rfqInfoSignature = signature;

      //  PMM Selection Info: Selected PMM Info + RFQ Info
      const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
        rfqInfo: rfqInfo[0],
        pmmInfo: pmmInfo,
      };

      await expect(
        router.connect(admin).selectPMM(tradeId[0], pmmSelectionInfo),
      ).to.be.revertedWithCustomError(solbtc, "Unauthorized");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.SELECT_PMM,
      );
      expect(await router.getPMMSelection(tradeId[0])).deep.eq(
        EMPTY_PMM_SELECTION_INFO,
      );

      //  set back to normal
      await management.connect(admin).setSolver(admin.address, false);
    });

    it("Should revert when Solver submits the PMM selection, but PMM's signature is expired", async () => {
      //  Selected PMM Info
      const timestamp = await getBlockTimestamp(provider);
      const expiry = BigInt(timestamp - 1);
      amountOut[0] =
        (rfqInfo[0].minAmountOut as bigint) + parseUnits("1000", 8);
      const selectedPMMId = presigns[0][0].pmmId;
      const pmmRecvAddress = presigns[0][0].pmmRecvAddress;
      const selectedPMMInfoHash: string = getSelectPMMHash(
        selectedPMMId,
        pmmRecvAddress,
        tradeInfo[0].toChain[1],
        tradeInfo[0].toChain[2],
        amountOut[0],
        expiry,
      );
      let signature: string = await getSignature(
        accounts[0],
        tradeId[0],
        selectedPMMInfoHash,
        SignatureType.SelectPMM,
        domain,
      );
      const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
      const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
        amountOut: amountOut[0],
        selectedPMMId: selectedPMMId,
        info: info,
        sigExpiry: expiry,
      };

      //  RFQ Info
      const rfqInfoHash: string = getRFQHash(
        rfqInfo[0].minAmountOut as bigint,
        rfqInfo[0].tradeTimeout as bigint,
        affiliateInfo[0],
      );
      signature = await getSignature(
        ephemeralL2Wallet[0],
        tradeId[0],
        rfqInfoHash,
        SignatureType.RFQ,
        domain,
      );
      rfqInfo[0].rfqInfoSignature = signature;

      //  PMM Selection Info: Selected PMM Info + RFQ Info
      const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
        rfqInfo: rfqInfo[0],
        pmmInfo: pmmInfo,
      };

      await expect(
        router.connect(solver).selectPMM(tradeId[0], pmmSelectionInfo),
      ).to.be.revertedWithCustomError(solbtc, "SignatureExpired");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.SELECT_PMM,
      );
      expect(await router.getPMMSelection(tradeId[0])).deep.eq(
        EMPTY_PMM_SELECTION_INFO,
      );
    });

    it("Should revert when Solver submits the PMM selection, but selected PMM not in the list", async () => {
      //  Selected PMM Info
      const timestamp = await getBlockTimestamp(provider);
      const expiry = BigInt(timestamp + 30 * 60);
      amountOut[0] =
        (rfqInfo[0].minAmountOut as bigint) + parseUnits("1000", 8);
      const selectedPMMId = keccak256(toUtf8Bytes("PMM_not_in_the_list"));
      const pmmRecvAddress = presigns[0][0].pmmRecvAddress;
      const selectedPMMInfoHash: string = getSelectPMMHash(
        selectedPMMId,
        pmmRecvAddress,
        tradeInfo[0].toChain[1],
        tradeInfo[0].toChain[2],
        amountOut[0],
        expiry,
      );
      let signature: string = await getSignature(
        accounts[0],
        tradeId[0],
        selectedPMMInfoHash,
        SignatureType.SelectPMM,
        domain,
      );
      const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
      const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
        amountOut: amountOut[0],
        selectedPMMId: selectedPMMId,
        info: info,
        sigExpiry: expiry,
      };

      //  RFQ Info
      const rfqInfoHash: string = getRFQHash(
        rfqInfo[0].minAmountOut as bigint,
        rfqInfo[0].tradeTimeout as bigint,
        affiliateInfo[0],
      );
      signature = await getSignature(
        ephemeralL2Wallet[0],
        tradeId[0],
        rfqInfoHash,
        SignatureType.RFQ,
        domain,
      );
      rfqInfo[0].rfqInfoSignature = signature;

      //  PMM Selection Info: Selected PMM Info + RFQ Info
      const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
        rfqInfo: rfqInfo[0],
        pmmInfo: pmmInfo,
      };

      await expect(
        router.connect(solver).selectPMM(tradeId[0], pmmSelectionInfo),
      ).to.be.revertedWithCustomError(solbtc, "InvalidPMMSelection");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.SELECT_PMM,
      );
      expect(await router.getPMMSelection(tradeId[0])).deep.eq(
        EMPTY_PMM_SELECTION_INFO,
      );
    });

    it("Should revert when Solver submits the PMM selection, but PMM's receiving address not match", async () => {
      //  Selected PMM Info
      const timestamp = await getBlockTimestamp(provider);
      const expiry = BigInt(timestamp + 30 * 60);
      amountOut[0] =
        (rfqInfo[0].minAmountOut as bigint) + parseUnits("1000", 8);
      const selectedPMMId = presigns[0][0].pmmId;
      const pmmRecvAddress = toUtf8Bytes("Invalid_pmmRecvAddress") as BytesLike;
      const selectedPMMInfoHash: string = getSelectPMMHash(
        selectedPMMId,
        pmmRecvAddress,
        tradeInfo[0].toChain[1],
        tradeInfo[0].toChain[2],
        amountOut[0],
        expiry,
      );
      let signature: string = await getSignature(
        accounts[0],
        tradeId[0],
        selectedPMMInfoHash,
        SignatureType.SelectPMM,
        domain,
      );
      const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
      const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
        amountOut: amountOut[0],
        selectedPMMId: selectedPMMId,
        info: info,
        sigExpiry: expiry,
      };

      //  RFQ Info
      const rfqInfoHash: string = getRFQHash(
        rfqInfo[0].minAmountOut as bigint,
        rfqInfo[0].tradeTimeout as bigint,
        affiliateInfo[0],
      );
      signature = await getSignature(
        ephemeralL2Wallet[0],
        tradeId[0],
        rfqInfoHash,
        SignatureType.RFQ,
        domain,
      );
      rfqInfo[0].rfqInfoSignature = signature;

      //  PMM Selection Info: Selected PMM Info + RFQ Info
      const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
        rfqInfo: rfqInfo[0],
        pmmInfo: pmmInfo,
      };

      await expect(
        router.connect(solver).selectPMM(tradeId[0], pmmSelectionInfo),
      ).to.be.revertedWithCustomError(solbtc, "PMMAddrNotMatched");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.SELECT_PMM,
      );
      expect(await router.getPMMSelection(tradeId[0])).deep.eq(
        EMPTY_PMM_SELECTION_INFO,
      );
    });

    it("Should revert when Solver submits the PMM selection, but quote amount is insufficient", async () => {
      //  Selected PMM Info
      const timestamp = await getBlockTimestamp(provider);
      const expiry = BigInt(timestamp + 30 * 60);
      amountOut[0] = (rfqInfo[0].minAmountOut as bigint) - BigInt(1);
      const selectedPMMId = presigns[0][0].pmmId;
      const pmmRecvAddress = presigns[0][0].pmmRecvAddress;
      const selectedPMMInfoHash: string = getSelectPMMHash(
        selectedPMMId,
        pmmRecvAddress,
        tradeInfo[0].toChain[1],
        tradeInfo[0].toChain[2],
        amountOut[0],
        expiry,
      );
      let signature: string = await getSignature(
        accounts[0],
        tradeId[0],
        selectedPMMInfoHash,
        SignatureType.SelectPMM,
        domain,
      );
      const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
      const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
        amountOut: amountOut[0],
        selectedPMMId: selectedPMMId,
        info: info,
        sigExpiry: expiry,
      };

      //  RFQ Info
      const rfqInfoHash: string = getRFQHash(
        rfqInfo[0].minAmountOut as bigint,
        rfqInfo[0].tradeTimeout as bigint,
        affiliateInfo[0],
      );
      signature = await getSignature(
        ephemeralL2Wallet[0],
        tradeId[0],
        rfqInfoHash,
        SignatureType.RFQ,
        domain,
      );
      rfqInfo[0].rfqInfoSignature = signature;

      //  PMM Selection Info: Selected PMM Info + RFQ Info
      const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
        rfqInfo: rfqInfo[0],
        pmmInfo: pmmInfo,
      };

      await expect(
        router.connect(solver).selectPMM(tradeId[0], pmmSelectionInfo),
      ).to.be.revertedWithCustomError(solbtc, "InsufficientQuoteAmount");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.SELECT_PMM,
      );
      expect(await router.getPMMSelection(tradeId[0])).deep.eq(
        EMPTY_PMM_SELECTION_INFO,
      );
    });

    it("Should revert when Solver submits the PMM selection, but invalid PMM's signature - Signer not match", async () => {
      //  Selected PMM Info
      const timestamp = await getBlockTimestamp(provider);
      const expiry = BigInt(timestamp + 30 * 60);
      amountOut[0] =
        (rfqInfo[0].minAmountOut as bigint) + parseUnits("1000", 8);
      const selectedPMMId = presigns[0][0].pmmId;
      const pmmRecvAddress = presigns[0][0].pmmRecvAddress;
      const selectedPMMInfoHash: string = getSelectPMMHash(
        selectedPMMId,
        pmmRecvAddress,
        tradeInfo[0].toChain[1],
        tradeInfo[0].toChain[2],
        amountOut[0],
        expiry,
      );
      let signature: string = await getSignature(
        accounts[1], //  should be accounts[0]
        tradeId[0],
        selectedPMMInfoHash,
        SignatureType.SelectPMM,
        domain,
      );
      const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
      const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
        amountOut: amountOut[0],
        selectedPMMId: selectedPMMId,
        info: info,
        sigExpiry: expiry,
      };

      //  RFQ Info
      const rfqInfoHash: string = getRFQHash(
        rfqInfo[0].minAmountOut as bigint,
        rfqInfo[0].tradeTimeout as bigint,
        affiliateInfo[0],
      );
      signature = await getSignature(
        ephemeralL2Wallet[0],
        tradeId[0],
        rfqInfoHash,
        SignatureType.RFQ,
        domain,
      );
      rfqInfo[0].rfqInfoSignature = signature;

      //  PMM Selection Info: Selected PMM Info + RFQ Info
      const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
        rfqInfo: rfqInfo[0],
        pmmInfo: pmmInfo,
      };

      await expect(
        router.connect(solver).selectPMM(tradeId[0], pmmSelectionInfo),
      ).to.be.revertedWithCustomError(solbtc, "InvalidPMMSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.SELECT_PMM,
      );
      expect(await router.getPMMSelection(tradeId[0])).deep.eq(
        EMPTY_PMM_SELECTION_INFO,
      );
    });

    it("Should revert when Solver submits the PMM selection, but invalid PMM's signature - tradeId not match", async () => {
      //  Selected PMM Info
      const timestamp = await getBlockTimestamp(provider);
      const expiry = BigInt(timestamp + 30 * 60);
      amountOut[0] =
        (rfqInfo[0].minAmountOut as bigint) + parseUnits("1000", 8);
      const selectedPMMId = presigns[0][0].pmmId;
      const pmmRecvAddress = presigns[0][0].pmmRecvAddress;
      const selectedPMMInfoHash: string = getSelectPMMHash(
        selectedPMMId,
        pmmRecvAddress,
        tradeInfo[0].toChain[1],
        tradeInfo[0].toChain[2],
        amountOut[0],
        expiry,
      );
      let signature: string = await getSignature(
        accounts[0],
        tradeId[1], //  un-match tradeId
        selectedPMMInfoHash,
        SignatureType.SelectPMM,
        domain,
      );
      const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
      const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
        amountOut: amountOut[0],
        selectedPMMId: selectedPMMId,
        info: info,
        sigExpiry: expiry,
      };

      //  RFQ Info
      const rfqInfoHash: string = getRFQHash(
        rfqInfo[0].minAmountOut as bigint,
        rfqInfo[0].tradeTimeout as bigint,
        affiliateInfo[0],
      );
      signature = await getSignature(
        ephemeralL2Wallet[0],
        tradeId[0],
        rfqInfoHash,
        SignatureType.RFQ,
        domain,
      );
      rfqInfo[0].rfqInfoSignature = signature;

      //  PMM Selection Info: Selected PMM Info + RFQ Info
      const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
        rfqInfo: rfqInfo[0],
        pmmInfo: pmmInfo,
      };

      await expect(
        router.connect(solver).selectPMM(tradeId[0], pmmSelectionInfo),
      ).to.be.revertedWithCustomError(solbtc, "InvalidPMMSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.SELECT_PMM,
      );
      expect(await router.getPMMSelection(tradeId[0])).deep.eq(
        EMPTY_PMM_SELECTION_INFO,
      );
    });

    it("Should revert when Solver submits the PMM selection, but invalid PMM's signature - pmmId not match", async () => {
      //  Selected PMM Info
      const timestamp = await getBlockTimestamp(provider);
      const expiry = BigInt(timestamp + 30 * 60);
      amountOut[0] =
        (rfqInfo[0].minAmountOut as bigint) + parseUnits("1000", 8);
      const selectedPMMId = presigns[0][0].pmmId;
      const pmmRecvAddress = presigns[0][0].pmmRecvAddress;
      const selectedPMMInfoHash: string = getSelectPMMHash(
        presigns[0][1].pmmId, // un-match pmmId
        pmmRecvAddress,
        tradeInfo[0].toChain[1],
        tradeInfo[0].toChain[2],
        amountOut[0],
        expiry,
      );
      let signature: string = await getSignature(
        accounts[0],
        tradeId[0],
        selectedPMMInfoHash,
        SignatureType.SelectPMM,
        domain,
      );
      const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
      const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
        amountOut: amountOut[0],
        selectedPMMId: selectedPMMId,
        info: info,
        sigExpiry: expiry,
      };

      //  RFQ Info
      const rfqInfoHash: string = getRFQHash(
        rfqInfo[0].minAmountOut as bigint,
        rfqInfo[0].tradeTimeout as bigint,
        affiliateInfo[0],
      );
      signature = await getSignature(
        ephemeralL2Wallet[0],
        tradeId[0],
        rfqInfoHash,
        SignatureType.RFQ,
        domain,
      );
      rfqInfo[0].rfqInfoSignature = signature;

      //  PMM Selection Info: Selected PMM Info + RFQ Info
      const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
        rfqInfo: rfqInfo[0],
        pmmInfo: pmmInfo,
      };

      await expect(
        router.connect(solver).selectPMM(tradeId[0], pmmSelectionInfo),
      ).to.be.revertedWithCustomError(solbtc, "InvalidPMMSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.SELECT_PMM,
      );
      expect(await router.getPMMSelection(tradeId[0])).deep.eq(
        EMPTY_PMM_SELECTION_INFO,
      );
    });

    it("Should revert when Solver submits the PMM selection, but invalid PMM's signature - pmmRecvAddress not match", async () => {
      //  Selected PMM Info
      const timestamp = await getBlockTimestamp(provider);
      const expiry = BigInt(timestamp + 30 * 60);
      amountOut[0] =
        (rfqInfo[0].minAmountOut as bigint) + parseUnits("1000", 8);
      const selectedPMMId = presigns[0][0].pmmId;
      const pmmRecvAddress = presigns[0][0].pmmRecvAddress;
      const selectedPMMInfoHash: string = getSelectPMMHash(
        selectedPMMId,
        presigns[0][1].pmmRecvAddress, //  un-match pmmRecvAddress
        tradeInfo[0].toChain[1],
        tradeInfo[0].toChain[2],
        amountOut[0],
        expiry,
      );
      let signature: string = await getSignature(
        accounts[0],
        tradeId[0],
        selectedPMMInfoHash,
        SignatureType.SelectPMM,
        domain,
      );
      const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
      const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
        amountOut: amountOut[0],
        selectedPMMId: selectedPMMId,
        info: info,
        sigExpiry: expiry,
      };

      //  RFQ Info
      const rfqInfoHash: string = getRFQHash(
        rfqInfo[0].minAmountOut as bigint,
        rfqInfo[0].tradeTimeout as bigint,
        affiliateInfo[0],
      );
      signature = await getSignature(
        ephemeralL2Wallet[0],
        tradeId[0],
        rfqInfoHash,
        SignatureType.RFQ,
        domain,
      );
      rfqInfo[0].rfqInfoSignature = signature;

      //  PMM Selection Info: Selected PMM Info + RFQ Info
      const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
        rfqInfo: rfqInfo[0],
        pmmInfo: pmmInfo,
      };

      await expect(
        router.connect(solver).selectPMM(tradeId[0], pmmSelectionInfo),
      ).to.be.revertedWithCustomError(solbtc, "InvalidPMMSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.SELECT_PMM,
      );
      expect(await router.getPMMSelection(tradeId[0])).deep.eq(
        EMPTY_PMM_SELECTION_INFO,
      );
    });

    it("Should revert when Solver submits the PMM selection, but invalid PMM's signature - toChain not match", async () => {
      //  Selected PMM Info
      const timestamp = await getBlockTimestamp(provider);
      const expiry = BigInt(timestamp + 30 * 60);
      amountOut[0] =
        (rfqInfo[0].minAmountOut as bigint) + parseUnits("1000", 8);
      const selectedPMMId = presigns[0][0].pmmId;
      const pmmRecvAddress = presigns[0][0].pmmRecvAddress;
      const selectedPMMInfoHash: string = getSelectPMMHash(
        selectedPMMId,
        pmmRecvAddress,
        toUtf8Bytes("Invalid_Chain"), //  un-match toChain
        tradeInfo[0].toChain[2],
        amountOut[0],
        expiry,
      );
      let signature: string = await getSignature(
        accounts[0],
        tradeId[0],
        selectedPMMInfoHash,
        SignatureType.SelectPMM,
        domain,
      );
      const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
      const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
        amountOut: amountOut[0],
        selectedPMMId: selectedPMMId,
        info: info,
        sigExpiry: expiry,
      };

      //  RFQ Info
      const rfqInfoHash: string = getRFQHash(
        rfqInfo[0].minAmountOut as bigint,
        rfqInfo[0].tradeTimeout as bigint,
        affiliateInfo[0],
      );
      signature = await getSignature(
        ephemeralL2Wallet[0],
        tradeId[0],
        rfqInfoHash,
        SignatureType.RFQ,
        domain,
      );
      rfqInfo[0].rfqInfoSignature = signature;

      //  PMM Selection Info: Selected PMM Info + RFQ Info
      const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
        rfqInfo: rfqInfo[0],
        pmmInfo: pmmInfo,
      };

      await expect(
        router.connect(solver).selectPMM(tradeId[0], pmmSelectionInfo),
      ).to.be.revertedWithCustomError(solbtc, "InvalidPMMSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.SELECT_PMM,
      );
      expect(await router.getPMMSelection(tradeId[0])).deep.eq(
        EMPTY_PMM_SELECTION_INFO,
      );
    });

    it("Should revert when Solver submits the PMM selection, but invalid PMM's signature - toToken not match", async () => {
      //  Selected PMM Info
      const timestamp = await getBlockTimestamp(provider);
      const expiry = BigInt(timestamp + 30 * 60);
      amountOut[0] =
        (rfqInfo[0].minAmountOut as bigint) + parseUnits("1000", 8);
      const selectedPMMId = presigns[0][0].pmmId;
      const pmmRecvAddress = presigns[0][0].pmmRecvAddress;
      const selectedPMMInfoHash: string = getSelectPMMHash(
        selectedPMMId,
        pmmRecvAddress,
        tradeInfo[0].toChain[1],
        hexlify(solver.address),
        amountOut[0],
        expiry,
      );
      let signature: string = await getSignature(
        accounts[0],
        tradeId[0],
        selectedPMMInfoHash,
        SignatureType.SelectPMM,
        domain,
      );
      const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
      const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
        amountOut: amountOut[0],
        selectedPMMId: selectedPMMId,
        info: info,
        sigExpiry: expiry,
      };

      //  RFQ Info
      const rfqInfoHash: string = getRFQHash(
        rfqInfo[0].minAmountOut as bigint,
        rfqInfo[0].tradeTimeout as bigint,
        affiliateInfo[0],
      );
      signature = await getSignature(
        ephemeralL2Wallet[0],
        tradeId[0],
        rfqInfoHash,
        SignatureType.RFQ,
        domain,
      );
      rfqInfo[0].rfqInfoSignature = signature;

      //  PMM Selection Info: Selected PMM Info + RFQ Info
      const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
        rfqInfo: rfqInfo[0],
        pmmInfo: pmmInfo,
      };

      await expect(
        router.connect(solver).selectPMM(tradeId[0], pmmSelectionInfo),
      ).to.be.revertedWithCustomError(solbtc, "InvalidPMMSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.SELECT_PMM,
      );
      expect(await router.getPMMSelection(tradeId[0])).deep.eq(
        EMPTY_PMM_SELECTION_INFO,
      );
    });

    it("Should revert when Solver submits the PMM selection, but invalid PMM's signature - amountOut not match", async () => {
      //  Selected PMM Info
      const timestamp = await getBlockTimestamp(provider);
      const expiry = BigInt(timestamp + 30 * 60);
      amountOut[0] =
        (rfqInfo[0].minAmountOut as bigint) + parseUnits("1000", 8);
      const selectedPMMId = presigns[0][0].pmmId;
      const pmmRecvAddress = presigns[0][0].pmmRecvAddress;
      const selectedPMMInfoHash: string = getSelectPMMHash(
        selectedPMMId,
        pmmRecvAddress,
        tradeInfo[0].toChain[1],
        tradeInfo[0].toChain[2],
        amountOut[0] - BigInt(1),
        expiry,
      );
      let signature: string = await getSignature(
        accounts[0],
        tradeId[0],
        selectedPMMInfoHash,
        SignatureType.SelectPMM,
        domain,
      );
      const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
      const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
        amountOut: amountOut[0],
        selectedPMMId: selectedPMMId,
        info: info,
        sigExpiry: expiry,
      };

      //  RFQ Info
      const rfqInfoHash: string = getRFQHash(
        rfqInfo[0].minAmountOut as bigint,
        rfqInfo[0].tradeTimeout as bigint,
        affiliateInfo[0],
      );
      signature = await getSignature(
        ephemeralL2Wallet[0],
        tradeId[0],
        rfqInfoHash,
        SignatureType.RFQ,
        domain,
      );
      rfqInfo[0].rfqInfoSignature = signature;

      //  PMM Selection Info: Selected PMM Info + RFQ Info
      const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
        rfqInfo: rfqInfo[0],
        pmmInfo: pmmInfo,
      };

      await expect(
        router.connect(solver).selectPMM(tradeId[0], pmmSelectionInfo),
      ).to.be.revertedWithCustomError(solbtc, "InvalidPMMSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.SELECT_PMM,
      );
      expect(await router.getPMMSelection(tradeId[0])).deep.eq(
        EMPTY_PMM_SELECTION_INFO,
      );
    });

    it("Should revert when Solver submits the PMM selection, but invalid PMM's signature - signature expiry not match", async () => {
      //  This test case covers the scenario that PMM's signature already expired
      //  and Solver tries to modify the data pushed onto contract
      //  Selected PMM Info
      const timestamp = await getBlockTimestamp(provider);
      const expiry = BigInt(timestamp + 30 * 60);
      amountOut[0] =
        (rfqInfo[0].minAmountOut as bigint) + parseUnits("1000", 8);
      const selectedPMMId = presigns[0][0].pmmId;
      const pmmRecvAddress = presigns[0][0].pmmRecvAddress;
      const selectedPMMInfoHash: string = getSelectPMMHash(
        selectedPMMId,
        pmmRecvAddress,
        tradeInfo[0].toChain[1],
        tradeInfo[0].toChain[2],
        amountOut[0],
        expiry - BigInt(2 * 60),
      );
      let signature: string = await getSignature(
        accounts[0],
        tradeId[0],
        selectedPMMInfoHash,
        SignatureType.SelectPMM,
        domain,
      );
      const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
      const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
        amountOut: amountOut[0],
        selectedPMMId: selectedPMMId,
        info: info,
        sigExpiry: expiry,
      };

      //  RFQ Info
      const rfqInfoHash: string = getRFQHash(
        rfqInfo[0].minAmountOut as bigint,
        rfqInfo[0].tradeTimeout as bigint,
        affiliateInfo[0],
      );
      signature = await getSignature(
        ephemeralL2Wallet[0],
        tradeId[0],
        rfqInfoHash,
        SignatureType.RFQ,
        domain,
      );
      rfqInfo[0].rfqInfoSignature = signature;

      //  PMM Selection Info: Selected PMM Info + RFQ Info
      const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
        rfqInfo: rfqInfo[0],
        pmmInfo: pmmInfo,
      };

      await expect(
        router.connect(solver).selectPMM(tradeId[0], pmmSelectionInfo),
      ).to.be.revertedWithCustomError(solbtc, "InvalidPMMSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.SELECT_PMM,
      );
      expect(await router.getPMMSelection(tradeId[0])).deep.eq(
        EMPTY_PMM_SELECTION_INFO,
      );
    });

    it("Should revert when Solver submits the PMM selection, but invalid PMM's signature - Wrong domain - Wrong contract name", async () => {
      const wrongDomain: TypedDataDomain = {
        ...domain,
        name: "Wrong Contract Name",
      };

      //  Selected PMM Info
      const timestamp = await getBlockTimestamp(provider);
      const expiry = BigInt(timestamp + 30 * 60);
      amountOut[0] =
        (rfqInfo[0].minAmountOut as bigint) + parseUnits("1000", 8);
      const selectedPMMId = presigns[0][0].pmmId;
      const pmmRecvAddress = presigns[0][0].pmmRecvAddress;
      const selectedPMMInfoHash: string = getSelectPMMHash(
        selectedPMMId,
        pmmRecvAddress,
        tradeInfo[0].toChain[1],
        tradeInfo[0].toChain[2],
        amountOut[0],
        expiry,
      );
      let signature: string = await getSignature(
        accounts[0],
        tradeId[0],
        selectedPMMInfoHash,
        SignatureType.SelectPMM,
        wrongDomain,
      );
      const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
      const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
        amountOut: amountOut[0],
        selectedPMMId: selectedPMMId,
        info: info,
        sigExpiry: expiry,
      };

      //  RFQ Info
      const rfqInfoHash: string = getRFQHash(
        rfqInfo[0].minAmountOut as bigint,
        rfqInfo[0].tradeTimeout as bigint,
        affiliateInfo[0],
      );
      signature = await getSignature(
        ephemeralL2Wallet[0],
        tradeId[0],
        rfqInfoHash,
        SignatureType.RFQ,
        domain,
      );
      rfqInfo[0].rfqInfoSignature = signature;

      //  PMM Selection Info: Selected PMM Info + RFQ Info
      const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
        rfqInfo: rfqInfo[0],
        pmmInfo: pmmInfo,
      };

      await expect(
        router.connect(solver).selectPMM(tradeId[0], pmmSelectionInfo),
      ).to.be.revertedWithCustomError(solbtc, "InvalidPMMSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.SELECT_PMM,
      );
      expect(await router.getPMMSelection(tradeId[0])).deep.eq(
        EMPTY_PMM_SELECTION_INFO,
      );
    });

    it("Should revert when Solver submits the PMM selection, but invalid PMM's signature - Wrong domain - Wrong version", async () => {
      const wrongDomain: TypedDataDomain = {
        ...domain,
        version: "Wrong Contract Version",
      };

      //  Selected PMM Info
      const timestamp = await getBlockTimestamp(provider);
      const expiry = BigInt(timestamp + 30 * 60);
      amountOut[0] =
        (rfqInfo[0].minAmountOut as bigint) + parseUnits("1000", 8);
      const selectedPMMId = presigns[0][0].pmmId;
      const pmmRecvAddress = presigns[0][0].pmmRecvAddress;
      const selectedPMMInfoHash: string = getSelectPMMHash(
        selectedPMMId,
        pmmRecvAddress,
        tradeInfo[0].toChain[1],
        tradeInfo[0].toChain[2],
        amountOut[0],
        expiry,
      );
      let signature: string = await getSignature(
        accounts[0],
        tradeId[0],
        selectedPMMInfoHash,
        SignatureType.SelectPMM,
        wrongDomain,
      );
      const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
      const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
        amountOut: amountOut[0],
        selectedPMMId: selectedPMMId,
        info: info,
        sigExpiry: expiry,
      };

      //  RFQ Info
      const rfqInfoHash: string = getRFQHash(
        rfqInfo[0].minAmountOut as bigint,
        rfqInfo[0].tradeTimeout as bigint,
        affiliateInfo[0],
      );
      signature = await getSignature(
        ephemeralL2Wallet[0],
        tradeId[0],
        rfqInfoHash,
        SignatureType.RFQ,
        domain,
      );
      rfqInfo[0].rfqInfoSignature = signature;

      //  PMM Selection Info: Selected PMM Info + RFQ Info
      const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
        rfqInfo: rfqInfo[0],
        pmmInfo: pmmInfo,
      };

      await expect(
        router.connect(solver).selectPMM(tradeId[0], pmmSelectionInfo),
      ).to.be.revertedWithCustomError(solbtc, "InvalidPMMSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.SELECT_PMM,
      );
      expect(await router.getPMMSelection(tradeId[0])).deep.eq(
        EMPTY_PMM_SELECTION_INFO,
      );
    });

    it("Should revert when Solver submits the PMM selection, but invalid PMM's signature - Wrong domain - Wrong chainId", async () => {
      const wrongDomain: TypedDataDomain = {
        ...domain,
        chainId: (domain.chainId as bigint) + BigInt(1),
      };

      //  Selected PMM Info
      const timestamp = await getBlockTimestamp(provider);
      const expiry = BigInt(timestamp + 30 * 60);
      amountOut[0] =
        (rfqInfo[0].minAmountOut as bigint) + parseUnits("1000", 8);
      const selectedPMMId = presigns[0][0].pmmId;
      const pmmRecvAddress = presigns[0][0].pmmRecvAddress;
      const selectedPMMInfoHash: string = getSelectPMMHash(
        selectedPMMId,
        pmmRecvAddress,
        tradeInfo[0].toChain[1],
        tradeInfo[0].toChain[2],
        amountOut[0],
        expiry,
      );
      let signature: string = await getSignature(
        accounts[0],
        tradeId[0],
        selectedPMMInfoHash,
        SignatureType.SelectPMM,
        wrongDomain,
      );
      const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
      const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
        amountOut: amountOut[0],
        selectedPMMId: selectedPMMId,
        info: info,
        sigExpiry: expiry,
      };

      //  RFQ Info
      const rfqInfoHash: string = getRFQHash(
        rfqInfo[0].minAmountOut as bigint,
        rfqInfo[0].tradeTimeout as bigint,
        affiliateInfo[0],
      );
      signature = await getSignature(
        ephemeralL2Wallet[0],
        tradeId[0],
        rfqInfoHash,
        SignatureType.RFQ,
        domain,
      );
      rfqInfo[0].rfqInfoSignature = signature;

      //  PMM Selection Info: Selected PMM Info + RFQ Info
      const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
        rfqInfo: rfqInfo[0],
        pmmInfo: pmmInfo,
      };

      await expect(
        router.connect(solver).selectPMM(tradeId[0], pmmSelectionInfo),
      ).to.be.revertedWithCustomError(solbtc, "InvalidPMMSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.SELECT_PMM,
      );
      expect(await router.getPMMSelection(tradeId[0])).deep.eq(
        EMPTY_PMM_SELECTION_INFO,
      );
    });

    it("Should revert when Solver submits the PMM selection, but invalid PMM's signature - Wrong domain - Wrong contract address", async () => {
      const wrongDomain: TypedDataDomain = {
        ...domain,
        verifyingContract: admin.address,
      };

      //  Selected PMM Info
      const timestamp = await getBlockTimestamp(provider);
      const expiry = BigInt(timestamp + 30 * 60);
      amountOut[0] =
        (rfqInfo[0].minAmountOut as bigint) + parseUnits("1000", 8);
      const selectedPMMId = presigns[0][0].pmmId;
      const pmmRecvAddress = presigns[0][0].pmmRecvAddress;
      const selectedPMMInfoHash: string = getSelectPMMHash(
        selectedPMMId,
        pmmRecvAddress,
        tradeInfo[0].toChain[1],
        tradeInfo[0].toChain[2],
        amountOut[0],
        expiry,
      );
      let signature: string = await getSignature(
        accounts[0],
        tradeId[0],
        selectedPMMInfoHash,
        SignatureType.SelectPMM,
        wrongDomain,
      );
      const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
      const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
        amountOut: amountOut[0],
        selectedPMMId: selectedPMMId,
        info: info,
        sigExpiry: expiry,
      };

      //  RFQ Info
      const rfqInfoHash: string = getRFQHash(
        rfqInfo[0].minAmountOut as bigint,
        rfqInfo[0].tradeTimeout as bigint,
        affiliateInfo[0],
      );
      signature = await getSignature(
        ephemeralL2Wallet[0],
        tradeId[0],
        rfqInfoHash,
        SignatureType.RFQ,
        domain,
      );
      rfqInfo[0].rfqInfoSignature = signature;

      //  PMM Selection Info: Selected PMM Info + RFQ Info
      const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
        rfqInfo: rfqInfo[0],
        pmmInfo: pmmInfo,
      };

      await expect(
        router.connect(solver).selectPMM(tradeId[0], pmmSelectionInfo),
      ).to.be.revertedWithCustomError(solbtc, "InvalidPMMSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.SELECT_PMM,
      );
      expect(await router.getPMMSelection(tradeId[0])).deep.eq(
        EMPTY_PMM_SELECTION_INFO,
      );
    });

    it("Should revert when Solver submits the PMM selection, but invalid RFQ's signature - Signer not match", async () => {
      //  Selected PMM Info
      const timestamp = await getBlockTimestamp(provider);
      const expiry = BigInt(timestamp + 30 * 60);
      amountOut[0] =
        (rfqInfo[0].minAmountOut as bigint) + parseUnits("1000", 8);
      const selectedPMMId = presigns[0][0].pmmId;
      const pmmRecvAddress = presigns[0][0].pmmRecvAddress;
      const selectedPMMInfoHash: string = getSelectPMMHash(
        selectedPMMId,
        pmmRecvAddress,
        tradeInfo[0].toChain[1],
        tradeInfo[0].toChain[2],
        amountOut[0],
        expiry,
      );
      let signature: string = await getSignature(
        accounts[0],
        tradeId[0],
        selectedPMMInfoHash,
        SignatureType.SelectPMM,
        domain,
      );
      const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
      const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
        amountOut: amountOut[0],
        selectedPMMId: selectedPMMId,
        info: info,
        sigExpiry: expiry,
      };

      //  RFQ Info
      const rfqInfoHash: string = getRFQHash(
        rfqInfo[0].minAmountOut as bigint,
        rfqInfo[0].tradeTimeout as bigint,
        affiliateInfo[0],
      );
      signature = await getSignature(
        solver, // should be ephemeralL2Wallet1
        tradeId[0],
        rfqInfoHash,
        SignatureType.RFQ,
        domain,
      );
      rfqInfo[0].rfqInfoSignature = signature;

      //  PMM Selection Info: Selected PMM Info + RFQ Info
      const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
        rfqInfo: rfqInfo[0],
        pmmInfo: pmmInfo,
      };

      await expect(
        router.connect(solver).selectPMM(tradeId[0], pmmSelectionInfo),
      ).to.be.revertedWithCustomError(solbtc, "InvalidRFQSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.SELECT_PMM,
      );
      expect(await router.getPMMSelection(tradeId[0])).deep.eq(
        EMPTY_PMM_SELECTION_INFO,
      );
    });

    it("Should revert when Solver submits the PMM selection, but invalid RFQ's signature - tradeId not match", async () => {
      //  Selected PMM Info
      const timestamp = await getBlockTimestamp(provider);
      const expiry = BigInt(timestamp + 30 * 60);
      amountOut[0] =
        (rfqInfo[0].minAmountOut as bigint) + parseUnits("1000", 8);
      const selectedPMMId = presigns[0][0].pmmId;
      const pmmRecvAddress = presigns[0][0].pmmRecvAddress;
      const selectedPMMInfoHash: string = getSelectPMMHash(
        selectedPMMId,
        pmmRecvAddress,
        tradeInfo[0].toChain[1],
        tradeInfo[0].toChain[2],
        amountOut[0],
        expiry,
      );
      let signature: string = await getSignature(
        accounts[0],
        tradeId[0],
        selectedPMMInfoHash,
        SignatureType.SelectPMM,
        domain,
      );
      const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
      const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
        amountOut: amountOut[0],
        selectedPMMId: selectedPMMId,
        info: info,
        sigExpiry: expiry,
      };

      //  RFQ Info
      const rfqInfoHash: string = getRFQHash(
        rfqInfo[0].minAmountOut as bigint,
        rfqInfo[0].tradeTimeout as bigint,
        affiliateInfo[0],
      );
      signature = await getSignature(
        ephemeralL2Wallet[0],
        tradeId[1], // un-match tradeId
        rfqInfoHash,
        SignatureType.RFQ,
        domain,
      );
      rfqInfo[0].rfqInfoSignature = signature;

      //  PMM Selection Info: Selected PMM Info + RFQ Info
      const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
        rfqInfo: rfqInfo[0],
        pmmInfo: pmmInfo,
      };

      await expect(
        router.connect(solver).selectPMM(tradeId[0], pmmSelectionInfo),
      ).to.be.revertedWithCustomError(solbtc, "InvalidRFQSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.SELECT_PMM,
      );
      expect(await router.getPMMSelection(tradeId[0])).deep.eq(
        EMPTY_PMM_SELECTION_INFO,
      );
    });

    it("Should revert when Solver submits the PMM selection, but invalid RFQ's signature - minAmountOut not match", async () => {
      //  Selected PMM Info
      const timestamp = await getBlockTimestamp(provider);
      const expiry = BigInt(timestamp + 30 * 60);
      amountOut[0] =
        (rfqInfo[0].minAmountOut as bigint) + parseUnits("1000", 8);
      const selectedPMMId = presigns[0][0].pmmId;
      const pmmRecvAddress = presigns[0][0].pmmRecvAddress;
      const selectedPMMInfoHash: string = getSelectPMMHash(
        selectedPMMId,
        pmmRecvAddress,
        tradeInfo[0].toChain[1],
        tradeInfo[0].toChain[2],
        amountOut[0],
        expiry,
      );
      let signature: string = await getSignature(
        accounts[0],
        tradeId[0],
        selectedPMMInfoHash,
        SignatureType.SelectPMM,
        domain,
      );
      const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
      const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
        amountOut: amountOut[0],
        selectedPMMId: selectedPMMId,
        info: info,
        sigExpiry: expiry,
      };

      //  RFQ Info
      const rfqInfoHash: string = getRFQHash(
        (rfqInfo[0].minAmountOut as bigint) + BigInt(1),
        rfqInfo[0].tradeTimeout as bigint,
        affiliateInfo[0],
      );
      signature = await getSignature(
        ephemeralL2Wallet[0],
        tradeId[0],
        rfqInfoHash,
        SignatureType.RFQ,
        domain,
      );
      rfqInfo[0].rfqInfoSignature = signature;

      //  PMM Selection Info: Selected PMM Info + RFQ Info
      const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
        rfqInfo: rfqInfo[0],
        pmmInfo: pmmInfo,
      };

      await expect(
        router.connect(solver).selectPMM(tradeId[0], pmmSelectionInfo),
      ).to.be.revertedWithCustomError(solbtc, "InvalidRFQSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.SELECT_PMM,
      );
      expect(await router.getPMMSelection(tradeId[0])).deep.eq(
        EMPTY_PMM_SELECTION_INFO,
      );
    });

    it("Should revert when Solver submits the PMM selection, but invalid RFQ's signature - tradeTimeout not match", async () => {
      //  Selected PMM Info
      const timestamp = await getBlockTimestamp(provider);
      const expiry = BigInt(timestamp + 30 * 60);
      amountOut[0] =
        (rfqInfo[0].minAmountOut as bigint) + parseUnits("1000", 8);
      const selectedPMMId = presigns[0][0].pmmId;
      const pmmRecvAddress = presigns[0][0].pmmRecvAddress;
      const selectedPMMInfoHash: string = getSelectPMMHash(
        selectedPMMId,
        pmmRecvAddress,
        tradeInfo[0].toChain[1],
        tradeInfo[0].toChain[2],
        amountOut[0],
        expiry,
      );
      let signature: string = await getSignature(
        accounts[0],
        tradeId[0],
        selectedPMMInfoHash,
        SignatureType.SelectPMM,
        domain,
      );
      const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
      const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
        amountOut: amountOut[0],
        selectedPMMId: selectedPMMId,
        info: info,
        sigExpiry: expiry,
      };

      //  RFQ Info
      const rfqInfoHash: string = getRFQHash(
        rfqInfo[0].minAmountOut as bigint,
        BigInt(Number(rfqInfo[0].tradeTimeout) - 3600),
        affiliateInfo[0],
      );
      signature = await getSignature(
        ephemeralL2Wallet[0],
        tradeId[0],
        rfqInfoHash,
        SignatureType.RFQ,
        domain,
      );
      rfqInfo[0].rfqInfoSignature = signature;

      //  PMM Selection Info: Selected PMM Info + RFQ Info
      const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
        rfqInfo: rfqInfo[0],
        pmmInfo: pmmInfo,
      };

      await expect(
        router.connect(solver).selectPMM(tradeId[0], pmmSelectionInfo),
      ).to.be.revertedWithCustomError(solbtc, "InvalidRFQSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.SELECT_PMM,
      );
      expect(await router.getPMMSelection(tradeId[0])).deep.eq(
        EMPTY_PMM_SELECTION_INFO,
      );
    });

    it("Should revert when Solver submits the PMM selection, but invalid RFQ's signature - affiliateInfo not match", async () => {
      //  Selected PMM Info
      const timestamp = await getBlockTimestamp(provider);
      const expiry = BigInt(timestamp + 30 * 60);
      amountOut[0] =
        (rfqInfo[0].minAmountOut as bigint) + parseUnits("1000", 8);
      const selectedPMMId = presigns[0][0].pmmId;
      const pmmRecvAddress = presigns[0][0].pmmRecvAddress;
      const selectedPMMInfoHash: string = getSelectPMMHash(
        selectedPMMId,
        pmmRecvAddress,
        tradeInfo[0].toChain[1],
        tradeInfo[0].toChain[2],
        amountOut[0],
        expiry,
      );
      let signature: string = await getSignature(
        accounts[0],
        tradeId[0],
        selectedPMMInfoHash,
        SignatureType.SelectPMM,
        domain,
      );
      const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
      const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
        amountOut: amountOut[0],
        selectedPMMId: selectedPMMId,
        info: info,
        sigExpiry: expiry,
      };

      //  RFQ Info
      const invalidAffiliate: CoreTypes.AffiliateStruct = structuredClone(
        affiliateInfo[0],
      );
      invalidAffiliate.aggregatedValue =
        (invalidAffiliate.aggregatedValue as bigint) + BigInt(1);
      const rfqInfoHash: string = getRFQHash(
        rfqInfo[0].minAmountOut as bigint,
        rfqInfo[0].tradeTimeout as bigint,
        invalidAffiliate,
      );
      signature = await getSignature(
        ephemeralL2Wallet[0],
        tradeId[0],
        rfqInfoHash,
        SignatureType.RFQ,
        domain,
      );
      rfqInfo[0].rfqInfoSignature = signature;

      //  PMM Selection Info: Selected PMM Info + RFQ Info
      const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
        rfqInfo: rfqInfo[0],
        pmmInfo: pmmInfo,
      };

      await expect(
        router.connect(solver).selectPMM(tradeId[0], pmmSelectionInfo),
      ).to.be.revertedWithCustomError(solbtc, "InvalidRFQSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.SELECT_PMM,
      );
      expect(await router.getPMMSelection(tradeId[0])).deep.eq(
        EMPTY_PMM_SELECTION_INFO,
      );
    });

    it("Should revert when Solver submits the PMM selection, but invalid RFQ's signature - Wrong domain - Wrong contract name", async () => {
      const wrongDomain: TypedDataDomain = {
        ...domain,
        name: "Wrong Contract Name",
      };

      //  Selected PMM Info
      const timestamp = await getBlockTimestamp(provider);
      const expiry = BigInt(timestamp + 30 * 60);
      amountOut[0] =
        (rfqInfo[0].minAmountOut as bigint) + parseUnits("1000", 8);
      const selectedPMMId = presigns[0][0].pmmId;
      const pmmRecvAddress = presigns[0][0].pmmRecvAddress;
      const selectedPMMInfoHash: string = getSelectPMMHash(
        selectedPMMId,
        pmmRecvAddress,
        tradeInfo[0].toChain[1],
        tradeInfo[0].toChain[2],
        amountOut[0],
        expiry,
      );
      let signature: string = await getSignature(
        accounts[0],
        tradeId[0],
        selectedPMMInfoHash,
        SignatureType.SelectPMM,
        domain,
      );
      const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
      const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
        amountOut: amountOut[0],
        selectedPMMId: selectedPMMId,
        info: info,
        sigExpiry: expiry,
      };

      //  RFQ Info
      const rfqInfoHash: string = getRFQHash(
        rfqInfo[0].minAmountOut as bigint,
        rfqInfo[0].tradeTimeout as bigint,
        affiliateInfo[0],
      );
      signature = await getSignature(
        ephemeralL2Wallet[0],
        tradeId[0],
        rfqInfoHash,
        SignatureType.RFQ,
        wrongDomain,
      );
      rfqInfo[0].rfqInfoSignature = signature;

      //  PMM Selection Info: Selected PMM Info + RFQ Info
      const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
        rfqInfo: rfqInfo[0],
        pmmInfo: pmmInfo,
      };

      await expect(
        router.connect(solver).selectPMM(tradeId[0], pmmSelectionInfo),
      ).to.be.revertedWithCustomError(solbtc, "InvalidRFQSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.SELECT_PMM,
      );
      expect(await router.getPMMSelection(tradeId[0])).deep.eq(
        EMPTY_PMM_SELECTION_INFO,
      );
    });

    it("Should revert when Solver submits the PMM selection, but invalid RFQ's signature - Wrong domain - Wrong version", async () => {
      const wrongDomain: TypedDataDomain = {
        ...domain,
        version: "Wrong Contract Version",
      };

      //  Selected PMM Info
      const timestamp = await getBlockTimestamp(provider);
      const expiry = BigInt(timestamp + 30 * 60);
      amountOut[0] =
        (rfqInfo[0].minAmountOut as bigint) + parseUnits("1000", 8);
      const selectedPMMId = presigns[0][0].pmmId;
      const pmmRecvAddress = presigns[0][0].pmmRecvAddress;
      const selectedPMMInfoHash: string = getSelectPMMHash(
        selectedPMMId,
        pmmRecvAddress,
        tradeInfo[0].toChain[1],
        tradeInfo[0].toChain[2],
        amountOut[0],
        expiry,
      );
      let signature: string = await getSignature(
        accounts[0],
        tradeId[0],
        selectedPMMInfoHash,
        SignatureType.SelectPMM,
        domain,
      );
      const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
      const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
        amountOut: amountOut[0],
        selectedPMMId: selectedPMMId,
        info: info,
        sigExpiry: expiry,
      };

      //  RFQ Info
      const rfqInfoHash: string = getRFQHash(
        rfqInfo[0].minAmountOut as bigint,
        rfqInfo[0].tradeTimeout as bigint,
        affiliateInfo[0],
      );
      signature = await getSignature(
        ephemeralL2Wallet[0],
        tradeId[0],
        rfqInfoHash,
        SignatureType.RFQ,
        wrongDomain,
      );
      rfqInfo[0].rfqInfoSignature = signature;

      //  PMM Selection Info: Selected PMM Info + RFQ Info
      const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
        rfqInfo: rfqInfo[0],
        pmmInfo: pmmInfo,
      };

      await expect(
        router.connect(solver).selectPMM(tradeId[0], pmmSelectionInfo),
      ).to.be.revertedWithCustomError(solbtc, "InvalidRFQSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.SELECT_PMM,
      );
      expect(await router.getPMMSelection(tradeId[0])).deep.eq(
        EMPTY_PMM_SELECTION_INFO,
      );
    });

    it("Should revert when Solver submits the PMM selection, but invalid RFQ's signature - Wrong domain - Wrong chainId", async () => {
      const wrongDomain: TypedDataDomain = {
        ...domain,
        chainId: (domain.chainId as bigint) + BigInt(1),
      };

      //  Selected PMM Info
      const timestamp = await getBlockTimestamp(provider);
      const expiry = BigInt(timestamp + 30 * 60);
      amountOut[0] =
        (rfqInfo[0].minAmountOut as bigint) + parseUnits("1000", 8);
      const selectedPMMId = presigns[0][0].pmmId;
      const pmmRecvAddress = presigns[0][0].pmmRecvAddress;
      const selectedPMMInfoHash: string = getSelectPMMHash(
        selectedPMMId,
        pmmRecvAddress,
        tradeInfo[0].toChain[1],
        tradeInfo[0].toChain[2],
        amountOut[0],
        expiry,
      );
      let signature: string = await getSignature(
        accounts[0],
        tradeId[0],
        selectedPMMInfoHash,
        SignatureType.SelectPMM,
        domain,
      );
      const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
      const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
        amountOut: amountOut[0],
        selectedPMMId: selectedPMMId,
        info: info,
        sigExpiry: expiry,
      };

      //  RFQ Info
      const rfqInfoHash: string = getRFQHash(
        rfqInfo[0].minAmountOut as bigint,
        rfqInfo[0].tradeTimeout as bigint,
        affiliateInfo[0],
      );
      signature = await getSignature(
        ephemeralL2Wallet[0],
        tradeId[0],
        rfqInfoHash,
        SignatureType.RFQ,
        wrongDomain,
      );
      rfqInfo[0].rfqInfoSignature = signature;

      //  PMM Selection Info: Selected PMM Info + RFQ Info
      const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
        rfqInfo: rfqInfo[0],
        pmmInfo: pmmInfo,
      };

      await expect(
        router.connect(solver).selectPMM(tradeId[0], pmmSelectionInfo),
      ).to.be.revertedWithCustomError(solbtc, "InvalidRFQSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.SELECT_PMM,
      );
      expect(await router.getPMMSelection(tradeId[0])).deep.eq(
        EMPTY_PMM_SELECTION_INFO,
      );
    });

    it("Should revert when Solver submits the PMM selection, but invalid RFQ's signature - Wrong domain - Wrong contract address", async () => {
      const wrongDomain: TypedDataDomain = {
        ...domain,
        verifyingContract: admin.address,
      };

      //  Selected PMM Info
      const timestamp = await getBlockTimestamp(provider);
      const expiry = BigInt(timestamp + 30 * 60);
      amountOut[0] =
        (rfqInfo[0].minAmountOut as bigint) + parseUnits("1000", 8);
      const selectedPMMId = presigns[0][0].pmmId;
      const pmmRecvAddress = presigns[0][0].pmmRecvAddress;
      const selectedPMMInfoHash: string = getSelectPMMHash(
        selectedPMMId,
        pmmRecvAddress,
        tradeInfo[0].toChain[1],
        tradeInfo[0].toChain[2],
        amountOut[0],
        expiry,
      );
      let signature: string = await getSignature(
        accounts[0],
        tradeId[0],
        selectedPMMInfoHash,
        SignatureType.SelectPMM,
        domain,
      );
      const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
      const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
        amountOut: amountOut[0],
        selectedPMMId: selectedPMMId,
        info: info,
        sigExpiry: expiry,
      };

      //  RFQ Info
      const rfqInfoHash: string = getRFQHash(
        rfqInfo[0].minAmountOut as bigint,
        rfqInfo[0].tradeTimeout as bigint,
        affiliateInfo[0],
      );
      signature = await getSignature(
        ephemeralL2Wallet[0],
        tradeId[0],
        rfqInfoHash,
        SignatureType.RFQ,
        wrongDomain,
      );
      rfqInfo[0].rfqInfoSignature = signature;

      //  PMM Selection Info: Selected PMM Info + RFQ Info
      const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
        rfqInfo: rfqInfo[0],
        pmmInfo: pmmInfo,
      };

      await expect(
        router.connect(solver).selectPMM(tradeId[0], pmmSelectionInfo),
      ).to.be.revertedWithCustomError(solbtc, "InvalidRFQSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.SELECT_PMM,
      );
      expect(await router.getPMMSelection(tradeId[0])).deep.eq(
        EMPTY_PMM_SELECTION_INFO,
      );
    });

    it("Should succeed when Solver submits selected PMM", async () => {
      //  Selected PMM Info
      const timestamp = await getBlockTimestamp(provider);
      const expiry = BigInt(timestamp + 30 * 60);
      amountOut[0] =
        (rfqInfo[0].minAmountOut as bigint) + parseUnits("1000", 8);
      const selectedPMMId = presigns[0][0].pmmId;
      const pmmRecvAddress = presigns[0][0].pmmRecvAddress;
      const selectedPMMInfoHash: string = getSelectPMMHash(
        selectedPMMId,
        pmmRecvAddress,
        tradeInfo[0].toChain[1],
        tradeInfo[0].toChain[2],
        amountOut[0],
        expiry,
      );
      let signature: string = await getSignature(
        accounts[0],
        tradeId[0],
        selectedPMMInfoHash,
        SignatureType.SelectPMM,
        domain,
      );
      const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
      const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
        amountOut: amountOut[0],
        selectedPMMId: selectedPMMId,
        info: info,
        sigExpiry: expiry,
      };

      //  RFQ Info
      const rfqInfoHash: string = getRFQHash(
        rfqInfo[0].minAmountOut as bigint,
        rfqInfo[0].tradeTimeout as bigint,
        affiliateInfo[0],
      );
      signature = await getSignature(
        ephemeralL2Wallet[0],
        tradeId[0],
        rfqInfoHash,
        SignatureType.RFQ,
        domain,
      );
      rfqInfo[0].rfqInfoSignature = signature;

      //  PMM Selection Info: Selected PMM Info + RFQ Info
      const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
        rfqInfo: rfqInfo[0],
        pmmInfo: pmmInfo,
      };

      const tx = router.connect(solver).selectPMM(tradeId[0], pmmSelectionInfo);

      await expect(tx)
        .to.emit(router, "SelectPMM")
        .withArgs(solver.address, tradeId[0]);
      await expect(tx)
        .to.emit(solbtc, "SelectedPMM")
        .withArgs(
          await router.getAddress(),
          solver.address,
          tradeId[0],
          pmmSelectionInfo.pmmInfo.selectedPMMId,
        );

      const expectedPMMSelectionInfo = [
        [
          rfqInfo[0].minAmountOut,
          rfqInfo[0].tradeTimeout,
          rfqInfo[0].rfqInfoSignature,
        ],
        [
          pmmInfo.amountOut,
          pmmInfo.selectedPMMId,
          [hexlify(info[0]), hexlify(info[1])],
          pmmInfo.sigExpiry,
        ],
      ];
      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.MAKE_PAYMENT,
      );
      expect(await router.getPMMSelection(tradeId[0])).deep.eq(
        expectedPMMSelectionInfo,
      );
    });

    it("Should revert when Solver tries to update the PMM selection after submission", async () => {
      //  Selected PMM Info
      const timestamp = await getBlockTimestamp(provider);
      const expiry = BigInt(timestamp + 30 * 60);
      amountOut[0] =
        (rfqInfo[0].minAmountOut as bigint) + parseUnits("1000", 8);
      const selectedPMMId = presigns[0][0].pmmId;
      const pmmRecvAddress = presigns[0][0].pmmRecvAddress;
      const selectedPMMInfoHash: string = getSelectPMMHash(
        selectedPMMId,
        pmmRecvAddress,
        tradeInfo[0].toChain[1],
        tradeInfo[0].toChain[2],
        amountOut[0],
        expiry,
      );
      let signature: string = await getSignature(
        accounts[0],
        tradeId[0],
        selectedPMMInfoHash,
        SignatureType.SelectPMM,
        domain,
      );
      const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
      const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
        amountOut: amountOut[0],
        selectedPMMId: selectedPMMId,
        info: info,
        sigExpiry: expiry,
      };

      //  RFQ Info
      const rfqInfoHash: string = getRFQHash(
        rfqInfo[0].minAmountOut as bigint,
        rfqInfo[0].tradeTimeout as bigint,
        affiliateInfo[0],
      );
      signature = await getSignature(
        ephemeralL2Wallet[0],
        tradeId[0],
        rfqInfoHash,
        SignatureType.RFQ,
        domain,
      );
      rfqInfo[0].rfqInfoSignature = signature;

      //  PMM Selection Info: Selected PMM Info + RFQ Info
      const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
        rfqInfo: rfqInfo[0],
        pmmInfo: pmmInfo,
      };

      const currentStage = await router.getCurrentStage(tradeId[0]);
      const lastInfo = await router.getPMMSelection(tradeId[0]);

      await expect(
        router.connect(solver).selectPMM(tradeId[0], pmmSelectionInfo),
      ).to.be.revertedWithCustomError(solbtc, "InvalidProcedureState");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(currentStage);
      expect(await router.getPMMSelection(tradeId[0])).deep.eq(lastInfo);
    });

    it("Should succeed when Solver submits the second trade's pmm selection", async () => {
      //  temporarily set "admin" as Solver
      await management.connect(admin).setSolver(admin.address, true);

      //  Selected PMM Info
      const timestamp = await getBlockTimestamp(provider);
      const expiry = BigInt(timestamp + 30 * 60);
      amountOut[1] =
        (rfqInfo[1].minAmountOut as bigint) + parseUnits("1000", 8);
      const selectedPMMId = presigns[1][0].pmmId;
      const pmmRecvAddress = presigns[1][0].pmmRecvAddress;
      const selectedPMMInfoHash: string = getSelectPMMHash(
        selectedPMMId,
        pmmRecvAddress,
        tradeInfo[1].toChain[1],
        tradeInfo[1].toChain[2],
        amountOut[1],
        expiry,
      );
      let signature: string = await getSignature(
        accounts[0],
        tradeId[1],
        selectedPMMInfoHash,
        SignatureType.SelectPMM,
        domain,
      );
      const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
      const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
        amountOut: amountOut[1],
        selectedPMMId: selectedPMMId,
        info: info,
        sigExpiry: expiry,
      };

      //  RFQ Info
      const rfqInfoHash: string = getRFQHash(
        rfqInfo[1].minAmountOut as bigint,
        rfqInfo[1].tradeTimeout as bigint,
        affiliateInfo[1],
      );
      signature = await getSignature(
        ephemeralL2Wallet[1],
        tradeId[1],
        rfqInfoHash,
        SignatureType.RFQ,
        domain,
      );
      rfqInfo[1].rfqInfoSignature = signature;

      //  PMM Selection Info: Selected PMM Info + RFQ Info
      const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
        rfqInfo: rfqInfo[1],
        pmmInfo: pmmInfo,
      };

      const tx = router.connect(admin).selectPMM(tradeId[1], pmmSelectionInfo);

      await expect(tx)
        .to.emit(router, "SelectPMM")
        .withArgs(admin.address, tradeId[1]);
      await expect(tx)
        .to.emit(solbtc, "SelectedPMM")
        .withArgs(
          await router.getAddress(),
          admin.address,
          tradeId[1],
          pmmSelectionInfo.pmmInfo.selectedPMMId,
        );

      const expectedPMMSelectionInfo = [
        [
          rfqInfo[1].minAmountOut,
          rfqInfo[1].tradeTimeout,
          rfqInfo[1].rfqInfoSignature,
        ],
        [
          pmmInfo.amountOut,
          pmmInfo.selectedPMMId,
          [hexlify(info[0]), hexlify(info[1])],
          pmmInfo.sigExpiry,
        ],
      ];
      expect(await router.getCurrentStage(tradeId[1])).deep.eq(
        STAGE.MAKE_PAYMENT,
      );
      expect(await router.getPMMSelection(tradeId[1])).deep.eq(
        expectedPMMSelectionInfo,
      );

      //  set back to normal
      await management.connect(admin).setSolver(admin.address, false);
    });

    it("Should succeed when Solver submits the third trade's pmm selection", async () => {
      //  Selected PMM Info
      const timestamp = await getBlockTimestamp(provider);
      const expiry = BigInt(timestamp + 30 * 60);
      amountOut[2] =
        (rfqInfo[2].minAmountOut as bigint) + parseUnits("1000", 8);
      const selectedPMMId = presigns[2][0].pmmId;
      const pmmRecvAddress = presigns[2][0].pmmRecvAddress;
      const selectedPMMInfoHash: string = getSelectPMMHash(
        selectedPMMId,
        pmmRecvAddress,
        tradeInfo[2].toChain[1],
        tradeInfo[2].toChain[2],
        amountOut[2],
        expiry,
      );
      let signature: string = await getSignature(
        accounts[0],
        tradeId[2],
        selectedPMMInfoHash,
        SignatureType.SelectPMM,
        domain,
      );
      const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
      const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
        amountOut: amountOut[2],
        selectedPMMId: selectedPMMId,
        info: info,
        sigExpiry: expiry,
      };

      //  RFQ Info
      const rfqInfoHash: string = getRFQHash(
        rfqInfo[2].minAmountOut as bigint,
        rfqInfo[2].tradeTimeout as bigint,
        affiliateInfo[2],
      );
      signature = await getSignature(
        ephemeralL2Wallet[2],
        tradeId[2],
        rfqInfoHash,
        SignatureType.RFQ,
        domain,
      );
      rfqInfo[2].rfqInfoSignature = signature;

      //  PMM Selection Info: Selected PMM Info + RFQ Info
      const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
        rfqInfo: rfqInfo[2],
        pmmInfo: pmmInfo,
      };

      const tx = router.connect(solver).selectPMM(tradeId[2], pmmSelectionInfo);

      await expect(tx)
        .to.emit(router, "SelectPMM")
        .withArgs(solver.address, tradeId[2]);
      await expect(tx)
        .to.emit(solbtc, "SelectedPMM")
        .withArgs(
          await router.getAddress(),
          solver.address,
          tradeId[2],
          pmmSelectionInfo.pmmInfo.selectedPMMId,
        );

      const expectedPMMSelectionInfo = [
        [
          rfqInfo[2].minAmountOut,
          rfqInfo[2].tradeTimeout,
          rfqInfo[2].rfqInfoSignature,
        ],
        [
          pmmInfo.amountOut,
          pmmInfo.selectedPMMId,
          [hexlify(info[0]), hexlify(info[1])],
          pmmInfo.sigExpiry,
        ],
      ];
      expect(await router.getCurrentStage(tradeId[2])).deep.eq(
        STAGE.MAKE_PAYMENT,
      );
      expect(await router.getPMMSelection(tradeId[2])).deep.eq(
        expectedPMMSelectionInfo,
      );
    });
  });

  describe("bundlePayment() functional testing", async () => {
    it("Should revert when Unauthorized client, an arbitrary account, tries to call bundlePayment()", async () => {
      const startIdx = BigInt(0);
      const tradeIds = [tradeId[0]];
      const signedAt = BigInt(Math.floor(Date.now() / 1000));
      const infoHash: string = getMakePaymentHash(
        tradeIds,
        signedAt,
        startIdx,
        paymentTxId[0],
      );
      const signature = await getSignature(
        accounts[0],
        tradeId[0],
        infoHash,
        SignatureType.MakePayment,
        domain,
      );
      const bundle: CoreTypes.BundlePaymentStruct = {
        tradeIds: tradeIds,
        signedAt: signedAt,
        startIdx: startIdx,
        paymentTxId: paymentTxId[0],
        signature: signature,
      };

      await expect(
        router.connect(accounts[1]).bundlePayment(bundle),
      ).to.be.revertedWithCustomError(solbtc, "Unauthorized");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.MAKE_PAYMENT,
      );
      expect(await router.getSettledPayment(tradeId[0])).deep.eq(
        EMPTY_SETTLED_PAYMENT,
      );
    });

    it("Should revert when Unauthorized client, non-selected PMM's account, tries to call bundlePayment()", async () => {
      const startIdx = BigInt(0);
      const tradeIds = [tradeId[0]];
      const signedAt = BigInt(Math.floor(Date.now() / 1000));
      const infoHash: string = getMakePaymentHash(
        tradeIds,
        signedAt,
        startIdx,
        paymentTxId[0],
      );
      const signature = await getSignature(
        accounts[0],
        tradeId[0],
        infoHash,
        SignatureType.MakePayment,
        domain,
      );
      const bundle: CoreTypes.BundlePaymentStruct = {
        tradeIds: tradeIds,
        signedAt: signedAt,
        startIdx: startIdx,
        paymentTxId: paymentTxId[0],
        signature: signature,
      };

      await expect(
        router.connect(accounts[1]).bundlePayment(bundle),
      ).to.be.revertedWithCustomError(solbtc, "Unauthorized");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.MAKE_PAYMENT,
      );
      expect(await router.getSettledPayment(tradeId[0])).deep.eq(
        EMPTY_SETTLED_PAYMENT,
      );
    });

    it("Should revert when Unauthorized client, the MPC, tries to call bundlePayment()", async () => {
      const startIdx = BigInt(0);
      const tradeIds = [tradeId[0]];
      const signedAt = BigInt(Math.floor(Date.now() / 1000));
      const infoHash: string = getMakePaymentHash(
        tradeIds,
        signedAt,
        startIdx,
        paymentTxId[0],
      );
      const signature = await getSignature(
        accounts[0],
        tradeId[0],
        infoHash,
        SignatureType.MakePayment,
        domain,
      );

      const bundle: CoreTypes.BundlePaymentStruct = {
        tradeIds: tradeIds,
        signedAt: signedAt,
        startIdx: startIdx,
        paymentTxId: paymentTxId[0],
        signature: signature,
      };

      await expect(
        router.connect(mpcL2).bundlePayment(bundle),
      ).to.be.revertedWithCustomError(solbtc, "Unauthorized");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.MAKE_PAYMENT,
      );
      expect(await router.getSettledPayment(tradeId[0])).deep.eq(
        EMPTY_SETTLED_PAYMENT,
      );
    });

    it("Should revert when Unauthorized client, the Solver that not handles the tradeId, tries to call bundlePayment()", async () => {
      //  temporarily set `admin` as Solver role
      await management.connect(admin).setSolver(admin.address, true);
      expect(await management.solvers(admin.address)).deep.eq(true);

      const startIdx = BigInt(0);
      const tradeIds = [tradeId[0]];
      const signedAt = BigInt(Math.floor(Date.now() / 1000));
      const infoHash: string = getMakePaymentHash(
        tradeIds,
        signedAt,
        startIdx,
        paymentTxId[0],
      );
      const signature = await getSignature(
        accounts[1],
        tradeId[0],
        infoHash,
        SignatureType.MakePayment,
        domain,
      );
      const bundle: CoreTypes.BundlePaymentStruct = {
        tradeIds: tradeIds,
        signedAt: signedAt,
        startIdx: startIdx,
        paymentTxId: paymentTxId[0],
        signature: signature,
      };

      await expect(
        router.connect(admin).bundlePayment(bundle),
      ).to.be.revertedWithCustomError(solbtc, "Unauthorized");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.MAKE_PAYMENT,
      );
      expect(await router.getSettledPayment(tradeId[0])).deep.eq(
        EMPTY_SETTLED_PAYMENT,
      );

      //  set back to normal
      //  temporarily set `admin` as Solver role
      await management.connect(admin).setSolver(admin.address, false);
      expect(await management.solvers(admin.address)).deep.eq(false);
    });

    it("Should revert when Unauthorized client, the Admin, tries to call bundlePayment()", async () => {
      const startIdx = BigInt(0);
      const tradeIds = [tradeId[0]];
      const signedAt = BigInt(Math.floor(Date.now() / 1000));
      const infoHash: string = getMakePaymentHash(
        tradeIds,
        signedAt,
        startIdx,
        paymentTxId[0],
      );
      const signature = await getSignature(
        accounts[1],
        tradeId[0],
        infoHash,
        SignatureType.MakePayment,
        domain,
      );
      const bundle: CoreTypes.BundlePaymentStruct = {
        tradeIds: tradeIds,
        signedAt: signedAt,
        startIdx: startIdx,
        paymentTxId: paymentTxId[0],
        signature: signature,
      };

      await expect(
        router.connect(admin).bundlePayment(bundle),
      ).to.be.revertedWithCustomError(solbtc, "Unauthorized");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.MAKE_PAYMENT,
      );
      expect(await router.getSettledPayment(tradeId[0])).deep.eq(
        EMPTY_SETTLED_PAYMENT,
      );
    });

    it("Should revert when Solver calls bundlePayment() to submit an empty paymentTxId", async () => {
      const startIdx = BigInt(0);
      const tradeIds = [tradeId[0]];
      const signedAt = BigInt(Math.floor(Date.now() / 1000));
      const emptyPaymentTxId = hexlify("0x");
      const infoHash: string = getMakePaymentHash(
        tradeIds,
        signedAt,
        startIdx,
        emptyPaymentTxId,
      );
      const signature = await getSignature(
        accounts[0],
        tradeId[0],
        infoHash,
        SignatureType.MakePayment,
        domain,
      );
      const bundle: CoreTypes.BundlePaymentStruct = {
        tradeIds: tradeIds,
        signedAt: signedAt,
        startIdx: startIdx,
        paymentTxId: emptyPaymentTxId,
        signature: signature,
      };

      await expect(
        router.connect(solver).bundlePayment(bundle),
      ).to.be.revertedWithCustomError(solbtc, "InvalidPaymentIdLength");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.MAKE_PAYMENT,
      );
      expect(await router.getSettledPayment(tradeId[0])).deep.eq(
        EMPTY_SETTLED_PAYMENT,
      );
    });

    it("Should succeed when Solver calls bundlePayment() even though the protocol is triggered the Suspension Mode", async () => {
      await management.connect(admin).suspend();
      await management.connect(admin).setSolver(admin.address, true);

      const startIdx = BigInt(0);
      const tradeIds = [tradeId[1]];
      const signedAt = BigInt(await getBlockTimestamp(provider));
      const infoHash: string = getMakePaymentHash(
        tradeIds,
        signedAt,
        startIdx,
        paymentTxId[1],
      );
      const signature = await getSignature(
        accounts[0],
        tradeId[1],
        infoHash,
        SignatureType.MakePayment,
        domain,
      );
      const bundle: CoreTypes.BundlePaymentStruct = {
        tradeIds: tradeIds,
        signedAt: signedAt,
        startIdx: startIdx,
        paymentTxId: paymentTxId[1],
        signature: signature,
      };

      const tx = router.connect(admin).bundlePayment(bundle);

      await expect(tx)
        .to.emit(router, "MakePayment")
        .withArgs(admin.address, tradeId[1]);
      await expect(tx)
        .to.emit(solbtc, "MadePayment")
        .withArgs(
          await router.getAddress(),
          admin.address,
          tradeId[1],
          hexlify(tradeInfo[1].toChain[1]),
          hexlify(paymentTxId[1]),
          tradeIds,
          startIdx,
        );

      expect(await router.getCurrentStage(tradeId[1])).deep.eq(
        STAGE.CONFIRM_PAYMENT,
      );
      expect(await router.getSettledPayment(tradeId[1])).deep.eq([
        bundlerHash(tradeIds),
        hexlify(paymentTxId[1]),
        EMPTY_BYTES,
        false,
      ]);

      //  set back to normal
      await management.connect(admin).resume();
      await management.connect(admin).setSolver(admin.address, false);
    });

    it("Should revert when the Solver calls bundlePayment(), but Protocol is triggered the Shutdown Mode", async () => {
      await management.connect(admin).shutdown();

      const startIdx = BigInt(0);
      const tradeIds = [tradeId[0]];
      const signedAt = BigInt(Math.floor(Date.now() / 1000));
      const infoHash: string = getMakePaymentHash(
        tradeIds,
        signedAt,
        startIdx,
        paymentTxId[0],
      );
      const signature = await getSignature(
        accounts[0],
        tradeId[0],
        infoHash,
        SignatureType.MakePayment,
        domain,
      );
      const bundle: CoreTypes.BundlePaymentStruct = {
        tradeIds: tradeIds,
        signedAt: signedAt,
        startIdx: startIdx,
        paymentTxId: paymentTxId[0],
        signature: signature,
      };

      await expect(
        router.connect(solver).bundlePayment(bundle),
      ).to.be.revertedWithCustomError(solbtc, "InSuspension");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.MAKE_PAYMENT,
      );
      expect(await router.getSettledPayment(tradeId[0])).deep.eq(
        EMPTY_SETTLED_PAYMENT,
      );

      //  set back to normal
      await management.connect(admin).resume();
    });

    it("Should revert when the Solver calls bundlePayment() after scriptTimeout", async () => {
      const timestamp = await getBlockTimestamp(provider);
      const exceedTimeout = Number(scriptInfo[0].scriptTimeout) + 1;

      //  take a snapshot before increasing block.timestamp
      const snapshot = await takeSnapshot();
      if (timestamp < exceedTimeout) await adjustTime(exceedTimeout);

      const startIdx = BigInt(0);
      const tradeIds = [tradeId[0]];
      const signedAt = BigInt(Math.floor(Date.now() / 1000));
      const infoHash: string = getMakePaymentHash(
        tradeIds,
        signedAt,
        startIdx,
        paymentTxId[0],
      );
      const signature = await getSignature(
        accounts[0],
        tradeId[0],
        infoHash,
        SignatureType.MakePayment,
        domain,
      );
      const bundle: CoreTypes.BundlePaymentStruct = {
        tradeIds: tradeIds,
        signedAt: signedAt,
        startIdx: startIdx,
        paymentTxId: paymentTxId[0],
        signature: signature,
      };

      await expect(
        router.connect(solver).bundlePayment(bundle),
      ).to.be.revertedWithCustomError(solbtc, "DeadlineExceeded");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.MAKE_PAYMENT,
      );
      expect(await router.getSettledPayment(tradeId[0])).deep.eq(
        EMPTY_SETTLED_PAYMENT,
      );

      //  set back to normal
      await snapshot.restore();
    });

    it("Should revert when the Solver calls bundlePayment(), but PMM's signature invalid - Signer not match", async () => {
      const startIdx = BigInt(0);
      const tradeIds = [tradeId[0]];
      const signedAt = BigInt(Math.floor(Date.now() / 1000));
      const infoHash: string = getMakePaymentHash(
        tradeIds,
        signedAt,
        startIdx,
        paymentTxId[0],
      );
      const signature = await getSignature(
        solver, // invalid signer
        tradeId[0],
        infoHash,
        SignatureType.MakePayment,
        domain,
      );
      const bundle: CoreTypes.BundlePaymentStruct = {
        tradeIds: tradeIds,
        signedAt: signedAt,
        startIdx: startIdx,
        paymentTxId: paymentTxId[0],
        signature: signature,
      };

      await expect(
        router.connect(solver).bundlePayment(bundle),
      ).to.be.revertedWithCustomError(solbtc, "InvalidPMMSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.MAKE_PAYMENT,
      );
      expect(await router.getSettledPayment(tradeId[0])).deep.eq(
        EMPTY_SETTLED_PAYMENT,
      );
    });

    it("Should revert when the Solver calls bundlePayment(), but PMM's signature invalid - Signed by non-selected PMM", async () => {
      const startIdx = BigInt(0);
      const tradeIds = [tradeId[0]];
      const signedAt = BigInt(Math.floor(Date.now() / 1000));
      const infoHash: string = getMakePaymentHash(
        tradeIds,
        signedAt,
        startIdx,
        paymentTxId[0],
      );
      const signature = await getSignature(
        accounts[1], //  non-selected pmm
        tradeId[0],
        infoHash,
        SignatureType.MakePayment,
        domain,
      );
      const bundle: CoreTypes.BundlePaymentStruct = {
        tradeIds: tradeIds,
        signedAt: signedAt,
        startIdx: startIdx,
        paymentTxId: paymentTxId[0],
        signature: signature,
      };

      await expect(
        router.connect(solver).bundlePayment(bundle),
      ).to.be.revertedWithCustomError(solbtc, "InvalidPMMSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.MAKE_PAYMENT,
      );
      expect(await router.getSettledPayment(tradeId[0])).deep.eq(
        EMPTY_SETTLED_PAYMENT,
      );
    });

    it("Should revert when the Solver calls bundlePayment(), but PMM's signature invalid - Wrong Domain - Wrong contract name", async () => {
      const wrongDomain: TypedDataDomain = {
        ...domain,
        name: "Wrong Contract Name",
      };

      const startIdx = BigInt(0);
      const tradeIds = [tradeId[0]];
      const signedAt = BigInt(Math.floor(Date.now() / 1000));
      const infoHash: string = getMakePaymentHash(
        tradeIds,
        signedAt,
        startIdx,
        paymentTxId[0],
      );
      const signature = await getSignature(
        accounts[0],
        tradeId[0],
        infoHash,
        SignatureType.MakePayment,
        wrongDomain,
      );
      const bundle: CoreTypes.BundlePaymentStruct = {
        tradeIds: tradeIds,
        signedAt: signedAt,
        startIdx: startIdx,
        paymentTxId: paymentTxId[0],
        signature: signature,
      };

      await expect(
        router.connect(solver).bundlePayment(bundle),
      ).to.be.revertedWithCustomError(solbtc, "InvalidPMMSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.MAKE_PAYMENT,
      );
      expect(await router.getSettledPayment(tradeId[0])).deep.eq(
        EMPTY_SETTLED_PAYMENT,
      );
    });

    it("Should revert when the Solver calls bundlePayment(), but PMM's signature invalid - Wrong Domain - Wrong version", async () => {
      const wrongDomain: TypedDataDomain = {
        ...domain,
        version: "Wrong Contract Version",
      };

      const startIdx = BigInt(0);
      const tradeIds = [tradeId[0]];
      const signedAt = BigInt(Math.floor(Date.now() / 1000));
      const infoHash: string = getMakePaymentHash(
        tradeIds,
        signedAt,
        startIdx,
        paymentTxId[0],
      );
      const signature = await getSignature(
        accounts[0],
        tradeId[0],
        infoHash,
        SignatureType.MakePayment,
        wrongDomain,
      );
      const bundle: CoreTypes.BundlePaymentStruct = {
        tradeIds: tradeIds,
        signedAt: signedAt,
        startIdx: startIdx,
        paymentTxId: paymentTxId[0],
        signature: signature,
      };

      await expect(
        router.connect(solver).bundlePayment(bundle),
      ).to.be.revertedWithCustomError(solbtc, "InvalidPMMSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.MAKE_PAYMENT,
      );
      expect(await router.getSettledPayment(tradeId[0])).deep.eq(
        EMPTY_SETTLED_PAYMENT,
      );
    });

    it("Should revert when the Solver calls bundlePayment(), but PMM's signature invalid - Wrong Domain - Wrong chainId", async () => {
      const wrongDomain: TypedDataDomain = {
        ...domain,
        chainId: (domain.chainId as bigint) + BigInt(1),
      };

      const startIdx = BigInt(0);
      const tradeIds = [tradeId[0]];
      const signedAt = BigInt(Math.floor(Date.now() / 1000));
      const infoHash: string = getMakePaymentHash(
        tradeIds,
        signedAt,
        startIdx,
        paymentTxId[0],
      );
      const signature = await getSignature(
        accounts[0],
        tradeId[0],
        infoHash,
        SignatureType.MakePayment,
        wrongDomain,
      );
      const bundle: CoreTypes.BundlePaymentStruct = {
        tradeIds: tradeIds,
        signedAt: signedAt,
        startIdx: startIdx,
        paymentTxId: paymentTxId[0],
        signature: signature,
      };

      await expect(
        router.connect(solver).bundlePayment(bundle),
      ).to.be.revertedWithCustomError(solbtc, "InvalidPMMSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.MAKE_PAYMENT,
      );
      expect(await router.getSettledPayment(tradeId[0])).deep.eq(
        EMPTY_SETTLED_PAYMENT,
      );
    });

    it("Should revert when the Solver calls bundlePayment(), but PMM's signature invalid - Wrong Domain - Wrong contract address", async () => {
      const wrongDomain: TypedDataDomain = {
        ...domain,
        name: "Wrong Contract Name",
      };

      const startIdx = BigInt(0);
      const tradeIds = [tradeId[0]];
      const signedAt = BigInt(Math.floor(Date.now() / 1000));
      const infoHash: string = getMakePaymentHash(
        tradeIds,
        signedAt,
        startIdx,
        paymentTxId[0],
      );
      const signature = await getSignature(
        accounts[0],
        tradeId[0],
        infoHash,
        SignatureType.MakePayment,
        wrongDomain,
      );
      const bundle: CoreTypes.BundlePaymentStruct = {
        tradeIds: tradeIds,
        signedAt: signedAt,
        startIdx: startIdx,
        paymentTxId: paymentTxId[0],
        signature: signature,
      };

      await expect(
        router.connect(solver).bundlePayment(bundle),
      ).to.be.revertedWithCustomError(solbtc, "InvalidPMMSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.MAKE_PAYMENT,
      );
      expect(await router.getSettledPayment(tradeId[0])).deep.eq(
        EMPTY_SETTLED_PAYMENT,
      );
    });

    it("Should revert when the selected PMM calls bundlePayment() to submit an empty paymentTxId", async () => {
      const startIdx = BigInt(0);
      const tradeIds = [tradeId[0]];
      const signedAt = BigInt(Math.floor(Date.now() / 1000));
      const emptyPaymentTxId = hexlify("0x");
      const infoHash: string = getMakePaymentHash(
        tradeIds,
        signedAt,
        startIdx,
        emptyPaymentTxId,
      );
      const signature = await getSignature(
        accounts[0],
        tradeId[0],
        infoHash,
        SignatureType.MakePayment,
        domain,
      );
      const bundle: CoreTypes.BundlePaymentStruct = {
        tradeIds: tradeIds,
        signedAt: signedAt,
        startIdx: startIdx,
        paymentTxId: emptyPaymentTxId,
        signature: signature,
      };

      await expect(
        router.connect(accounts[0]).bundlePayment(bundle),
      ).to.be.revertedWithCustomError(solbtc, "InvalidPaymentIdLength");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.MAKE_PAYMENT,
      );
      expect(await router.getSettledPayment(tradeId[0])).deep.eq(
        EMPTY_SETTLED_PAYMENT,
      );
    });

    it("Should succeed when Solver calls bundlePayment() to submit PMM's payment transaction", async () => {
      const startIdx = BigInt(0);
      const tradeIds = [tradeId[0], tradeId[2]];
      const signedAt = BigInt(await getBlockTimestamp(provider));
      savedSignedAt = signedAt; // save `signedAt` for another scenario
      const infoHash: string = getMakePaymentHash(
        tradeIds,
        signedAt,
        startIdx,
        paymentTxId[0],
      );
      const signature = await getSignature(
        accounts[0],
        tradeId[0],
        infoHash,
        SignatureType.MakePayment,
        domain,
      );
      const bundle: CoreTypes.BundlePaymentStruct = {
        tradeIds: tradeIds,
        signedAt: signedAt,
        startIdx: startIdx,
        paymentTxId: paymentTxId[0],
        signature: signature,
      };

      const tx = router.connect(solver).bundlePayment(bundle);

      await expect(tx)
        .to.emit(router, "MakePayment")
        .withArgs(solver.address, tradeId[0]);
      await expect(tx)
        .to.emit(solbtc, "MadePayment")
        .withArgs(
          await router.getAddress(),
          solver.address,
          tradeId[0],
          hexlify(tradeInfo[0].toChain[1]),
          hexlify(paymentTxId[0]),
          tradeIds,
          startIdx,
        );
      await expect(tx)
        .to.emit(router, "MakePayment")
        .withArgs(solver.address, tradeId[2]);
      await expect(tx)
        .to.emit(solbtc, "MadePayment")
        .withArgs(
          await router.getAddress(),
          solver.address,
          tradeId[2],
          hexlify(tradeInfo[2].toChain[1]),
          hexlify(paymentTxId[0]),
          tradeIds,
          startIdx,
        );

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.CONFIRM_PAYMENT,
      );
      expect(await router.getSettledPayment(tradeId[0])).deep.eq([
        bundlerHash(tradeIds),
        hexlify(paymentTxId[0]),
        EMPTY_BYTES,
        false,
      ]);
      expect(await router.getCurrentStage(tradeId[2])).deep.eq(
        STAGE.CONFIRM_PAYMENT,
      );
      expect(await router.getSettledPayment(tradeId[2])).deep.eq([
        bundlerHash(tradeIds),
        hexlify(paymentTxId[0]),
        EMPTY_BYTES,
        false,
      ]);
    });

    it("Should succeed when the selected PMM calls bundlePayment() to update paymentTxId", async () => {
      const startIdx = BigInt(0);
      const tradeIds = [tradeId[0], tradeId[2]];
      const signedAt = BigInt(await getBlockTimestamp(provider));
      const newPaymentTxId = randomTxId();
      const infoHash: string = getMakePaymentHash(
        tradeIds,
        signedAt,
        startIdx,
        newPaymentTxId,
      );
      const signature = await getSignature(
        accounts[0],
        tradeId[0],
        infoHash,
        SignatureType.MakePayment,
        domain,
      );
      const bundle: CoreTypes.BundlePaymentStruct = {
        tradeIds: tradeIds,
        signedAt: signedAt,
        startIdx: startIdx,
        paymentTxId: newPaymentTxId,
        signature: signature,
      };

      const tx = router.connect(accounts[0]).bundlePayment(bundle);

      await expect(tx)
        .to.emit(router, "MakePayment")
        .withArgs(accounts[0].address, tradeId[0]);
      await expect(tx)
        .to.emit(solbtc, "MadePayment")
        .withArgs(
          await router.getAddress(),
          accounts[0].address,
          tradeId[0],
          hexlify(tradeInfo[0].toChain[1]),
          hexlify(newPaymentTxId),
          tradeIds,
          startIdx,
        );
      await expect(tx)
        .to.emit(router, "MakePayment")
        .withArgs(accounts[0].address, tradeId[2]);
      await expect(tx)
        .to.emit(solbtc, "MadePayment")
        .withArgs(
          await router.getAddress(),
          accounts[0].address,
          tradeId[2],
          hexlify(tradeInfo[2].toChain[1]),
          hexlify(newPaymentTxId),
          tradeIds,
          startIdx,
        );

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.CONFIRM_PAYMENT,
      );
      expect(await router.getSettledPayment(tradeId[0])).deep.eq([
        bundlerHash(tradeIds),
        hexlify(newPaymentTxId),
        EMPTY_BYTES,
        false,
      ]);
      expect(await router.getCurrentStage(tradeId[2])).deep.eq(
        STAGE.CONFIRM_PAYMENT,
      );
      expect(await router.getSettledPayment(tradeId[2])).deep.eq([
        bundlerHash(tradeIds),
        hexlify(newPaymentTxId),
        EMPTY_BYTES,
        false,
      ]);
    });

    it("Should revert when Solver calls bundlePayment() to update paymentTxId, but signedAt is outdated", async () => {
      const startIdx = BigInt(0);
      const tradeIds = [tradeId[0], tradeId[2]];
      const signedAt = savedSignedAt;
      const infoHash: string = getMakePaymentHash(
        tradeIds,
        signedAt,
        startIdx,
        paymentTxId[0],
      );
      const signature = await getSignature(
        accounts[0],
        tradeId[0],
        infoHash,
        SignatureType.MakePayment,
        domain,
      );
      const bundle: CoreTypes.BundlePaymentStruct = {
        tradeIds: tradeIds,
        signedAt: signedAt,
        startIdx: startIdx,
        paymentTxId: paymentTxId[0],
        signature: signature,
      };

      const currentStage1 = await router.getCurrentStage(tradeId[0]);
      const lastInfo1 = await router.getSettledPayment(tradeId[0]);
      const currentStage2 = await router.getCurrentStage(tradeId[2]);
      const lastInfo2 = await router.getSettledPayment(tradeId[2]);

      await expect(
        router.connect(solver).bundlePayment(bundle),
      ).to.be.revertedWithCustomError(solbtc, "OutdatedSignature");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(currentStage1);
      expect(await router.getSettledPayment(tradeId[0])).deep.eq(lastInfo1);
      expect(await router.getCurrentStage(tradeId[2])).deep.eq(currentStage2);
      expect(await router.getSettledPayment(tradeId[2])).deep.eq(lastInfo2);
    });

    it("Should succeed when the selected PMM calls bundlePayment() to update another paymentTxId", async () => {
      const startIdx = BigInt(0);
      const tradeIds = [tradeId[0], tradeId[2]];
      const signedAt = BigInt(await getBlockTimestamp(provider));
      const infoHash: string = getMakePaymentHash(
        tradeIds,
        signedAt,
        startIdx,
        paymentTxId[0],
      );
      const signature = await getSignature(
        accounts[0],
        tradeId[0],
        infoHash,
        SignatureType.MakePayment,
        domain,
      );
      const bundle: CoreTypes.BundlePaymentStruct = {
        tradeIds: tradeIds,
        signedAt: signedAt,
        startIdx: startIdx,
        paymentTxId: paymentTxId[0],
        signature: signature,
      };

      const tx = router.connect(accounts[0]).bundlePayment(bundle);

      await expect(tx)
        .to.emit(router, "MakePayment")
        .withArgs(accounts[0].address, tradeId[0]);
      await expect(tx)
        .to.emit(solbtc, "MadePayment")
        .withArgs(
          await router.getAddress(),
          accounts[0].address,
          tradeId[0],
          hexlify(tradeInfo[0].toChain[1]),
          hexlify(paymentTxId[0]),
          tradeIds,
          startIdx,
        );
      await expect(tx)
        .to.emit(router, "MakePayment")
        .withArgs(accounts[0].address, tradeId[2]);
      await expect(tx)
        .to.emit(solbtc, "MadePayment")
        .withArgs(
          await router.getAddress(),
          accounts[0].address,
          tradeId[2],
          hexlify(tradeInfo[2].toChain[1]),
          hexlify(paymentTxId[0]),
          tradeIds,
          startIdx,
        );

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.CONFIRM_PAYMENT,
      );
      expect(await router.getSettledPayment(tradeId[0])).deep.eq([
        bundlerHash(tradeIds),
        hexlify(paymentTxId[0]),
        EMPTY_BYTES,
        false,
      ]);
      expect(await router.getCurrentStage(tradeId[2])).deep.eq(
        STAGE.CONFIRM_PAYMENT,
      );
      expect(await router.getSettledPayment(tradeId[2])).deep.eq([
        bundlerHash(tradeIds),
        hexlify(paymentTxId[0]),
        EMPTY_BYTES,
        false,
      ]);
    });
  });

  describe("confirmPayment() functional testing", async () => {
    it("Should revert when Unauthorized client, an arbitrary account, tries to submit a payment confirmation", async () => {
      const infoHash = getConfirmPaymentHash(
        ZERO_VALUE,
        amountOut[0],
        tradeInfo[0].toChain,
        paymentTxId[0],
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[0],
        infoHash,
        SignatureType.ConfirmPayment,
        domain,
      );

      const currentStage = await router.getCurrentStage(tradeId[0]);
      const lastInfo = await router.getSettledPayment(tradeId[0]);

      await expect(
        router.connect(accounts[0]).confirmPayment(tradeId[0], signature),
      ).to.be.revertedWithCustomError(solbtc, "Unauthorized");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(currentStage);
      expect(await router.getSettledPayment(tradeId[0])).deep.eq(lastInfo);
    });

    it("Should revert when Unauthorized client, the Solver, tries to submit a payment confirmation", async () => {
      const infoHash = getConfirmPaymentHash(
        ZERO_VALUE,
        amountOut[0],
        tradeInfo[0].toChain,
        paymentTxId[0],
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[0],
        infoHash,
        SignatureType.ConfirmPayment,
        domain,
      );

      const currentStage = await router.getCurrentStage(tradeId[0]);
      const lastInfo = await router.getSettledPayment(tradeId[0]);

      await expect(
        router.connect(solver).confirmPayment(tradeId[0], signature),
      ).to.be.revertedWithCustomError(solbtc, "Unauthorized");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(currentStage);
      expect(await router.getSettledPayment(tradeId[0])).deep.eq(lastInfo);
    });

    it("Should revert when Unauthorized client, the Admin, tries to submit a payment confirmation", async () => {
      const infoHash = getConfirmPaymentHash(
        ZERO_VALUE,
        amountOut[0],
        tradeInfo[0].toChain,
        paymentTxId[0],
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[0],
        infoHash,
        SignatureType.ConfirmPayment,
        domain,
      );

      const currentStage = await router.getCurrentStage(tradeId[0]);
      const lastInfo = await router.getSettledPayment(tradeId[0]);

      await expect(
        router.connect(admin).confirmPayment(tradeId[0], signature),
      ).to.be.revertedWithCustomError(solbtc, "Unauthorized");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(currentStage);
      expect(await router.getSettledPayment(tradeId[0])).deep.eq(lastInfo);
    });

    it("Should succeed when MPC Node submits a payment confirmation even though the protocol is triggered the Suspension Mode", async () => {
      await management.connect(admin).suspend();

      const infoHash = getConfirmPaymentHash(
        ZERO_VALUE,
        amountOut[1],
        tradeInfo[1].toChain,
        paymentTxId[1],
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[1],
        infoHash,
        SignatureType.ConfirmPayment,
        domain,
      );

      const tx = router.connect(mpcNode2).confirmPayment(tradeId[1], signature);

      await expect(tx)
        .to.emit(router, "ConfirmPayment")
        .withArgs(mpcNode2.address, tradeId[1]);
      await expect(tx)
        .to.emit(solbtc, "PaymentConfirmed")
        .withArgs(
          await router.getAddress(),
          mpcL2.address,
          tradeId[1],
          hexlify(paymentTxId[1]),
        );

      expect(await router.getCurrentStage(tradeId[1])).deep.eq(
        STAGE.CONFIRM_SETTLEMENT,
      );
      expect(await router.getSettledPayment(tradeId[1])).deep.eq([
        bundlerHash([tradeId[1]]),
        hexlify(paymentTxId[1]),
        EMPTY_BYTES,
        true,
      ]);

      //  set back to normal
      await management.connect(admin).resume();
    });

    it("Should revert when MPC Node submits a payment confirmation, but the protocol is triggered the Shutdown Mode", async () => {
      await management.connect(admin).shutdown();

      const infoHash = getConfirmPaymentHash(
        ZERO_VALUE,
        amountOut[0],
        tradeInfo[0].toChain,
        paymentTxId[0],
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[0],
        infoHash,
        SignatureType.ConfirmPayment,
        domain,
      );

      const currentStage = await router.getCurrentStage(tradeId[0]);
      const lastInfo = await router.getSettledPayment(tradeId[0]);

      await expect(
        router.connect(mpcNode1).confirmPayment(tradeId[0], signature),
      ).to.be.revertedWithCustomError(solbtc, "InSuspension");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(currentStage);
      expect(await router.getSettledPayment(tradeId[0])).deep.eq(lastInfo);

      //  set back to normal
      await management.connect(admin).resume();
    });

    it("Should revert when MPC Node submits a payment confirmation, but scriptTimeout is reached", async () => {
      const timestamp = await getBlockTimestamp(provider);
      const exceedTimeout = Number(scriptInfo[0].scriptTimeout) + 1;

      //  take a snapshot before increasing block.timestamp
      const snapshot = await takeSnapshot();
      if (timestamp < exceedTimeout) await adjustTime(exceedTimeout);

      const infoHash = getConfirmPaymentHash(
        ZERO_VALUE,
        amountOut[0],
        tradeInfo[0].toChain,
        paymentTxId[0],
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[0],
        infoHash,
        SignatureType.ConfirmPayment,
        domain,
      );

      const currentStage = await router.getCurrentStage(tradeId[0]);
      const lastInfo = await router.getSettledPayment(tradeId[0]);

      await expect(
        router.connect(mpcNode1).confirmPayment(tradeId[0], signature),
      ).to.be.revertedWithCustomError(solbtc, "DeadlineExceeded");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(currentStage);
      expect(await router.getSettledPayment(tradeId[0])).deep.eq(lastInfo);

      //  set back to normal
      await snapshot.restore();
    });

    it("Should revert when MPC Node submits a payment confirmation, but invalid MPC's signature - Invalid Signer", async () => {
      const infoHash = getConfirmPaymentHash(
        ZERO_VALUE,
        amountOut[0],
        tradeInfo[0].toChain,
        paymentTxId[0],
      );
      const signature: string = await getSignature(
        mpcNode1, //  should be "mpc"
        tradeId[0],
        infoHash,
        SignatureType.ConfirmPayment,
        domain,
      );

      const currentStage = await router.getCurrentStage(tradeId[0]);
      const lastInfo = await router.getSettledPayment(tradeId[0]);

      await expect(
        router.connect(mpcNode1).confirmPayment(tradeId[0], signature),
      ).to.be.revertedWithCustomError(solbtc, "InvalidMPCSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(currentStage);
      expect(await router.getSettledPayment(tradeId[0])).deep.eq(lastInfo);
    });

    it("Should revert when MPC Node submits a payment confirmation, but invalid MPC's signature - Un-match paymentAmount", async () => {
      const invalidInfoHash = getConfirmPaymentHash(
        ZERO_VALUE,
        amountOut[0] - BigInt(1),
        tradeInfo[0].toChain,
        paymentTxId[0],
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[0],
        invalidInfoHash,
        SignatureType.ConfirmPayment,
        domain,
      );

      const currentStage = await router.getCurrentStage(tradeId[0]);
      const lastInfo = await router.getSettledPayment(tradeId[0]);

      await expect(
        router.connect(mpcNode1).confirmPayment(tradeId[0], signature),
      ).to.be.revertedWithCustomError(solbtc, "InvalidMPCSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(currentStage);
      expect(await router.getSettledPayment(tradeId[0])).deep.eq(lastInfo);
    });

    it("Should revert when MPC Node submits a payment confirmation, but invalid MPC's signature - Un-match toUserAddress", async () => {
      const invalidInfoHash = getConfirmPaymentHash(
        ZERO_VALUE,
        amountOut[0],
        [
          hexlify(Keypair.generate().publicKey.toBytes()),
          tradeInfo[0].toChain[1],
          tradeInfo[0].toChain[2],
        ],
        paymentTxId[0],
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[0],
        invalidInfoHash,
        SignatureType.ConfirmPayment,
        domain,
      );

      const currentStage = await router.getCurrentStage(tradeId[0]);
      const lastInfo = await router.getSettledPayment(tradeId[0]);

      await expect(
        router.connect(mpcNode1).confirmPayment(tradeId[0], signature),
      ).to.be.revertedWithCustomError(solbtc, "InvalidMPCSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(currentStage);
      expect(await router.getSettledPayment(tradeId[0])).deep.eq(lastInfo);
    });

    it("Should revert when MPC Node submits a payment confirmation, but invalid MPC's signature - Un-match tochain", async () => {
      const invalidInfoHash = getConfirmPaymentHash(
        ZERO_VALUE,
        amountOut[0],
        [
          tradeInfo[0].toChain[0],
          toUtf8Bytes("Invalid_chain"),
          tradeInfo[0].toChain[2],
        ],
        paymentTxId[0],
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[0],
        invalidInfoHash,
        SignatureType.ConfirmPayment,
        domain,
      );

      const currentStage = await router.getCurrentStage(tradeId[0]);
      const lastInfo = await router.getSettledPayment(tradeId[0]);

      await expect(
        router.connect(mpcNode1).confirmPayment(tradeId[0], signature),
      ).to.be.revertedWithCustomError(solbtc, "InvalidMPCSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(currentStage);
      expect(await router.getSettledPayment(tradeId[0])).deep.eq(lastInfo);
    });

    it("Should revert when MPC Node submits a payment confirmation, but invalid MPC's signature - Un-match toToken", async () => {
      const invalidInfoHash = getConfirmPaymentHash(
        ZERO_VALUE,
        amountOut[0],
        [
          tradeInfo[0].toChain[0],
          tradeInfo[0].toChain[1],
          toUtf8Bytes("Invalid_token"),
        ],
        paymentTxId[0],
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[0],
        invalidInfoHash,
        SignatureType.ConfirmPayment,
        domain,
      );

      const currentStage = await router.getCurrentStage(tradeId[0]);
      const lastInfo = await router.getSettledPayment(tradeId[0]);

      await expect(
        router.connect(mpcNode1).confirmPayment(tradeId[0], signature),
      ).to.be.revertedWithCustomError(solbtc, "InvalidMPCSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(currentStage);
      expect(await router.getSettledPayment(tradeId[0])).deep.eq(lastInfo);
    });

    it("Should revert when MPC Node submits a payment confirmation, but invalid MPC's signature - Un-match paymentTxId", async () => {
      const invalidInfoHash = getConfirmPaymentHash(
        ZERO_VALUE,
        amountOut[0],
        tradeInfo[0].toChain,
        randomTxId(),
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[0],
        invalidInfoHash,
        SignatureType.ConfirmPayment,
        domain,
      );

      const currentStage = await router.getCurrentStage(tradeId[0]);
      const lastInfo = await router.getSettledPayment(tradeId[0]);

      await expect(
        router.connect(mpcNode1).confirmPayment(tradeId[0], signature),
      ).to.be.revertedWithCustomError(solbtc, "InvalidMPCSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(currentStage);
      expect(await router.getSettledPayment(tradeId[0])).deep.eq(lastInfo);
    });

    it("Should revert when MPC Node submits a payment confirmation, but invalid MPC's signature - Un-match tradeId", async () => {
      const infoHash = getConfirmPaymentHash(
        ZERO_VALUE,
        amountOut[0],
        tradeInfo[0].toChain,
        paymentTxId[0],
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[1],
        infoHash,
        SignatureType.ConfirmPayment,
        domain,
      );

      const currentStage = await router.getCurrentStage(tradeId[0]);
      const lastInfo = await router.getSettledPayment(tradeId[0]);

      await expect(
        router.connect(mpcNode1).confirmPayment(tradeId[0], signature),
      ).to.be.revertedWithCustomError(solbtc, "InvalidMPCSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(currentStage);
      expect(await router.getSettledPayment(tradeId[0])).deep.eq(lastInfo);
    });

    it("Should revert when MPC Node submits a payment confirmation, but invalid MPC's signature - totalFeeAmount != 0", async () => {
      //  @dev: For SOL->BTC, the `totalFeeAmount` will be charged on deposited amount
      //  when MPC calls to settle the trade. Thus, `totalFeeAmount`, at this step, should be "0"
      const infoHash = getConfirmPaymentHash(
        BigInt(1),
        amountOut[0],
        tradeInfo[0].toChain,
        paymentTxId[0],
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[0],
        infoHash,
        SignatureType.ConfirmPayment,
        domain,
      );

      const currentStage = await router.getCurrentStage(tradeId[0]);
      const lastInfo = await router.getSettledPayment(tradeId[0]);

      await expect(
        router.connect(mpcNode1).confirmPayment(tradeId[0], signature),
      ).to.be.revertedWithCustomError(solbtc, "InvalidMPCSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(currentStage);
      expect(await router.getSettledPayment(tradeId[0])).deep.eq(lastInfo);
    });

    it("Should revert when MPC Node submits a payment confirmation, but invalid MPC's signature - Wrong domain - Wrong contract name", async () => {
      const wrongDomain: TypedDataDomain = {
        ...domain,
        name: "Wrong Contract Name",
      };

      const infoHash = getConfirmPaymentHash(
        ZERO_VALUE,
        amountOut[0],
        tradeInfo[0].toChain,
        paymentTxId[0],
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[0],
        infoHash,
        SignatureType.ConfirmPayment,
        wrongDomain,
      );

      const currentStage = await router.getCurrentStage(tradeId[0]);
      const lastInfo = await router.getSettledPayment(tradeId[0]);

      await expect(
        router.connect(mpcNode1).confirmPayment(tradeId[0], signature),
      ).to.be.revertedWithCustomError(solbtc, "InvalidMPCSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(currentStage);
      expect(await router.getSettledPayment(tradeId[0])).deep.eq(lastInfo);
    });

    it("Should revert when MPC Node submits a payment confirmation, but invalid MPC's signature - Wrong domain - Wrong version", async () => {
      const wrongDomain: TypedDataDomain = {
        ...domain,
        version: "Wrong Contract Version",
      };

      const infoHash = getConfirmPaymentHash(
        ZERO_VALUE,
        amountOut[0],
        tradeInfo[0].toChain,
        paymentTxId[0],
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[0],
        infoHash,
        SignatureType.ConfirmPayment,
        wrongDomain,
      );

      const currentStage = await router.getCurrentStage(tradeId[0]);
      const lastInfo = await router.getSettledPayment(tradeId[0]);

      await expect(
        router.connect(mpcNode1).confirmPayment(tradeId[0], signature),
      ).to.be.revertedWithCustomError(solbtc, "InvalidMPCSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(currentStage);
      expect(await router.getSettledPayment(tradeId[0])).deep.eq(lastInfo);
    });

    it("Should revert when MPC Node submits a payment confirmation, but invalid MPC's signature - Wrong domain - Wrong chainId", async () => {
      const wrongDomain: TypedDataDomain = {
        ...domain,
        chainId: (domain.chainId as bigint) + BigInt(1),
      };

      const infoHash = getConfirmPaymentHash(
        ZERO_VALUE,
        amountOut[0],
        tradeInfo[0].toChain,
        paymentTxId[0],
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[0],
        infoHash,
        SignatureType.ConfirmPayment,
        wrongDomain,
      );

      const currentStage = await router.getCurrentStage(tradeId[0]);
      const lastInfo = await router.getSettledPayment(tradeId[0]);

      await expect(
        router.connect(mpcNode1).confirmPayment(tradeId[0], signature),
      ).to.be.revertedWithCustomError(solbtc, "InvalidMPCSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(currentStage);
      expect(await router.getSettledPayment(tradeId[0])).deep.eq(lastInfo);
    });

    it("Should revert when MPC Node submits a payment confirmation, but invalid MPC's signature - Wrong domain - Wrong contract address", async () => {
      const wrongDomain: TypedDataDomain = {
        ...domain,
        verifyingContract: admin.address,
      };

      const infoHash = getConfirmPaymentHash(
        ZERO_VALUE,
        amountOut[0],
        tradeInfo[0].toChain,
        paymentTxId[0],
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[0],
        infoHash,
        SignatureType.ConfirmPayment,
        wrongDomain,
      );

      const currentStage = await router.getCurrentStage(tradeId[0]);
      const lastInfo = await router.getSettledPayment(tradeId[0]);

      await expect(
        router.connect(mpcNode1).confirmPayment(tradeId[0], signature),
      ).to.be.revertedWithCustomError(solbtc, "InvalidMPCSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(currentStage);
      expect(await router.getSettledPayment(tradeId[0])).deep.eq(lastInfo);
    });

    it("Should succeed when MPC Node submits a payment confirmation", async () => {
      const infoHash = getConfirmPaymentHash(
        ZERO_VALUE,
        amountOut[0],
        tradeInfo[0].toChain,
        paymentTxId[0],
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[0],
        infoHash,
        SignatureType.ConfirmPayment,
        domain,
      );

      const tx = router.connect(mpcNode1).confirmPayment(tradeId[0], signature);

      await expect(tx)
        .to.emit(router, "ConfirmPayment")
        .withArgs(mpcNode1.address, tradeId[0]);
      await expect(tx)
        .to.emit(solbtc, "PaymentConfirmed")
        .withArgs(
          await router.getAddress(),
          mpcL2.address,
          tradeId[0],
          hexlify(paymentTxId[0]),
        );

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.CONFIRM_SETTLEMENT,
      );
      expect(await router.getSettledPayment(tradeId[0])).deep.eq([
        bundlerHash([tradeId[0], tradeId[2]]),
        hexlify(paymentTxId[0]),
        EMPTY_BYTES,
        true,
      ]);
    });

    it("Should revert when selected PMM calls bundlePayment() to update paymentTxId for one trade in the bundle", async () => {
      const startIdx = BigInt(0);
      const tradeIds = [tradeId[2]];
      const signedAt = BigInt(await getBlockTimestamp(provider));
      const newPaymentTxId = randomTxId();
      const infoHash: string = getMakePaymentHash(
        tradeIds,
        signedAt,
        startIdx,
        newPaymentTxId,
      );
      const signature = await getSignature(
        accounts[0],
        tradeId[0],
        infoHash,
        SignatureType.MakePayment,
        domain,
      );
      const bundle: CoreTypes.BundlePaymentStruct = {
        tradeIds: tradeIds,
        signedAt: signedAt,
        startIdx: startIdx,
        paymentTxId: newPaymentTxId,
        signature: signature,
      };

      const currentStage = await router.getCurrentStage(tradeId[2]);
      const lastInfo = await router.getSettledPayment(tradeId[2]);
      expect(await router.getCurrentStage(tradeId[0])).deep.eq(
        STAGE.CONFIRM_SETTLEMENT,
      );

      //  @dev: tradeId[0] and tradeId[2] are bundled by one `paymentTxId`
      //  In previous test, tradeId[0] is confirmed by the MPC for the payment.
      //  thus, tradeId[2] is not allowed to be updated the `paymentTxId`
      await expect(
        router.connect(solver).bundlePayment(bundle),
      ).to.be.revertedWithCustomError(solbtc, "UpdateNotAllowed");

      expect(await router.getCurrentStage(tradeId[2])).deep.eq(currentStage);
      expect(await router.getSettledPayment(tradeId[2])).deep.eq(lastInfo);
    });

    it("Should revert when MPC Node tries to update payment confirmation after submission", async () => {
      const newPaymentTxId = randomTxId();
      const infoHash = getConfirmPaymentHash(
        ZERO_VALUE,
        amountOut[0],
        tradeInfo[0].toChain,
        newPaymentTxId,
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[0],
        infoHash,
        SignatureType.ConfirmPayment,
        domain,
      );

      const currentStage = await router.getCurrentStage(tradeId[0]);
      const settledPaymentData = await router.getSettledPayment(tradeId[0]);

      await expect(
        router.connect(mpcNode2).confirmPayment(tradeId[0], signature),
      ).to.be.revertedWithCustomError(solbtc, "InvalidProcedureState");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(currentStage);
      expect(await router.getSettledPayment(tradeId[0])).deep.eq(
        settledPaymentData,
      );
    });

    it("Should succeed when MPC Node submits another payment confirmation", async () => {
      const infoHash = getConfirmPaymentHash(
        ZERO_VALUE,
        amountOut[2],
        tradeInfo[2].toChain,
        paymentTxId[0],
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[2],
        infoHash,
        SignatureType.ConfirmPayment,
        domain,
      );

      const tx = router.connect(mpcNode1).confirmPayment(tradeId[2], signature);

      await expect(tx)
        .to.emit(router, "ConfirmPayment")
        .withArgs(mpcNode1.address, tradeId[2]);
      await expect(tx)
        .to.emit(solbtc, "PaymentConfirmed")
        .withArgs(
          await router.getAddress(),
          mpcL2.address,
          tradeId[2],
          hexlify(paymentTxId[0]),
        );

      expect(await router.getCurrentStage(tradeId[2])).deep.eq(
        STAGE.CONFIRM_SETTLEMENT,
      );
      expect(await router.getSettledPayment(tradeId[2])).deep.eq([
        bundlerHash([tradeId[0], tradeId[2]]),
        hexlify(paymentTxId[0]),
        EMPTY_BYTES,
        true,
      ]);
    });
  });

  describe("confirmSettlement() functional testing", async () => {
    it("Should revert when Unauthorized client, an arbitrary account, tries to submit a settlement confirmation", async () => {
      const infoHash: string = getConfirmSettlementHash(
        pFeeAmount[0] + aFeeAmount[0],
        releaseTxId[0],
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[0],
        infoHash,
        SignatureType.ConfirmSettlement,
        domain,
      );

      const currentStage = await router.getCurrentStage(tradeId[0]);
      const lastInfo = await router.getSettledPayment(tradeId[0]);

      await expect(
        router
          .connect(accounts[0])
          .confirmSettlement(tradeId[0], releaseTxId[0], signature),
      ).to.be.revertedWithCustomError(solbtc, "Unauthorized");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(currentStage);
      expect(await router.getSettledPayment(tradeId[0])).deep.eq(lastInfo);
    });

    it("Should revert when Unauthorized client, the Solver, tries to submit a settlement confirmation", async () => {
      const infoHash: string = getConfirmSettlementHash(
        pFeeAmount[0] + aFeeAmount[0],
        releaseTxId[0],
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[0],
        infoHash,
        SignatureType.ConfirmSettlement,
        domain,
      );

      const currentStage = await router.getCurrentStage(tradeId[0]);
      const lastInfo = await router.getSettledPayment(tradeId[0]);

      await expect(
        router
          .connect(solver)
          .confirmSettlement(tradeId[0], releaseTxId[0], signature),
      ).to.be.revertedWithCustomError(solbtc, "Unauthorized");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(currentStage);
      expect(await router.getSettledPayment(tradeId[0])).deep.eq(lastInfo);
    });

    it("Should revert when Unauthorized client, the Admin, tries to submit a settlement confirmation", async () => {
      const infoHash: string = getConfirmSettlementHash(
        pFeeAmount[0] + aFeeAmount[0],
        releaseTxId[0],
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[0],
        infoHash,
        SignatureType.ConfirmSettlement,
        domain,
      );

      const currentStage = await router.getCurrentStage(tradeId[0]);
      const lastInfo = await router.getSettledPayment(tradeId[0]);

      await expect(
        router
          .connect(admin)
          .confirmSettlement(tradeId[0], releaseTxId[0], signature),
      ).to.be.revertedWithCustomError(solbtc, "Unauthorized");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(currentStage);
      expect(await router.getSettledPayment(tradeId[0])).deep.eq(lastInfo);
    });

    it("Should succeed when MPC Node submits a settlement confirmation even though the protocol is triggered the Suspension Mode", async () => {
      await management.connect(admin).suspend();

      const infoHash: string = getConfirmSettlementHash(
        pFeeAmount[1] + aFeeAmount[1],
        releaseTxId[1],
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[1],
        infoHash,
        SignatureType.ConfirmSettlement,
        domain,
      );

      const tx = router
        .connect(mpcNode2)
        .confirmSettlement(tradeId[1], releaseTxId[1], signature);

      await expect(tx)
        .to.emit(router, "ConfirmSettlement")
        .withArgs(mpcNode2.address, tradeId[1]);
      await expect(tx)
        .to.emit(solbtc, "SettlementConfirmed")
        .withArgs(
          await router.getAddress(),
          mpcL2.address,
          tradeId[1],
          hexlify(releaseTxId[1]),
        );

      expect(await router.getCurrentStage(tradeId[1])).deep.eq(STAGE.COMPLETE);
      expect(await router.getSettledPayment(tradeId[1])).deep.eq([
        bundlerHash([tradeId[1]]),
        hexlify(paymentTxId[1]),
        hexlify(releaseTxId[1]),
        true,
      ]);

      //  set back to normal
      await management.connect(admin).resume();
    });

    it("Should revert when MPC Node submits a settlement confirmation, but the protocol is triggered the Shutdown Mode", async () => {
      await management.connect(admin).shutdown();

      const infoHash: string = getConfirmSettlementHash(
        pFeeAmount[0] + aFeeAmount[0],
        releaseTxId[0],
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[0],
        infoHash,
        SignatureType.ConfirmSettlement,
        domain,
      );

      const currentStage = await router.getCurrentStage(tradeId[0]);
      const lastInfo = await router.getSettledPayment(tradeId[0]);

      await expect(
        router
          .connect(mpcNode1)
          .confirmSettlement(tradeId[0], releaseTxId[0], signature),
      ).to.be.revertedWithCustomError(solbtc, "InSuspension");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(currentStage);
      expect(await router.getSettledPayment(tradeId[0])).deep.eq(lastInfo);

      //  set back to normal
      await management.connect(admin).resume();
    });

    it("Should revert when MPC Node submits a settlement confirmation, but invalid MPC's signature - Invalid Signer", async () => {
      const infoHash: string = getConfirmSettlementHash(
        pFeeAmount[0] + aFeeAmount[0],
        releaseTxId[0],
      );
      const signature: string = await getSignature(
        mpcNode1, //  should be "mpc"
        tradeId[0],
        infoHash,
        SignatureType.ConfirmSettlement,
        domain,
      );

      const currentStage = await router.getCurrentStage(tradeId[0]);
      const lastInfo = await router.getSettledPayment(tradeId[0]);

      await expect(
        router
          .connect(mpcNode1)
          .confirmSettlement(tradeId[0], releaseTxId[0], signature),
      ).to.be.revertedWithCustomError(solbtc, "InvalidMPCSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(currentStage);
      expect(await router.getSettledPayment(tradeId[0])).deep.eq(lastInfo);
    });

    it("Should revert when MPC Node submits a settlement confirmation, but invalid MPC's signature - Un-match totalFeeAmount", async () => {
      const infoHash: string = getConfirmSettlementHash(
        pFeeAmount[0] + aFeeAmount[0] - BigInt(1),
        randomTxId(),
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[0],
        infoHash,
        SignatureType.ConfirmSettlement,
        domain,
      );

      const currentStage = await router.getCurrentStage(tradeId[0]);
      const lastInfo = await router.getSettledPayment(tradeId[0]);

      await expect(
        router
          .connect(mpcNode1)
          .confirmSettlement(tradeId[0], releaseTxId[0], signature),
      ).to.be.revertedWithCustomError(solbtc, "InvalidMPCSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(currentStage);
      expect(await router.getSettledPayment(tradeId[0])).deep.eq(lastInfo);
    });

    it("Should revert when MPC Node submits a settlement confirmation, but invalid MPC's signature - Un-match releaseTxId", async () => {
      const infoHash: string = getConfirmSettlementHash(
        pFeeAmount[0] + aFeeAmount[0],
        randomTxId(),
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[0],
        infoHash,
        SignatureType.ConfirmSettlement,
        domain,
      );

      const currentStage = await router.getCurrentStage(tradeId[0]);
      const lastInfo = await router.getSettledPayment(tradeId[0]);

      await expect(
        router
          .connect(mpcNode1)
          .confirmSettlement(tradeId[0], releaseTxId[0], signature),
      ).to.be.revertedWithCustomError(solbtc, "InvalidMPCSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(currentStage);
      expect(await router.getSettledPayment(tradeId[0])).deep.eq(lastInfo);
    });

    it("Should revert when MPC Node submits a settlement confirmation, but invalid MPC's signature - Wrong domain - Wrong contract name", async () => {
      const wrongDomain: TypedDataDomain = {
        ...domain,
        name: "Wrong Contract Name",
      };

      const infoHash: string = getConfirmSettlementHash(
        pFeeAmount[0] + aFeeAmount[0],
        releaseTxId[0],
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[0],
        infoHash,
        SignatureType.ConfirmSettlement,
        wrongDomain,
      );

      const currentStage = await router.getCurrentStage(tradeId[0]);
      const lastInfo = await router.getSettledPayment(tradeId[0]);

      await expect(
        router
          .connect(mpcNode1)
          .confirmSettlement(tradeId[0], releaseTxId[0], signature),
      ).to.be.revertedWithCustomError(solbtc, "InvalidMPCSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(currentStage);
      expect(await router.getSettledPayment(tradeId[0])).deep.eq(lastInfo);
    });

    it("Should revert when MPC Node submits a settlement confirmation, but invalid MPC's signature - Wrong domain - Wrong version", async () => {
      const wrongDomain: TypedDataDomain = {
        ...domain,
        version: "Wrong Contract Version",
      };

      const infoHash: string = getConfirmSettlementHash(
        pFeeAmount[0] + aFeeAmount[0],
        releaseTxId[0],
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[0],
        infoHash,
        SignatureType.ConfirmSettlement,
        wrongDomain,
      );

      const currentStage = await router.getCurrentStage(tradeId[0]);
      const lastInfo = await router.getSettledPayment(tradeId[0]);

      await expect(
        router
          .connect(mpcNode1)
          .confirmSettlement(tradeId[0], releaseTxId[0], signature),
      ).to.be.revertedWithCustomError(solbtc, "InvalidMPCSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(currentStage);
      expect(await router.getSettledPayment(tradeId[0])).deep.eq(lastInfo);
    });

    it("Should revert when MPC Node submits a settlement confirmation, but invalid MPC's signature - Wrong domain - Wrong chainId", async () => {
      const wrongDomain: TypedDataDomain = {
        ...domain,
        chainId: (domain.chainId as bigint) + BigInt(1),
      };

      const infoHash: string = getConfirmSettlementHash(
        pFeeAmount[0] + aFeeAmount[0],
        releaseTxId[0],
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[0],
        infoHash,
        SignatureType.ConfirmSettlement,
        wrongDomain,
      );

      const currentStage = await router.getCurrentStage(tradeId[0]);
      const lastInfo = await router.getSettledPayment(tradeId[0]);

      await expect(
        router
          .connect(mpcNode1)
          .confirmSettlement(tradeId[0], releaseTxId[0], signature),
      ).to.be.revertedWithCustomError(solbtc, "InvalidMPCSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(currentStage);
      expect(await router.getSettledPayment(tradeId[0])).deep.eq(lastInfo);
    });

    it("Should revert when MPC Node submits a settlement confirmation, but invalid MPC's signature - Wrong domain - Wrong contract address", async () => {
      const wrongDomain: TypedDataDomain = {
        ...domain,
        verifyingContract: admin.address,
      };

      const infoHash: string = getConfirmSettlementHash(
        pFeeAmount[0] + aFeeAmount[0],
        releaseTxId[0],
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[0],
        infoHash,
        SignatureType.ConfirmSettlement,
        wrongDomain,
      );

      const currentStage = await router.getCurrentStage(tradeId[0]);
      const lastInfo = await router.getSettledPayment(tradeId[0]);

      await expect(
        router
          .connect(mpcNode1)
          .confirmSettlement(tradeId[0], releaseTxId[0], signature),
      ).to.be.revertedWithCustomError(solbtc, "InvalidMPCSign");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(currentStage);
      expect(await router.getSettledPayment(tradeId[0])).deep.eq(lastInfo);
    });

    it("Should succeed when MPC Node submits a settlement confirmation", async () => {
      const infoHash: string = getConfirmSettlementHash(
        pFeeAmount[0] + aFeeAmount[0],
        releaseTxId[0],
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[0],
        infoHash,
        SignatureType.ConfirmSettlement,
        domain,
      );

      const tx = router
        .connect(mpcNode1)
        .confirmSettlement(tradeId[0], releaseTxId[0], signature);

      await expect(tx)
        .to.emit(router, "ConfirmSettlement")
        .withArgs(mpcNode1.address, tradeId[0]);
      await expect(tx)
        .to.emit(solbtc, "SettlementConfirmed")
        .withArgs(
          await router.getAddress(),
          mpcL2.address,
          tradeId[0],
          hexlify(releaseTxId[0]),
        );

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(STAGE.COMPLETE);
      expect(await router.getSettledPayment(tradeId[0])).deep.eq([
        bundlerHash([tradeId[0], tradeId[2]]),
        hexlify(paymentTxId[0]),
        hexlify(releaseTxId[0]),
        true,
      ]);
    });

    it("Should revert when MPC Node tries to update settlement confirmation after submission", async () => {
      const newReleaseTxId = randomTxId();

      const infoHash: string = getConfirmSettlementHash(
        pFeeAmount[0] + aFeeAmount[0],
        newReleaseTxId,
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[0],
        infoHash,
        SignatureType.ConfirmSettlement,
        domain,
      );

      const currentStage = await router.getCurrentStage(tradeId[0]);
      const lastInfo = await router.getSettledPayment(tradeId[0]);

      await expect(
        router
          .connect(mpcNode2)
          .confirmSettlement(tradeId[0], newReleaseTxId, signature),
      ).to.be.revertedWithCustomError(solbtc, "InvalidProcedureState");

      expect(await router.getCurrentStage(tradeId[0])).deep.eq(currentStage);
      expect(await router.getSettledPayment(tradeId[0])).deep.eq(lastInfo);
    });

    it("Should succeed when MPC Node submits another settlement confirmation", async () => {
      const infoHash: string = getConfirmSettlementHash(
        pFeeAmount[2] + aFeeAmount[2],
        releaseTxId[2],
      );
      const signature: string = await getSignature(
        mpcL2,
        tradeId[2],
        infoHash,
        SignatureType.ConfirmSettlement,
        domain,
      );

      const tx = router
        .connect(mpcNode1)
        .confirmSettlement(tradeId[2], releaseTxId[2], signature);

      await expect(tx)
        .to.emit(router, "ConfirmSettlement")
        .withArgs(mpcNode1.address, tradeId[2]);
      await expect(tx)
        .to.emit(solbtc, "SettlementConfirmed")
        .withArgs(
          await router.getAddress(),
          mpcL2.address,
          tradeId[2],
          hexlify(releaseTxId[2]),
        );

      expect(await router.getCurrentStage(tradeId[2])).deep.eq(STAGE.COMPLETE);
      expect(await router.getSettledPayment(tradeId[2])).deep.eq([
        bundlerHash([tradeId[0], tradeId[2]]),
        hexlify(paymentTxId[0]),
        hexlify(releaseTxId[2]),
        true,
      ]);
    });
  });
});
