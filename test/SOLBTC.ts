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
} from "ethers";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";
import { HardhatEthersProvider } from "@nomicfoundation/hardhat-ethers/internal/hardhat-ethers-provider";
import { Keypair, PublicKey } from "@solana/web3.js";

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

function bundlerHash(tradeIds: BytesLike[]): string {
  return keccak256(abiCoder.encode(["bytes32[]"], [tradeIds]));
}

async function getBlockTimestamp(provider: HardhatEthersProvider) {
  const block = await provider.getBlockNumber();
  const timestamp = (await provider.getBlock(block))?.timestamp as number;

  return timestamp;
}

describe("SOLBTC Contract Testing", () => {
  let admin: HardhatEthersSigner, solver: HardhatEthersSigner;
  let mpcL2: Wallet, mpcAssetPubkey: PublicKey;
  let mpcNode1: HardhatEthersSigner, mpcNode2: HardhatEthersSigner;
  let accounts: HardhatEthersSigner[];
  let user: Keypair;

  let management: Management;
  let solbtc: SOLBTC, signerHelper: SignerHelper;
  let router: Router, clone: Router;

  let btcTokenInfo: ManagementTypes.TokenInfoStruct,
    solNativeInfo: ManagementTypes.TokenInfoStruct,
    solTokenInfo: ManagementTypes.TokenInfoStruct;

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

  const pFeeRate: bigint = BigInt(50);
  const fromChain = "solana-devnet";
  const fromToken = ["native", "So11111111111111111111111111111111111111112"];

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
    clone = await Router.deploy(
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
    for (let i = 0; i < fromToken.length; i++) {
      sessionId[i] = BigInt(keccak256(toUtf8Bytes(crypto.randomUUID())));
      affiliateInfo[i] = getAffiliateInfo();
      tradeInfo[i] = getTradeInfo(
        fromChain,
        fromToken[i],
        user.publicKey,
        decimals,
      );
      rfqInfo[i] = getRFQInfo();
      tradeId[i] = getTradeId(sessionId[i], solver.address, tradeInfo[i]);
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
      aFeeAmount[i] =
        (BigInt(tradeInfo[i].amountIn) *
          BigInt(affiliateInfo[i].aggregatedValue)) /
        DENOM;
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

    solTokenInfo = {
      info: [
        tradeInfo[1].fromChain[2], // tokenId
        tradeInfo[1].fromChain[1], // networkId
        toUtf8Bytes("SOL"), // symbol
        toUtf8Bytes(
          "https://explorer.solana.com/address/So11111111111111111111111111111111111111112?cluster=devnet",
        ),
        toUtf8Bytes("Wrapped SOL (SOL) - Solana Devnet"),
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
    await management.connect(admin).setToken(solTokenInfo);
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

    //  set MPC Pubkey
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

  it("Should be able to check the initialized settings of btcsol contract", async () => {
    expect(await solbtc.router()).deep.equal(await router.getAddress());
    expect(await solbtc.typeOfHandler()).deep.eq("SOLBTC");
  });

  describe("setRouter() functional testing", async () => {
    it("Should revert when Unauthorized client, a arbitrary account, tries to update new Router contract", async () => {
      expect(await solbtc.router()).deep.equal(await router.getAddress());

      await expect(
        solbtc.connect(accounts[0]).setRouter(accounts[0].address),
      ).to.be.revertedWithCustomError(solbtc, "Unauthorized");

      expect(await solbtc.router()).deep.equal(await router.getAddress());
    });

    it("Should revert when Unauthorized client, the Solver account, tries to update new Router contract", async () => {
      expect(await solbtc.router()).deep.equal(await router.getAddress());

      await expect(
        solbtc.connect(solver).setRouter(solver.address),
      ).to.be.revertedWithCustomError(solbtc, "Unauthorized");

      expect(await solbtc.router()).deep.equal(await router.getAddress());
    });

    it("Should revert when Unauthorized client, the MPC account, tries to update new Router contract", async () => {
      expect(await solbtc.router()).deep.equal(await router.getAddress());

      await expect(
        solbtc.connect(mpcL2).setRouter(mpcL2.address),
      ).to.be.revertedWithCustomError(solbtc, "Unauthorized");

      expect(await solbtc.router()).deep.equal(await router.getAddress());
    });

    it("Should revert when Owner updates 0x0 as a new address of Router contract", async () => {
      expect(await solbtc.router()).deep.equal(await router.getAddress());

      await expect(
        solbtc.connect(admin).setRouter(ZeroAddress),
      ).to.be.revertedWithCustomError(solbtc, "AddressZero");

      expect(await solbtc.router()).deep.equal(await router.getAddress());
    });

    it("Should succeed when Owner updates a new address of Router contract", async () => {
      expect(await solbtc.router()).deep.equal(await router.getAddress());

      await solbtc.connect(admin).setRouter(await clone.getAddress());

      expect(await solbtc.router()).deep.equal(await clone.getAddress());
    });

    it("Should succeed when Owner changes back to previous Router contract", async () => {
      expect(await solbtc.router()).deep.equal(await clone.getAddress());

      await solbtc.connect(admin).setRouter(await router.getAddress());

      expect(await solbtc.router()).deep.equal(await router.getAddress());
    });
  });

  describe("submitTrade() functional testing", async () => {
    it("Should revert when Solver tries to submit trade data directly", async () => {
      //  Note: Solver cannot submit trade data and presigns directly
      //  by calling submitTrade() function
      //  Instead, Solver should call Router contract to submit trade data.
      const tradeData: CoreTypes.TradeDataStruct = {
        sessionId: sessionId[0],
        tradeInfo: tradeInfo[0],
        scriptInfo: scriptInfo[0],
      };

      await expect(
        solbtc
          .connect(solver)
          .submitTrade(
            solver.address,
            tradeId[0],
            tradeData,
            affiliateInfo[0],
            presigns[0],
          ),
      ).to.be.revertedWithCustomError(solbtc, "Unauthorized");

      expect(await solbtc.currentStage(tradeId[0])).deep.eq(STAGE.SUBMIT);
      expect(await solbtc.trade(tradeId[0])).deep.eq(EMPTY_TRADE_DATA);
      expect(await solbtc.presign(tradeId[0])).deep.eq(EMPTY_PRESIGNS);
      expect(await solbtc.feeDetails(tradeId[0])).deep.eq(EMPTY_FEE_DETAILS);
      expect(await solbtc.affiliate(tradeId[0])).deep.eq(EMPTY_AFFILIATE_INFO);
    });

    it("Should revert when Admin tries to submit trade data directly", async () => {
      //  Note: Solver cannot submit trade data and presigns directly
      //  by calling submitTrade() function
      //  Instead, Solver should call Router contract to submit trade data.
      const tradeData: CoreTypes.TradeDataStruct = {
        sessionId: sessionId[0],
        tradeInfo: tradeInfo[0],
        scriptInfo: scriptInfo[0],
      };

      await expect(
        solbtc
          .connect(admin)
          .submitTrade(
            solver.address,
            tradeId[0],
            tradeData,
            affiliateInfo[0],
            presigns[0],
          ),
      ).to.be.revertedWithCustomError(solbtc, "Unauthorized");

      expect(await solbtc.currentStage(tradeId[0])).deep.eq(STAGE.SUBMIT);
      expect(await solbtc.trade(tradeId[0])).deep.eq(EMPTY_TRADE_DATA);
      expect(await solbtc.presign(tradeId[0])).deep.eq(EMPTY_PRESIGNS);
      expect(await solbtc.feeDetails(tradeId[0])).deep.eq(EMPTY_FEE_DETAILS);
      expect(await solbtc.affiliate(tradeId[0])).deep.eq(EMPTY_AFFILIATE_INFO);
    });

    it("Should succeed when Solver submits trade data via Router", async () => {
      //  Note: Solver cannot submit trade data and presigns directly
      //  by calling submitTrade() function
      //  Instead, Solver should call Router contract to submit trade data.
      const tradeData: CoreTypes.TradeDataStruct = {
        sessionId: sessionId[0],
        tradeInfo: tradeInfo[0],
        scriptInfo: scriptInfo[0],
      };

      const tx = router
        .connect(solver)
        .submitTrade(tradeId[0], tradeData, affiliateInfo[0], presigns[0]);

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

      expect(await solbtc.currentStage(tradeId[0])).deep.eq(
        STAGE.CONFIRM_DEPOSIT,
      );
      expect(await solbtc.trade(tradeId[0])).deep.eq(
        Object.values(expectedTradeData),
      );
      expect(await solbtc.presign(tradeId[0])).deep.eq(
        Object.values(expectedPresigns),
      );
      expect(await solbtc.feeDetails(tradeId[0])).deep.eq([
        pFeeAmount[0] + aFeeAmount[0],
        pFeeAmount[0], // pFeeAmount
        aFeeAmount[0], // aFeeAmount
        pFeeRate,
        affiliateInfo[0].aggregatedValue, //  aFeeRate
      ]);
      expect(await solbtc.affiliate(tradeId[0])).deep.eq(
        Object.values(affiliateInfo[0]),
      );
    });

    it("Should succeed when Solver submits another trade via Router", async () => {
      //  Note: Solver cannot submit trade data and presigns directly
      //  by calling submitTrade() function
      //  Instead, Solver should call Router contract to submit trade data.
      const tradeData: CoreTypes.TradeDataStruct = {
        sessionId: sessionId[1],
        tradeInfo: tradeInfo[1],
        scriptInfo: scriptInfo[1],
      };

      const tx = router
        .connect(solver)
        .submitTrade(tradeId[1], tradeData, affiliateInfo[1], presigns[1]);

      await expect(tx)
        .to.emit(solbtc, "TradeInfoSubmitted")
        .withArgs(
          await router.getAddress(), // forwarder
          solver.address, // requester
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

      expect(await solbtc.currentStage(tradeId[1])).deep.eq(
        STAGE.CONFIRM_DEPOSIT,
      );
      expect(await solbtc.trade(tradeId[1])).deep.eq(
        Object.values(expectedTradeData),
      );
      expect(await solbtc.presign(tradeId[1])).deep.eq(
        Object.values(expectedPresigns),
      );
      expect(await solbtc.feeDetails(tradeId[1])).deep.eq([
        pFeeAmount[1] + aFeeAmount[1],
        pFeeAmount[1], // pFeeAmount
        aFeeAmount[1], // aFeeAmount
        pFeeRate,
        affiliateInfo[1].aggregatedValue, //  aFeeRate
      ]);
      expect(await solbtc.affiliate(tradeId[1])).deep.eq(
        Object.values(affiliateInfo[1]),
      );
    });
  });

  describe("confirmDeposit() functional testing", async () => {
    it("Should revert when MPC Nodes try to submit a deposit confirmation directly", async () => {
      //  Note: Authorized MPC Nodes cannot submit a deposit confirmation directly
      //  by calling confirmDeposit() function
      //  Instead, MPC Nodes should call Router contract to submit the confirmation
      const amountIn = tradeInfo[0].amountIn as bigint;
      const depositedFromList: BytesLike[] = [user.publicKey.toBytes()];
      const infoHash: string = getDepositConfirmationHash(
        amountIn,
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

      const currentStage = await solbtc.currentStage(tradeId[0]);
      const lastInfo = await solbtc.depositAddressList(tradeId[0]);

      await expect(
        solbtc
          .connect(mpcNode1)
          .confirmDeposit(
            mpcNode1.address,
            tradeId[0],
            signature,
            depositedFromList,
          ),
      ).to.be.revertedWithCustomError(solbtc, "Unauthorized");

      expect(await solbtc.currentStage(tradeId[0])).deep.eq(currentStage);
      expect(await solbtc.depositAddressList(tradeId[0])).deep.eq(lastInfo);
    });

    it("Should revert when Admin tries to submit a deposit confirmation directly", async () => {
      //  Note: Authorized MPC Nodes cannot submit a deposit confirmation directly
      //  by calling confirmDeposit() function
      //  Instead, MPC Nodes should call Router contract to submit the confirmation
      const amountIn = tradeInfo[0].amountIn as bigint;
      const depositedFromList: BytesLike[] = [user.publicKey.toBytes()];
      const infoHash: string = getDepositConfirmationHash(
        amountIn,
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

      const currentStage = await solbtc.currentStage(tradeId[0]);
      const lastInfo = await solbtc.depositAddressList(tradeId[0]);

      await expect(
        solbtc
          .connect(admin)
          .confirmDeposit(
            mpcNode1.address,
            tradeId[0],
            signature,
            depositedFromList,
          ),
      ).to.be.revertedWithCustomError(solbtc, "Unauthorized");

      expect(await solbtc.currentStage(tradeId[0])).deep.eq(currentStage);
      expect(await solbtc.depositAddressList(tradeId[0])).deep.eq(lastInfo);
    });

    it("Should succeed when MPC Nodes submit a deposit confirmation via Router", async () => {
      //  Note: Authorized MPC Nodes cannot submit a deposit confirmation directly
      //  by calling confirmDeposit() function
      //  Instead, MPC Nodes should call Router contract to submit the confirmation
      const amountIn = tradeInfo[0].amountIn as bigint;
      const depositedFromList: BytesLike[] = [user.publicKey.toBytes()];
      const infoHash = getDepositConfirmationHash(
        amountIn,
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
        .to.emit(solbtc, "DepositConfirmed")
        .withArgs(
          await router.getAddress(),
          mpcL2.address,
          tradeId[0],
          (affiliateInfo[0].aggregatedValue as bigint) + pFeeRate,
        );

      const expectedList = depositedFromList.map((data) => hexlify(data));
      expect(await solbtc.currentStage(tradeId[0])).deep.eq(STAGE.SELECT_PMM);
      expect(await solbtc.depositAddressList(tradeId[0])).deep.eq(expectedList);
    });

    it("Should succeed when MPC Nodes submit another confirmation via Router", async () => {
      //  Note: Authorized MPC Nodes cannot submit a deposit confirmation directly
      //  by calling confirmDeposit() function
      //  Instead, MPC Nodes should call Router contract to submit the confirmation
      const amountIn = tradeInfo[1].amountIn as bigint;
      const depositedFromList: BytesLike[] = [user.publicKey.toBytes()];
      const infoHash = getDepositConfirmationHash(
        amountIn,
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
        .connect(mpcNode1)
        .confirmDeposit(tradeId[1], signature, depositedFromList);

      await expect(tx)
        .to.emit(solbtc, "DepositConfirmed")
        .withArgs(
          await router.getAddress(),
          mpcL2.address,
          tradeId[1],
          (affiliateInfo[1].aggregatedValue as bigint) + pFeeRate,
        );

      const expectedList = depositedFromList.map((data) => hexlify(data));
      expect(await solbtc.currentStage(tradeId[1])).deep.eq(STAGE.SELECT_PMM);
      expect(await solbtc.depositAddressList(tradeId[1])).deep.eq(expectedList);
    });
  });

  describe("selectPMM() functional testing", async () => {
    it("Should revert when Solver tries to submit pmm selection directly", async () => {
      //  Note: Solver cannot submit a pmm selection directly by calling selectPMM() function
      //  Instead, Solver should call Router contract to submit the selection info
      const timestamp = await getBlockTimestamp(provider);
      const expiry = BigInt(timestamp + 30 * 60);
      amountOut[0] =
        (rfqInfo[0].minAmountOut as bigint) + parseUnits("5000", decimals);
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

      const currentStage = await solbtc.currentStage(tradeId[0]);
      const lastSelection = await solbtc.pmmSelection(tradeId[0]);

      await expect(
        solbtc
          .connect(solver)
          .selectPMM(solver.address, tradeId[0], pmmSelectionInfo),
      ).to.be.revertedWithCustomError(solbtc, "Unauthorized");

      expect(await solbtc.currentStage(tradeId[0])).deep.eq(currentStage);
      expect(await solbtc.pmmSelection(tradeId[0])).deep.eq(lastSelection);
    });

    it("Should revert when Admin tries to submit a pmm selection directly", async () => {
      //  Note: Solver cannot submit a pmm selection directly by calling selectPMM() function
      //  Instead, Solver should call Router contract to submit the selection info
      const timestamp = await getBlockTimestamp(provider);
      const expiry = BigInt(timestamp + 30 * 60);
      amountOut[0] =
        (rfqInfo[0].minAmountOut as bigint) + parseUnits("5000", decimals);
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

      const currentStage = await solbtc.currentStage(tradeId[0]);
      const lastSelection = await solbtc.pmmSelection(tradeId[0]);

      await expect(
        solbtc
          .connect(admin)
          .selectPMM(solver.address, tradeId[0], pmmSelectionInfo),
      ).to.be.revertedWithCustomError(solbtc, "Unauthorized");

      expect(await solbtc.currentStage(tradeId[0])).deep.eq(currentStage);
      expect(await solbtc.pmmSelection(tradeId[0])).deep.eq(lastSelection);
    });

    it("Should succeed when Solver submits a pmm selection via Router", async () => {
      //  Note: Solver cannot submit a pmm selection directly by calling selectPMM() function
      //  Instead, Solver should call Router contract to submit the selection info
      const timestamp = await getBlockTimestamp(provider);
      const expiry = BigInt(timestamp + 30 * 60);
      amountOut[0] =
        (rfqInfo[0].minAmountOut as bigint) + parseUnits("5000", decimals);
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
      expect(await solbtc.currentStage(tradeId[0])).deep.eq(STAGE.MAKE_PAYMENT);
      expect(await solbtc.pmmSelection(tradeId[0])).deep.eq(
        expectedPMMSelectionInfo,
      );
    });

    it("Should succeed when Solver submits another selection via Router", async () => {
      //  Note: Solver cannot submit a pmm selection directly by calling selectPMM() function
      //  Instead, Solver should call Router contract to submit the selection info
      const timestamp = await getBlockTimestamp(provider);
      const expiry = BigInt(timestamp + 30 * 60);
      amountOut[1] =
        (rfqInfo[1].minAmountOut as bigint) + parseUnits("5000", decimals);
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

      const tx = router.connect(solver).selectPMM(tradeId[1], pmmSelectionInfo);

      await expect(tx)
        .to.emit(solbtc, "SelectedPMM")
        .withArgs(
          await router.getAddress(),
          solver.address,
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
      expect(await solbtc.currentStage(tradeId[1])).deep.eq(STAGE.MAKE_PAYMENT);
      expect(await solbtc.pmmSelection(tradeId[1])).deep.eq(
        expectedPMMSelectionInfo,
      );
    });
  });

  describe("makePayment() functional testing", async () => {
    it("Should revert when Solver tries to submit paymentTxId directly", async () => {
      //  Note: Solver or a selected PMM cannot submit payment announcement by calling makePayment() function
      //  Instead, they should call Router contract to submit it
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
      const indexOfTrade: bigint = BigInt(tradeIds.indexOf(tradeId[0]));
      const bundle: CoreTypes.BundlePaymentStruct = {
        tradeIds: tradeIds,
        signedAt: signedAt,
        startIdx: startIdx,
        paymentTxId: paymentTxId[0],
        signature: signature,
      };

      const currentStage = await solbtc.currentStage(tradeId[0]);
      const lastInfo = await solbtc.settledPayment(tradeId[0]);

      await expect(
        solbtc
          .connect(solver)
          .makePayment(solver.address, indexOfTrade, bundle),
      ).to.be.revertedWithCustomError(solbtc, "Unauthorized");

      expect(await solbtc.currentStage(tradeId[0])).deep.eq(currentStage);
      expect(await solbtc.settledPayment(tradeId[0])).deep.eq(lastInfo);
    });

    it("Should revert when a selected PMM tries to submit paymentTxId directly", async () => {
      //  Note: Solver or a selected PMM cannot submit payment announcement by calling makePayment() function
      //  Instead, they should call Router contract to submit it
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
      const indexOfTrade: bigint = BigInt(tradeIds.indexOf(tradeId[0]));
      const bundle: CoreTypes.BundlePaymentStruct = {
        tradeIds: tradeIds,
        signedAt: signedAt,
        startIdx: startIdx,
        paymentTxId: paymentTxId[0],
        signature: signature,
      };

      const currentStage = await solbtc.currentStage(tradeId[0]);
      const lastInfo = await solbtc.settledPayment(tradeId[0]);

      await expect(
        solbtc
          .connect(accounts[0])
          .makePayment(accounts[0].address, indexOfTrade, bundle),
      ).to.be.revertedWithCustomError(solbtc, "Unauthorized");

      expect(await solbtc.currentStage(tradeId[0])).deep.eq(currentStage);
      expect(await solbtc.settledPayment(tradeId[0])).deep.eq(lastInfo);
    });

    it("Should revert when Admin tries to submit paymentTxId directly", async () => {
      //  Note: Solver or a selected PMM cannot submit payment announcement by calling makePayment() function
      //  Instead, they should call Router contract to submit it
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
      const indexOfTrade: bigint = BigInt(tradeIds.indexOf(tradeId[0]));
      const bundle: CoreTypes.BundlePaymentStruct = {
        tradeIds: tradeIds,
        signedAt: signedAt,
        startIdx: startIdx,
        paymentTxId: paymentTxId[0],
        signature: signature,
      };

      const currentStage = await solbtc.currentStage(tradeId[0]);
      const lastInfo = await solbtc.settledPayment(tradeId[0]);

      await expect(
        solbtc.connect(admin).makePayment(solver.address, indexOfTrade, bundle),
      ).to.be.revertedWithCustomError(solbtc, "Unauthorized");

      expect(await solbtc.currentStage(tradeId[0])).deep.eq(currentStage);
      expect(await solbtc.settledPayment(tradeId[0])).deep.eq(lastInfo);
    });

    it("Should succeed when Solver submits paymentTxId via Router", async () => {
      //  Note: Solver or a selected PMM cannot submit payment announcement by calling makePayment() function
      //  Instead, they should call Router contract to submit it
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

      const tx = router.connect(solver).bundlePayment(bundle);

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

      expect(await solbtc.currentStage(tradeId[0])).deep.eq(
        STAGE.CONFIRM_PAYMENT,
      );
      expect(await solbtc.settledPayment(tradeId[0])).deep.eq([
        bundlerHash(tradeIds),
        hexlify(paymentTxId[0]),
        EMPTY_BYTES,
        false,
      ]);
    });

    it("Should succeed when the selected PMM submits paymentTxId via Router", async () => {
      //  Note: Solver or a selected PMM cannot submit payment announcement by calling makePayment() function
      //  Instead, they should call Router contract to submit it
      const startIdx = BigInt(0);
      const tradeIds = [tradeId[1]];
      const signedAt = BigInt(Math.floor(Date.now() / 1000));
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

      const tx = router.connect(accounts[0]).bundlePayment(bundle);

      await expect(tx)
        .to.emit(solbtc, "MadePayment")
        .withArgs(
          await router.getAddress(),
          accounts[0].address,
          tradeId[1],
          hexlify(tradeInfo[1].toChain[1]),
          hexlify(paymentTxId[1]),
          tradeIds,
          startIdx,
        );

      expect(await solbtc.currentStage(tradeId[1])).deep.eq(
        STAGE.CONFIRM_PAYMENT,
      );
      expect(await solbtc.settledPayment(tradeId[1])).deep.eq([
        bundlerHash(tradeIds),
        hexlify(paymentTxId[1]),
        EMPTY_BYTES,
        false,
      ]);
    });
  });

  describe("confirmPayment() functional testing", async () => {
    it("Should revert when MPC Nodes try to submit payment confirmation directly", async () => {
      //  Note: Authorized MPC Nodes cannot submit payment confirmation by call confirmPayment() directly
      //  Instead, they should call Router contract to submit it
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

      const currentStage = await solbtc.currentStage(tradeId[0]);
      const lastInfo = await solbtc.settledPayment(tradeId[0]);

      await expect(
        solbtc
          .connect(mpcNode1)
          .confirmPayment(mpcNode1.address, tradeId[0], signature),
      ).to.be.revertedWithCustomError(solbtc, "Unauthorized");

      expect(await solbtc.currentStage(tradeId[0])).deep.eq(currentStage);
      expect(await solbtc.settledPayment(tradeId[0])).deep.eq(lastInfo);
    });

    it("Should revert when Admin tries to submit payment confirmation directly", async () => {
      //  Note: Authorized MPC Nodes cannot submit payment confirmation by call confirmPayment() directly
      //  Instead, they should call Router contract to submit it
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

      const currentStage = await solbtc.currentStage(tradeId[0]);
      const lastInfo = await solbtc.settledPayment(tradeId[0]);

      await expect(
        solbtc
          .connect(admin)
          .confirmPayment(mpcNode1.address, tradeId[0], signature),
      ).to.be.revertedWithCustomError(solbtc, "Unauthorized");

      expect(await solbtc.currentStage(tradeId[0])).deep.eq(currentStage);
      expect(await solbtc.settledPayment(tradeId[0])).deep.eq(lastInfo);
    });

    it("Should succeed when MPC submits a payment confirmation", async () => {
      //  Note: Authorized MPC Nodes cannot submit payment confirmation by call confirmPayment() directly
      //  Instead, they should call Router contract to submit it
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
        .to.emit(solbtc, "PaymentConfirmed")
        .withArgs(
          await router.getAddress(),
          mpcL2.address,
          tradeId[0],
          hexlify(paymentTxId[0]),
        );

      expect(await solbtc.currentStage(tradeId[0])).deep.eq(
        STAGE.CONFIRM_SETTLEMENT,
      );
      expect(await solbtc.settledPayment(tradeId[0])).deep.eq([
        bundlerHash([tradeId[0]]),
        hexlify(paymentTxId[0]),
        EMPTY_BYTES,
        true,
      ]);
    });

    it("Should succeed when MPC submits another payment confirmation", async () => {
      //  Note: Authorized MPC Nodes cannot submit payment confirmation by call confirmPayment() directly
      //  Instead, they should call Router contract to submit it
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

      const tx = router.connect(mpcNode1).confirmPayment(tradeId[1], signature);

      await expect(tx)
        .to.emit(solbtc, "PaymentConfirmed")
        .withArgs(
          await router.getAddress(),
          mpcL2.address,
          tradeId[1],
          hexlify(paymentTxId[1]),
        );

      expect(await solbtc.currentStage(tradeId[1])).deep.eq(
        STAGE.CONFIRM_SETTLEMENT,
      );
      expect(await solbtc.settledPayment(tradeId[1])).deep.eq([
        bundlerHash([tradeId[1]]),
        hexlify(paymentTxId[1]),
        EMPTY_BYTES,
        true,
      ]);
    });
  });

  describe("confirmSettlement() functional testing", async () => {
    it("Should revert when MPC Nodes try to submit settlement confirmation directly", async () => {
      //  Note: Authorized MPC Nodes cannot submit settlement confirmation by call confirmSettlement() directly
      //  Instead, they should call Router contract to submit it
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

      const currentStage = await solbtc.currentStage(tradeId[0]);
      const lastInfo = await solbtc.settledPayment(tradeId[0]);

      await expect(
        solbtc
          .connect(mpcNode1)
          .confirmSettlement(
            mpcNode1.address,
            tradeId[0],
            releaseTxId[0],
            signature,
          ),
      ).to.be.revertedWithCustomError(solbtc, "Unauthorized");

      expect(await solbtc.currentStage(tradeId[0])).deep.eq(currentStage);
      expect(await solbtc.settledPayment(tradeId[0])).deep.eq(lastInfo);
    });

    it("Should revert when Admin tries to submit settlement confirmation directly", async () => {
      //  Note: Authorized MPC Nodes cannot submit settlement confirmation by call confirmSettlement() directly
      //  Instead, they should call Router contract to submit it
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

      const currentStage = await solbtc.currentStage(tradeId[0]);
      const lastInfo = await solbtc.settledPayment(tradeId[0]);

      await expect(
        solbtc
          .connect(solver)
          .confirmSettlement(
            mpcNode1.address,
            tradeId[0],
            releaseTxId[0],
            signature,
          ),
      ).to.be.revertedWithCustomError(solbtc, "Unauthorized");

      expect(await solbtc.currentStage(tradeId[0])).deep.eq(currentStage);
      expect(await solbtc.settledPayment(tradeId[0])).deep.eq(lastInfo);
    });

    it("Should succeed when MPC Nodes submit settlement confirmation via Router", async () => {
      //  Note: Authorized MPC Nodes cannot submit settlement confirmation by call confirmSettlement() directly
      //  Instead, they should call Router contract to submit it
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
        .to.emit(solbtc, "SettlementConfirmed")
        .withArgs(
          await router.getAddress(),
          mpcL2.address,
          tradeId[0],
          hexlify(releaseTxId[0]),
        );

      expect(await solbtc.currentStage(tradeId[0])).deep.eq(STAGE.COMPLETE);
      expect(await solbtc.settledPayment(tradeId[0])).deep.eq([
        bundlerHash([tradeId[0]]),
        hexlify(paymentTxId[0]),
        hexlify(releaseTxId[0]),
        true,
      ]);
    });

    it("Should succeed when MPC Nodes submit another settlement confirmation via Router", async () => {
      //  Note: Authorized MPC Nodes cannot submit settlement confirmation by call confirmSettlement() directly
      //  Instead, they should call Router contract to submit it
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
        .connect(mpcNode1)
        .confirmSettlement(tradeId[1], releaseTxId[1], signature);

      await expect(tx)
        .to.emit(solbtc, "SettlementConfirmed")
        .withArgs(
          await router.getAddress(),
          mpcL2.address,
          tradeId[1],
          hexlify(releaseTxId[1]),
        );

      expect(await solbtc.currentStage(tradeId[1])).deep.eq(STAGE.COMPLETE);
      expect(await solbtc.settledPayment(tradeId[1])).deep.eq([
        bundlerHash([tradeId[1]]),
        hexlify(paymentTxId[1]),
        hexlify(releaseTxId[1]),
        true,
      ]);
    });
  });
});
