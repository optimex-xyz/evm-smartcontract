import { expect } from "chai";
import { ethers, network } from "hardhat";
import {
  AbiCoder,
  BytesLike,
  hexlify,
  keccak256,
  parseUnits,
  toUtf8Bytes,
  TypedDataDomain,
  Wallet,
  ZeroAddress,
  ZeroHash,
} from "ethers";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";
import { HardhatEthersProvider } from "@nomicfoundation/hardhat-ethers/internal/hardhat-ethers-provider";
import { Keypair } from "@solana/web3.js";

import {
  Management,
  Management__factory,
  BTCSOL,
  BTCSOL__factory,
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
  getPresigns,
  getRFQInfo,
  getScriptInfo,
  getTradeInfo,
} from "../sample-data/btcsol";
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
const EMPTY_SETTLED_PAYMENT = [ZeroHash, EMPTY_BYTES, EMPTY_BYTES, false];

function bundlerHash(tradeIds: BytesLike[]): string {
  return keccak256(abiCoder.encode(["bytes32[]"], [tradeIds]));
}

async function getBlockTimestamp(provider: HardhatEthersProvider) {
  const block = await provider.getBlockNumber();
  const timestamp = (await provider.getBlock(block))?.timestamp as number;

  return timestamp;
}

describe("BTCSOL Contract Testing", () => {
  let admin: HardhatEthersSigner, solver: HardhatEthersSigner, mpc: Wallet;
  let mpcNode1: HardhatEthersSigner, mpcNode2: HardhatEthersSigner;
  let accounts: HardhatEthersSigner[];
  let user: Keypair;

  let management: Management;
  let btcsol: BTCSOL, signerHelper: SignerHelper;
  let router: Router, clone: Router;

  let btcTokenInfo: ManagementTypes.TokenInfoStruct,
    solTokenInfo: ManagementTypes.TokenInfoStruct;

  let tradeInfo: CoreTypes.TradeInfoStruct;
  let affiliateInfo: CoreTypes.AffiliateStruct;
  let rfqInfo: CoreTypes.RFQInfoStruct;
  let scriptInfo: CoreTypes.ScriptInfoStruct;
  let presigns: CoreTypes.PresignStruct[];
  let tradeId: string, amountOut: bigint, sessionId: bigint;
  let ephemeralL2Wallet: Wallet;
  let domain: TypedDataDomain;

  const pFeeRate: bigint = BigInt(50);
  const paymentTxId = randomTxId();
  const releaseTxId = randomTxId();
  const toChain = "solana-devnet";
  const toToken = "So11111111111111111111111111111111111111112"; // Wrapped SOL on Solana

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

    //  Deploy BTCSOL contract
    const BTCSOL = (await ethers.getContractFactory(
      "BTCSOL",
      admin,
    )) as BTCSOL__factory;
    btcsol = await BTCSOL.deploy(await router.getAddress());

    //  set `maxAffiliateFeeRate`
    await btcsol.connect(admin).setMaxAffiliateFeeRate(MAX_AFFILIATE_FEE_RATE);

    //  Whitelist Solver and MPC Node associated accounts
    await management.connect(admin).setSolver(solver.address, true);
    await management.connect(admin).setMPCNode(mpcNode1.address, true);
    await management.connect(admin).setMPCNode(mpcNode2.address, true);

    //  Generate MPC Wallet
    const mpcPrivkey = hexlify(testMPCKP.privateKey as Uint8Array);
    mpc = new Wallet(mpcPrivkey, provider);

    //  Prepare trade data
    sessionId = BigInt(keccak256(toUtf8Bytes(crypto.randomUUID())));
    tradeInfo = getTradeInfo(toChain, toToken, user.publicKey.toString());
    affiliateInfo = getAffiliateInfo();
    rfqInfo = getRFQInfo();
    tradeId = getTradeId(sessionId, solver.address, tradeInfo);
    let { scriptInfo: info, ephemeralL2Key } = getScriptInfo(
      tradeId,
      Number(rfqInfo.tradeTimeout),
    );
    scriptInfo = structuredClone(info);
    ephemeralL2Wallet = new Wallet(ephemeralL2Key, provider);
    presigns = getPresigns();

    btcTokenInfo = {
      info: [
        tradeInfo.fromChain[2], // tokenId
        tradeInfo.fromChain[1], // networkId
        toUtf8Bytes("BTC"), // symbol
        toUtf8Bytes("https://example.com"),
        toUtf8Bytes("Bitcoin (BTC) - Bitcoin Testnet Token"),
      ],
      decimals: BigInt(8),
    };

    solTokenInfo = {
      info: [
        tradeInfo.toChain[2], // tokenId
        tradeInfo.toChain[1], // networkId
        toUtf8Bytes("SOL"), // symbol
        toUtf8Bytes(
          "https://explorer.solana.com/address/So11111111111111111111111111111111111111112?cluster=devnet",
        ),
        toUtf8Bytes("Wrapped SOL (SOL) - Wrapped SOL on Solana Devnet"),
      ],
      decimals: BigInt(9),
    };

    //  generate eip-712 domain
    domain = await getEIP712Domain(await signerHelper.getAddress(), admin);

    //  Set `fromNetworkId` and `toNetworkId` in the Management
    //  Note: `networkId` is registered if and only if
    //  there's at least one Token being supported
    await management.connect(admin).setToken(btcTokenInfo);
    await management.connect(admin).setToken(solTokenInfo);
    await router
      .connect(admin)
      .setRoute(
        await btcsol.getAddress(),
        tradeInfo.fromChain[1],
        tradeInfo.toChain[1],
      );

    // set PMM
    await management
      .connect(admin)
      .setPMM(presigns[0].pmmId, accounts[0].address);
    await management
      .connect(admin)
      .setPMM(presigns[1].pmmId, accounts[1].address);

    //  set MPC Pubkey
    const mpcInfo: ManagementTypes.MPCInfoStruct = {
      mpcL2Address: mpc.address,
      expireTime: MAX_UINT64,
      mpcAssetPubkey: mpc.signingKey.compressedPublicKey,
      mpcL2Pubkey: mpc.signingKey.compressedPublicKey, //  For Bitcoin, `mpcAssetPubkey` = `mpcL2Pubkey`
    };
    const prevExpireTime = BigInt(0);
    await management
      .connect(admin)
      .setMPCInfo(tradeInfo.fromChain[1], mpcInfo, prevExpireTime);
  });

  it("Should be able to check the initialized settings of btcsol contract", async () => {
    expect(await btcsol.router()).deep.equal(await router.getAddress());
    expect(await btcsol.typeOfHandler()).deep.eq("BTCSOL");
  });

  describe("setRouter() functional testing", async () => {
    it("Should revert when Unauthorized client, a arbitrary account, tries to update new Router contract", async () => {
      expect(await btcsol.router()).deep.equal(await router.getAddress());

      await expect(
        btcsol.connect(accounts[0]).setRouter(accounts[0].address),
      ).to.be.revertedWithCustomError(btcsol, "Unauthorized");

      expect(await btcsol.router()).deep.equal(await router.getAddress());
    });

    it("Should revert when Unauthorized client, the Solver account, tries to update new Router contract", async () => {
      expect(await btcsol.router()).deep.equal(await router.getAddress());

      await expect(
        btcsol.connect(solver).setRouter(solver.address),
      ).to.be.revertedWithCustomError(btcsol, "Unauthorized");

      expect(await btcsol.router()).deep.equal(await router.getAddress());
    });

    it("Should revert when Unauthorized client, the MPC account, tries to update new Router contract", async () => {
      expect(await btcsol.router()).deep.equal(await router.getAddress());

      await expect(
        btcsol.connect(mpc).setRouter(mpc.address),
      ).to.be.revertedWithCustomError(btcsol, "Unauthorized");

      expect(await btcsol.router()).deep.equal(await router.getAddress());
    });

    it("Should revert when Owner updates 0x0 as a new address of Router contract", async () => {
      expect(await btcsol.router()).deep.equal(await router.getAddress());

      await expect(
        btcsol.connect(admin).setRouter(ZeroAddress),
      ).to.be.revertedWithCustomError(btcsol, "AddressZero");

      expect(await btcsol.router()).deep.equal(await router.getAddress());
    });

    it("Should succeed when Owner updates a new address of Router contract", async () => {
      expect(await btcsol.router()).deep.equal(await router.getAddress());

      await btcsol.connect(admin).setRouter(await clone.getAddress());

      expect(await btcsol.router()).deep.equal(await clone.getAddress());
    });

    it("Should succeed when Owner changes back to previous Router contract", async () => {
      expect(await btcsol.router()).deep.equal(await clone.getAddress());

      await btcsol.connect(admin).setRouter(await router.getAddress());

      expect(await btcsol.router()).deep.equal(await router.getAddress());
    });
  });

  describe("submitTrade() functional testing", async () => {
    it("Should revert when Solver tries to submit trade data directly", async () => {
      //  Note: Solver cannot submit trade data and presigns directly
      //  by calling submitTrade() function
      //  Instead, Solver should call Router contract to submit trade data.
      const tradeData: CoreTypes.TradeDataStruct = {
        sessionId: sessionId,
        tradeInfo: tradeInfo,
        scriptInfo: scriptInfo,
      };

      await expect(
        btcsol
          .connect(solver)
          .submitTrade(
            solver.address,
            tradeId,
            tradeData,
            affiliateInfo,
            presigns,
          ),
      ).to.be.revertedWithCustomError(btcsol, "Unauthorized");

      expect(await btcsol.currentStage(tradeId)).deep.eq(STAGE.SUBMIT);
      expect(await btcsol.trade(tradeId)).deep.eq(EMPTY_TRADE_DATA);
      expect(await btcsol.presign(tradeId)).deep.eq(EMPTY_PRESIGNS);
      expect(await btcsol.feeDetails(tradeId)).deep.eq(EMPTY_FEE_DETAILS);
      expect(await btcsol.affiliate(tradeId)).deep.eq(EMPTY_AFFILIATE_INFO);
    });

    it("Should revert when Admin tries to submit trade data directly", async () => {
      //  Note: Solver cannot submit trade data and presigns directly
      //  by calling submitTrade() function
      //  Instead, Solver should call Router contract to submit trade data.
      const tradeData: CoreTypes.TradeDataStruct = {
        sessionId: sessionId,
        tradeInfo: tradeInfo,
        scriptInfo: scriptInfo,
      };

      await expect(
        btcsol
          .connect(admin)
          .submitTrade(
            solver.address,
            tradeId,
            tradeData,
            affiliateInfo,
            presigns,
          ),
      ).to.be.revertedWithCustomError(btcsol, "Unauthorized");

      expect(await btcsol.currentStage(tradeId)).deep.eq(STAGE.SUBMIT);
      expect(await btcsol.trade(tradeId)).deep.eq(EMPTY_TRADE_DATA);
      expect(await btcsol.presign(tradeId)).deep.eq(EMPTY_PRESIGNS);
      expect(await btcsol.feeDetails(tradeId)).deep.eq(EMPTY_FEE_DETAILS);
      expect(await btcsol.affiliate(tradeId)).deep.eq(EMPTY_AFFILIATE_INFO);
    });

    it("Should succeed when Solver submits trade data via Router", async () => {
      //  Note: Solver cannot submit trade data and presigns directly
      //  by calling submitTrade() function
      //  Instead, Solver should call Router contract to submit trade data.
      const tradeData: CoreTypes.TradeDataStruct = {
        sessionId: sessionId,
        tradeInfo: tradeInfo,
        scriptInfo: scriptInfo,
      };

      const tx = router
        .connect(solver)
        .submitTrade(tradeId, tradeData, affiliateInfo, presigns);

      await expect(tx)
        .to.emit(btcsol, "TradeInfoSubmitted")
        .withArgs(
          await router.getAddress(), // forwarder
          solver.address, // requester
          tradeId,
          tradeInfo.fromChain[1], //  fromChain
          scriptInfo.depositInfo[1], // depositTxId
        );

      const expectedTradeData = [
        sessionId,
        //  tradeInfo
        [
          tradeInfo.amountIn,
          tradeInfo.fromChain.map((data) => hexlify(data)),
          tradeInfo.toChain.map((data) => hexlify(data)),
        ],
        //  scriptInfo
        [
          scriptInfo.depositInfo.map((data) => hexlify(data)), //  depositInfo
          scriptInfo.userEphemeralL2Address, //  userEphemeralL2Address
          scriptInfo.scriptTimeout, //  scriptTimeout
        ],
      ];
      const expectedPresigns = [
        [
          presigns[0].pmmId,
          hexlify(presigns[0].pmmRecvAddress),
          [hexlify(presigns[0].presigns[0])],
        ],
        [
          presigns[1].pmmId,
          hexlify(presigns[1].pmmRecvAddress),
          [hexlify(presigns[1].presigns[0])],
        ],
      ];

      expect(await btcsol.currentStage(tradeId)).deep.eq(STAGE.CONFIRM_DEPOSIT);
      expect(await btcsol.trade(tradeId)).deep.eq(
        Object.values(expectedTradeData),
      );
      expect(await btcsol.presign(tradeId)).deep.eq(
        Object.values(expectedPresigns),
      );
      expect(await btcsol.feeDetails(tradeId)).deep.eq([
        BigInt(0),
        BigInt(0), // pFeeAmount
        BigInt(0), // aFeeAmount
        pFeeRate,
        affiliateInfo.aggregatedValue, //  aFeeRate
      ]);
      expect(await btcsol.affiliate(tradeId)).deep.eq(
        Object.values(affiliateInfo),
      );
    });
  });

  describe("confirmDeposit() functional testing", async () => {
    it("Should revert when MPC Nodes try to submit a deposit confirmation directly", async () => {
      //  Note: Authorized MPC Nodes cannot submit a deposit confirmation directly
      //  by calling confirmDeposit() function
      //  Instead, MPC Nodes should call Router contract to submit the confirmation
      const amountIn = tradeInfo.amountIn as bigint;
      const depositedFromList: BytesLike[] = [
        toUtf8Bytes("Bitcoin_Account_1"),
        toUtf8Bytes("Bitcoin_Account_2"),
        toUtf8Bytes("Bitcoin_Account_3"),
      ];
      const infoHash: string = getDepositConfirmationHash(
        amountIn,
        tradeInfo.fromChain,
        scriptInfo.depositInfo[1],
        depositedFromList,
      );
      const signature: string = await getSignature(
        mpc,
        tradeId,
        infoHash,
        SignatureType.ConfirmDeposit,
        domain,
      );

      const currentStage = await btcsol.currentStage(tradeId);
      const lastInfo = await btcsol.depositAddressList(tradeId);

      await expect(
        btcsol
          .connect(mpcNode1)
          .confirmDeposit(
            mpcNode1.address,
            tradeId,
            signature,
            depositedFromList,
          ),
      ).to.be.revertedWithCustomError(btcsol, "Unauthorized");

      expect(await btcsol.currentStage(tradeId)).deep.eq(currentStage);
      expect(await btcsol.depositAddressList(tradeId)).deep.eq(lastInfo);
    });

    it("Should revert when Admin tries to submit a deposit confirmation directly", async () => {
      //  Note: Authorized MPC Nodes cannot submit a deposit confirmation directly
      //  by calling confirmDeposit() function
      //  Instead, MPC Nodes should call Router contract to submit the confirmation
      const amountIn = tradeInfo.amountIn as bigint;
      const depositedFromList: BytesLike[] = [
        toUtf8Bytes("Bitcoin_Account_1"),
        toUtf8Bytes("Bitcoin_Account_2"),
        toUtf8Bytes("Bitcoin_Account_3"),
      ];
      const infoHash: string = getDepositConfirmationHash(
        amountIn,
        tradeInfo.fromChain,
        scriptInfo.depositInfo[1],
        depositedFromList,
      );
      const signature: string = await getSignature(
        mpc,
        tradeId,
        infoHash,
        SignatureType.ConfirmDeposit,
        domain,
      );

      const currentStage = await btcsol.currentStage(tradeId);
      const lastInfo = await btcsol.depositAddressList(tradeId);

      await expect(
        btcsol
          .connect(admin)
          .confirmDeposit(
            mpcNode1.address,
            tradeId,
            signature,
            depositedFromList,
          ),
      ).to.be.revertedWithCustomError(btcsol, "Unauthorized");

      expect(await btcsol.currentStage(tradeId)).deep.eq(currentStage);
      expect(await btcsol.depositAddressList(tradeId)).deep.eq(lastInfo);
    });

    it("Should succeed when MPC Nodes submit a deposit confirmation via Router", async () => {
      //  Note: Authorized MPC Nodes cannot submit a deposit confirmation directly
      //  by calling confirmDeposit() function
      //  Instead, MPC Nodes should call Router contract to submit the confirmation
      const amountIn = tradeInfo.amountIn as bigint;
      const depositedFromList: BytesLike[] = [
        toUtf8Bytes("Bitcoin_Account_1"),
        toUtf8Bytes("Bitcoin_Account_2"),
        toUtf8Bytes("Bitcoin_Account_3"),
      ];
      const infoHash = getDepositConfirmationHash(
        amountIn,
        tradeInfo.fromChain,
        scriptInfo.depositInfo[1],
        depositedFromList,
      );
      const signature: string = await getSignature(
        mpc,
        tradeId,
        infoHash,
        SignatureType.ConfirmDeposit,
        domain,
      );

      const tx = router
        .connect(mpcNode1)
        .confirmDeposit(tradeId, signature, depositedFromList);

      await expect(tx)
        .to.emit(btcsol, "DepositConfirmed")
        .withArgs(
          await router.getAddress(),
          mpc.address,
          tradeId,
          (affiliateInfo.aggregatedValue as bigint) + pFeeRate, //  total fee rate
        );

      const expectedList = depositedFromList.map((data) => hexlify(data));
      expect(await btcsol.currentStage(tradeId)).deep.eq(STAGE.SELECT_PMM);
      expect(await btcsol.depositAddressList(tradeId)).deep.eq(expectedList);
    });
  });

  describe("selectPMM() functional testing", async () => {
    it("Should revert when Solver tries to submit pmm selection directly", async () => {
      //  Note: Solver cannot submit a pmm selection directly by calling selectPMM() function
      //  Instead, Solver should call Router contract to submit the selection info
      const timestamp = await getBlockTimestamp(provider);
      const expiry = BigInt(timestamp + 30 * 60);
      amountOut =
        (rfqInfo.minAmountOut as bigint) + parseUnits("5000", decimals);
      const selectedPMMId = presigns[0].pmmId;
      const pmmRecvAddress = presigns[0].pmmRecvAddress;
      const selectedPMMInfoHash: string = getSelectPMMHash(
        selectedPMMId,
        pmmRecvAddress,
        tradeInfo.toChain[1],
        tradeInfo.toChain[2],
        amountOut,
        expiry,
      );
      let signature: string = await getSignature(
        accounts[0],
        tradeId,
        selectedPMMInfoHash,
        SignatureType.SelectPMM,
        domain,
      );
      const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
      const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
        amountOut: amountOut,
        selectedPMMId: selectedPMMId,
        info: info,
        sigExpiry: expiry,
      };

      //  RFQ Info
      const rfqInfoHash: string = getRFQHash(
        rfqInfo.minAmountOut as bigint,
        rfqInfo.tradeTimeout as bigint,
        affiliateInfo,
      );
      signature = await getSignature(
        ephemeralL2Wallet,
        tradeId,
        rfqInfoHash,
        SignatureType.RFQ,
        domain,
      );
      rfqInfo.rfqInfoSignature = signature;

      //  PMM Selection Info: Selected PMM Info + RFQ Info
      const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
        rfqInfo: rfqInfo,
        pmmInfo: pmmInfo,
      };

      const currentStage = await btcsol.currentStage(tradeId);
      const lastSelection = await btcsol.pmmSelection(tradeId);
      const lastDetails = await btcsol.feeDetails(tradeId);

      await expect(
        btcsol
          .connect(solver)
          .selectPMM(solver.address, tradeId, pmmSelectionInfo),
      ).to.be.revertedWithCustomError(btcsol, "Unauthorized");

      expect(await btcsol.currentStage(tradeId)).deep.eq(currentStage);
      expect(await btcsol.pmmSelection(tradeId)).deep.eq(lastSelection);
      expect(await btcsol.feeDetails(tradeId)).deep.eq(lastDetails);
    });

    it("Should revert when Admin tries to submit a pmm selection directly", async () => {
      //  Note: Solver cannot submit a pmm selection directly by calling selectPMM() function
      //  Instead, Solver should call Router contract to submit the selection info
      const timestamp = await getBlockTimestamp(provider);
      const expiry = BigInt(timestamp + 30 * 60);
      amountOut =
        (rfqInfo.minAmountOut as bigint) + parseUnits("5000", decimals);
      const selectedPMMId = presigns[0].pmmId;
      const pmmRecvAddress = presigns[0].pmmRecvAddress;
      const selectedPMMInfoHash: string = getSelectPMMHash(
        selectedPMMId,
        pmmRecvAddress,
        tradeInfo.toChain[1],
        tradeInfo.toChain[2],
        amountOut,
        expiry,
      );
      let signature: string = await getSignature(
        accounts[0],
        tradeId,
        selectedPMMInfoHash,
        SignatureType.SelectPMM,
        domain,
      );
      const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
      const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
        amountOut: amountOut,
        selectedPMMId: selectedPMMId,
        info: info,
        sigExpiry: expiry,
      };

      //  RFQ Info
      const rfqInfoHash: string = getRFQHash(
        rfqInfo.minAmountOut as bigint,
        rfqInfo.tradeTimeout as bigint,
        affiliateInfo,
      );
      signature = await getSignature(
        ephemeralL2Wallet,
        tradeId,
        rfqInfoHash,
        SignatureType.RFQ,
        domain,
      );
      rfqInfo.rfqInfoSignature = signature;

      //  PMM Selection Info: Selected PMM Info + RFQ Info
      const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
        rfqInfo: rfqInfo,
        pmmInfo: pmmInfo,
      };

      const currentStage = await btcsol.currentStage(tradeId);
      const lastSelection = await btcsol.pmmSelection(tradeId);
      const lastDetails = await btcsol.feeDetails(tradeId);

      await expect(
        btcsol
          .connect(admin)
          .selectPMM(solver.address, tradeId, pmmSelectionInfo),
      ).to.be.revertedWithCustomError(btcsol, "Unauthorized");

      expect(await btcsol.currentStage(tradeId)).deep.eq(currentStage);
      expect(await btcsol.pmmSelection(tradeId)).deep.eq(lastSelection);
      expect(await btcsol.feeDetails(tradeId)).deep.eq(lastDetails);
    });

    it("Should succeed when Solver submits a pmm selection via Router", async () => {
      //  Note: Solver cannot submit a pmm selection directly by calling selectPMM() function
      //  Instead, Solver should call Router contract to submit the selection info
      const timestamp = await getBlockTimestamp(provider);
      const expiry = BigInt(timestamp + 30 * 60);
      amountOut =
        (rfqInfo.minAmountOut as bigint) + parseUnits("50000", decimals);
      const selectedPMMId = presigns[0].pmmId;
      const pmmRecvAddress = presigns[0].pmmRecvAddress;
      const selectedPMMInfoHash: string = getSelectPMMHash(
        selectedPMMId,
        pmmRecvAddress,
        tradeInfo.toChain[1],
        tradeInfo.toChain[2],
        amountOut,
        expiry,
      );
      let signature: string = await getSignature(
        accounts[0],
        tradeId,
        selectedPMMInfoHash,
        SignatureType.SelectPMM,
        domain,
      );
      const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
      const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
        amountOut: amountOut,
        selectedPMMId: selectedPMMId,
        info: info,
        sigExpiry: expiry,
      };

      //  RFQ Info
      const rfqInfoHash: string = getRFQHash(
        rfqInfo.minAmountOut as bigint,
        rfqInfo.tradeTimeout as bigint,
        affiliateInfo,
      );
      signature = await getSignature(
        ephemeralL2Wallet,
        tradeId,
        rfqInfoHash,
        SignatureType.RFQ,
        domain,
      );
      rfqInfo.rfqInfoSignature = signature;

      //  PMM Selection Info: Selected PMM Info + RFQ Info
      const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
        rfqInfo: rfqInfo,
        pmmInfo: pmmInfo,
      };
      const pFeeAmount = (pFeeRate * amountOut) / DENOM;
      const aFeeAmount =
        ((affiliateInfo.aggregatedValue as bigint) * amountOut) / DENOM;

      const tx = router.connect(solver).selectPMM(tradeId, pmmSelectionInfo);

      await expect(tx)
        .to.emit(btcsol, "SelectedPMM")
        .withArgs(
          await router.getAddress(),
          solver.address,
          tradeId,
          pmmSelectionInfo.pmmInfo.selectedPMMId,
        );

      const expectedPMMSelectionInfo = [
        [rfqInfo.minAmountOut, rfqInfo.tradeTimeout, rfqInfo.rfqInfoSignature],
        [
          pmmInfo.amountOut,
          pmmInfo.selectedPMMId,
          [hexlify(info[0]), hexlify(info[1])],
          pmmInfo.sigExpiry,
        ],
      ];
      expect(await btcsol.currentStage(tradeId)).deep.eq(STAGE.MAKE_PAYMENT);
      expect(await btcsol.pmmSelection(tradeId)).deep.eq(
        expectedPMMSelectionInfo,
      );
      expect(await btcsol.feeDetails(tradeId)).deep.eq([
        pFeeAmount + aFeeAmount, //  totalAmount
        pFeeAmount,
        aFeeAmount,
        pFeeRate,
        affiliateInfo.aggregatedValue,
      ]);
    });
  });

  describe("makePayment() functional testing", async () => {
    it("Should revert when Solver tries to submit paymentTxId directly", async () => {
      //  Note: Solver or a selected PMM cannot submit payment announcement by calling makePayment() function
      //  Instead, they should call Router contract to submit it
      const startIdx = BigInt(0);
      const tradeIds = [tradeId];
      const signedAt = BigInt(Math.floor(Date.now() / 1000));
      const infoHash: string = getMakePaymentHash(
        tradeIds,
        signedAt,
        startIdx,
        paymentTxId,
      );
      const signature = await getSignature(
        accounts[0],
        tradeId,
        infoHash,
        SignatureType.MakePayment,
        domain,
      );
      const indexOfTrade: bigint = BigInt(tradeIds.indexOf(tradeId));
      const bundle: CoreTypes.BundlePaymentStruct = {
        tradeIds: tradeIds,
        signedAt: signedAt,
        startIdx: startIdx,
        paymentTxId: paymentTxId,
        signature: signature,
      };

      const currentStage = await btcsol.currentStage(tradeId);
      const lastInfo = await btcsol.settledPayment(tradeId);

      await expect(
        btcsol
          .connect(solver)
          .makePayment(solver.address, indexOfTrade, bundle),
      ).to.be.revertedWithCustomError(btcsol, "Unauthorized");

      expect(await btcsol.currentStage(tradeId)).deep.eq(currentStage);
      expect(await btcsol.settledPayment(tradeId)).deep.eq(lastInfo);
    });

    it("Should revert when a selected PMM tries to submit paymentTxId directly", async () => {
      //  Note: Solver or a selected PMM cannot submit payment announcement by calling makePayment() function
      //  Instead, they should call Router contract to submit it
      const startIdx = BigInt(0);
      const tradeIds = [tradeId];
      const signedAt = BigInt(Math.floor(Date.now() / 1000));
      const infoHash: string = getMakePaymentHash(
        tradeIds,
        signedAt,
        startIdx,
        paymentTxId,
      );
      const signature = await getSignature(
        accounts[0],
        tradeId,
        infoHash,
        SignatureType.MakePayment,
        domain,
      );
      const indexOfTrade: bigint = BigInt(tradeIds.indexOf(tradeId));
      const bundle: CoreTypes.BundlePaymentStruct = {
        tradeIds: tradeIds,
        signedAt: signedAt,
        startIdx: startIdx,
        paymentTxId: paymentTxId,
        signature: signature,
      };

      const currentStage = await btcsol.currentStage(tradeId);
      const lastInfo = await btcsol.settledPayment(tradeId);

      await expect(
        btcsol
          .connect(accounts[0])
          .makePayment(accounts[0].address, indexOfTrade, bundle),
      ).to.be.revertedWithCustomError(btcsol, "Unauthorized");

      expect(await btcsol.currentStage(tradeId)).deep.eq(currentStage);
      expect(await btcsol.settledPayment(tradeId)).deep.eq(lastInfo);
    });

    it("Should revert when Admin tries to submit paymentTxId directly", async () => {
      //  Note: Solver or a selected PMM cannot submit payment announcement by calling makePayment() function
      //  Instead, they should call Router contract to submit it
      const startIdx = BigInt(0);
      const tradeIds = [tradeId];
      const signedAt = BigInt(Math.floor(Date.now() / 1000));
      const infoHash: string = getMakePaymentHash(
        tradeIds,
        signedAt,
        startIdx,
        paymentTxId,
      );
      const signature = await getSignature(
        accounts[0],
        tradeId,
        infoHash,
        SignatureType.MakePayment,
        domain,
      );
      const indexOfTrade: bigint = BigInt(tradeIds.indexOf(tradeId));
      const bundle: CoreTypes.BundlePaymentStruct = {
        tradeIds: tradeIds,
        signedAt: signedAt,
        startIdx: startIdx,
        paymentTxId: paymentTxId,
        signature: signature,
      };

      const currentStage = await btcsol.currentStage(tradeId);
      const lastInfo = await btcsol.settledPayment(tradeId);

      await expect(
        btcsol
          .connect(admin)
          .makePayment(accounts[0].address, indexOfTrade, bundle),
      ).to.be.revertedWithCustomError(btcsol, "Unauthorized");

      expect(await btcsol.currentStage(tradeId)).deep.eq(currentStage);
      expect(await btcsol.settledPayment(tradeId)).deep.eq(lastInfo);
    });

    it("Should succeed when the selected PMM submits paymentTxId via Router", async () => {
      const startIdx = BigInt(0);
      const tradeIds = [tradeId];
      const signedAt = BigInt(Math.floor(Date.now() / 1000));
      const infoHash: string = getMakePaymentHash(
        tradeIds,
        signedAt,
        startIdx,
        paymentTxId,
      );
      const signature = await getSignature(
        accounts[0],
        tradeId,
        infoHash,
        SignatureType.MakePayment,
        domain,
      );
      const bundle: CoreTypes.BundlePaymentStruct = {
        tradeIds: tradeIds,
        signedAt: signedAt,
        startIdx: startIdx,
        paymentTxId: paymentTxId,
        signature: signature,
      };

      expect(await btcsol.currentStage(tradeId)).deep.eq(3);
      expect(await btcsol.settledPayment(tradeId)).deep.eq(
        EMPTY_SETTLED_PAYMENT,
      );

      const tx = router.connect(accounts[0]).bundlePayment(bundle);

      await expect(tx)
        .to.emit(btcsol, "MadePayment")
        .withArgs(
          await router.getAddress(),
          accounts[0].address,
          tradeId,
          hexlify(tradeInfo.toChain[1]),
          hexlify(paymentTxId),
          tradeIds,
          startIdx,
        );

      expect(await btcsol.currentStage(tradeId)).deep.eq(STAGE.CONFIRM_PAYMENT);
      expect(await btcsol.settledPayment(tradeId)).deep.eq([
        bundlerHash(tradeIds),
        hexlify(paymentTxId),
        EMPTY_BYTES,
        false,
      ]);
    });
  });

  describe("confirmPayment() functional testing", async () => {
    it("Should revert when MPC Nodes try to submit payment confirmation directly", async () => {
      //  Note: Authorized MPC Nodes cannot submit payment confirmation by call confirmPayment() directly
      //  Instead, they should call Router contract to submit it
      const pFeeAmount: bigint = (amountOut * pFeeRate) / DENOM;
      const aFeeAmount: bigint =
        ((affiliateInfo.aggregatedValue as bigint) * amountOut) / DENOM;
      const totalAmount: bigint = pFeeAmount + aFeeAmount;
      const paymentAmount: bigint = amountOut - totalAmount;
      const infoHash = getConfirmPaymentHash(
        totalAmount,
        paymentAmount,
        tradeInfo.toChain,
        paymentTxId,
      );
      const signature: string = await getSignature(
        mpc,
        tradeId,
        infoHash,
        SignatureType.ConfirmPayment,
        domain,
      );

      const currentStage = await btcsol.currentStage(tradeId);
      const lastInfo = await btcsol.settledPayment(tradeId);

      await expect(
        btcsol
          .connect(mpcNode1)
          .confirmPayment(mpcNode1.address, tradeId, signature),
      ).to.be.revertedWithCustomError(btcsol, "Unauthorized");

      expect(await btcsol.currentStage(tradeId)).deep.eq(currentStage);
      expect(await btcsol.settledPayment(tradeId)).deep.eq(lastInfo);
    });

    it("Should revert when Admin tries to submit payment confirmation directly", async () => {
      //  Note: Authorized MPC Nodes cannot submit payment confirmation by call confirmPayment() directly
      //  Instead, they should call Router contract to submit it
      const pFeeAmount: bigint = (amountOut * pFeeRate) / DENOM;
      const aFeeAmount: bigint =
        ((affiliateInfo.aggregatedValue as bigint) * amountOut) / DENOM;
      const totalAmount: bigint = pFeeAmount + aFeeAmount;
      const paymentAmount: bigint = amountOut - totalAmount;
      const infoHash = getConfirmPaymentHash(
        totalAmount,
        paymentAmount,
        tradeInfo.toChain,
        paymentTxId,
      );
      const signature: string = await getSignature(
        mpc,
        tradeId,
        infoHash,
        SignatureType.ConfirmPayment,
        domain,
      );

      const currentStage = await btcsol.currentStage(tradeId);
      const lastInfo = await btcsol.settledPayment(tradeId);

      await expect(
        btcsol
          .connect(admin)
          .confirmPayment(mpcNode1.address, tradeId, signature),
      ).to.be.revertedWithCustomError(btcsol, "Unauthorized");

      expect(await btcsol.currentStage(tradeId)).deep.eq(currentStage);
      expect(await btcsol.settledPayment(tradeId)).deep.eq(lastInfo);
    });

    it("Should succeed when MPC submits a payment confirmation", async () => {
      //  Note: Authorized MPC Nodes cannot submit payment confirmation by call confirmPayment() directly
      //  Instead, they should call Router contract to submit it
      const pFeeAmount: bigint = (amountOut * pFeeRate) / DENOM;
      const aFeeAmount: bigint =
        ((affiliateInfo.aggregatedValue as bigint) * amountOut) / DENOM;
      const totalAmount: bigint = pFeeAmount + aFeeAmount;
      const paymentAmount: bigint = amountOut - totalAmount;
      const infoHash = getConfirmPaymentHash(
        totalAmount,
        paymentAmount,
        tradeInfo.toChain,
        paymentTxId,
      );
      const signature: string = await getSignature(
        mpc,
        tradeId,
        infoHash,
        SignatureType.ConfirmPayment,
        domain,
      );

      const tx = router.connect(mpcNode1).confirmPayment(tradeId, signature);

      await expect(tx)
        .to.emit(btcsol, "PaymentConfirmed")
        .withArgs(
          await router.getAddress(),
          mpc.address,
          tradeId,
          hexlify(paymentTxId),
        );

      expect(await btcsol.currentStage(tradeId)).deep.eq(
        STAGE.CONFIRM_SETTLEMENT,
      );
      expect(await btcsol.settledPayment(tradeId)).deep.eq([
        bundlerHash([tradeId]),
        hexlify(paymentTxId),
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
        ZERO_VALUE,
        releaseTxId,
      );
      const signature: string = await getSignature(
        mpc,
        tradeId,
        infoHash,
        SignatureType.ConfirmSettlement,
        domain,
      );

      const currentStage = await btcsol.currentStage(tradeId);
      const lastInfo = await btcsol.settledPayment(tradeId);

      await expect(
        btcsol
          .connect(mpcNode1)
          .confirmSettlement(mpcNode1.address, tradeId, releaseTxId, signature),
      ).to.be.revertedWithCustomError(btcsol, "Unauthorized");

      expect(await btcsol.currentStage(tradeId)).deep.eq(currentStage);
      expect(await btcsol.settledPayment(tradeId)).deep.eq(lastInfo);
    });

    it("Should revert when Admin tries to submit settlement confirmation directly", async () => {
      //  Note: Authorized MPC Nodes cannot submit settlement confirmation by call confirmSettlement() directly
      //  Instead, they should call Router contract to submit it
      const infoHash: string = getConfirmSettlementHash(
        ZERO_VALUE,
        releaseTxId,
      );
      const signature: string = await getSignature(
        mpc,
        tradeId,
        infoHash,
        SignatureType.ConfirmSettlement,
        domain,
      );

      const currentStage = await btcsol.currentStage(tradeId);
      const lastInfo = await btcsol.settledPayment(tradeId);

      await expect(
        btcsol
          .connect(admin)
          .confirmSettlement(mpcNode1.address, tradeId, releaseTxId, signature),
      ).to.be.revertedWithCustomError(btcsol, "Unauthorized");

      expect(await btcsol.currentStage(tradeId)).deep.eq(currentStage);
      expect(await btcsol.settledPayment(tradeId)).deep.eq(lastInfo);
    });

    it("Should succeed when MPC Nodes submit settlement confirmation via Router", async () => {
      //  Note: Authorized MPC Nodes cannot submit settlement confirmation by call confirmSettlement() directly
      //  Instead, they should call Router contract to submit it
      const infoHash: string = getConfirmSettlementHash(
        ZERO_VALUE,
        releaseTxId,
      );
      const signature: string = await getSignature(
        mpc,
        tradeId,
        infoHash,
        SignatureType.ConfirmSettlement,
        domain,
      );

      const tx = router
        .connect(mpcNode1)
        .confirmSettlement(tradeId, releaseTxId, signature);

      await expect(tx)
        .to.emit(btcsol, "SettlementConfirmed")
        .withArgs(
          await router.getAddress(),
          mpc.address,
          tradeId,
          hexlify(releaseTxId),
        );

      expect(await btcsol.currentStage(tradeId)).deep.eq(STAGE.COMPLETE);
      expect(await btcsol.settledPayment(tradeId)).deep.eq([
        bundlerHash([tradeId]),
        hexlify(paymentTxId),
        hexlify(releaseTxId),
        true,
      ]);
    });
  });
});
