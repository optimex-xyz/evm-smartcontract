import { expect } from "chai";
import { ethers, network } from "hardhat";
import {
  BytesLike,
  ZeroAddress,
  ZeroHash,
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

import {
  Management,
  Management__factory,
  BTCEVM,
  BTCEVM__factory,
  Router,
  Router__factory,
  Signer as SignerHelper,
  Signer__factory as SignerHelperFactory,
  Token20,
  Token20__factory,
} from "../typechain-types";
import { ITypes as CoreTypes } from "../typechain-types/contracts/utils/Core";
import { ITypes as ManagementTypes } from "../typechain-types/contracts/Management";
import {
  getTradeInfo,
  getRFQInfo,
  getScriptInfo,
  getPresigns,
  getAffiliateInfo,
} from "../sample-data/btcevm";
import { randomTxId } from "../sample-data/utils";
import getTradeId from "../scripts/utils/others/getTradeId";
import { testMPCKP } from "../scripts/utils/bitcoin/btc";
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
import { getEIP712Domain } from "../scripts/utils/evm/getEIP712Domain";

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

describe("BTCEVM Contract Testing", () => {
  let admin: HardhatEthersSigner, user: HardhatEthersSigner;
  let solver: HardhatEthersSigner, mpc: Wallet;
  let mpcNode1: HardhatEthersSigner, mpcNode2: HardhatEthersSigner;
  let accounts: HardhatEthersSigner[];

  let management: Management;
  let btcevm: BTCEVM, signerHelper: SignerHelper;
  let router: Router, clone: Router;
  let weth: Token20;

  let btcTokenInfo: ManagementTypes.TokenInfoStruct,
    ethTokenInfo: ManagementTypes.TokenInfoStruct;

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

  before(async () => {
    await network.provider.request({
      method: "hardhat_reset",
      params: [],
    });

    [admin, solver, user, mpcNode1, mpcNode2, ...accounts] =
      await ethers.getSigners();

    //  Deploy `toToken` contract
    const WETH = (await ethers.getContractFactory(
      "Token20",
      admin,
    )) as Token20__factory;
    weth = await WETH.deploy("Wrapped ETH", "WETH");

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

    //  Deploy BTCEVM contract
    const BTCEVM = (await ethers.getContractFactory(
      "BTCEVM",
      admin,
    )) as BTCEVM__factory;
    btcevm = await BTCEVM.deploy(await router.getAddress());

    //  set `maxAffiliateFeeRate`
    await btcevm.connect(admin).setMaxAffiliateFeeRate(MAX_AFFILIATE_FEE_RATE);

    //  Whitelist Solver and MPC Node associated accounts
    await management.connect(admin).setSolver(solver.address, true);
    await management.connect(admin).setMPCNode(mpcNode1.address, true);
    await management.connect(admin).setMPCNode(mpcNode2.address, true);

    //  Generate MPC Wallet
    const mpcPrivkey = hexlify(testMPCKP.privateKey as Uint8Array);
    mpc = new Wallet(mpcPrivkey, provider);

    //  Prepare trade data
    sessionId = BigInt(keccak256(toUtf8Bytes(crypto.randomUUID())));
    tradeInfo = getTradeInfo(
      "base-sepolia",
      await weth.getAddress(),
      user.address,
    );
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

    ethTokenInfo = {
      info: [
        tradeInfo.toChain[2], // tokenId
        tradeInfo.toChain[1], // networkId
        toUtf8Bytes("ETH"), // symbol
        toUtf8Bytes("https://example.com"),
        toUtf8Bytes("Ethereum (ETH) - Sepolia Base Token"),
      ],
      decimals: BigInt(18),
    };

    //  generate eip-712 domain
    domain = await getEIP712Domain(await signerHelper.getAddress(), admin);

    //  Set `fromNetworkId` and `toNetworkId` in the Management
    //  Note: `networkId` is registered if and only if
    //  there's at least one Token being supported
    await management.connect(admin).setToken(btcTokenInfo);
    await management.connect(admin).setToken(ethTokenInfo);
    await router
      .connect(admin)
      .setRoute(
        await btcevm.getAddress(),
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

  it("Should be able to check the initialized settings of BTCEVM contract", async () => {
    expect(await btcevm.router()).deep.equal(await router.getAddress());
    expect(await btcevm.typeOfHandler()).deep.eq("BTCEVM");
  });

  describe("setRouter() functional testing", async () => {
    it("Should revert when Unauthorized client, a arbitrary account, tries to update new Router contract", async () => {
      expect(await btcevm.router()).deep.equal(await router.getAddress());

      await expect(
        btcevm.connect(accounts[0]).setRouter(accounts[0].address),
      ).to.be.revertedWithCustomError(btcevm, "Unauthorized");

      expect(await btcevm.router()).deep.equal(await router.getAddress());
    });

    it("Should revert when Unauthorized client, the Solver account, tries to update new Router contract", async () => {
      expect(await btcevm.router()).deep.equal(await router.getAddress());

      await expect(
        btcevm.connect(solver).setRouter(solver.address),
      ).to.be.revertedWithCustomError(btcevm, "Unauthorized");

      expect(await btcevm.router()).deep.equal(await router.getAddress());
    });

    it("Should revert when Unauthorized client, the MPC account, tries to update new Router contract", async () => {
      expect(await btcevm.router()).deep.equal(await router.getAddress());

      await expect(
        btcevm.connect(mpc).setRouter(mpc.address),
      ).to.be.revertedWithCustomError(btcevm, "Unauthorized");

      expect(await btcevm.router()).deep.equal(await router.getAddress());
    });

    it("Should revert when Owner updates 0x0 as a new address of Router contract", async () => {
      expect(await btcevm.router()).deep.equal(await router.getAddress());

      await expect(
        btcevm.connect(admin).setRouter(ZeroAddress),
      ).to.be.revertedWithCustomError(btcevm, "AddressZero");

      expect(await btcevm.router()).deep.equal(await router.getAddress());
    });

    it("Should succeed when Owner updates a new address of Router contract", async () => {
      expect(await btcevm.router()).deep.equal(await router.getAddress());

      await btcevm.connect(admin).setRouter(await clone.getAddress());

      expect(await btcevm.router()).deep.equal(await clone.getAddress());
    });

    it("Should succeed when Owner changes back to previous Router contract", async () => {
      expect(await btcevm.router()).deep.equal(await clone.getAddress());

      await btcevm.connect(admin).setRouter(await router.getAddress());

      expect(await btcevm.router()).deep.equal(await router.getAddress());
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
        btcevm
          .connect(solver)
          .submitTrade(
            solver.address,
            tradeId,
            tradeData,
            affiliateInfo,
            presigns,
          ),
      ).to.be.revertedWithCustomError(btcevm, "Unauthorized");

      expect(await btcevm.currentStage(tradeId)).deep.eq(STAGE.SUBMIT);
      expect(await btcevm.trade(tradeId)).deep.eq(EMPTY_TRADE_DATA);
      expect(await btcevm.presign(tradeId)).deep.eq(EMPTY_PRESIGNS);
      expect(await btcevm.feeDetails(tradeId)).deep.eq(EMPTY_FEE_DETAILS);
      expect(await btcevm.affiliate(tradeId)).deep.eq(EMPTY_AFFILIATE_INFO);
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
        btcevm
          .connect(admin)
          .submitTrade(
            solver.address,
            tradeId,
            tradeData,
            affiliateInfo,
            presigns,
          ),
      ).to.be.revertedWithCustomError(btcevm, "Unauthorized");

      expect(await btcevm.currentStage(tradeId)).deep.eq(STAGE.SUBMIT);
      expect(await btcevm.trade(tradeId)).deep.eq(EMPTY_TRADE_DATA);
      expect(await btcevm.presign(tradeId)).deep.eq(EMPTY_PRESIGNS);
      expect(await btcevm.feeDetails(tradeId)).deep.eq(EMPTY_FEE_DETAILS);
      expect(await btcevm.affiliate(tradeId)).deep.eq(EMPTY_AFFILIATE_INFO);
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
        .to.emit(btcevm, "TradeInfoSubmitted")
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

      expect(await btcevm.currentStage(tradeId)).deep.eq(STAGE.CONFIRM_DEPOSIT);
      expect(await btcevm.trade(tradeId)).deep.eq(
        Object.values(expectedTradeData),
      );
      expect(await btcevm.presign(tradeId)).deep.eq(
        Object.values(expectedPresigns),
      );
      expect(await btcevm.feeDetails(tradeId)).deep.eq([
        BigInt(0),
        BigInt(0), // pFeeAmount
        BigInt(0), // aFeeAmount
        pFeeRate,
        affiliateInfo.aggregatedValue, //  aFeeRate
      ]);
      expect(await btcevm.affiliate(tradeId)).deep.eq(
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

      const currentStage = await btcevm.currentStage(tradeId);
      const lastInfo = await btcevm.depositAddressList(tradeId);

      await expect(
        btcevm
          .connect(mpcNode1)
          .confirmDeposit(
            mpcNode1.address,
            tradeId,
            signature,
            depositedFromList,
          ),
      ).to.be.revertedWithCustomError(btcevm, "Unauthorized");

      expect(await btcevm.currentStage(tradeId)).deep.eq(currentStage);
      expect(await btcevm.depositAddressList(tradeId)).deep.eq(lastInfo);
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

      const currentStage = await btcevm.currentStage(tradeId);
      const lastInfo = await btcevm.depositAddressList(tradeId);

      await expect(
        btcevm
          .connect(admin)
          .confirmDeposit(
            mpcNode1.address,
            tradeId,
            signature,
            depositedFromList,
          ),
      ).to.be.revertedWithCustomError(btcevm, "Unauthorized");

      expect(await btcevm.currentStage(tradeId)).deep.eq(currentStage);
      expect(await btcevm.depositAddressList(tradeId)).deep.eq(lastInfo);
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
        .to.emit(btcevm, "DepositConfirmed")
        .withArgs(
          await router.getAddress(),
          mpc.address,
          tradeId,
          (affiliateInfo.aggregatedValue as bigint) + pFeeRate, //  total fee rate
        );

      const expectedList = depositedFromList.map((data) => hexlify(data));
      expect(await btcevm.currentStage(tradeId)).deep.eq(STAGE.SELECT_PMM);
      expect(await btcevm.depositAddressList(tradeId)).deep.eq(expectedList);
    });
  });

  describe("selectPMM() functional testing", async () => {
    it("Should revert when Solver tries to submit pmm selection directly", async () => {
      //  Note: Solver cannot submit a pmm selection directly by calling selectPMM() function
      //  Instead, Solver should call Router contract to submit the selection info
      const timestamp = await getBlockTimestamp(provider);
      const expiry = BigInt(timestamp + 30 * 60);
      amountOut = (rfqInfo.minAmountOut as bigint) + parseUnits("100", "ether");
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

      const currentStage = await btcevm.currentStage(tradeId);
      const lastSelection = await btcevm.pmmSelection(tradeId);
      const lastDetails = await btcevm.feeDetails(tradeId);

      await expect(
        btcevm
          .connect(solver)
          .selectPMM(solver.address, tradeId, pmmSelectionInfo),
      ).to.be.revertedWithCustomError(btcevm, "Unauthorized");

      expect(await btcevm.currentStage(tradeId)).deep.eq(currentStage);
      expect(await btcevm.pmmSelection(tradeId)).deep.eq(lastSelection);
      expect(await btcevm.feeDetails(tradeId)).deep.eq(lastDetails);
    });

    it("Should revert when Admin tries to submit a pmm selection directly", async () => {
      //  Note: Solver cannot submit a pmm selection directly by calling selectPMM() function
      //  Instead, Solver should call Router contract to submit the selection info
      const timestamp = await getBlockTimestamp(provider);
      const expiry = BigInt(timestamp + 30 * 60);
      amountOut = (rfqInfo.minAmountOut as bigint) + parseUnits("100", "ether");
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

      const currentStage = await btcevm.currentStage(tradeId);
      const lastSelection = await btcevm.pmmSelection(tradeId);
      const lastDetails = await btcevm.feeDetails(tradeId);

      await expect(
        btcevm
          .connect(admin)
          .selectPMM(solver.address, tradeId, pmmSelectionInfo),
      ).to.be.revertedWithCustomError(btcevm, "Unauthorized");

      expect(await btcevm.currentStage(tradeId)).deep.eq(currentStage);
      expect(await btcevm.pmmSelection(tradeId)).deep.eq(lastSelection);
      expect(await btcevm.feeDetails(tradeId)).deep.eq(lastDetails);
    });

    it("Should succeed when Solver submits a pmm selection via Router", async () => {
      //  Note: Solver cannot submit a pmm selection directly by calling selectPMM() function
      //  Instead, Solver should call Router contract to submit the selection info
      const timestamp = await getBlockTimestamp(provider);
      const expiry = BigInt(timestamp + 30 * 60);
      amountOut =
        (rfqInfo.minAmountOut as bigint) + parseUnits("1000", "ether");
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
        .to.emit(btcevm, "SelectedPMM")
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
      expect(await btcevm.currentStage(tradeId)).deep.eq(STAGE.MAKE_PAYMENT);
      expect(await btcevm.pmmSelection(tradeId)).deep.eq(
        expectedPMMSelectionInfo,
      );
      expect(await btcevm.feeDetails(tradeId)).deep.eq([
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

      const currentStage = await btcevm.currentStage(tradeId);
      const lastInfo = await btcevm.settledPayment(tradeId);

      await expect(
        btcevm
          .connect(solver)
          .makePayment(solver.address, indexOfTrade, bundle),
      ).to.be.revertedWithCustomError(btcevm, "Unauthorized");

      expect(await btcevm.currentStage(tradeId)).deep.eq(currentStage);
      expect(await btcevm.settledPayment(tradeId)).deep.eq(lastInfo);
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

      const currentStage = await btcevm.currentStage(tradeId);
      const lastInfo = await btcevm.settledPayment(tradeId);

      await expect(
        btcevm
          .connect(accounts[0])
          .makePayment(accounts[0].address, indexOfTrade, bundle),
      ).to.be.revertedWithCustomError(btcevm, "Unauthorized");

      expect(await btcevm.currentStage(tradeId)).deep.eq(currentStage);
      expect(await btcevm.settledPayment(tradeId)).deep.eq(lastInfo);
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

      const currentStage = await btcevm.currentStage(tradeId);
      const lastInfo = await btcevm.settledPayment(tradeId);

      await expect(
        btcevm
          .connect(admin)
          .makePayment(accounts[0].address, indexOfTrade, bundle),
      ).to.be.revertedWithCustomError(btcevm, "Unauthorized");

      expect(await btcevm.currentStage(tradeId)).deep.eq(currentStage);
      expect(await btcevm.settledPayment(tradeId)).deep.eq(lastInfo);
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

      expect(await btcevm.currentStage(tradeId)).deep.eq(STAGE.MAKE_PAYMENT);
      expect(await btcevm.settledPayment(tradeId)).deep.eq(
        EMPTY_SETTLED_PAYMENT,
      );

      const tx = router.connect(accounts[0]).bundlePayment(bundle);

      await expect(tx)
        .to.emit(btcevm, "MadePayment")
        .withArgs(
          await router.getAddress(),
          accounts[0].address,
          tradeId,
          hexlify(tradeInfo.toChain[1]),
          hexlify(paymentTxId),
          tradeIds,
          startIdx,
        );

      expect(await btcevm.currentStage(tradeId)).deep.eq(STAGE.CONFIRM_PAYMENT);
      expect(await btcevm.settledPayment(tradeId)).deep.eq([
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

      const currentStage = await btcevm.currentStage(tradeId);
      const lastInfo = await btcevm.settledPayment(tradeId);

      await expect(
        btcevm
          .connect(mpcNode1)
          .confirmPayment(mpcNode1.address, tradeId, signature),
      ).to.be.revertedWithCustomError(btcevm, "Unauthorized");

      expect(await btcevm.currentStage(tradeId)).deep.eq(currentStage);
      expect(await btcevm.settledPayment(tradeId)).deep.eq(lastInfo);
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

      const currentStage = await btcevm.currentStage(tradeId);
      const lastInfo = await btcevm.settledPayment(tradeId);

      await expect(
        btcevm
          .connect(admin)
          .confirmPayment(mpcNode1.address, tradeId, signature),
      ).to.be.revertedWithCustomError(btcevm, "Unauthorized");

      expect(await btcevm.currentStage(tradeId)).deep.eq(currentStage);
      expect(await btcevm.settledPayment(tradeId)).deep.eq(lastInfo);
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
        .to.emit(btcevm, "PaymentConfirmed")
        .withArgs(
          await router.getAddress(),
          mpc.address,
          tradeId,
          hexlify(paymentTxId),
        );

      expect(await btcevm.currentStage(tradeId)).deep.eq(
        STAGE.CONFIRM_SETTLEMENT,
      );
      expect(await btcevm.settledPayment(tradeId)).deep.eq([
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

      const currentStage = await btcevm.currentStage(tradeId);
      const lastInfo = await btcevm.settledPayment(tradeId);

      await expect(
        btcevm
          .connect(mpcNode1)
          .confirmSettlement(mpcNode1.address, tradeId, releaseTxId, signature),
      ).to.be.revertedWithCustomError(btcevm, "Unauthorized");

      expect(await btcevm.currentStage(tradeId)).deep.eq(currentStage);
      expect(await btcevm.settledPayment(tradeId)).deep.eq(lastInfo);
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

      const currentStage = await btcevm.currentStage(tradeId);
      const lastInfo = await btcevm.settledPayment(tradeId);

      await expect(
        btcevm
          .connect(admin)
          .confirmSettlement(mpcNode1.address, tradeId, releaseTxId, signature),
      ).to.be.revertedWithCustomError(btcevm, "Unauthorized");

      expect(await btcevm.currentStage(tradeId)).deep.eq(currentStage);
      expect(await btcevm.settledPayment(tradeId)).deep.eq(lastInfo);
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
        .to.emit(btcevm, "SettlementConfirmed")
        .withArgs(
          await router.getAddress(),
          mpc.address,
          tradeId,
          hexlify(releaseTxId),
        );

      expect(await btcevm.currentStage(tradeId)).deep.eq(STAGE.COMPLETE);
      expect(await btcevm.settledPayment(tradeId)).deep.eq([
        bundlerHash([tradeId]),
        hexlify(paymentTxId),
        hexlify(releaseTxId),
        true,
      ]);
    });
  });
});
