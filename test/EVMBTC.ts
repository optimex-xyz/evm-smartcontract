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

import {
  Management,
  Management__factory,
  EVMBTC,
  EVMBTC__factory,
  VaultRegistry,
  VaultRegistry__factory,
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
} from "../sample-data/evmbtc";
import { randomTxId } from "../sample-data/utils";
import getTradeId from "../scripts/utils/others/getTradeId";
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
import { testMPCKP } from "../scripts/utils/bitcoin/btc";
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

function bundlerHash(tradeIds: BytesLike[]): string {
  return keccak256(abiCoder.encode(["bytes32[]"], [tradeIds]));
}

async function getBlockTimestamp(provider: HardhatEthersProvider) {
  const block = await provider.getBlockNumber();
  const timestamp = (await provider.getBlock(block))?.timestamp as number;

  return timestamp;
}

describe("EVMBTC Contract Testing", () => {
  let admin: HardhatEthersSigner, user: HardhatEthersSigner;
  let solver: HardhatEthersSigner, mpc: Wallet;
  let mpcNode1: HardhatEthersSigner, mpcNode2: HardhatEthersSigner;
  let accounts: HardhatEthersSigner[], vault: HardhatEthersSigner;

  let management: Management;
  let evmbtc: EVMBTC, registry: VaultRegistry, signerHelper: SignerHelper;
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
  let pFeeAmount: bigint;
  let aFeeAmount: bigint;
  let domain: TypedDataDomain;

  const fromNetworkId = "base-sepolia";
  const pFeeRate: bigint = BigInt(50);
  const paymentTxId = randomTxId();
  const releaseTxId = randomTxId();

  before(async () => {
    await network.provider.request({
      method: "hardhat_reset",
      params: [],
    });

    [admin, solver, user, vault, mpcNode1, mpcNode2, ...accounts] =
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

    //  Deploy VaultRegistry contract
    const Registry = (await ethers.getContractFactory(
      "VaultRegistry",
      admin,
    )) as VaultRegistry__factory;
    registry = await Registry.deploy(await management.getAddress());

    //  Deploy evmbtc contract
    const EVMBTC = (await ethers.getContractFactory(
      "EVMBTC",
      admin,
    )) as EVMBTC__factory;
    evmbtc = await EVMBTC.deploy(
      await router.getAddress(),
      await registry.getAddress(),
    );

    //  set `maxAffiliateFeeRate`
    await evmbtc.connect(admin).setMaxAffiliateFeeRate(MAX_AFFILIATE_FEE_RATE);

    const presignDomain: TypedDataDomain = {
      name: "Token Vault",
      version: "Version 1",
      chainId: (await provider.getNetwork()).chainId,
      verifyingContract: vault.address,
    };

    //  generate eip-712 domain
    domain = await getEIP712Domain(await signerHelper.getAddress(), admin);

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
      fromNetworkId,
      await weth.getAddress(),
      user.address,
    );
    affiliateInfo = getAffiliateInfo();
    rfqInfo = getRFQInfo();
    tradeId = getTradeId(sessionId, solver.address, tradeInfo);
    const lockingVault = vault.address;
    const { scriptInfo: info, ephemeralL2Key } = await getScriptInfo(
      tradeId,
      Number(rfqInfo.tradeTimeout),
      user.address,
      tradeInfo.fromChain[1],
      tradeInfo.fromChain[2],
      lockingVault,
    );
    scriptInfo = structuredClone(info);
    ephemeralL2Wallet = new Wallet(ephemeralL2Key, provider);
    presigns = await getPresigns(
      tradeId,
      tradeInfo.amountIn as bigint,
      presignDomain,
    );

    ethTokenInfo = {
      info: [
        tradeInfo.fromChain[2], // tokenId
        tradeInfo.fromChain[1], // networkId
        toUtf8Bytes("ETH"), // symbol
        toUtf8Bytes("https://example.com"),
        toUtf8Bytes("Ethereum (ETH) - Sepolia Base Token"),
      ],
      decimals: BigInt(18),
    };

    btcTokenInfo = {
      info: [
        tradeInfo.toChain[2], // tokenId
        tradeInfo.toChain[1], // networkId
        toUtf8Bytes("BTC"), // symbol
        toUtf8Bytes("https://example.com"),
        toUtf8Bytes("Bitcoin (BTC) - Bitcoin Testnet Token"),
      ],
      decimals: BigInt(8),
    };

    pFeeAmount = (BigInt(tradeInfo.amountIn) * pFeeRate) / DENOM;
    aFeeAmount =
      (BigInt(affiliateInfo.aggregatedValue) * BigInt(tradeInfo.amountIn)) /
      DENOM;

    //  Set `fromNetworkId` and `toNetworkId` in the Management
    //  Note: `networkId` is registered if and only if
    //  there's at least one Token being supported
    await management.connect(admin).setToken(btcTokenInfo);
    await management.connect(admin).setToken(ethTokenInfo);
    await router
      .connect(admin)
      .setRoute(
        await evmbtc.getAddress(),
        tradeInfo.fromChain[1],
        tradeInfo.toChain[1],
      );

    //  set Vault for `base-sepolia`
    await registry.setVault(
      vault.address,
      tradeInfo.fromChain[1],
      tradeInfo.fromChain[2],
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
      mpcL2Pubkey: mpc.signingKey.compressedPublicKey, //  For EVM, `mpcAssetPubkey` = `mpcL2Pubkey`
    };
    const prevExpireTime = BigInt(0);
    await management
      .connect(admin)
      .setMPCInfo(tradeInfo.fromChain[1], mpcInfo, prevExpireTime);
  });

  it("Should be able to check the initialized settings of EVMBTC contract", async () => {
    expect(await evmbtc.router()).deep.equal(await router.getAddress());
    expect(await evmbtc.registry()).deep.equal(await registry.getAddress());
    expect(await evmbtc.typeOfHandler()).deep.eq("EVMBTC");
  });

  describe("setRouter() functional testing", async () => {
    it("Should revert when Unauthorized client, a arbitrary account, tries to update new Router contract", async () => {
      expect(await evmbtc.router()).deep.equal(await router.getAddress());

      await expect(
        evmbtc.connect(accounts[0]).setRouter(accounts[0].address),
      ).to.be.revertedWithCustomError(evmbtc, "Unauthorized");

      expect(await evmbtc.router()).deep.equal(await router.getAddress());
    });

    it("Should revert when Unauthorized client, the Solver account, tries to update new Router contract", async () => {
      expect(await evmbtc.router()).deep.equal(await router.getAddress());

      await expect(
        evmbtc.connect(solver).setRouter(solver.address),
      ).to.be.revertedWithCustomError(evmbtc, "Unauthorized");

      expect(await evmbtc.router()).deep.equal(await router.getAddress());
    });

    it("Should revert when Unauthorized client, the MPC account, tries to update new Router contract", async () => {
      expect(await evmbtc.router()).deep.equal(await router.getAddress());

      await expect(
        evmbtc.connect(mpc).setRouter(mpc.address),
      ).to.be.revertedWithCustomError(evmbtc, "Unauthorized");

      expect(await evmbtc.router()).deep.equal(await router.getAddress());
    });

    it("Should revert when Owner updates 0x0 as a new address of Router contract", async () => {
      expect(await evmbtc.router()).deep.equal(await router.getAddress());

      await expect(
        evmbtc.connect(admin).setRouter(ZeroAddress),
      ).to.be.revertedWithCustomError(evmbtc, "AddressZero");

      expect(await evmbtc.router()).deep.equal(await router.getAddress());
    });

    it("Should succeed when Owner updates a new address of Router contract", async () => {
      expect(await evmbtc.router()).deep.equal(await router.getAddress());

      await evmbtc.connect(admin).setRouter(await clone.getAddress());

      expect(await evmbtc.router()).deep.equal(await clone.getAddress());
    });

    it("Should succeed when Owner changes back to previous Router contract", async () => {
      expect(await evmbtc.router()).deep.equal(await clone.getAddress());

      await evmbtc.connect(admin).setRouter(await router.getAddress());

      expect(await evmbtc.router()).deep.equal(await router.getAddress());
    });
  });

  describe("setVaultRegistry() functional testing", async () => {
    it("Should revert when Unauthorized client, a arbitrary account, tries to update new VaultRegistry contract", async () => {
      expect(await evmbtc.registry()).deep.equal(await registry.getAddress());

      await expect(
        evmbtc.connect(accounts[0]).setVaultRegistry(accounts[0].address),
      ).to.be.revertedWithCustomError(evmbtc, "Unauthorized");

      expect(await evmbtc.registry()).deep.equal(await registry.getAddress());
    });

    it("Should revert when Unauthorized client, the Solver account, tries to update new VaultRegistry contract", async () => {
      expect(await evmbtc.registry()).deep.equal(await registry.getAddress());

      await expect(
        evmbtc.connect(solver).setVaultRegistry(solver.address),
      ).to.be.revertedWithCustomError(evmbtc, "Unauthorized");

      expect(await evmbtc.registry()).deep.equal(await registry.getAddress());
    });

    it("Should revert when Unauthorized client, the MPC account, tries to update new VaultRegistry contract", async () => {
      expect(await evmbtc.registry()).deep.equal(await registry.getAddress());

      await expect(
        evmbtc.connect(mpc).setVaultRegistry(mpc.address),
      ).to.be.revertedWithCustomError(evmbtc, "Unauthorized");

      expect(await evmbtc.registry()).deep.equal(await registry.getAddress());
    });

    it("Should revert when Owner updates 0x0 as a new address of VaultRegistry contract", async () => {
      expect(await evmbtc.registry()).deep.equal(await registry.getAddress());

      await expect(
        evmbtc.connect(admin).setVaultRegistry(ZeroAddress),
      ).to.be.revertedWithCustomError(evmbtc, "AddressZero");

      expect(await evmbtc.registry()).deep.equal(await registry.getAddress());
    });

    it("Should succeed when Owner updates a new address of VaultRegistry contract", async () => {
      expect(await evmbtc.registry()).deep.equal(await registry.getAddress());

      await evmbtc.connect(admin).setVaultRegistry(admin.address);

      expect(await evmbtc.registry()).deep.equal(admin.address);

      //  change back to normal
      await evmbtc.connect(admin).setVaultRegistry(await registry.getAddress());
      expect(await evmbtc.registry()).deep.equal(await registry.getAddress());
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
        evmbtc
          .connect(solver)
          .submitTrade(
            solver.address,
            tradeId,
            tradeData,
            affiliateInfo,
            presigns,
          ),
      ).to.be.revertedWithCustomError(evmbtc, "Unauthorized");

      expect(await evmbtc.currentStage(tradeId)).deep.eq(STAGE.SUBMIT);
      expect(await evmbtc.trade(tradeId)).deep.eq(EMPTY_TRADE_DATA);
      expect(await evmbtc.presign(tradeId)).deep.eq(EMPTY_PRESIGNS);
      expect(await evmbtc.feeDetails(tradeId)).deep.eq(EMPTY_FEE_DETAILS);
      expect(await evmbtc.affiliate(tradeId)).deep.eq(EMPTY_AFFILIATE_INFO);
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
        evmbtc
          .connect(admin)
          .submitTrade(
            solver.address,
            tradeId,
            tradeData,
            affiliateInfo,
            presigns,
          ),
      ).to.be.revertedWithCustomError(evmbtc, "Unauthorized");

      expect(await evmbtc.currentStage(tradeId)).deep.eq(STAGE.SUBMIT);
      expect(await evmbtc.trade(tradeId)).deep.eq(EMPTY_TRADE_DATA);
      expect(await evmbtc.presign(tradeId)).deep.eq(EMPTY_PRESIGNS);
      expect(await evmbtc.feeDetails(tradeId)).deep.eq(EMPTY_FEE_DETAILS);
      expect(await evmbtc.affiliate(tradeId)).deep.eq(EMPTY_AFFILIATE_INFO);
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
        .to.emit(evmbtc, "TradeInfoSubmitted")
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

      expect(await evmbtc.currentStage(tradeId)).deep.eq(STAGE.CONFIRM_DEPOSIT);
      expect(await evmbtc.trade(tradeId)).deep.eq(
        Object.values(expectedTradeData),
      );
      expect(await evmbtc.presign(tradeId)).deep.eq(
        Object.values(expectedPresigns),
      );
      expect(await evmbtc.feeDetails(tradeId)).deep.eq([
        pFeeAmount + aFeeAmount,
        pFeeAmount, // pFeeAmount
        aFeeAmount, // aFeeAmount
        pFeeRate,
        affiliateInfo.aggregatedValue, //  aFeeRate
      ]);
      expect(await evmbtc.affiliate(tradeId)).deep.eq(
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
      const depositedFromList: BytesLike[] = [hexlify(user.address)];
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

      const currentStage = await evmbtc.currentStage(tradeId);
      const lastInfo = await evmbtc.depositAddressList(tradeId);

      await expect(
        evmbtc
          .connect(mpcNode1)
          .confirmDeposit(
            mpcNode1.address,
            tradeId,
            signature,
            depositedFromList,
          ),
      ).to.be.revertedWithCustomError(evmbtc, "Unauthorized");

      expect(await evmbtc.currentStage(tradeId)).deep.eq(currentStage);
      expect(await evmbtc.depositAddressList(tradeId)).deep.eq(lastInfo);
    });

    it("Should revert when Admin tries to submit a deposit confirmation directly", async () => {
      //  Note: Authorized MPC Nodes cannot submit a deposit confirmation directly
      //  by calling confirmDeposit() function
      //  Instead, MPC Nodes should call Router contract to submit the confirmation
      const amountIn = tradeInfo.amountIn as bigint;
      const depositedFromList: BytesLike[] = [hexlify(user.address)];
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

      const currentStage = await evmbtc.currentStage(tradeId);
      const lastInfo = await evmbtc.depositAddressList(tradeId);

      await expect(
        evmbtc
          .connect(admin)
          .confirmDeposit(
            mpcNode1.address,
            tradeId,
            signature,
            depositedFromList,
          ),
      ).to.be.revertedWithCustomError(evmbtc, "Unauthorized");

      expect(await evmbtc.currentStage(tradeId)).deep.eq(currentStage);
      expect(await evmbtc.depositAddressList(tradeId)).deep.eq(lastInfo);
    });

    it("Should succeed when MPC Nodes submit a deposit confirmation via Router", async () => {
      //  Note: Authorized MPC Nodes cannot submit a deposit confirmation directly
      //  by calling confirmDeposit() function
      //  Instead, MPC Nodes should call Router contract to submit the confirmation
      const amountIn = tradeInfo.amountIn as bigint;
      const depositedFromList: BytesLike[] = [hexlify(user.address)];
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
        .to.emit(evmbtc, "DepositConfirmed")
        .withArgs(
          await router.getAddress(),
          mpc.address,
          tradeId,
          (affiliateInfo.aggregatedValue as bigint) + pFeeRate, //  total fee rate
        );

      const expectedList = depositedFromList.map((data) => hexlify(data));
      expect(await evmbtc.currentStage(tradeId)).deep.eq(STAGE.SELECT_PMM);
      expect(await evmbtc.depositAddressList(tradeId)).deep.eq(expectedList);
    });
  });

  describe("selectPMM() functional testing", async () => {
    it("Should revert when Solver tries to submit pmm selection directly", async () => {
      //  Note: Solver cannot submit a pmm selection directly by calling selectPMM() function
      //  Instead, Solver should call Router contract to submit the selection info
      const timestamp = await getBlockTimestamp(provider);
      const expiry = BigInt(timestamp + 30 * 60);
      amountOut = (rfqInfo.minAmountOut as bigint) + parseUnits("100", 8);
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

      const currentStage = await evmbtc.currentStage(tradeId);
      const lastInfo = await evmbtc.pmmSelection(tradeId);

      await expect(
        evmbtc
          .connect(solver)
          .selectPMM(solver.address, tradeId, pmmSelectionInfo),
      ).to.be.revertedWithCustomError(evmbtc, "Unauthorized");

      expect(await evmbtc.currentStage(tradeId)).deep.eq(currentStage);
      expect(await evmbtc.pmmSelection(tradeId)).deep.eq(lastInfo);
    });

    it("Should revert when Admin tries to submit a deposit confirmation directly", async () => {
      //  Note: Solver cannot submit a pmm selection directly by calling selectPMM() function
      //  Instead, Solver should call Router contract to submit the selection info
      const timestamp = await getBlockTimestamp(provider);
      const expiry = BigInt(timestamp + 30 * 60);
      amountOut = (rfqInfo.minAmountOut as bigint) + parseUnits("100", 8);
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

      const currentStage = await evmbtc.currentStage(tradeId);
      const lastInfo = await evmbtc.pmmSelection(tradeId);

      await expect(
        evmbtc
          .connect(admin)
          .selectPMM(solver.address, tradeId, pmmSelectionInfo),
      ).to.be.revertedWithCustomError(evmbtc, "Unauthorized");

      expect(await evmbtc.currentStage(tradeId)).deep.eq(currentStage);
      expect(await evmbtc.pmmSelection(tradeId)).deep.eq(lastInfo);
    });

    it("Should succeed when MPC Nodes submit a deposit confirmation via Router", async () => {
      //  Note: Solver cannot submit a pmm selection directly by calling selectPMM() function
      //  Instead, Solver should call Router contract to submit the selection info
      const timestamp = await getBlockTimestamp(provider);
      const expiry = BigInt(timestamp + 30 * 60);
      amountOut = (rfqInfo.minAmountOut as bigint) + parseUnits("100", 8);
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

      const tx = router.connect(solver).selectPMM(tradeId, pmmSelectionInfo);

      await expect(tx)
        .to.emit(evmbtc, "SelectedPMM")
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
      expect(await evmbtc.currentStage(tradeId)).deep.eq(STAGE.MAKE_PAYMENT);
      expect(await evmbtc.pmmSelection(tradeId)).deep.eq(
        expectedPMMSelectionInfo,
      );
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

      const currentStage = await evmbtc.currentStage(tradeId);
      const lastInfo = await evmbtc.settledPayment(tradeId);

      await expect(
        evmbtc
          .connect(solver)
          .makePayment(solver.address, indexOfTrade, bundle),
      ).to.be.revertedWithCustomError(evmbtc, "Unauthorized");

      expect(await evmbtc.currentStage(tradeId)).deep.eq(currentStage);
      expect(await evmbtc.settledPayment(tradeId)).deep.eq(lastInfo);
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

      const currentStage = await evmbtc.currentStage(tradeId);
      const lastInfo = await evmbtc.settledPayment(tradeId);

      await expect(
        evmbtc
          .connect(accounts[0])
          .makePayment(accounts[0].address, indexOfTrade, bundle),
      ).to.be.revertedWithCustomError(evmbtc, "Unauthorized");

      expect(await evmbtc.currentStage(tradeId)).deep.eq(currentStage);
      expect(await evmbtc.settledPayment(tradeId)).deep.eq(lastInfo);
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

      const currentStage = await evmbtc.currentStage(tradeId);
      const lastInfo = await evmbtc.settledPayment(tradeId);

      await expect(
        evmbtc.connect(admin).makePayment(solver.address, indexOfTrade, bundle),
      ).to.be.revertedWithCustomError(evmbtc, "Unauthorized");

      expect(await evmbtc.currentStage(tradeId)).deep.eq(currentStage);
      expect(await evmbtc.settledPayment(tradeId)).deep.eq(lastInfo);
    });

    it("Should succeed when Solver submits paymentTxId via Router", async () => {
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
      const bundle: CoreTypes.BundlePaymentStruct = {
        tradeIds: tradeIds,
        signedAt: signedAt,
        startIdx: startIdx,
        paymentTxId: paymentTxId,
        signature: signature,
      };

      const tx = router.connect(solver).bundlePayment(bundle);

      await expect(tx)
        .to.emit(evmbtc, "MadePayment")
        .withArgs(
          await router.getAddress(),
          solver.address,
          tradeId,
          hexlify(tradeInfo.toChain[1]),
          hexlify(paymentTxId),
          tradeIds,
          startIdx,
        );

      expect(await evmbtc.currentStage(tradeId)).deep.eq(STAGE.CONFIRM_PAYMENT);
      expect(await evmbtc.settledPayment(tradeId)).deep.eq([
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
      const infoHash = getConfirmPaymentHash(
        ZERO_VALUE,
        amountOut,
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

      const currentStage = await evmbtc.currentStage(tradeId);
      const lastInfo = await evmbtc.settledPayment(tradeId);

      await expect(
        evmbtc
          .connect(mpcNode1)
          .confirmPayment(mpcNode1.address, tradeId, signature),
      ).to.be.revertedWithCustomError(evmbtc, "Unauthorized");

      expect(await evmbtc.currentStage(tradeId)).deep.eq(currentStage);
      expect(await evmbtc.settledPayment(tradeId)).deep.eq(lastInfo);
    });

    it("Should revert when Admin tries to submit payment confirmation directly", async () => {
      //  Note: Authorized MPC Nodes cannot submit payment confirmation by call confirmPayment() directly
      //  Instead, they should call Router contract to submit it
      const infoHash = getConfirmPaymentHash(
        ZERO_VALUE,
        amountOut,
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

      const currentStage = await evmbtc.currentStage(tradeId);
      const lastInfo = await evmbtc.settledPayment(tradeId);

      await expect(
        evmbtc
          .connect(admin)
          .confirmPayment(mpcNode1.address, tradeId, signature),
      ).to.be.revertedWithCustomError(evmbtc, "Unauthorized");

      expect(await evmbtc.currentStage(tradeId)).deep.eq(currentStage);
      expect(await evmbtc.settledPayment(tradeId)).deep.eq(lastInfo);
    });

    it("Should succeed when MPC submits a payment confirmation", async () => {
      //  Note: Authorized MPC Nodes cannot submit payment confirmation by call confirmPayment() directly
      //  Instead, they should call Router contract to submit it
      const infoHash = getConfirmPaymentHash(
        ZERO_VALUE,
        amountOut,
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
        .to.emit(evmbtc, "PaymentConfirmed")
        .withArgs(
          await router.getAddress(),
          mpc.address,
          tradeId,
          hexlify(paymentTxId),
        );

      expect(await evmbtc.currentStage(tradeId)).deep.eq(
        STAGE.CONFIRM_SETTLEMENT,
      );
      expect(await evmbtc.settledPayment(tradeId)).deep.eq([
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
        pFeeAmount + aFeeAmount,
        releaseTxId,
      );
      const signature: string = await getSignature(
        mpc,
        tradeId,
        infoHash,
        SignatureType.ConfirmSettlement,
        domain,
      );

      const currentStage = await evmbtc.currentStage(tradeId);
      const lastInfo = await evmbtc.settledPayment(tradeId);

      await expect(
        evmbtc
          .connect(mpcNode1)
          .confirmSettlement(mpcNode1.address, tradeId, releaseTxId, signature),
      ).to.be.revertedWithCustomError(evmbtc, "Unauthorized");

      expect(await evmbtc.currentStage(tradeId)).deep.eq(currentStage);
      expect(await evmbtc.settledPayment(tradeId)).deep.eq(lastInfo);
    });

    it("Should revert when Admin tries to submit settlement confirmation directly", async () => {
      //  Note: Authorized MPC Nodes cannot submit settlement confirmation by call confirmSettlement() directly
      //  Instead, they should call Router contract to submit it
      const infoHash: string = getConfirmSettlementHash(
        pFeeAmount + aFeeAmount,
        releaseTxId,
      );
      const signature: string = await getSignature(
        mpc,
        tradeId,
        infoHash,
        SignatureType.ConfirmSettlement,
        domain,
      );

      const currentStage = await evmbtc.currentStage(tradeId);
      const lastInfo = await evmbtc.settledPayment(tradeId);

      await expect(
        evmbtc
          .connect(solver)
          .confirmSettlement(mpcNode1.address, tradeId, releaseTxId, signature),
      ).to.be.revertedWithCustomError(evmbtc, "Unauthorized");

      expect(await evmbtc.currentStage(tradeId)).deep.eq(currentStage);
      expect(await evmbtc.settledPayment(tradeId)).deep.eq(lastInfo);
    });

    it("Should succeed when MPC Nodes submit settlement confirmation via Router", async () => {
      //  Note: Authorized MPC Nodes cannot submit settlement confirmation by call confirmSettlement() directly
      //  Instead, they should call Router contract to submit it
      const infoHash: string = getConfirmSettlementHash(
        pFeeAmount + aFeeAmount,
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
        .to.emit(evmbtc, "SettlementConfirmed")
        .withArgs(
          await router.getAddress(),
          mpc.address,
          tradeId,
          hexlify(releaseTxId),
        );

      expect(await evmbtc.currentStage(tradeId)).deep.eq(STAGE.COMPLETE);
      expect(await evmbtc.settledPayment(tradeId)).deep.eq([
        bundlerHash([tradeId]),
        hexlify(paymentTxId),
        hexlify(releaseTxId),
        true,
      ]);
    });
  });
});
