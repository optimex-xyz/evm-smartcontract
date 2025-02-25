import { expect } from "chai";
import { ethers, network } from "hardhat";
import {
  BytesLike,
  ZeroAddress,
  ZeroHash,
  TypedDataDomain,
  Wallet,
  keccak256,
  hexlify,
  toUtf8Bytes,
  parseUnits,
  AbiCoder,
} from "ethers";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";
import { time } from "@nomicfoundation/hardhat-network-helpers";
import { HardhatEthersProvider } from "@nomicfoundation/hardhat-ethers/internal/hardhat-ethers-provider";
import { Keypair } from "@solana/web3.js";

import {
  Management,
  Management__factory,
  Core,
  BTCEVM__factory,
  EVMBTC__factory,
  BTCSOL__factory,
  SOLBTC__factory,
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
  getTradeInfo as getBTCEVMTradeInfo,
  getRFQInfo as getBTCEVMRFQInfo,
  getScriptInfo as getBTCEVMScriptInfo,
  getPresigns as getBTCEVMPresigns,
  getAffiliateInfo as getBTCEVMAffiliateInfo,
} from "../sample-data/btcevm";
import {
  getTradeInfo as getBTCSOLTradeInfo,
  getRFQInfo as getBTCSOLRFQInfo,
  getScriptInfo as getBTCSOLScriptInfo,
  getPresigns as getBTCSOLPresigns,
  getAffiliateInfo as getBTCSOLAffiliateInfo,
} from "../sample-data/btcsol";
import {
  getTradeInfo as getEVMBTCTradeInfo,
  getRFQInfo as getEVMBTCRFQInfo,
  getScriptInfo as getEVMBTCScriptInfo,
  getPresigns as getEVMBTCPresigns,
  getAffiliateInfo as getEVMBTCAffiliateInfo,
} from "../sample-data/evmbtc";
import {
  getTradeInfo as getSOLBTCTradeInfo,
  getRFQInfo as getSOLBTCRFQInfo,
  getScriptInfo as getSOLBTCScriptInfo,
  getAffiliateInfo as getSOLBTCAffiliateInfo,
  getMockPresign,
} from "../sample-data/solbtc";

import { randomTxId } from "../sample-data/utils";
import getTradeId from "../scripts/utils/others/getTradeId";
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
import { testMPCKP } from "../scripts/utils/bitcoin/btc";
import { getUserEphemeralKeys as getEVMBTCUserEphemeralKeys } from "../scripts/utils/evm/evm";
import { getEIP712Domain } from "../scripts/utils/evm/getEIP712Domain";

enum Status {
  OPERATING,
  SUSPENDED,
  SHUTDOWN,
}

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

describe("Router Contract Testing", () => {
  let admin: HardhatEthersSigner, evmUser: HardhatEthersSigner;
  let solver: HardhatEthersSigner, mpc: Wallet;
  let mpcNode1: HardhatEthersSigner, mpcNode2: HardhatEthersSigner;
  let accounts: HardhatEthersSigner[], vault: HardhatEthersSigner;
  let solUser: Keypair;

  let management: Management, clone: Management;
  let evmbtc: Core, btcevm: Core, btcsol: Core, solbtc: Core;
  let vaultRegistry: VaultRegistry, signerHelper: SignerHelper;
  let router: Router, weth: Token20;

  let btcTokenInfo: ManagementTypes.TokenInfoStruct;
  let ethTokenInfo: ManagementTypes.TokenInfoStruct;
  let solTokenInfo: ManagementTypes.TokenInfoStruct;

  let btcevmTradeInfo: CoreTypes.TradeInfoStruct[] = [];
  let btcevmAffiliateInfo: CoreTypes.AffiliateStruct[] = [];
  let btcevmRfqInfo: CoreTypes.RFQInfoStruct[] = [];
  let btcevmScriptInfo: CoreTypes.ScriptInfoStruct[] = [];
  let btcevmPresigns: CoreTypes.PresignStruct[][] = [];
  let btcevmTradeId: string[] = [],
    btcevmAmountOut: bigint[] = [],
    btcevmSessionId: bigint[] = [];
  let btcevmEphemeralL2Wallet: Wallet[] = [];

  let btcsolTradeInfo: CoreTypes.TradeInfoStruct[] = [];
  let btcsolAffiliateInfo: CoreTypes.AffiliateStruct[] = [];
  let btcsolRfqInfo: CoreTypes.RFQInfoStruct[] = [];
  let btcsolScriptInfo: CoreTypes.ScriptInfoStruct[] = [];
  let btcsolPresigns: CoreTypes.PresignStruct[][] = [];
  let btcsolTradeId: string[] = [],
    btcsolAmountOut: bigint[] = [],
    btcsolSessionId: bigint[] = [];
  let btcsolEphemeralL2Wallet: Wallet[] = [];

  let evmbtcTradeInfo: CoreTypes.TradeInfoStruct[] = [];
  let evmbtcAffiliateInfo: CoreTypes.AffiliateStruct[] = [];
  let evmbtcRfqInfo: CoreTypes.RFQInfoStruct[] = [];
  let evmbtcScriptInfo: CoreTypes.ScriptInfoStruct[] = [];
  let evmbtcPresigns: CoreTypes.PresignStruct[][] = [];
  let evmbtcTradeId: string[] = [],
    evmbtcAmountOut: bigint[] = [],
    evmbtcSessionId: bigint[] = [];
  let evmbtcEphemeralL2Wallet: Wallet[] = [];
  let evmbtcPFeeAmount: bigint[] = [];
  let evmbtcAFeeAmount: bigint[] = [];

  let solbtcTradeInfo: CoreTypes.TradeInfoStruct[] = [];
  let solbtcAffiliateInfo: CoreTypes.AffiliateStruct[] = [];
  let solbtcRfqInfo: CoreTypes.RFQInfoStruct[] = [];
  let solbtcScriptInfo: CoreTypes.ScriptInfoStruct[] = [];
  let solbtcPresigns: CoreTypes.PresignStruct[][] = [];
  let solbtcTradeId: string[] = [],
    solbtcAmountOut: bigint[] = [],
    solbtcSessionId: bigint[] = [];
  let solbtcEphemeralL2Wallet: Wallet[] = [];
  let solbtcPFeeAmount: bigint[] = [];
  let solbtcAFeeAmount: bigint[] = [];

  // [0,1,2]: btcevm
  // [3,4,5]: evmbtc
  // [6,7,8]: btcsol
  // [9,10,11]: solbtc
  let paymentTxId: string[] = [];
  let releaseTxHash: string[] = [];
  let domain: TypedDataDomain;

  const pFeeRate: bigint = BigInt(50);
  const evmChain = "ethereum-sepolia";
  const solChain = "solana-devnet";
  const solToken = "So11111111111111111111111111111111111111112";

  before(async () => {
    await network.provider.request({
      method: "hardhat_reset",
      params: [],
    });

    [admin, solver, evmUser, vault, mpcNode1, mpcNode2, ...accounts] =
      await ethers.getSigners();
    solUser = testUserKP;

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
    clone = await Management.deploy(admin.address, pFeeRate);

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

    //  Deploy VaultRegistry contract
    const Registry = (await ethers.getContractFactory(
      "VaultRegistry",
      admin,
    )) as VaultRegistry__factory;
    vaultRegistry = await Registry.deploy(await management.getAddress());

    //  Deploy BTCEVM contract
    const BTCEVM = (await ethers.getContractFactory(
      "BTCEVM",
      admin,
    )) as BTCEVM__factory;
    btcevm = await BTCEVM.deploy(await router.getAddress());

    //  Deploy BTCSOL contract
    const BTCSOL = (await ethers.getContractFactory(
      "BTCSOL",
      admin,
    )) as BTCSOL__factory;
    btcsol = await BTCSOL.deploy(await router.getAddress());

    //  Deploy EVMBTC contract
    const EVMBTC = (await ethers.getContractFactory(
      "EVMBTC",
      admin,
    )) as EVMBTC__factory;
    evmbtc = await EVMBTC.deploy(
      await router.getAddress(),
      await vaultRegistry.getAddress(),
    );

    //  Deploy SOLBTC contract
    const SOLBTC = (await ethers.getContractFactory(
      "SOLBTC",
      admin,
    )) as SOLBTC__factory;
    solbtc = await SOLBTC.deploy(await router.getAddress());

    //  set `maxAffiliateFeeRate`
    await btcevm.connect(admin).setMaxAffiliateFeeRate(MAX_AFFILIATE_FEE_RATE);
    await evmbtc.connect(admin).setMaxAffiliateFeeRate(MAX_AFFILIATE_FEE_RATE);
    await btcsol.connect(admin).setMaxAffiliateFeeRate(MAX_AFFILIATE_FEE_RATE);
    await solbtc.connect(admin).setMaxAffiliateFeeRate(MAX_AFFILIATE_FEE_RATE);

    //  generate eip-712 domain
    domain = await getEIP712Domain(await signerHelper.getAddress(), admin);

    const presignDomain: TypedDataDomain = {
      name: "Token Vault",
      version: "Version 1",
      chainId: (await provider.getNetwork()).chainId,
      verifyingContract: vault.address,
    };

    //  Whitelist Solver and MPC Node associated accounts
    await management.connect(admin).setSolver(solver.address, true);
    await management.connect(admin).setMPCNode(mpcNode1.address, true);
    await management.connect(admin).setMPCNode(mpcNode2.address, true);

    //  Generate MPC Wallet and transfer some test Ether
    const mpcPrivkey = hexlify(testMPCKP.privateKey as Uint8Array);
    mpc = new Wallet(mpcPrivkey, provider);

    //  Generate three BTCEVM Trade Data
    for (let i = 0; i < 3; i++) {
      btcevmSessionId.push(BigInt(keccak256(toUtf8Bytes(crypto.randomUUID()))));
      btcevmAffiliateInfo.push(getBTCEVMAffiliateInfo());
      btcevmTradeInfo.push(
        getBTCEVMTradeInfo(evmChain, await weth.getAddress(), evmUser.address),
      );
      btcevmRfqInfo.push(getBTCEVMRFQInfo());
      btcevmTradeId.push(
        getTradeId(
          btcevmSessionId[i],
          i % 2 == 0 ? solver.address : admin.address,
          btcevmTradeInfo[i],
        ),
      );
      const { scriptInfo: info, ephemeralL2Key: btcevmKey } =
        getBTCEVMScriptInfo(
          btcevmTradeId[i],
          Number(btcevmRfqInfo[i].tradeTimeout),
        );
      btcevmScriptInfo.push(info);
      btcevmEphemeralL2Wallet.push(new Wallet(btcevmKey, provider));
      btcevmPresigns.push(getBTCEVMPresigns());

      paymentTxId.push(randomTxId());
      releaseTxHash.push(randomTxId());
    }

    //  Generate three EVMBTC Trade Data
    for (let i = 0; i < 3; i++) {
      evmbtcSessionId.push(BigInt(keccak256(toUtf8Bytes(crypto.randomUUID()))));
      evmbtcTradeInfo.push(
        getEVMBTCTradeInfo(evmChain, await weth.getAddress(), evmUser.address),
      );
      evmbtcAffiliateInfo.push(getEVMBTCAffiliateInfo());
      evmbtcRfqInfo.push(getEVMBTCRFQInfo());
      evmbtcTradeId.push(
        getTradeId(
          evmbtcSessionId[i],
          i % 2 == 0 ? solver.address : admin.address,
          evmbtcTradeInfo[i],
        ),
      );
      const { ephemeralL2Key: evmbtcPrivkey } =
        await getEVMBTCUserEphemeralKeys(evmbtcTradeId[i]);
      const lockingVault = vault.address;
      const { scriptInfo: info } = await getEVMBTCScriptInfo(
        evmbtcTradeId[i],
        Number(evmbtcRfqInfo[i].tradeTimeout),
        evmUser.address,
        evmbtcTradeInfo[i].fromChain[1],
        evmbtcTradeInfo[i].fromChain[2],
        lockingVault,
      );
      evmbtcScriptInfo.push(info);
      evmbtcEphemeralL2Wallet.push(new Wallet(evmbtcPrivkey, provider));
      evmbtcPresigns.push(
        await getEVMBTCPresigns(
          evmbtcTradeId[i],
          evmbtcTradeInfo[i].amountIn as bigint,
          presignDomain,
        ),
      );

      evmbtcPFeeAmount.push(
        (BigInt(evmbtcTradeInfo[i].amountIn) * pFeeRate) / DENOM,
      );
      evmbtcAFeeAmount.push(
        (BigInt(evmbtcTradeInfo[i].amountIn) *
          BigInt(evmbtcAffiliateInfo[i].aggregatedValue)) /
          DENOM,
      );

      paymentTxId.push(randomTxId());
      releaseTxHash.push(randomTxId());
    }

    //  Generate three BTCSOL Trade Data
    for (let i = 0; i < 3; i++) {
      btcsolSessionId.push(BigInt(keccak256(toUtf8Bytes(crypto.randomUUID()))));
      btcsolAffiliateInfo.push(getBTCSOLAffiliateInfo());
      btcsolTradeInfo.push(
        getBTCSOLTradeInfo(solChain, solToken, solUser.publicKey.toString()),
      );
      btcsolRfqInfo.push(getBTCSOLRFQInfo());
      btcsolTradeId.push(
        getTradeId(
          btcsolSessionId[i],
          i % 2 == 0 ? solver.address : admin.address,
          btcsolTradeInfo[i],
        ),
      );
      const { scriptInfo: info, ephemeralL2Key: btcsolKey } =
        getBTCSOLScriptInfo(
          btcsolTradeId[i],
          Number(btcsolRfqInfo[i].tradeTimeout),
        );
      btcsolScriptInfo.push(info);
      btcsolEphemeralL2Wallet.push(new Wallet(btcsolKey, provider));
      btcsolPresigns.push(getBTCSOLPresigns());

      paymentTxId.push(randomTxId());
      releaseTxHash.push(randomTxId());
    }

    //  Generate three SOLBTC Trade Data
    for (let i = 0; i < 3; i++) {
      solbtcSessionId.push(BigInt(keccak256(toUtf8Bytes(crypto.randomUUID()))));
      solbtcTradeInfo.push(
        getSOLBTCTradeInfo(solChain, solToken, solUser.publicKey, 9),
      );
      solbtcAffiliateInfo.push(getSOLBTCAffiliateInfo());
      solbtcRfqInfo.push(getSOLBTCRFQInfo());
      solbtcTradeId.push(
        getTradeId(
          solbtcSessionId[i],
          i % 2 == 0 ? solver.address : admin.address,
          solbtcTradeInfo[i],
        ),
      );
      const { scriptInfo: info, ephemeralL2Key: solbtcKey } =
        await getSOLBTCScriptInfo(
          solbtcTradeId[i],
          Number(solbtcRfqInfo[i].tradeTimeout),
          solUser.publicKey.toBytes(),
        );
      solbtcScriptInfo.push(info);
      solbtcEphemeralL2Wallet.push(new Wallet(solbtcKey, provider));
      solbtcPresigns.push(getMockPresign(solbtcTradeId[i]));

      solbtcPFeeAmount.push(
        (BigInt(solbtcTradeInfo[i].amountIn) * pFeeRate) / DENOM,
      );
      solbtcAFeeAmount.push(
        (BigInt(solbtcTradeInfo[i].amountIn) *
          BigInt(solbtcAffiliateInfo[i].aggregatedValue)) /
          DENOM,
      );

      paymentTxId.push(randomTxId());
      releaseTxHash.push(randomTxId());
    }

    btcTokenInfo = {
      info: [
        btcevmTradeInfo[0].fromChain[2], // tokenId
        btcevmTradeInfo[0].fromChain[1], // networkId
        toUtf8Bytes("BTC"), // symbol
        toUtf8Bytes("https://example.com"),
        toUtf8Bytes("Bitcoin (BTC) - Bitcoin Testnet Token"),
      ],
      decimals: BigInt(8),
    };

    ethTokenInfo = {
      info: [
        evmbtcTradeInfo[0].fromChain[2], // tokenId
        evmbtcTradeInfo[0].fromChain[1], // networkId
        toUtf8Bytes("ETH"), // symbol
        toUtf8Bytes("https://example.com"),
        toUtf8Bytes("Ethereum (ETH) - Sepolia Base Token"),
      ],
      decimals: BigInt(18),
    };

    solTokenInfo = {
      info: [
        btcsolTradeInfo[0].toChain[2], // tokenId
        btcsolTradeInfo[0].toChain[1], // networkId
        toUtf8Bytes("SOL"), // symbol
        toUtf8Bytes(
          "https://explorer.solana.com/address/So11111111111111111111111111111111111111112?cluster=devnet",
        ),
        toUtf8Bytes("Wrapped SOL (SOL) - Wrapped SOL on Solana Devnet"),
      ],
      decimals: BigInt(9),
    };

    //  Set `fromNetworkId` and `toNetworkId` in the Management
    //  Note: `networkId` is registered if and only if
    //  there's at least one Token being supported
    await management.connect(admin).setToken(btcTokenInfo);
    await management.connect(admin).setToken(ethTokenInfo);
    await management.connect(admin).setToken(solTokenInfo);

    // set PMM
    await management
      .connect(admin)
      .setPMM(btcevmPresigns[0][0].pmmId, accounts[0].address);
    await management
      .connect(admin)
      .setPMM(btcevmPresigns[0][1].pmmId, accounts[1].address);

    //  set MPC Pubkey
    //  For Bitcoin and EVM, `mpcAssetPubkey` = `mpcL2Pubkey` => config is the same
    const mpcInfo: ManagementTypes.MPCInfoStruct = {
      mpcL2Address: mpc.address,
      expireTime: MAX_UINT64,
      mpcAssetPubkey: mpc.signingKey.compressedPublicKey,
      mpcL2Pubkey: mpc.signingKey.compressedPublicKey,
    };
    const mpcSOLInfo: ManagementTypes.MPCInfoStruct = {
      mpcL2Address: mpc.address,
      expireTime: MAX_UINT64,
      mpcAssetPubkey: solbtcScriptInfo[0].depositInfo[3],
      mpcL2Pubkey: mpc.signingKey.compressedPublicKey, //  For Solana, `mpcAssetPubkey` != `mpcL2Pubkey`
    };
    const prevExpireTime = BigInt(0);
    await management
      .connect(admin)
      .setMPCInfo(btcevmTradeInfo[0].fromChain[1], mpcInfo, prevExpireTime);
    await management
      .connect(admin)
      .setMPCInfo(evmbtcTradeInfo[0].fromChain[1], mpcInfo, prevExpireTime);
    await management
      .connect(admin)
      .setMPCInfo(solbtcTradeInfo[0].fromChain[1], mpcSOLInfo, prevExpireTime);

    //  set Vault
    await vaultRegistry.setVault(
      vault.address,
      evmbtcTradeInfo[0].fromChain[1],
      evmbtcTradeInfo[0].fromChain[2],
    );
  });

  it("Should be able to check the initialized settings of Router contract", async () => {
    expect(await router.management()).deep.equal(await management.getAddress());
    expect(await router.SIGNER()).deep.equal(await signerHelper.getAddress());
  });

  describe("setManagement() functional testing", async () => {
    it("Should revert when unauthorized account attempts to update new Management contract", async () => {
      expect(await router.management()).deep.equal(
        await management.getAddress(),
      );

      await expect(
        router.connect(accounts[0]).setManagement(accounts[0].address),
      ).to.be.revertedWithCustomError(router, "Unauthorized");

      expect(await router.management()).deep.equal(
        await management.getAddress(),
      );
    });

    it("Should revert when Solver account attempts to update new Management contract", async () => {
      expect(await router.management()).deep.equal(
        await management.getAddress(),
      );

      await expect(
        router.connect(solver).setManagement(solver.address),
      ).to.be.revertedWithCustomError(router, "Unauthorized");

      expect(await router.management()).deep.equal(
        await management.getAddress(),
      );
    });

    it("Should revert when MPC's associated account attempts to update new Management contract", async () => {
      expect(await router.management()).deep.equal(
        await management.getAddress(),
      );

      await expect(
        router.connect(mpc).setManagement(mpc.address),
      ).to.be.revertedWithCustomError(router, "Unauthorized");

      expect(await router.management()).deep.equal(
        await management.getAddress(),
      );
    });

    it("Should revert when Owner updates 0x0 as the Management contract's address", async () => {
      expect(await router.management()).deep.equal(
        await management.getAddress(),
      );

      await expect(
        router.connect(admin).setManagement(ZeroAddress),
      ).to.be.revertedWithCustomError(router, "AddressZero");

      expect(await router.management()).deep.equal(
        await management.getAddress(),
      );
    });

    it("Should succeed when Owner updates a new Management contract's address", async () => {
      expect(await router.management()).deep.equal(
        await management.getAddress(),
      );

      await router.connect(admin).setManagement(await clone.getAddress());

      expect(await router.management()).deep.equal(await clone.getAddress());
    });

    it("Should succeed when Owner changes back to previous Management contract", async () => {
      expect(await router.management()).deep.equal(await clone.getAddress());

      await router.connect(admin).setManagement(await management.getAddress());

      expect(await router.management()).deep.equal(
        await management.getAddress(),
      );
    });
  });

  describe("setRoute() functional testing", async () => {
    it("Should revert when Non-Owner tries to setRoute", async () => {
      const core = await btcevm.getAddress();
      expect(
        (
          await router.getHandler(
            btcevmTradeInfo[0].fromChain[1],
            btcevmTradeInfo[0].toChain[1],
          )
        ).handler,
      ).deep.eq(ZeroAddress);

      await expect(
        router
          .connect(accounts[0])
          .setRoute(
            core,
            btcevmTradeInfo[0].fromChain[1],
            btcevmTradeInfo[0].toChain[1],
          ),
      ).to.be.revertedWithCustomError(router, "Unauthorized");

      expect(
        (
          await router.getHandler(
            btcevmTradeInfo[0].fromChain[1],
            btcevmTradeInfo[0].toChain[1],
          )
        ).handler,
      ).deep.eq(ZeroAddress);
    });

    it("Should revert when Owner calls to setRoute, but Core contract is 0x0", async () => {
      await expect(
        router
          .connect(admin)
          .setRoute(
            ZeroAddress,
            btcevmTradeInfo[0].fromChain[1],
            btcevmTradeInfo[0].toChain[1],
          ),
      ).to.be.revertedWithCustomError(router, "AddressZero");
    });

    it("Should revert when Owner calls to setRoute, but route not supported - fromChain", async () => {
      const invalidFromChain = toUtf8Bytes("Invalid_from_chain");
      const core = await btcevm.getAddress();
      expect(
        (
          await router.getHandler(
            invalidFromChain,
            btcevmTradeInfo[0].toChain[1],
          )
        ).handler,
      ).deep.eq(ZeroAddress);

      await expect(
        router
          .connect(admin)
          .setRoute(core, invalidFromChain, btcevmTradeInfo[0].toChain[1]),
      ).to.be.revertedWithCustomError(router, "RouteNotSupported");

      expect(
        (
          await router.getHandler(
            invalidFromChain,
            btcevmTradeInfo[0].toChain[1],
          )
        ).handler,
      ).deep.eq(ZeroAddress);
    });

    it("Should revert when Owner calls to setRoute, but route not supported - toChain", async () => {
      const invalidToChain = toUtf8Bytes("Invalid_to_chain");
      const core = await btcevm.getAddress();
      expect(
        (
          await router.getHandler(
            btcevmTradeInfo[0].fromChain[1],
            invalidToChain,
          )
        ).handler,
      ).deep.eq(ZeroAddress);

      await expect(
        router
          .connect(admin)
          .setRoute(core, btcevmTradeInfo[0].fromChain[1], invalidToChain),
      ).to.be.revertedWithCustomError(router, "RouteNotSupported");

      expect(
        (
          await router.getHandler(
            btcevmTradeInfo[0].fromChain[1],
            invalidToChain,
          )
        ).handler,
      ).deep.eq(ZeroAddress);
    });

    it("Should succeed when Owner calls to setRoute - BTCEVM", async () => {
      const core = await btcevm.getAddress();
      const version = await router.version(core);
      expect(
        (
          await router.getHandler(
            btcevmTradeInfo[0].fromChain[1],
            btcevmTradeInfo[0].toChain[1],
          )
        ).handler,
      ).deep.eq(ZeroAddress);

      const tx = router
        .connect(admin)
        .setRoute(
          core,
          btcevmTradeInfo[0].fromChain[1],
          btcevmTradeInfo[0].toChain[1],
        );

      await expect(tx)
        .to.emit(router, "UpdatedRoute")
        .withArgs(
          core,
          version + BigInt(1),
          hexlify(btcevmTradeInfo[0].fromChain[1]),
          hexlify(btcevmTradeInfo[0].toChain[1]),
        );

      expect(
        (
          await router.getHandler(
            btcevmTradeInfo[0].fromChain[1],
            btcevmTradeInfo[0].toChain[1],
          )
        ).handler,
      ).deep.eq(core);
    });

    it("Should revert when Owner sets route with same Core address as current route", async () => {
      const core = await btcevm.getAddress();
      const version = await router.version(core);
      expect(
        (
          await router.getHandler(
            btcevmTradeInfo[0].fromChain[1],
            btcevmTradeInfo[0].toChain[1],
          )
        ).handler,
      ).deep.eq(core);

      await expect(
        router
          .connect(admin)
          .setRoute(
            core,
            btcevmTradeInfo[0].fromChain[1],
            btcevmTradeInfo[0].toChain[1],
          ),
      ).to.be.revertedWithCustomError(router, "RegisteredAlready");

      expect(
        (
          await router.getHandler(
            btcevmTradeInfo[0].fromChain[1],
            btcevmTradeInfo[0].toChain[1],
          )
        ).handler,
      ).deep.eq(core);
      expect(await router.version(core)).deep.eq(version);
    });

    it("Should succeed when Owner calls to setRoute - EVMBTC", async () => {
      const core = await evmbtc.getAddress();
      const version = await router.version(core);
      expect(
        (
          await router.getHandler(
            evmbtcTradeInfo[0].fromChain[1],
            evmbtcTradeInfo[0].toChain[1],
          )
        ).handler,
      ).deep.eq(ZeroAddress);

      const tx = router
        .connect(admin)
        .setRoute(
          core,
          evmbtcTradeInfo[0].fromChain[1],
          evmbtcTradeInfo[0].toChain[1],
        );

      await expect(tx)
        .to.emit(router, "UpdatedRoute")
        .withArgs(
          core,
          version + BigInt(1),
          hexlify(evmbtcTradeInfo[0].fromChain[1]),
          hexlify(evmbtcTradeInfo[0].toChain[1]),
        );

      expect(
        (
          await router.getHandler(
            evmbtcTradeInfo[0].fromChain[1],
            evmbtcTradeInfo[0].toChain[1],
          )
        ).handler,
      ).deep.eq(core);
    });

    it("Should succeed when Owner calls to setRoute - BTCSOL", async () => {
      const core = await btcsol.getAddress();
      const version = await router.version(core);
      expect(
        (
          await router.getHandler(
            btcsolTradeInfo[0].fromChain[1],
            btcsolTradeInfo[0].toChain[1],
          )
        ).handler,
      ).deep.eq(ZeroAddress);

      const tx = router
        .connect(admin)
        .setRoute(
          core,
          btcsolTradeInfo[0].fromChain[1],
          btcsolTradeInfo[0].toChain[1],
        );

      await expect(tx)
        .to.emit(router, "UpdatedRoute")
        .withArgs(
          core,
          version + BigInt(1),
          hexlify(btcsolTradeInfo[0].fromChain[1]),
          hexlify(btcsolTradeInfo[0].toChain[1]),
        );

      expect(
        (
          await router.getHandler(
            btcsolTradeInfo[0].fromChain[1],
            btcsolTradeInfo[0].toChain[1],
          )
        ).handler,
      ).deep.eq(core);
    });

    it("Should succeed when Owner calls to setRoute - SOLBTC", async () => {
      const core = await solbtc.getAddress();
      const version = await router.version(core);
      expect(
        (
          await router.getHandler(
            solbtcTradeInfo[0].fromChain[1],
            solbtcTradeInfo[0].toChain[1],
          )
        ).handler,
      ).deep.eq(ZeroAddress);

      const tx = router
        .connect(admin)
        .setRoute(
          core,
          solbtcTradeInfo[0].fromChain[1],
          solbtcTradeInfo[0].toChain[1],
        );

      await expect(tx)
        .to.emit(router, "UpdatedRoute")
        .withArgs(
          core,
          version + BigInt(1),
          hexlify(solbtcTradeInfo[0].fromChain[1]),
          hexlify(solbtcTradeInfo[0].toChain[1]),
        );

      expect(
        (
          await router.getHandler(
            solbtcTradeInfo[0].fromChain[1],
            solbtcTradeInfo[0].toChain[1],
          )
        ).handler,
      ).deep.eq(core);
    });
  });

  describe("Core functional testing", async () => {
    describe("submitTrade() functional testing", async () => {
      describe("BTCEVM - submitTrade() testing", async () => {
        it("BTCEVM - Should succeed Solver submits the first trade", async () => {
          const tradeData: CoreTypes.TradeDataStruct = {
            sessionId: btcevmSessionId[0],
            tradeInfo: btcevmTradeInfo[0],
            scriptInfo: btcevmScriptInfo[0],
          };

          const tx = router
            .connect(solver)
            .submitTrade(
              btcevmTradeId[0],
              tradeData,
              btcevmAffiliateInfo[0],
              btcevmPresigns[0],
            );

          await expect(tx).to.emit(router, "SubmitTradeInfo").withArgs(
            solver.address, // sender
            btcevmTradeId[0],
          );
          await expect(tx)
            .to.emit(btcevm, "TradeInfoSubmitted")
            .withArgs(
              await router.getAddress(), // forwarder
              solver.address, // requester
              btcevmTradeId[0],
              btcevmTradeInfo[0].fromChain[1], //  fromChain
              btcevmScriptInfo[0].depositInfo[1], // depositTxId
            );

          const expectedTradeData = [
            btcevmSessionId[0],
            [
              //  tradeInfo
              btcevmTradeInfo[0].amountIn,
              btcevmTradeInfo[0].fromChain.map((data: BytesLike) =>
                hexlify(data),
              ),
              btcevmTradeInfo[0].toChain.map((data: BytesLike) =>
                hexlify(data),
              ),
            ],
            [
              //  scriptInfo
              [
                hexlify(btcevmScriptInfo[0].depositInfo[0]),
                hexlify(btcevmScriptInfo[0].depositInfo[1]),
                ...btcevmScriptInfo[0].depositInfo.slice(2),
              ], //  depositInfo
              btcevmScriptInfo[0].userEphemeralL2Address, //  userEphemeralL2Address
              btcevmScriptInfo[0].scriptTimeout, //  scriptTimeout
            ],
          ];
          const expectedPresigns = [
            [
              btcevmPresigns[0][0].pmmId,
              hexlify(btcevmPresigns[0][0].pmmRecvAddress),
              [hexlify(btcevmPresigns[0][0].presigns[0])],
            ],
            [
              btcevmPresigns[0][1].pmmId,
              hexlify(btcevmPresigns[0][1].pmmRecvAddress),
              [hexlify(btcevmPresigns[0][1].presigns[0])],
            ],
          ];
          expect(await router.getCurrentStage(btcevmTradeId[0])).deep.eq(
            STAGE.CONFIRM_DEPOSIT,
          );
          expect(await router.getTradeData(btcevmTradeId[0])).deep.eq(
            Object.values(expectedTradeData),
          );
          expect(await router.getPresigns(btcevmTradeId[0])).deep.eq(
            Object.values(expectedPresigns),
          );
          expect(await router.getFeeDetails(btcevmTradeId[0])).deep.eq([
            BigInt(0),
            BigInt(0), // pFeeAmount
            BigInt(0), // aFeeAmount
            pFeeRate,
            btcevmAffiliateInfo[0].aggregatedValue, //  aFeeRate
          ]);
          expect(await router.getAffiliateInfo(btcevmTradeId[0])).deep.eq(
            Object.values(btcevmAffiliateInfo[0]),
          );
        });

        it("BTCEVM - Should succeed Solver submits the second trade", async () => {
          //  temporarily set "admin" as Solver role
          await management.connect(admin).setSolver(admin.address, true);

          const tradeData: CoreTypes.TradeDataStruct = {
            sessionId: btcevmSessionId[1],
            tradeInfo: btcevmTradeInfo[1],
            scriptInfo: btcevmScriptInfo[1],
          };

          const tx = router
            .connect(admin)
            .submitTrade(
              btcevmTradeId[1],
              tradeData,
              btcevmAffiliateInfo[1],
              btcevmPresigns[1],
            );

          await expect(tx).to.emit(router, "SubmitTradeInfo").withArgs(
            admin.address, // sender
            btcevmTradeId[1],
          );
          await expect(tx)
            .to.emit(btcevm, "TradeInfoSubmitted")
            .withArgs(
              await router.getAddress(), // forwarder
              admin.address, // requester
              btcevmTradeId[1],
              btcevmTradeInfo[1].fromChain[1], //  fromChain
              btcevmScriptInfo[1].depositInfo[1], // depositTxId
            );

          const expectedTradeData = [
            btcevmSessionId[1],
            [
              //  tradeInfo
              btcevmTradeInfo[1].amountIn,
              btcevmTradeInfo[1].fromChain.map((data: BytesLike) =>
                hexlify(data),
              ),
              btcevmTradeInfo[1].toChain.map((data: BytesLike) =>
                hexlify(data),
              ),
            ],
            [
              //  scriptInfo
              [
                hexlify(btcevmScriptInfo[1].depositInfo[0]),
                hexlify(btcevmScriptInfo[1].depositInfo[1]),
                ...btcevmScriptInfo[1].depositInfo.slice(2),
              ], //  depositInfo
              btcevmScriptInfo[1].userEphemeralL2Address, //  userEphemeralL2Address
              btcevmScriptInfo[1].scriptTimeout, //  scriptTimeout
            ],
          ];
          const expectedPresigns = [
            [
              btcevmPresigns[1][0].pmmId,
              hexlify(btcevmPresigns[1][0].pmmRecvAddress),
              [hexlify(btcevmPresigns[1][0].presigns[0])],
            ],
            [
              btcevmPresigns[1][1].pmmId,
              hexlify(btcevmPresigns[1][1].pmmRecvAddress),
              [hexlify(btcevmPresigns[1][1].presigns[0])],
            ],
          ];
          expect(await router.getCurrentStage(btcevmTradeId[1])).deep.eq(
            STAGE.CONFIRM_DEPOSIT,
          );
          expect(await router.getTradeData(btcevmTradeId[1])).deep.eq(
            Object.values(expectedTradeData),
          );
          expect(await router.getPresigns(btcevmTradeId[1])).deep.eq(
            Object.values(expectedPresigns),
          );
          expect(await router.getFeeDetails(btcevmTradeId[1])).deep.eq([
            BigInt(0),
            BigInt(0), // pFeeAmount
            BigInt(0), // aFeeAmount
            pFeeRate,
            btcevmAffiliateInfo[1].aggregatedValue, //  aFeeRate
          ]);
          expect(await router.getAffiliateInfo(btcevmTradeId[1])).deep.eq(
            Object.values(btcevmAffiliateInfo[1]),
          );

          //  set back to normal
          await management.connect(admin).setSolver(admin.address, false);
        });

        it("BTCEVM - Should succeed Solver submits the third trade", async () => {
          const tradeData: CoreTypes.TradeDataStruct = {
            sessionId: btcevmSessionId[2],
            tradeInfo: btcevmTradeInfo[2],
            scriptInfo: btcevmScriptInfo[2],
          };

          const tx = router
            .connect(solver)
            .submitTrade(
              btcevmTradeId[2],
              tradeData,
              btcevmAffiliateInfo[2],
              btcevmPresigns[2],
            );

          await expect(tx).to.emit(router, "SubmitTradeInfo").withArgs(
            solver.address, // sender
            btcevmTradeId[2],
          );
          await expect(tx)
            .to.emit(btcevm, "TradeInfoSubmitted")
            .withArgs(
              await router.getAddress(), // forwarder
              solver.address, // requester
              btcevmTradeId[2],
              btcevmTradeInfo[2].fromChain[1], //  fromChain
              btcevmScriptInfo[2].depositInfo[1], // depositTxId
            );

          const expectedTradeData = [
            btcevmSessionId[2],
            [
              //  tradeInfo
              btcevmTradeInfo[2].amountIn,
              btcevmTradeInfo[2].fromChain.map((data: BytesLike) =>
                hexlify(data),
              ),
              btcevmTradeInfo[2].toChain.map((data: BytesLike) =>
                hexlify(data),
              ),
            ],
            [
              //  scriptInfo
              [
                hexlify(btcevmScriptInfo[2].depositInfo[0]),
                hexlify(btcevmScriptInfo[2].depositInfo[1]),
                ...btcevmScriptInfo[2].depositInfo.slice(2),
              ], //  depositInfo
              btcevmScriptInfo[2].userEphemeralL2Address, //  userEphemeralL2Address
              btcevmScriptInfo[2].scriptTimeout, //  scriptTimeout
            ],
          ];
          const expectedPresigns = [
            [
              btcevmPresigns[2][0].pmmId,
              hexlify(btcevmPresigns[2][0].pmmRecvAddress),
              [hexlify(btcevmPresigns[2][0].presigns[0])],
            ],
            [
              btcevmPresigns[2][1].pmmId,
              hexlify(btcevmPresigns[2][1].pmmRecvAddress),
              [hexlify(btcevmPresigns[2][1].presigns[0])],
            ],
          ];
          expect(await router.getCurrentStage(btcevmTradeId[2])).deep.eq(
            STAGE.CONFIRM_DEPOSIT,
          );
          expect(await router.getTradeData(btcevmTradeId[2])).deep.eq(
            Object.values(expectedTradeData),
          );
          expect(await router.getPresigns(btcevmTradeId[2])).deep.eq(
            Object.values(expectedPresigns),
          );
          expect(await router.getFeeDetails(btcevmTradeId[2])).deep.eq([
            BigInt(0),
            BigInt(0), // pFeeAmount
            BigInt(0), // aFeeAmount
            pFeeRate,
            btcevmAffiliateInfo[2].aggregatedValue, //  aFeeRate
          ]);
          expect(await router.getAffiliateInfo(btcevmTradeId[2])).deep.eq(
            Object.values(btcevmAffiliateInfo[2]),
          );
        });
      });

      describe("EVMBTC - submitTrade() testing", async () => {
        it("EVMBTC - Should succeed Solver submits the first trade", async () => {
          const tradeData: CoreTypes.TradeDataStruct = {
            sessionId: evmbtcSessionId[0],
            tradeInfo: evmbtcTradeInfo[0],
            scriptInfo: evmbtcScriptInfo[0],
          };

          const tx = router
            .connect(solver)
            .submitTrade(
              evmbtcTradeId[0],
              tradeData,
              evmbtcAffiliateInfo[0],
              evmbtcPresigns[0],
            );

          await expect(tx).to.emit(router, "SubmitTradeInfo").withArgs(
            solver.address, // sender
            evmbtcTradeId[0],
          );
          await expect(tx)
            .to.emit(evmbtc, "TradeInfoSubmitted")
            .withArgs(
              await router.getAddress(), // forwarder
              solver.address, // requester
              evmbtcTradeId[0],
              evmbtcTradeInfo[0].fromChain[1], //  fromChain
              evmbtcScriptInfo[0].depositInfo[1], // depositTxId
            );

          const expectedTradeData = [
            evmbtcSessionId[0],
            [
              //  tradeInfo
              evmbtcTradeInfo[0].amountIn,
              evmbtcTradeInfo[0].fromChain.map((data: BytesLike) =>
                hexlify(data),
              ),
              evmbtcTradeInfo[0].toChain.map((data: BytesLike) =>
                hexlify(data),
              ),
            ],
            [
              //  scriptInfo
              [
                evmbtcScriptInfo[0].depositInfo[0],
                hexlify(evmbtcScriptInfo[0].depositInfo[1]),
                ...evmbtcScriptInfo[0].depositInfo.slice(2),
              ], //  depositInfo
              evmbtcScriptInfo[0].userEphemeralL2Address, //  userEphemeralL2Address
              evmbtcScriptInfo[0].scriptTimeout, //  scriptTimeout
            ],
          ];
          const expectedPresigns = [
            [
              evmbtcPresigns[0][0].pmmId,
              hexlify(evmbtcPresigns[0][0].pmmRecvAddress),
              [hexlify(evmbtcPresigns[0][0].presigns[0])],
            ],
            [
              evmbtcPresigns[0][1].pmmId,
              hexlify(evmbtcPresigns[0][1].pmmRecvAddress),
              [hexlify(evmbtcPresigns[0][1].presigns[0])],
            ],
          ];
          expect(await router.getCurrentStage(evmbtcTradeId[0])).deep.eq(
            STAGE.CONFIRM_DEPOSIT,
          );
          expect(await router.getTradeData(evmbtcTradeId[0])).deep.eq(
            Object.values(expectedTradeData),
          );
          expect(await router.getPresigns(evmbtcTradeId[0])).deep.eq(
            Object.values(expectedPresigns),
          );
          expect(await router.getFeeDetails(evmbtcTradeId[0])).deep.eq([
            evmbtcPFeeAmount[0] + evmbtcAFeeAmount[0],
            evmbtcPFeeAmount[0], // pFeeAmount
            evmbtcAFeeAmount[0], // aFeeAmount
            pFeeRate,
            evmbtcAffiliateInfo[0].aggregatedValue, //  aFeeRate
          ]);
          expect(await router.getAffiliateInfo(evmbtcTradeId[0])).deep.eq(
            Object.values(evmbtcAffiliateInfo[0]),
          );
        });

        it("EVMBTC - Should succeed Solver submits the second trade", async () => {
          //  temporarily set "admin" as Solver role
          await management.connect(admin).setSolver(admin.address, true);

          const tradeData: CoreTypes.TradeDataStruct = {
            sessionId: evmbtcSessionId[1],
            tradeInfo: evmbtcTradeInfo[1],
            scriptInfo: evmbtcScriptInfo[1],
          };

          const tx = router
            .connect(admin)
            .submitTrade(
              evmbtcTradeId[1],
              tradeData,
              evmbtcAffiliateInfo[1],
              evmbtcPresigns[1],
            );

          await expect(tx).to.emit(router, "SubmitTradeInfo").withArgs(
            admin.address, // sender
            evmbtcTradeId[1],
          );
          await expect(tx)
            .to.emit(evmbtc, "TradeInfoSubmitted")
            .withArgs(
              await router.getAddress(), // forwarder
              admin.address, // requester
              evmbtcTradeId[1],
              evmbtcTradeInfo[1].fromChain[1], //  fromChain
              evmbtcScriptInfo[1].depositInfo[1], // depositTxId
            );

          const expectedTradeData = [
            evmbtcSessionId[1],
            [
              //  tradeInfo
              evmbtcTradeInfo[1].amountIn,
              evmbtcTradeInfo[1].fromChain.map((data: BytesLike) =>
                hexlify(data),
              ),
              evmbtcTradeInfo[1].toChain.map((data: BytesLike) =>
                hexlify(data),
              ),
            ],
            [
              //  scriptInfo
              [
                evmbtcScriptInfo[1].depositInfo[0],
                hexlify(evmbtcScriptInfo[1].depositInfo[1]),
                ...evmbtcScriptInfo[1].depositInfo.slice(2),
              ], //  depositInfo
              evmbtcScriptInfo[1].userEphemeralL2Address, //  userEphemeralL2Address
              evmbtcScriptInfo[1].scriptTimeout, //  scriptTimeout
            ],
          ];
          const expectedPresigns = [
            [
              evmbtcPresigns[1][0].pmmId,
              hexlify(evmbtcPresigns[1][0].pmmRecvAddress),
              [hexlify(evmbtcPresigns[1][0].presigns[0])],
            ],
            [
              evmbtcPresigns[1][1].pmmId,
              hexlify(evmbtcPresigns[1][1].pmmRecvAddress),
              [hexlify(evmbtcPresigns[1][1].presigns[0])],
            ],
          ];
          expect(await router.getCurrentStage(evmbtcTradeId[1])).deep.eq(
            STAGE.CONFIRM_DEPOSIT,
          );
          expect(await router.getTradeData(evmbtcTradeId[1])).deep.eq(
            Object.values(expectedTradeData),
          );
          expect(await router.getPresigns(evmbtcTradeId[1])).deep.eq(
            Object.values(expectedPresigns),
          );
          expect(await router.getFeeDetails(evmbtcTradeId[1])).deep.eq([
            evmbtcPFeeAmount[1] + evmbtcAFeeAmount[1],
            evmbtcPFeeAmount[1], // pFeeAmount
            evmbtcAFeeAmount[1], // aFeeAmount
            pFeeRate,
            evmbtcAffiliateInfo[1].aggregatedValue, //  aFeeRate
          ]);
          expect(await router.getAffiliateInfo(evmbtcTradeId[1])).deep.eq(
            Object.values(evmbtcAffiliateInfo[1]),
          );

          //  set back to normal
          await management.connect(admin).setSolver(admin.address, false);
        });

        it("EVMBTC - Should succeed Solver submits the third trade", async () => {
          const tradeData: CoreTypes.TradeDataStruct = {
            sessionId: evmbtcSessionId[2],
            tradeInfo: evmbtcTradeInfo[2],
            scriptInfo: evmbtcScriptInfo[2],
          };

          const tx = router
            .connect(solver)
            .submitTrade(
              evmbtcTradeId[2],
              tradeData,
              evmbtcAffiliateInfo[2],
              evmbtcPresigns[2],
            );

          await expect(tx).to.emit(router, "SubmitTradeInfo").withArgs(
            solver.address, // sender
            evmbtcTradeId[2],
          );
          await expect(tx)
            .to.emit(evmbtc, "TradeInfoSubmitted")
            .withArgs(
              await router.getAddress(), // forwarder
              solver.address, // requester
              evmbtcTradeId[2],
              evmbtcTradeInfo[2].fromChain[1], //  fromChain
              evmbtcScriptInfo[2].depositInfo[1], // depositTxId
            );

          const expectedTradeData = [
            evmbtcSessionId[2],
            [
              //  tradeInfo
              evmbtcTradeInfo[2].amountIn,
              evmbtcTradeInfo[2].fromChain.map((data: BytesLike) =>
                hexlify(data),
              ),
              evmbtcTradeInfo[2].toChain.map((data: BytesLike) =>
                hexlify(data),
              ),
            ],
            [
              //  scriptInfo
              [
                evmbtcScriptInfo[2].depositInfo[0],
                hexlify(evmbtcScriptInfo[2].depositInfo[1]),
                ...evmbtcScriptInfo[2].depositInfo.slice(2),
              ], //  depositInfo
              evmbtcScriptInfo[2].userEphemeralL2Address, //  userEphemeralL2Address
              evmbtcScriptInfo[2].scriptTimeout, //  scriptTimeout
            ],
          ];
          const expectedPresigns = [
            [
              evmbtcPresigns[2][0].pmmId,
              hexlify(evmbtcPresigns[2][0].pmmRecvAddress),
              [hexlify(evmbtcPresigns[2][0].presigns[0])],
            ],
            [
              evmbtcPresigns[2][1].pmmId,
              hexlify(evmbtcPresigns[2][1].pmmRecvAddress),
              [hexlify(evmbtcPresigns[2][1].presigns[0])],
            ],
          ];
          expect(await router.getCurrentStage(evmbtcTradeId[2])).deep.eq(
            STAGE.CONFIRM_DEPOSIT,
          );
          expect(await router.getTradeData(evmbtcTradeId[2])).deep.eq(
            Object.values(expectedTradeData),
          );
          expect(await router.getPresigns(evmbtcTradeId[2])).deep.eq(
            Object.values(expectedPresigns),
          );
          expect(await router.getFeeDetails(evmbtcTradeId[2])).deep.eq([
            evmbtcPFeeAmount[2] + evmbtcAFeeAmount[2],
            evmbtcPFeeAmount[2], // pFeeAmount
            evmbtcAFeeAmount[2], // aFeeAmount
            pFeeRate,
            evmbtcAffiliateInfo[2].aggregatedValue, //  aFeeRate
          ]);
          expect(await router.getAffiliateInfo(evmbtcTradeId[2])).deep.eq(
            Object.values(evmbtcAffiliateInfo[2]),
          );
        });
      });

      describe("BTCSOL - submitTrade() testing", async () => {
        it("BTCSOL - Should succeed when Solver submits the first trade", async () => {
          const tradeData: CoreTypes.TradeDataStruct = {
            sessionId: btcsolSessionId[0],
            tradeInfo: btcsolTradeInfo[0],
            scriptInfo: btcsolScriptInfo[0],
          };

          const tx = router
            .connect(solver)
            .submitTrade(
              btcsolTradeId[0],
              tradeData,
              btcsolAffiliateInfo[0],
              btcsolPresigns[0],
            );

          await expect(tx)
            .to.emit(btcsol, "TradeInfoSubmitted")
            .withArgs(
              await router.getAddress(), // forwarder
              solver.address, // requester
              btcsolTradeId[0],
              btcsolTradeInfo[0].fromChain[1], //  fromChain
              btcsolScriptInfo[0].depositInfo[1], // depositTxId
            );

          const expectedTradeData = [
            btcsolSessionId[0],
            //  tradeInfo
            [
              btcsolTradeInfo[0].amountIn,
              btcsolTradeInfo[0].fromChain.map((data) => hexlify(data)),
              btcsolTradeInfo[0].toChain.map((data) => hexlify(data)),
            ],
            //  scriptInfo
            [
              btcsolScriptInfo[0].depositInfo.map((data) => hexlify(data)), //  depositInfo
              btcsolScriptInfo[0].userEphemeralL2Address, //  userEphemeralL2Address
              btcsolScriptInfo[0].scriptTimeout, //  scriptTimeout
            ],
          ];
          const expectedPresigns = [
            [
              btcsolPresigns[0][0].pmmId,
              hexlify(btcsolPresigns[0][0].pmmRecvAddress),
              [hexlify(btcsolPresigns[0][0].presigns[0])],
            ],
            [
              btcsolPresigns[0][1].pmmId,
              hexlify(btcsolPresigns[0][1].pmmRecvAddress),
              [hexlify(btcsolPresigns[0][1].presigns[0])],
            ],
          ];

          expect(await router.getCurrentStage(btcsolTradeId[0])).deep.eq(
            STAGE.CONFIRM_DEPOSIT,
          );
          expect(await router.getTradeData(btcsolTradeId[0])).deep.eq(
            Object.values(expectedTradeData),
          );
          expect(await router.getPresigns(btcsolTradeId[0])).deep.eq(
            Object.values(expectedPresigns),
          );
          expect(await router.getFeeDetails(btcsolTradeId[0])).deep.eq([
            BigInt(0),
            BigInt(0), // pFeeAmount
            BigInt(0), // aFeeAmount
            pFeeRate,
            btcsolAffiliateInfo[0].aggregatedValue, //  aFeeRate
          ]);
          expect(await router.getAffiliateInfo(btcsolTradeId[0])).deep.eq(
            Object.values(btcsolAffiliateInfo[0]),
          );
        });

        it("BTCSOL - Should succeed when Solver submits the second trade", async () => {
          //  temporarily set "admin" as Solver role
          await management.connect(admin).setSolver(admin.address, true);

          const tradeData: CoreTypes.TradeDataStruct = {
            sessionId: btcsolSessionId[1],
            tradeInfo: btcsolTradeInfo[1],
            scriptInfo: btcsolScriptInfo[1],
          };

          const tx = router
            .connect(admin)
            .submitTrade(
              btcsolTradeId[1],
              tradeData,
              btcsolAffiliateInfo[1],
              btcsolPresigns[1],
            );

          await expect(tx)
            .to.emit(btcsol, "TradeInfoSubmitted")
            .withArgs(
              await router.getAddress(), // forwarder
              admin.address, // requester
              btcsolTradeId[1],
              btcsolTradeInfo[1].fromChain[1], //  fromChain
              btcsolScriptInfo[1].depositInfo[1], // depositTxId
            );

          const expectedTradeData = [
            btcsolSessionId[1],
            //  tradeInfo
            [
              btcsolTradeInfo[1].amountIn,
              btcsolTradeInfo[1].fromChain.map((data) => hexlify(data)),
              btcsolTradeInfo[1].toChain.map((data) => hexlify(data)),
            ],
            //  scriptInfo
            [
              btcsolScriptInfo[1].depositInfo.map((data) => hexlify(data)), //  depositInfo
              btcsolScriptInfo[1].userEphemeralL2Address, //  userEphemeralL2Address
              btcsolScriptInfo[1].scriptTimeout, //  scriptTimeout
            ],
          ];
          const expectedPresigns = [
            [
              btcsolPresigns[1][0].pmmId,
              hexlify(btcsolPresigns[1][0].pmmRecvAddress),
              [hexlify(btcsolPresigns[1][0].presigns[0])],
            ],
            [
              btcsolPresigns[1][1].pmmId,
              hexlify(btcsolPresigns[1][1].pmmRecvAddress),
              [hexlify(btcsolPresigns[1][1].presigns[0])],
            ],
          ];

          expect(await router.getCurrentStage(btcsolTradeId[1])).deep.eq(
            STAGE.CONFIRM_DEPOSIT,
          );
          expect(await router.getTradeData(btcsolTradeId[1])).deep.eq(
            Object.values(expectedTradeData),
          );
          expect(await router.getPresigns(btcsolTradeId[1])).deep.eq(
            Object.values(expectedPresigns),
          );
          expect(await router.getFeeDetails(btcsolTradeId[1])).deep.eq([
            BigInt(0),
            BigInt(0), // pFeeAmount
            BigInt(0), // aFeeAmount
            pFeeRate,
            btcsolAffiliateInfo[1].aggregatedValue, //  aFeeRate
          ]);
          expect(await router.getAffiliateInfo(btcsolTradeId[1])).deep.eq(
            Object.values(btcsolAffiliateInfo[1]),
          );

          //  set back to normal
          await management.connect(admin).setSolver(admin.address, false);
        });

        it("BTCSOL - Should succeed when Solver submits the third trade", async () => {
          const tradeData: CoreTypes.TradeDataStruct = {
            sessionId: btcsolSessionId[2],
            tradeInfo: btcsolTradeInfo[2],
            scriptInfo: btcsolScriptInfo[2],
          };

          const tx = router
            .connect(solver)
            .submitTrade(
              btcsolTradeId[2],
              tradeData,
              btcsolAffiliateInfo[2],
              btcsolPresigns[2],
            );

          await expect(tx)
            .to.emit(btcsol, "TradeInfoSubmitted")
            .withArgs(
              await router.getAddress(), // forwarder
              solver.address, // requester
              btcsolTradeId[2],
              btcsolTradeInfo[2].fromChain[1], //  fromChain
              btcsolScriptInfo[2].depositInfo[1], // depositTxId
            );

          const expectedTradeData = [
            btcsolSessionId[2],
            //  tradeInfo
            [
              btcsolTradeInfo[2].amountIn,
              btcsolTradeInfo[2].fromChain.map((data) => hexlify(data)),
              btcsolTradeInfo[2].toChain.map((data) => hexlify(data)),
            ],
            //  scriptInfo
            [
              btcsolScriptInfo[2].depositInfo.map((data) => hexlify(data)), //  depositInfo
              btcsolScriptInfo[2].userEphemeralL2Address, //  userEphemeralL2Address
              btcsolScriptInfo[2].scriptTimeout, //  scriptTimeout
            ],
          ];
          const expectedPresigns = [
            [
              btcsolPresigns[2][0].pmmId,
              hexlify(btcsolPresigns[2][0].pmmRecvAddress),
              [hexlify(btcsolPresigns[2][0].presigns[0])],
            ],
            [
              btcsolPresigns[2][1].pmmId,
              hexlify(btcsolPresigns[2][1].pmmRecvAddress),
              [hexlify(btcsolPresigns[2][1].presigns[0])],
            ],
          ];

          expect(await router.getCurrentStage(btcsolTradeId[2])).deep.eq(
            STAGE.CONFIRM_DEPOSIT,
          );
          expect(await router.getTradeData(btcsolTradeId[2])).deep.eq(
            Object.values(expectedTradeData),
          );
          expect(await router.getPresigns(btcsolTradeId[2])).deep.eq(
            Object.values(expectedPresigns),
          );
          expect(await router.getFeeDetails(btcsolTradeId[2])).deep.eq([
            BigInt(0),
            BigInt(0), // pFeeAmount
            BigInt(0), // aFeeAmount
            pFeeRate,
            btcsolAffiliateInfo[2].aggregatedValue, //  aFeeRate
          ]);
          expect(await router.getAffiliateInfo(btcsolTradeId[2])).deep.eq(
            Object.values(btcsolAffiliateInfo[2]),
          );
        });
      });

      describe("SOLBTC - submitTrade() testing", async () => {
        it("SOLBTC - Should succeed when Solver submits the first trade", async () => {
          const tradeData: CoreTypes.TradeDataStruct = {
            sessionId: solbtcSessionId[0],
            tradeInfo: solbtcTradeInfo[0],
            scriptInfo: solbtcScriptInfo[0],
          };

          const tx = router
            .connect(solver)
            .submitTrade(
              solbtcTradeId[0],
              tradeData,
              solbtcAffiliateInfo[0],
              solbtcPresigns[0],
            );

          await expect(tx)
            .to.emit(solbtc, "TradeInfoSubmitted")
            .withArgs(
              await router.getAddress(), // forwarder
              solver.address, // requester
              solbtcTradeId[0],
              solbtcTradeInfo[0].fromChain[1], //  fromChain
              solbtcScriptInfo[0].depositInfo[1], // depositTxId
            );

          const expectedTradeData = [
            solbtcSessionId[0],
            //  tradeInfo
            [
              solbtcTradeInfo[0].amountIn,
              solbtcTradeInfo[0].fromChain.map((data) => hexlify(data)),
              solbtcTradeInfo[0].toChain.map((data) => hexlify(data)),
            ],
            //  scriptInfo
            [
              solbtcScriptInfo[0].depositInfo.map((data) => hexlify(data)), //  depositInfo
              solbtcScriptInfo[0].userEphemeralL2Address, //  userEphemeralL2Address
              solbtcScriptInfo[0].scriptTimeout, //  scriptTimeout
            ],
          ];
          const expectedPresigns = [
            [
              solbtcPresigns[0][0].pmmId,
              hexlify(solbtcPresigns[0][0].pmmRecvAddress),
              [hexlify(solbtcPresigns[0][0].presigns[0])],
            ],
            [
              solbtcPresigns[0][1].pmmId,
              hexlify(solbtcPresigns[0][1].pmmRecvAddress),
              [hexlify(solbtcPresigns[0][1].presigns[0])],
            ],
          ];

          expect(await router.getCurrentStage(solbtcTradeId[0])).deep.eq(
            STAGE.CONFIRM_DEPOSIT,
          );
          expect(await router.getTradeData(solbtcTradeId[0])).deep.eq(
            Object.values(expectedTradeData),
          );
          expect(await router.getPresigns(solbtcTradeId[0])).deep.eq(
            Object.values(expectedPresigns),
          );
          expect(await router.getFeeDetails(solbtcTradeId[0])).deep.eq([
            solbtcPFeeAmount[0] + solbtcAFeeAmount[0],
            solbtcPFeeAmount[0], // pFeeAmount
            solbtcAFeeAmount[0], // aFeeAmount
            pFeeRate,
            solbtcAffiliateInfo[0].aggregatedValue, //  aFeeRate
          ]);
          expect(await router.getAffiliateInfo(solbtcTradeId[0])).deep.eq(
            Object.values(solbtcAffiliateInfo[0]),
          );
        });

        it("SOLBTC - Should succeed when Solver submits the second trade", async () => {
          //  temporarily set "admin" as Solver role
          await management.connect(admin).setSolver(admin.address, true);

          const tradeData: CoreTypes.TradeDataStruct = {
            sessionId: solbtcSessionId[1],
            tradeInfo: solbtcTradeInfo[1],
            scriptInfo: solbtcScriptInfo[1],
          };

          const tx = router
            .connect(admin)
            .submitTrade(
              solbtcTradeId[1],
              tradeData,
              solbtcAffiliateInfo[1],
              solbtcPresigns[1],
            );

          await expect(tx)
            .to.emit(solbtc, "TradeInfoSubmitted")
            .withArgs(
              await router.getAddress(), // forwarder
              admin.address, // requester
              solbtcTradeId[1],
              solbtcTradeInfo[1].fromChain[1], //  fromChain
              solbtcScriptInfo[1].depositInfo[1], // depositTxId
            );

          const expectedTradeData = [
            solbtcSessionId[1],
            //  tradeInfo
            [
              solbtcTradeInfo[1].amountIn,
              solbtcTradeInfo[1].fromChain.map((data) => hexlify(data)),
              solbtcTradeInfo[1].toChain.map((data) => hexlify(data)),
            ],
            //  scriptInfo
            [
              solbtcScriptInfo[1].depositInfo.map((data) => hexlify(data)), //  depositInfo
              solbtcScriptInfo[1].userEphemeralL2Address, //  userEphemeralL2Address
              solbtcScriptInfo[1].scriptTimeout, //  scriptTimeout
            ],
          ];
          const expectedPresigns = [
            [
              solbtcPresigns[1][0].pmmId,
              hexlify(solbtcPresigns[1][0].pmmRecvAddress),
              [hexlify(solbtcPresigns[1][0].presigns[0])],
            ],
            [
              solbtcPresigns[1][1].pmmId,
              hexlify(solbtcPresigns[1][1].pmmRecvAddress),
              [hexlify(solbtcPresigns[1][1].presigns[0])],
            ],
          ];

          expect(await router.getCurrentStage(solbtcTradeId[1])).deep.eq(
            STAGE.CONFIRM_DEPOSIT,
          );
          expect(await router.getTradeData(solbtcTradeId[1])).deep.eq(
            Object.values(expectedTradeData),
          );
          expect(await router.getPresigns(solbtcTradeId[1])).deep.eq(
            Object.values(expectedPresigns),
          );
          expect(await router.getFeeDetails(solbtcTradeId[1])).deep.eq([
            solbtcPFeeAmount[1] + solbtcAFeeAmount[1],
            solbtcPFeeAmount[1], // pFeeAmount
            solbtcAFeeAmount[1], // aFeeAmount
            pFeeRate,
            solbtcAffiliateInfo[1].aggregatedValue, //  aFeeRate
          ]);
          expect(await router.getAffiliateInfo(solbtcTradeId[1])).deep.eq(
            Object.values(solbtcAffiliateInfo[1]),
          );

          //  set back to normal
          await management.connect(admin).setSolver(admin.address, false);
        });

        it("SOLBTC - Should succeed when Solver submits the third trade", async () => {
          const tradeData: CoreTypes.TradeDataStruct = {
            sessionId: solbtcSessionId[2],
            tradeInfo: solbtcTradeInfo[2],
            scriptInfo: solbtcScriptInfo[2],
          };

          const tx = router
            .connect(solver)
            .submitTrade(
              solbtcTradeId[2],
              tradeData,
              solbtcAffiliateInfo[2],
              solbtcPresigns[2],
            );

          await expect(tx)
            .to.emit(solbtc, "TradeInfoSubmitted")
            .withArgs(
              await router.getAddress(), // forwarder
              solver.address, // requester
              solbtcTradeId[2],
              solbtcTradeInfo[2].fromChain[1], //  fromChain
              solbtcScriptInfo[2].depositInfo[1], // depositTxId
            );

          const expectedTradeData = [
            solbtcSessionId[2],
            //  tradeInfo
            [
              solbtcTradeInfo[2].amountIn,
              solbtcTradeInfo[2].fromChain.map((data) => hexlify(data)),
              solbtcTradeInfo[2].toChain.map((data) => hexlify(data)),
            ],
            //  scriptInfo
            [
              solbtcScriptInfo[2].depositInfo.map((data) => hexlify(data)), //  depositInfo
              solbtcScriptInfo[2].userEphemeralL2Address, //  userEphemeralL2Address
              solbtcScriptInfo[2].scriptTimeout, //  scriptTimeout
            ],
          ];
          const expectedPresigns = [
            [
              solbtcPresigns[2][0].pmmId,
              hexlify(solbtcPresigns[2][0].pmmRecvAddress),
              [hexlify(solbtcPresigns[2][0].presigns[0])],
            ],
            [
              solbtcPresigns[2][1].pmmId,
              hexlify(solbtcPresigns[2][1].pmmRecvAddress),
              [hexlify(solbtcPresigns[2][1].presigns[0])],
            ],
          ];

          expect(await router.getCurrentStage(solbtcTradeId[2])).deep.eq(
            STAGE.CONFIRM_DEPOSIT,
          );
          expect(await router.getTradeData(solbtcTradeId[2])).deep.eq(
            Object.values(expectedTradeData),
          );
          expect(await router.getPresigns(solbtcTradeId[2])).deep.eq(
            Object.values(expectedPresigns),
          );
          expect(await router.getFeeDetails(solbtcTradeId[2])).deep.eq([
            solbtcPFeeAmount[2] + solbtcAFeeAmount[2],
            solbtcPFeeAmount[2], // pFeeAmount
            solbtcAFeeAmount[2], // aFeeAmount
            pFeeRate,
            solbtcAffiliateInfo[2].aggregatedValue, //  aFeeRate
          ]);
          expect(await router.getAffiliateInfo(solbtcTradeId[2])).deep.eq(
            Object.values(solbtcAffiliateInfo[2]),
          );
        });
      });
    });

    describe("confirmDeposit() functional testing", async () => {
      describe("BTCEVM - confirmDeposit() testing", async () => {
        it("BTCEVM - Should succeed when MPC Node submits the first trade's deposit confirmation", async () => {
          const amountIn = btcevmTradeInfo[0].amountIn as bigint;
          const depositedFromList: BytesLike[] = [
            toUtf8Bytes("Bitcoin_Account_1"),
            toUtf8Bytes("Bitcoin_Account_2"),
            toUtf8Bytes("Bitcoin_Account_3"),
          ];
          const infoHash = getDepositConfirmationHash(
            amountIn,
            btcevmTradeInfo[0].fromChain,
            btcevmScriptInfo[0].depositInfo[1],
            depositedFromList,
          );
          const signature: string = await getSignature(
            mpc,
            btcevmTradeId[0],
            infoHash,
            SignatureType.ConfirmDeposit,
            domain,
          );

          const tx = router
            .connect(mpcNode1)
            .confirmDeposit(btcevmTradeId[0], signature, depositedFromList);
          await expect(tx)
            .to.emit(router, "ConfirmDeposit")
            .withArgs(
              mpcNode1.address,
              btcevmTradeId[0],
              pFeeRate,
              btcevmAffiliateInfo[0].aggregatedValue,
              depositedFromList.map((data) => hexlify(data)),
            );
          await expect(tx)
            .to.emit(btcevm, "DepositConfirmed")
            .withArgs(
              await router.getAddress(),
              mpc.address,
              btcevmTradeId[0],
              (btcevmAffiliateInfo[0].aggregatedValue as bigint) + pFeeRate,
            );

          const expectedList = depositedFromList.map((data) => hexlify(data));
          expect(await router.getCurrentStage(btcevmTradeId[0])).deep.eq(
            STAGE.SELECT_PMM,
          );
          expect(await router.getDepositAddressList(btcevmTradeId[0])).deep.eq(
            expectedList,
          );
        });

        it("BTCEVM - Should succeed when MPC Node submits the second trade's deposit confirmation", async () => {
          const amountIn = btcevmTradeInfo[1].amountIn as bigint;
          const depositedFromList: BytesLike[] = [
            toUtf8Bytes("Bitcoin_Account_1"),
            toUtf8Bytes("Bitcoin_Account_2"),
            toUtf8Bytes("Bitcoin_Account_3"),
          ];
          const infoHash = getDepositConfirmationHash(
            amountIn,
            btcevmTradeInfo[1].fromChain,
            btcevmScriptInfo[1].depositInfo[1],
            depositedFromList,
          );
          const signature: string = await getSignature(
            mpc,
            btcevmTradeId[1],
            infoHash,
            SignatureType.ConfirmDeposit,
            domain,
          );

          const tx = router
            .connect(mpcNode1)
            .confirmDeposit(btcevmTradeId[1], signature, depositedFromList);
          await expect(tx)
            .to.emit(router, "ConfirmDeposit")
            .withArgs(
              mpcNode1.address,
              btcevmTradeId[1],
              pFeeRate,
              btcevmAffiliateInfo[1].aggregatedValue,
              depositedFromList.map((data) => hexlify(data)),
            );
          await expect(tx)
            .to.emit(btcevm, "DepositConfirmed")
            .withArgs(
              await router.getAddress(),
              mpc.address,
              btcevmTradeId[1],
              (btcevmAffiliateInfo[1].aggregatedValue as bigint) + pFeeRate,
            );

          const expectedList = depositedFromList.map((data) => hexlify(data));
          expect(await router.getCurrentStage(btcevmTradeId[1])).deep.eq(
            STAGE.SELECT_PMM,
          );
          expect(await router.getDepositAddressList(btcevmTradeId[1])).deep.eq(
            expectedList,
          );
        });

        it("BTCEVM - Should succeed when MPC Node submits the third trade's deposit confirmation", async () => {
          const amountIn = btcevmTradeInfo[2].amountIn as bigint;
          const depositedFromList: BytesLike[] = [
            toUtf8Bytes("Bitcoin_Account_1"),
            toUtf8Bytes("Bitcoin_Account_2"),
            toUtf8Bytes("Bitcoin_Account_3"),
          ];
          const infoHash = getDepositConfirmationHash(
            amountIn,
            btcevmTradeInfo[2].fromChain,
            btcevmScriptInfo[2].depositInfo[1],
            depositedFromList,
          );
          const signature: string = await getSignature(
            mpc,
            btcevmTradeId[2],
            infoHash,
            SignatureType.ConfirmDeposit,
            domain,
          );

          const tx = router
            .connect(mpcNode1)
            .confirmDeposit(btcevmTradeId[2], signature, depositedFromList);
          await expect(tx)
            .to.emit(router, "ConfirmDeposit")
            .withArgs(
              mpcNode1.address,
              btcevmTradeId[2],
              pFeeRate,
              btcevmAffiliateInfo[2].aggregatedValue,
              depositedFromList.map((data) => hexlify(data)),
            );
          await expect(tx)
            .to.emit(btcevm, "DepositConfirmed")
            .withArgs(
              await router.getAddress(),
              mpc.address,
              btcevmTradeId[2],
              (btcevmAffiliateInfo[2].aggregatedValue as bigint) + pFeeRate,
            );

          const expectedList = depositedFromList.map((data) => hexlify(data));
          expect(await router.getCurrentStage(btcevmTradeId[2])).deep.eq(
            STAGE.SELECT_PMM,
          );
          expect(await router.getDepositAddressList(btcevmTradeId[2])).deep.eq(
            expectedList,
          );
        });
      });

      describe("EVMBTC - confirmDeposit() testing", async () => {
        it("EVMBTC - Should succeed when MPC Node submits the first trade's deposit confirmation", async () => {
          const amountIn = evmbtcTradeInfo[0].amountIn as bigint;
          const depositedFromList: BytesLike[] = [hexlify(evmUser.address)];
          const infoHash = getDepositConfirmationHash(
            amountIn,
            evmbtcTradeInfo[0].fromChain,
            evmbtcScriptInfo[0].depositInfo[1],
            depositedFromList,
          );
          const signature: string = await getSignature(
            mpc,
            evmbtcTradeId[0],
            infoHash,
            SignatureType.ConfirmDeposit,
            domain,
          );

          const tx = router
            .connect(mpcNode1)
            .confirmDeposit(evmbtcTradeId[0], signature, depositedFromList);
          await expect(tx)
            .to.emit(router, "ConfirmDeposit")
            .withArgs(
              mpcNode1.address,
              evmbtcTradeId[0],
              pFeeRate,
              evmbtcAffiliateInfo[0].aggregatedValue,
              depositedFromList.map((data) => hexlify(data)),
            );
          await expect(tx)
            .to.emit(evmbtc, "DepositConfirmed")
            .withArgs(
              await router.getAddress(),
              mpc.address,
              evmbtcTradeId[0],
              (evmbtcAffiliateInfo[0].aggregatedValue as bigint) + pFeeRate,
            );

          const expectedList = depositedFromList.map((data) => hexlify(data));
          expect(await router.getCurrentStage(evmbtcTradeId[0])).deep.eq(
            STAGE.SELECT_PMM,
          );
          expect(await evmbtc.depositAddressList(evmbtcTradeId[0])).deep.eq(
            expectedList,
          );
        });

        it("EVMBTC - Should succeed when MPC Node submits the second trade's deposit confirmation", async () => {
          const amountIn = evmbtcTradeInfo[1].amountIn as bigint;
          const depositedFromList: BytesLike[] = [hexlify(evmUser.address)];
          const infoHash = getDepositConfirmationHash(
            amountIn,
            evmbtcTradeInfo[1].fromChain,
            evmbtcScriptInfo[1].depositInfo[1],
            depositedFromList,
          );
          const signature: string = await getSignature(
            mpc,
            evmbtcTradeId[1],
            infoHash,
            SignatureType.ConfirmDeposit,
            domain,
          );

          const tx = router
            .connect(mpcNode1)
            .confirmDeposit(evmbtcTradeId[1], signature, depositedFromList);
          await expect(tx)
            .to.emit(router, "ConfirmDeposit")
            .withArgs(
              mpcNode1.address,
              evmbtcTradeId[1],
              pFeeRate,
              evmbtcAffiliateInfo[1].aggregatedValue,
              depositedFromList.map((data) => hexlify(data)),
            );
          await expect(tx)
            .to.emit(evmbtc, "DepositConfirmed")
            .withArgs(
              await router.getAddress(),
              mpc.address,
              evmbtcTradeId[1],
              (evmbtcAffiliateInfo[0].aggregatedValue as bigint) + pFeeRate,
            );

          const expectedList = depositedFromList.map((data) => hexlify(data));
          expect(await router.getCurrentStage(evmbtcTradeId[1])).deep.eq(
            STAGE.SELECT_PMM,
          );
          expect(await evmbtc.depositAddressList(evmbtcTradeId[1])).deep.eq(
            expectedList,
          );
        });

        it("EVMBTC - Should succeed when MPC Node submits the third trade's deposit confirmation", async () => {
          const amountIn = evmbtcTradeInfo[2].amountIn as bigint;
          const depositedFromList: BytesLike[] = [hexlify(evmUser.address)];
          const infoHash = getDepositConfirmationHash(
            amountIn,
            evmbtcTradeInfo[2].fromChain,
            evmbtcScriptInfo[2].depositInfo[1],
            depositedFromList,
          );
          const signature: string = await getSignature(
            mpc,
            evmbtcTradeId[2],
            infoHash,
            SignatureType.ConfirmDeposit,
            domain,
          );

          const tx = router
            .connect(mpcNode1)
            .confirmDeposit(evmbtcTradeId[2], signature, depositedFromList);
          await expect(tx)
            .to.emit(router, "ConfirmDeposit")
            .withArgs(
              mpcNode1.address,
              evmbtcTradeId[2],
              pFeeRate,
              evmbtcAffiliateInfo[2].aggregatedValue,
              depositedFromList.map((data) => hexlify(data)),
            );
          await expect(tx)
            .to.emit(evmbtc, "DepositConfirmed")
            .withArgs(
              await router.getAddress(),
              mpc.address,
              evmbtcTradeId[2],
              (evmbtcAffiliateInfo[0].aggregatedValue as bigint) + pFeeRate,
            );

          const expectedList = depositedFromList.map((data) => hexlify(data));
          expect(await router.getCurrentStage(evmbtcTradeId[2])).deep.eq(
            STAGE.SELECT_PMM,
          );
          expect(await evmbtc.depositAddressList(evmbtcTradeId[2])).deep.eq(
            expectedList,
          );
        });
      });

      describe("BTCSOL - confirmDeposit() testing", async () => {
        it("BTCSOL - Should succeed when MPC Node submits the first trade's deposit confirmation", async () => {
          const amountIn = btcsolTradeInfo[0].amountIn as bigint;
          const depositedFromList: BytesLike[] = [
            toUtf8Bytes("Bitcoin_Account_1"),
            toUtf8Bytes("Bitcoin_Account_2"),
            toUtf8Bytes("Bitcoin_Account_3"),
          ];
          const infoHash = getDepositConfirmationHash(
            amountIn,
            btcsolTradeInfo[0].fromChain,
            btcsolScriptInfo[0].depositInfo[1],
            depositedFromList,
          );
          const signature: string = await getSignature(
            mpc,
            btcsolTradeId[0],
            infoHash,
            SignatureType.ConfirmDeposit,
            domain,
          );

          const tx = router
            .connect(mpcNode1)
            .confirmDeposit(btcsolTradeId[0], signature, depositedFromList);
          await expect(tx)
            .to.emit(router, "ConfirmDeposit")
            .withArgs(
              mpcNode1.address,
              btcsolTradeId[0],
              pFeeRate,
              btcsolAffiliateInfo[0].aggregatedValue,
              depositedFromList.map((data) => hexlify(data)),
            );
          await expect(tx)
            .to.emit(btcsol, "DepositConfirmed")
            .withArgs(
              await router.getAddress(),
              mpc.address,
              btcsolTradeId[0],
              (btcsolAffiliateInfo[0].aggregatedValue as bigint) + pFeeRate,
            );

          const expectedList = depositedFromList.map((data) => hexlify(data));
          expect(await router.getCurrentStage(btcsolTradeId[0])).deep.eq(
            STAGE.SELECT_PMM,
          );
          expect(await router.getDepositAddressList(btcsolTradeId[0])).deep.eq(
            expectedList,
          );
        });

        it("BTCSOL - Should succeed when MPC Node submits the second trade's deposit confirmation", async () => {
          const amountIn = btcsolTradeInfo[1].amountIn as bigint;
          const depositedFromList: BytesLike[] = [
            toUtf8Bytes("Bitcoin_Account_1"),
            toUtf8Bytes("Bitcoin_Account_2"),
            toUtf8Bytes("Bitcoin_Account_3"),
          ];
          const infoHash = getDepositConfirmationHash(
            amountIn,
            btcsolTradeInfo[1].fromChain,
            btcsolScriptInfo[1].depositInfo[1],
            depositedFromList,
          );
          const signature: string = await getSignature(
            mpc,
            btcsolTradeId[1],
            infoHash,
            SignatureType.ConfirmDeposit,
            domain,
          );

          const tx = router
            .connect(mpcNode1)
            .confirmDeposit(btcsolTradeId[1], signature, depositedFromList);
          await expect(tx)
            .to.emit(router, "ConfirmDeposit")
            .withArgs(
              mpcNode1.address,
              btcsolTradeId[1],
              pFeeRate,
              btcsolAffiliateInfo[1].aggregatedValue,
              depositedFromList.map((data) => hexlify(data)),
            );
          await expect(tx)
            .to.emit(btcsol, "DepositConfirmed")
            .withArgs(
              await router.getAddress(),
              mpc.address,
              btcsolTradeId[1],
              (btcsolAffiliateInfo[1].aggregatedValue as bigint) + pFeeRate,
            );

          const expectedList = depositedFromList.map((data) => hexlify(data));
          expect(await router.getCurrentStage(btcsolTradeId[1])).deep.eq(
            STAGE.SELECT_PMM,
          );
          expect(await router.getDepositAddressList(btcsolTradeId[1])).deep.eq(
            expectedList,
          );
        });

        it("BTCSOL - Should succeed when MPC Node submits the third trade's deposit confirmation", async () => {
          const amountIn = btcsolTradeInfo[2].amountIn as bigint;
          const depositedFromList: BytesLike[] = [
            toUtf8Bytes("Bitcoin_Account_1"),
            toUtf8Bytes("Bitcoin_Account_2"),
            toUtf8Bytes("Bitcoin_Account_3"),
          ];
          const infoHash = getDepositConfirmationHash(
            amountIn,
            btcsolTradeInfo[2].fromChain,
            btcsolScriptInfo[2].depositInfo[1],
            depositedFromList,
          );
          const signature: string = await getSignature(
            mpc,
            btcsolTradeId[2],
            infoHash,
            SignatureType.ConfirmDeposit,
            domain,
          );

          const tx = router
            .connect(mpcNode1)
            .confirmDeposit(btcsolTradeId[2], signature, depositedFromList);
          await expect(tx)
            .to.emit(router, "ConfirmDeposit")
            .withArgs(
              mpcNode1.address,
              btcsolTradeId[2],
              pFeeRate,
              btcsolAffiliateInfo[2].aggregatedValue,
              depositedFromList.map((data) => hexlify(data)),
            );
          await expect(tx)
            .to.emit(btcsol, "DepositConfirmed")
            .withArgs(
              await router.getAddress(),
              mpc.address,
              btcsolTradeId[2],
              (btcsolAffiliateInfo[2].aggregatedValue as bigint) + pFeeRate,
            );

          const expectedList = depositedFromList.map((data) => hexlify(data));
          expect(await router.getCurrentStage(btcsolTradeId[2])).deep.eq(
            STAGE.SELECT_PMM,
          );
          expect(await router.getDepositAddressList(btcsolTradeId[2])).deep.eq(
            expectedList,
          );
        });
      });

      describe("SOLBTC - confirmDeposit() testing", async () => {
        it("SOLBTC - Should succeed when MPC Nodes submits the first trade's deposit confirmation", async () => {
          const amountIn = solbtcTradeInfo[0].amountIn as bigint;
          const depositedFromList: BytesLike[] = [solUser.publicKey.toBytes()];
          const infoHash = getDepositConfirmationHash(
            amountIn,
            solbtcTradeInfo[0].fromChain,
            solbtcScriptInfo[0].depositInfo[1],
            depositedFromList,
          );
          const signature: string = await getSignature(
            mpc,
            solbtcTradeId[0],
            infoHash,
            SignatureType.ConfirmDeposit,
            domain,
          );

          const tx = router
            .connect(mpcNode1)
            .confirmDeposit(solbtcTradeId[0], signature, depositedFromList);

          await expect(tx)
            .to.emit(solbtc, "DepositConfirmed")
            .withArgs(
              await router.getAddress(),
              mpc.address,
              solbtcTradeId[0],
              (solbtcAffiliateInfo[0].aggregatedValue as bigint) + pFeeRate,
            );

          const expectedList = depositedFromList.map((data) => hexlify(data));
          expect(await router.getCurrentStage(solbtcTradeId[0])).deep.eq(
            STAGE.SELECT_PMM,
          );
          expect(await router.getDepositAddressList(solbtcTradeId[0])).deep.eq(
            expectedList,
          );
        });

        it("SOLBTC - Should succeed when MPC Nodes submits the second trade's deposit confirmation", async () => {
          const amountIn = solbtcTradeInfo[1].amountIn as bigint;
          const depositedFromList: BytesLike[] = [solUser.publicKey.toBytes()];
          const infoHash = getDepositConfirmationHash(
            amountIn,
            solbtcTradeInfo[1].fromChain,
            solbtcScriptInfo[1].depositInfo[1],
            depositedFromList,
          );
          const signature: string = await getSignature(
            mpc,
            solbtcTradeId[1],
            infoHash,
            SignatureType.ConfirmDeposit,
            domain,
          );

          const tx = router
            .connect(mpcNode1)
            .confirmDeposit(solbtcTradeId[1], signature, depositedFromList);

          await expect(tx)
            .to.emit(solbtc, "DepositConfirmed")
            .withArgs(
              await router.getAddress(),
              mpc.address,
              solbtcTradeId[1],
              (solbtcAffiliateInfo[1].aggregatedValue as bigint) + pFeeRate,
            );

          const expectedList = depositedFromList.map((data) => hexlify(data));
          expect(await router.getCurrentStage(solbtcTradeId[1])).deep.eq(
            STAGE.SELECT_PMM,
          );
          expect(await router.getDepositAddressList(solbtcTradeId[1])).deep.eq(
            expectedList,
          );
        });

        it("SOLBTC - Should succeed when MPC Nodes submits the third trade's deposit confirmation", async () => {
          const amountIn = solbtcTradeInfo[2].amountIn as bigint;
          const depositedFromList: BytesLike[] = [solUser.publicKey.toBytes()];
          const infoHash = getDepositConfirmationHash(
            amountIn,
            solbtcTradeInfo[2].fromChain,
            solbtcScriptInfo[2].depositInfo[1],
            depositedFromList,
          );
          const signature: string = await getSignature(
            mpc,
            solbtcTradeId[2],
            infoHash,
            SignatureType.ConfirmDeposit,
            domain,
          );

          const tx = router
            .connect(mpcNode1)
            .confirmDeposit(solbtcTradeId[2], signature, depositedFromList);

          await expect(tx)
            .to.emit(solbtc, "DepositConfirmed")
            .withArgs(
              await router.getAddress(),
              mpc.address,
              solbtcTradeId[2],
              (solbtcAffiliateInfo[2].aggregatedValue as bigint) + pFeeRate,
            );

          const expectedList = depositedFromList.map((data) => hexlify(data));
          expect(await router.getCurrentStage(solbtcTradeId[2])).deep.eq(
            STAGE.SELECT_PMM,
          );
          expect(await router.getDepositAddressList(solbtcTradeId[2])).deep.eq(
            expectedList,
          );
        });
      });
    });

    describe("selectPMM() functional testing", async () => {
      describe("BTCEVM - selectPMM() testing", async () => {
        it("BTCEVM - Should succeed when Solver submits the first trade's pmm selection", async () => {
          const timestamp = await getBlockTimestamp(provider);
          const expiry = BigInt(timestamp + 2 * 3600);
          btcevmAmountOut[0] =
            (btcevmRfqInfo[0].minAmountOut as bigint) +
            parseUnits("1000", "ether");
          const selectedPMMId = btcevmPresigns[0][0].pmmId;
          const pmmRecvAddress = btcevmPresigns[0][0].pmmRecvAddress;
          const selectedPMMInfoHash: string = getSelectPMMHash(
            selectedPMMId,
            pmmRecvAddress,
            btcevmTradeInfo[0].toChain[1],
            btcevmTradeInfo[0].toChain[2],
            btcevmAmountOut[0],
            expiry,
          );
          let signature: string = await getSignature(
            accounts[0],
            btcevmTradeId[0],
            selectedPMMInfoHash,
            SignatureType.SelectPMM,
            domain,
          );
          const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
          const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
            amountOut: btcevmAmountOut[0],
            selectedPMMId: selectedPMMId,
            info: info,
            sigExpiry: expiry,
          };

          //  RFQ Info
          const rfqInfoHash: string = getRFQHash(
            btcevmRfqInfo[0].minAmountOut as bigint,
            btcevmRfqInfo[0].tradeTimeout as bigint,
            btcevmAffiliateInfo[0],
          );
          signature = await getSignature(
            btcevmEphemeralL2Wallet[0],
            btcevmTradeId[0],
            rfqInfoHash,
            SignatureType.RFQ,
            domain,
          );
          btcevmRfqInfo[0].rfqInfoSignature = signature;

          //  PMM Selection Info: Selected PMM Info + RFQ Info
          const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
            rfqInfo: btcevmRfqInfo[0],
            pmmInfo: pmmInfo,
          };
          const pFeeAmount = (pFeeRate * btcevmAmountOut[0]) / DENOM;
          const aFeeAmount =
            ((btcevmAffiliateInfo[0].aggregatedValue as bigint) *
              btcevmAmountOut[0]) /
            DENOM;

          const tx = router
            .connect(solver)
            .selectPMM(btcevmTradeId[0], pmmSelectionInfo);
          await expect(tx)
            .to.emit(router, "SelectPMM")
            .withArgs(solver.address, btcevmTradeId[0]);
          await expect(tx)
            .to.emit(btcevm, "SelectedPMM")
            .withArgs(
              await router.getAddress(),
              solver.address,
              btcevmTradeId[0],
              pmmSelectionInfo.pmmInfo.selectedPMMId,
            );

          const expectedPMMSelectionInfo = [
            [
              btcevmRfqInfo[0].minAmountOut,
              btcevmRfqInfo[0].tradeTimeout,
              btcevmRfqInfo[0].rfqInfoSignature,
            ],
            [
              pmmInfo.amountOut,
              pmmInfo.selectedPMMId,
              [hexlify(info[0]), hexlify(info[1])],
              pmmInfo.sigExpiry,
            ],
          ];
          expect(await router.getCurrentStage(btcevmTradeId[0])).deep.eq(
            STAGE.MAKE_PAYMENT,
          );
          expect(await router.getPMMSelection(btcevmTradeId[0])).deep.eq(
            expectedPMMSelectionInfo,
          );
          expect(await router.getFeeDetails(btcevmTradeId[0])).deep.eq([
            pFeeAmount + aFeeAmount, //  totalAmount
            pFeeAmount,
            aFeeAmount,
            pFeeRate,
            btcevmAffiliateInfo[0].aggregatedValue,
          ]);
        });

        it("BTCEVM - Should succeed when Solver submits the second trade's pmm selection", async () => {
          //  temporarily set "admin" as Solver role
          await management.connect(admin).setSolver(admin.address, true);

          const timestamp = await getBlockTimestamp(provider);
          const expiry = BigInt(timestamp + 2 * 3600);
          btcevmAmountOut[1] =
            (btcevmRfqInfo[1].minAmountOut as bigint) +
            parseUnits("1000", "ether");
          const selectedPMMId = btcevmPresigns[1][1].pmmId;
          const pmmRecvAddress = btcevmPresigns[1][1].pmmRecvAddress;
          const selectedPMMInfoHash: string = getSelectPMMHash(
            selectedPMMId,
            pmmRecvAddress,
            btcevmTradeInfo[1].toChain[1],
            btcevmTradeInfo[1].toChain[2],
            btcevmAmountOut[1],
            expiry,
          );
          let signature: string = await getSignature(
            accounts[1],
            btcevmTradeId[1],
            selectedPMMInfoHash,
            SignatureType.SelectPMM,
            domain,
          );
          const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
          const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
            amountOut: btcevmAmountOut[1],
            selectedPMMId: selectedPMMId,
            info: info,
            sigExpiry: expiry,
          };

          //  RFQ Info
          const rfqInfoHash: string = getRFQHash(
            btcevmRfqInfo[1].minAmountOut as bigint,
            btcevmRfqInfo[1].tradeTimeout as bigint,
            btcevmAffiliateInfo[1],
          );
          signature = await getSignature(
            btcevmEphemeralL2Wallet[1],
            btcevmTradeId[1],
            rfqInfoHash,
            SignatureType.RFQ,
            domain,
          );
          btcevmRfqInfo[1].rfqInfoSignature = signature;

          //  PMM Selection Info: Selected PMM Info + RFQ Info
          const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
            rfqInfo: btcevmRfqInfo[1],
            pmmInfo: pmmInfo,
          };
          const pFeeAmount = (pFeeRate * btcevmAmountOut[1]) / DENOM;
          const aFeeAmount =
            ((btcevmAffiliateInfo[1].aggregatedValue as bigint) *
              btcevmAmountOut[1]) /
            DENOM;

          const tx = router
            .connect(admin)
            .selectPMM(btcevmTradeId[1], pmmSelectionInfo);

          await expect(tx)
            .to.emit(router, "SelectPMM")
            .withArgs(admin.address, btcevmTradeId[1]);
          await expect(tx)
            .to.emit(btcevm, "SelectedPMM")
            .withArgs(
              await router.getAddress(),
              admin.address,
              btcevmTradeId[1],
              pmmSelectionInfo.pmmInfo.selectedPMMId,
            );

          const expectedPMMSelectionInfo = [
            [
              btcevmRfqInfo[1].minAmountOut,
              btcevmRfqInfo[1].tradeTimeout,
              btcevmRfqInfo[1].rfqInfoSignature,
            ],
            [
              pmmInfo.amountOut,
              pmmInfo.selectedPMMId,
              [hexlify(info[0]), hexlify(info[1])],
              pmmInfo.sigExpiry,
            ],
          ];
          expect(await router.getCurrentStage(btcevmTradeId[1])).deep.eq(
            STAGE.MAKE_PAYMENT,
          );
          expect(await router.getPMMSelection(btcevmTradeId[1])).deep.eq(
            expectedPMMSelectionInfo,
          );
          expect(await router.getFeeDetails(btcevmTradeId[1])).deep.eq([
            pFeeAmount + aFeeAmount, //  totalAmount
            pFeeAmount,
            aFeeAmount,
            pFeeRate,
            btcevmAffiliateInfo[1].aggregatedValue,
          ]);

          //  set back to normal
          await management.connect(admin).setSolver(admin.address, false);
        });

        it("BTCEVM - Should succeed when Solver submits the third trade's pmm selection", async () => {
          const timestamp = await getBlockTimestamp(provider);
          const expiry = BigInt(timestamp + 2 * 3600);
          btcevmAmountOut[2] =
            (btcevmRfqInfo[2].minAmountOut as bigint) +
            parseUnits("1000", "ether");
          const selectedPMMId = btcevmPresigns[2][0].pmmId;
          const pmmRecvAddress = btcevmPresigns[2][0].pmmRecvAddress;
          const selectedPMMInfoHash: string = getSelectPMMHash(
            selectedPMMId,
            pmmRecvAddress,
            btcevmTradeInfo[2].toChain[1],
            btcevmTradeInfo[2].toChain[2],
            btcevmAmountOut[2],
            expiry,
          );
          let signature: string = await getSignature(
            accounts[0],
            btcevmTradeId[2],
            selectedPMMInfoHash,
            SignatureType.SelectPMM,
            domain,
          );
          const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
          const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
            amountOut: btcevmAmountOut[2],
            selectedPMMId: selectedPMMId,
            info: info,
            sigExpiry: expiry,
          };

          //  RFQ Info
          const rfqInfoHash: string = getRFQHash(
            btcevmRfqInfo[2].minAmountOut as bigint,
            btcevmRfqInfo[2].tradeTimeout as bigint,
            btcevmAffiliateInfo[2],
          );
          signature = await getSignature(
            btcevmEphemeralL2Wallet[2],
            btcevmTradeId[2],
            rfqInfoHash,
            SignatureType.RFQ,
            domain,
          );
          btcevmRfqInfo[2].rfqInfoSignature = signature;

          //  PMM Selection Info: Selected PMM Info + RFQ Info
          const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
            rfqInfo: btcevmRfqInfo[2],
            pmmInfo: pmmInfo,
          };
          const pFeeAmount = (pFeeRate * btcevmAmountOut[2]) / DENOM;
          const aFeeAmount =
            ((btcevmAffiliateInfo[2].aggregatedValue as bigint) *
              btcevmAmountOut[2]) /
            DENOM;

          const tx = router
            .connect(solver)
            .selectPMM(btcevmTradeId[2], pmmSelectionInfo);
          await expect(tx)
            .to.emit(router, "SelectPMM")
            .withArgs(solver.address, btcevmTradeId[2]);
          await expect(tx)
            .to.emit(btcevm, "SelectedPMM")
            .withArgs(
              await router.getAddress(),
              solver.address,
              btcevmTradeId[2],
              pmmSelectionInfo.pmmInfo.selectedPMMId,
            );

          const expectedPMMSelectionInfo = [
            [
              btcevmRfqInfo[2].minAmountOut,
              btcevmRfqInfo[2].tradeTimeout,
              btcevmRfqInfo[2].rfqInfoSignature,
            ],
            [
              pmmInfo.amountOut,
              pmmInfo.selectedPMMId,
              [hexlify(info[0]), hexlify(info[1])],
              pmmInfo.sigExpiry,
            ],
          ];
          expect(await router.getCurrentStage(btcevmTradeId[2])).deep.eq(
            STAGE.MAKE_PAYMENT,
          );
          expect(await router.getPMMSelection(btcevmTradeId[2])).deep.eq(
            expectedPMMSelectionInfo,
          );
          expect(await router.getFeeDetails(btcevmTradeId[2])).deep.eq([
            pFeeAmount + aFeeAmount, //  totalAmount
            pFeeAmount,
            aFeeAmount,
            pFeeRate,
            btcevmAffiliateInfo[2].aggregatedValue,
          ]);
        });
      });

      describe("EVMBTC - selectPMM() testing", async () => {
        it("EVMBTC - Should succeed when Solver submits the first trade's pmm selection", async () => {
          //  Selected PMM Info
          const timestamp = await getBlockTimestamp(provider);
          const expiry = BigInt(timestamp + 2 * 3600);
          evmbtcAmountOut[0] =
            (evmbtcRfqInfo[0].minAmountOut as bigint) + parseUnits("100", 8);
          const selectedPMMId = evmbtcPresigns[0][0].pmmId;
          const pmmRecvAddress = evmbtcPresigns[0][0].pmmRecvAddress;
          const selectedPMMInfoHash: string = getSelectPMMHash(
            selectedPMMId,
            pmmRecvAddress,
            evmbtcTradeInfo[0].toChain[1],
            evmbtcTradeInfo[0].toChain[2],
            evmbtcAmountOut[0],
            expiry,
          );
          let signature: string = await getSignature(
            accounts[0],
            evmbtcTradeId[0],
            selectedPMMInfoHash,
            SignatureType.SelectPMM,
            domain,
          );
          const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
          const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
            amountOut: evmbtcAmountOut[0],
            selectedPMMId: selectedPMMId,
            info: info,
            sigExpiry: expiry,
          };

          //  RFQ Info
          const rfqInfoHash: string = getRFQHash(
            evmbtcRfqInfo[0].minAmountOut as bigint,
            evmbtcRfqInfo[0].tradeTimeout as bigint,
            evmbtcAffiliateInfo[0],
          );
          signature = await getSignature(
            evmbtcEphemeralL2Wallet[0],
            evmbtcTradeId[0],
            rfqInfoHash,
            SignatureType.RFQ,
            domain,
          );
          evmbtcRfqInfo[0].rfqInfoSignature = signature;

          //  PMM Selection Info: Selected PMM Info + RFQ Info
          const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
            rfqInfo: evmbtcRfqInfo[0],
            pmmInfo: pmmInfo,
          };

          const tx = router
            .connect(solver)
            .selectPMM(evmbtcTradeId[0], pmmSelectionInfo);
          await expect(tx)
            .to.emit(router, "SelectPMM")
            .withArgs(solver.address, evmbtcTradeId[0]);
          await expect(tx)
            .to.emit(evmbtc, "SelectedPMM")
            .withArgs(
              await router.getAddress(),
              solver.address,
              evmbtcTradeId[0],
              pmmSelectionInfo.pmmInfo.selectedPMMId,
            );

          const expectedPMMSelectionInfo = [
            [
              evmbtcRfqInfo[0].minAmountOut,
              evmbtcRfqInfo[0].tradeTimeout,
              evmbtcRfqInfo[0].rfqInfoSignature,
            ],
            [
              pmmInfo.amountOut,
              pmmInfo.selectedPMMId,
              [hexlify(info[0]), hexlify(info[1])],
              pmmInfo.sigExpiry,
            ],
          ];
          expect(await router.getCurrentStage(evmbtcTradeId[0])).deep.eq(
            STAGE.MAKE_PAYMENT,
          );
          expect(await router.getPMMSelection(evmbtcTradeId[0])).deep.eq(
            expectedPMMSelectionInfo,
          );
        });

        it("EVMBTC - Should succeed when Solver submits the second trade's pmm selection", async () => {
          //  temporarily set "admin" as Solver role
          await management.connect(admin).setSolver(admin.address, true);

          const timestamp = await getBlockTimestamp(provider);
          const expiry = BigInt(timestamp + 2 * 3600);
          evmbtcAmountOut[1] =
            (evmbtcRfqInfo[1].minAmountOut as bigint) + parseUnits("100", 8);
          const selectedPMMId = evmbtcPresigns[1][1].pmmId;
          const pmmRecvAddress = evmbtcPresigns[1][1].pmmRecvAddress;
          const selectedPMMInfoHash: string = getSelectPMMHash(
            selectedPMMId,
            pmmRecvAddress,
            evmbtcTradeInfo[1].toChain[1],
            evmbtcTradeInfo[1].toChain[2],
            evmbtcAmountOut[1],
            expiry,
          );
          let signature: string = await getSignature(
            accounts[1],
            evmbtcTradeId[1],
            selectedPMMInfoHash,
            SignatureType.SelectPMM,
            domain,
          );
          const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
          const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
            amountOut: evmbtcAmountOut[1],
            selectedPMMId: selectedPMMId,
            info: info,
            sigExpiry: expiry,
          };

          //  RFQ Info
          const rfqInfoHash: string = getRFQHash(
            evmbtcRfqInfo[1].minAmountOut as bigint,
            evmbtcRfqInfo[1].tradeTimeout as bigint,
            evmbtcAffiliateInfo[1],
          );
          signature = await getSignature(
            evmbtcEphemeralL2Wallet[1],
            evmbtcTradeId[1],
            rfqInfoHash,
            SignatureType.RFQ,
            domain,
          );
          evmbtcRfqInfo[1].rfqInfoSignature = signature;

          //  PMM Selection Info: Selected PMM Info + RFQ Info
          const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
            rfqInfo: evmbtcRfqInfo[1],
            pmmInfo: pmmInfo,
          };

          const tx = router
            .connect(admin)
            .selectPMM(evmbtcTradeId[1], pmmSelectionInfo);

          await expect(tx)
            .to.emit(router, "SelectPMM")
            .withArgs(admin.address, evmbtcTradeId[1]);
          await expect(tx)
            .to.emit(evmbtc, "SelectedPMM")
            .withArgs(
              await router.getAddress(),
              admin.address,
              evmbtcTradeId[1],
              pmmSelectionInfo.pmmInfo.selectedPMMId,
            );

          const expectedPMMSelectionInfo = [
            [
              evmbtcRfqInfo[1].minAmountOut,
              evmbtcRfqInfo[1].tradeTimeout,
              evmbtcRfqInfo[1].rfqInfoSignature,
            ],
            [
              pmmInfo.amountOut,
              pmmInfo.selectedPMMId,
              [hexlify(info[0]), hexlify(info[1])],
              pmmInfo.sigExpiry,
            ],
          ];
          expect(await router.getCurrentStage(evmbtcTradeId[1])).deep.eq(
            STAGE.MAKE_PAYMENT,
          );
          expect(await router.getPMMSelection(evmbtcTradeId[1])).deep.eq(
            expectedPMMSelectionInfo,
          );

          //  set back to normal
          await management.connect(admin).setSolver(admin.address, false);
        });

        it("EVMBTC - Should succeed when Solver submits the third trade's pmm selection", async () => {
          const timestamp = await getBlockTimestamp(provider);
          const expiry = BigInt(timestamp + 2 * 3600);
          evmbtcAmountOut[2] =
            (evmbtcRfqInfo[2].minAmountOut as bigint) + parseUnits("100", 8);
          const selectedPMMId = evmbtcPresigns[2][0].pmmId;
          const pmmRecvAddress = evmbtcPresigns[2][0].pmmRecvAddress;
          const selectedPMMInfoHash: string = getSelectPMMHash(
            selectedPMMId,
            pmmRecvAddress,
            evmbtcTradeInfo[2].toChain[1],
            evmbtcTradeInfo[2].toChain[2],
            evmbtcAmountOut[2],
            expiry,
          );
          let signature: string = await getSignature(
            accounts[0],
            evmbtcTradeId[2],
            selectedPMMInfoHash,
            SignatureType.SelectPMM,
            domain,
          );
          const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
          const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
            amountOut: evmbtcAmountOut[2],
            selectedPMMId: selectedPMMId,
            info: info,
            sigExpiry: expiry,
          };

          //  RFQ Info
          const rfqInfoHash: string = getRFQHash(
            evmbtcRfqInfo[2].minAmountOut as bigint,
            evmbtcRfqInfo[2].tradeTimeout as bigint,
            evmbtcAffiliateInfo[2],
          );
          signature = await getSignature(
            evmbtcEphemeralL2Wallet[2],
            evmbtcTradeId[2],
            rfqInfoHash,
            SignatureType.RFQ,
            domain,
          );
          evmbtcRfqInfo[2].rfqInfoSignature = signature;

          //  PMM Selection Info: Selected PMM Info + RFQ Info
          const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
            rfqInfo: evmbtcRfqInfo[2],
            pmmInfo: pmmInfo,
          };

          const tx = router
            .connect(solver)
            .selectPMM(evmbtcTradeId[2], pmmSelectionInfo);

          await expect(tx)
            .to.emit(router, "SelectPMM")
            .withArgs(solver.address, evmbtcTradeId[2]);
          await expect(tx)
            .to.emit(evmbtc, "SelectedPMM")
            .withArgs(
              await router.getAddress(),
              solver.address,
              evmbtcTradeId[2],
              pmmSelectionInfo.pmmInfo.selectedPMMId,
            );

          const expectedPMMSelectionInfo = [
            [
              evmbtcRfqInfo[2].minAmountOut,
              evmbtcRfqInfo[2].tradeTimeout,
              evmbtcRfqInfo[2].rfqInfoSignature,
            ],
            [
              pmmInfo.amountOut,
              pmmInfo.selectedPMMId,
              [hexlify(info[0]), hexlify(info[1])],
              pmmInfo.sigExpiry,
            ],
          ];
          expect(await router.getCurrentStage(evmbtcTradeId[2])).deep.eq(
            STAGE.MAKE_PAYMENT,
          );
          expect(await router.getPMMSelection(evmbtcTradeId[2])).deep.eq(
            expectedPMMSelectionInfo,
          );
        });
      });

      describe("BTCSOL - selectPMM() testing", async () => {
        it("BTCSOL - Should succeed when Solver submits the first trade's pmm selection", async () => {
          const timestamp = await getBlockTimestamp(provider);
          const expiry = BigInt(timestamp + 2 * 3600);
          btcsolAmountOut[0] =
            (btcsolRfqInfo[0].minAmountOut as bigint) + parseUnits("50000", 9);
          const selectedPMMId = btcsolPresigns[0][0].pmmId;
          const pmmRecvAddress = btcsolPresigns[0][0].pmmRecvAddress;
          const selectedPMMInfoHash: string = getSelectPMMHash(
            selectedPMMId,
            pmmRecvAddress,
            btcsolTradeInfo[0].toChain[1],
            btcsolTradeInfo[0].toChain[2],
            btcsolAmountOut[0],
            expiry,
          );
          let signature: string = await getSignature(
            accounts[0],
            btcsolTradeId[0],
            selectedPMMInfoHash,
            SignatureType.SelectPMM,
            domain,
          );
          const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
          const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
            amountOut: btcsolAmountOut[0],
            selectedPMMId: selectedPMMId,
            info: info,
            sigExpiry: expiry,
          };

          //  RFQ Info
          const rfqInfoHash: string = getRFQHash(
            btcsolRfqInfo[0].minAmountOut as bigint,
            btcsolRfqInfo[0].tradeTimeout as bigint,
            btcsolAffiliateInfo[0],
          );
          signature = await getSignature(
            btcsolEphemeralL2Wallet[0],
            btcsolTradeId[0],
            rfqInfoHash,
            SignatureType.RFQ,
            domain,
          );
          btcsolRfqInfo[0].rfqInfoSignature = signature;

          //  PMM Selection Info: Selected PMM Info + RFQ Info
          const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
            rfqInfo: btcsolRfqInfo[0],
            pmmInfo: pmmInfo,
          };
          const pFeeAmount = (pFeeRate * btcsolAmountOut[0]) / DENOM;
          const aFeeAmount =
            ((btcsolAffiliateInfo[0].aggregatedValue as bigint) *
              btcsolAmountOut[0]) /
            DENOM;

          const tx = router
            .connect(solver)
            .selectPMM(btcsolTradeId[0], pmmSelectionInfo);
          await expect(tx)
            .to.emit(router, "SelectPMM")
            .withArgs(solver.address, btcsolTradeId[0]);
          await expect(tx)
            .to.emit(btcsol, "SelectedPMM")
            .withArgs(
              await router.getAddress(),
              solver.address,
              btcsolTradeId[0],
              pmmSelectionInfo.pmmInfo.selectedPMMId,
            );

          const expectedPMMSelectionInfo = [
            [
              btcsolRfqInfo[0].minAmountOut,
              btcsolRfqInfo[0].tradeTimeout,
              btcsolRfqInfo[0].rfqInfoSignature,
            ],
            [
              pmmInfo.amountOut,
              pmmInfo.selectedPMMId,
              [hexlify(info[0]), hexlify(info[1])],
              pmmInfo.sigExpiry,
            ],
          ];
          expect(await router.getCurrentStage(btcsolTradeId[0])).deep.eq(
            STAGE.MAKE_PAYMENT,
          );
          expect(await router.getPMMSelection(btcsolTradeId[0])).deep.eq(
            expectedPMMSelectionInfo,
          );
          expect(await router.getFeeDetails(btcsolTradeId[0])).deep.eq([
            pFeeAmount + aFeeAmount, //  totalAmount
            pFeeAmount,
            aFeeAmount,
            pFeeRate,
            btcsolAffiliateInfo[0].aggregatedValue,
          ]);
        });

        it("BTCSOL - Should succeed when Solver submits the second trade's pmm selection", async () => {
          //  temporarily set "admin" as Solver role
          await management.connect(admin).setSolver(admin.address, true);

          const timestamp = await getBlockTimestamp(provider);
          const expiry = BigInt(timestamp + 2 * 3600);
          btcsolAmountOut[1] =
            (btcsolRfqInfo[1].minAmountOut as bigint) + parseUnits("50000", 9);
          const selectedPMMId = btcsolPresigns[1][1].pmmId;
          const pmmRecvAddress = btcsolPresigns[1][1].pmmRecvAddress;
          const selectedPMMInfoHash: string = getSelectPMMHash(
            selectedPMMId,
            pmmRecvAddress,
            btcsolTradeInfo[1].toChain[1],
            btcsolTradeInfo[1].toChain[2],
            btcsolAmountOut[1],
            expiry,
          );
          let signature: string = await getSignature(
            accounts[1],
            btcsolTradeId[1],
            selectedPMMInfoHash,
            SignatureType.SelectPMM,
            domain,
          );
          const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
          const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
            amountOut: btcsolAmountOut[1],
            selectedPMMId: selectedPMMId,
            info: info,
            sigExpiry: expiry,
          };

          //  RFQ Info
          const rfqInfoHash: string = getRFQHash(
            btcsolRfqInfo[1].minAmountOut as bigint,
            btcsolRfqInfo[1].tradeTimeout as bigint,
            btcsolAffiliateInfo[1],
          );
          signature = await getSignature(
            btcsolEphemeralL2Wallet[1],
            btcsolTradeId[1],
            rfqInfoHash,
            SignatureType.RFQ,
            domain,
          );
          btcsolRfqInfo[1].rfqInfoSignature = signature;

          //  PMM Selection Info: Selected PMM Info + RFQ Info
          const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
            rfqInfo: btcsolRfqInfo[1],
            pmmInfo: pmmInfo,
          };
          const pFeeAmount = (pFeeRate * btcsolAmountOut[1]) / DENOM;
          const aFeeAmount =
            ((btcsolAffiliateInfo[1].aggregatedValue as bigint) *
              btcsolAmountOut[1]) /
            DENOM;

          const tx = router
            .connect(admin)
            .selectPMM(btcsolTradeId[1], pmmSelectionInfo);
          await expect(tx)
            .to.emit(router, "SelectPMM")
            .withArgs(admin.address, btcsolTradeId[1]);
          await expect(tx)
            .to.emit(btcsol, "SelectedPMM")
            .withArgs(
              await router.getAddress(),
              admin.address,
              btcsolTradeId[1],
              pmmSelectionInfo.pmmInfo.selectedPMMId,
            );

          const expectedPMMSelectionInfo = [
            [
              btcsolRfqInfo[1].minAmountOut,
              btcsolRfqInfo[1].tradeTimeout,
              btcsolRfqInfo[1].rfqInfoSignature,
            ],
            [
              pmmInfo.amountOut,
              pmmInfo.selectedPMMId,
              [hexlify(info[0]), hexlify(info[1])],
              pmmInfo.sigExpiry,
            ],
          ];
          expect(await router.getCurrentStage(btcsolTradeId[1])).deep.eq(
            STAGE.MAKE_PAYMENT,
          );
          expect(await router.getPMMSelection(btcsolTradeId[1])).deep.eq(
            expectedPMMSelectionInfo,
          );
          expect(await router.getFeeDetails(btcsolTradeId[1])).deep.eq([
            pFeeAmount + aFeeAmount, //  totalAmount
            pFeeAmount,
            aFeeAmount,
            pFeeRate,
            btcsolAffiliateInfo[1].aggregatedValue,
          ]);

          //  set back to normal
          await management.connect(admin).setSolver(admin.address, false);
        });

        it("BTCSOL - Should succeed when Solver submits the third trade's pmm selection", async () => {
          const timestamp = await getBlockTimestamp(provider);
          const expiry = BigInt(timestamp + 2 * 3600);
          btcsolAmountOut[2] =
            (btcsolRfqInfo[2].minAmountOut as bigint) + parseUnits("50000", 9);
          const selectedPMMId = btcsolPresigns[2][0].pmmId;
          const pmmRecvAddress = btcsolPresigns[2][0].pmmRecvAddress;
          const selectedPMMInfoHash: string = getSelectPMMHash(
            selectedPMMId,
            pmmRecvAddress,
            btcsolTradeInfo[2].toChain[1],
            btcsolTradeInfo[2].toChain[2],
            btcsolAmountOut[2],
            expiry,
          );
          let signature: string = await getSignature(
            accounts[0],
            btcsolTradeId[2],
            selectedPMMInfoHash,
            SignatureType.SelectPMM,
            domain,
          );
          const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
          const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
            amountOut: btcsolAmountOut[2],
            selectedPMMId: selectedPMMId,
            info: info,
            sigExpiry: expiry,
          };

          //  RFQ Info
          const rfqInfoHash: string = getRFQHash(
            btcsolRfqInfo[2].minAmountOut as bigint,
            btcsolRfqInfo[2].tradeTimeout as bigint,
            btcsolAffiliateInfo[2],
          );
          signature = await getSignature(
            btcsolEphemeralL2Wallet[2],
            btcsolTradeId[2],
            rfqInfoHash,
            SignatureType.RFQ,
            domain,
          );
          btcsolRfqInfo[2].rfqInfoSignature = signature;

          //  PMM Selection Info: Selected PMM Info + RFQ Info
          const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
            rfqInfo: btcsolRfqInfo[2],
            pmmInfo: pmmInfo,
          };
          const pFeeAmount = (pFeeRate * btcsolAmountOut[2]) / DENOM;
          const aFeeAmount =
            ((btcsolAffiliateInfo[2].aggregatedValue as bigint) *
              btcsolAmountOut[2]) /
            DENOM;

          const tx = router
            .connect(solver)
            .selectPMM(btcsolTradeId[2], pmmSelectionInfo);
          await expect(tx)
            .to.emit(router, "SelectPMM")
            .withArgs(solver.address, btcsolTradeId[2]);
          await expect(tx)
            .to.emit(btcsol, "SelectedPMM")
            .withArgs(
              await router.getAddress(),
              solver.address,
              btcsolTradeId[2],
              pmmSelectionInfo.pmmInfo.selectedPMMId,
            );

          const expectedPMMSelectionInfo = [
            [
              btcsolRfqInfo[2].minAmountOut,
              btcsolRfqInfo[2].tradeTimeout,
              btcsolRfqInfo[2].rfqInfoSignature,
            ],
            [
              pmmInfo.amountOut,
              pmmInfo.selectedPMMId,
              [hexlify(info[0]), hexlify(info[1])],
              pmmInfo.sigExpiry,
            ],
          ];
          expect(await router.getCurrentStage(btcsolTradeId[2])).deep.eq(
            STAGE.MAKE_PAYMENT,
          );
          expect(await router.getPMMSelection(btcsolTradeId[2])).deep.eq(
            expectedPMMSelectionInfo,
          );
          expect(await router.getFeeDetails(btcsolTradeId[2])).deep.eq([
            pFeeAmount + aFeeAmount, //  totalAmount
            pFeeAmount,
            aFeeAmount,
            pFeeRate,
            btcsolAffiliateInfo[2].aggregatedValue,
          ]);
        });
      });

      describe("SOLBTC - selectPMM() testing", async () => {
        it("SOLBTC - Should succeed when Solver submits the first trade's pmm selection", async () => {
          const timestamp = await getBlockTimestamp(provider);
          const expiry = BigInt(timestamp + 30 * 60);
          solbtcAmountOut[0] =
            (solbtcRfqInfo[0].minAmountOut as bigint) + parseUnits("5000", 9);
          const selectedPMMId = solbtcPresigns[0][0].pmmId;
          const pmmRecvAddress = solbtcPresigns[0][0].pmmRecvAddress;
          const selectedPMMInfoHash: string = getSelectPMMHash(
            selectedPMMId,
            pmmRecvAddress,
            solbtcTradeInfo[0].toChain[1],
            solbtcTradeInfo[0].toChain[2],
            solbtcAmountOut[0],
            expiry,
          );
          let signature: string = await getSignature(
            accounts[0],
            solbtcTradeId[0],
            selectedPMMInfoHash,
            SignatureType.SelectPMM,
            domain,
          );
          const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
          const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
            amountOut: solbtcAmountOut[0],
            selectedPMMId: selectedPMMId,
            info: info,
            sigExpiry: expiry,
          };

          //  RFQ Info
          const rfqInfoHash: string = getRFQHash(
            solbtcRfqInfo[0].minAmountOut as bigint,
            solbtcRfqInfo[0].tradeTimeout as bigint,
            solbtcAffiliateInfo[0],
          );
          signature = await getSignature(
            solbtcEphemeralL2Wallet[0],
            solbtcTradeId[0],
            rfqInfoHash,
            SignatureType.RFQ,
            domain,
          );
          solbtcRfqInfo[0].rfqInfoSignature = signature;

          //  PMM Selection Info: Selected PMM Info + RFQ Info
          const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
            rfqInfo: solbtcRfqInfo[0],
            pmmInfo: pmmInfo,
          };

          const tx = router
            .connect(solver)
            .selectPMM(solbtcTradeId[0], pmmSelectionInfo);
          await expect(tx)
            .to.emit(router, "SelectPMM")
            .withArgs(solver.address, solbtcTradeId[0]);
          await expect(tx)
            .to.emit(solbtc, "SelectedPMM")
            .withArgs(
              await router.getAddress(),
              solver.address,
              solbtcTradeId[0],
              pmmSelectionInfo.pmmInfo.selectedPMMId,
            );

          const expectedPMMSelectionInfo = [
            [
              solbtcRfqInfo[0].minAmountOut,
              solbtcRfqInfo[0].tradeTimeout,
              solbtcRfqInfo[0].rfqInfoSignature,
            ],
            [
              pmmInfo.amountOut,
              pmmInfo.selectedPMMId,
              [hexlify(info[0]), hexlify(info[1])],
              pmmInfo.sigExpiry,
            ],
          ];
          expect(await router.getCurrentStage(solbtcTradeId[0])).deep.eq(
            STAGE.MAKE_PAYMENT,
          );
          expect(await router.getPMMSelection(solbtcTradeId[0])).deep.eq(
            expectedPMMSelectionInfo,
          );
        });

        it("SOLBTC - Should succeed when Solver submits the second trade's pmm selection", async () => {
          //  temporarily set "admin" as Solver role
          await management.connect(admin).setSolver(admin.address, true);

          const timestamp = await getBlockTimestamp(provider);
          const expiry = BigInt(timestamp + 30 * 60);
          solbtcAmountOut[1] =
            (solbtcRfqInfo[1].minAmountOut as bigint) + parseUnits("5000", 9);
          const selectedPMMId = solbtcPresigns[1][1].pmmId;
          const pmmRecvAddress = solbtcPresigns[1][1].pmmRecvAddress;
          const selectedPMMInfoHash: string = getSelectPMMHash(
            selectedPMMId,
            pmmRecvAddress,
            solbtcTradeInfo[1].toChain[1],
            solbtcTradeInfo[1].toChain[2],
            solbtcAmountOut[1],
            expiry,
          );
          let signature: string = await getSignature(
            accounts[1],
            solbtcTradeId[1],
            selectedPMMInfoHash,
            SignatureType.SelectPMM,
            domain,
          );
          const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
          const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
            amountOut: solbtcAmountOut[1],
            selectedPMMId: selectedPMMId,
            info: info,
            sigExpiry: expiry,
          };

          //  RFQ Info
          const rfqInfoHash: string = getRFQHash(
            solbtcRfqInfo[1].minAmountOut as bigint,
            solbtcRfqInfo[1].tradeTimeout as bigint,
            solbtcAffiliateInfo[1],
          );
          signature = await getSignature(
            solbtcEphemeralL2Wallet[1],
            solbtcTradeId[1],
            rfqInfoHash,
            SignatureType.RFQ,
            domain,
          );
          solbtcRfqInfo[1].rfqInfoSignature = signature;

          //  PMM Selection Info: Selected PMM Info + RFQ Info
          const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
            rfqInfo: solbtcRfqInfo[1],
            pmmInfo: pmmInfo,
          };

          const tx = router
            .connect(admin)
            .selectPMM(solbtcTradeId[1], pmmSelectionInfo);
          await expect(tx)
            .to.emit(router, "SelectPMM")
            .withArgs(admin.address, solbtcTradeId[1]);
          await expect(tx)
            .to.emit(solbtc, "SelectedPMM")
            .withArgs(
              await router.getAddress(),
              admin.address,
              solbtcTradeId[1],
              pmmSelectionInfo.pmmInfo.selectedPMMId,
            );

          const expectedPMMSelectionInfo = [
            [
              solbtcRfqInfo[1].minAmountOut,
              solbtcRfqInfo[1].tradeTimeout,
              solbtcRfqInfo[1].rfqInfoSignature,
            ],
            [
              pmmInfo.amountOut,
              pmmInfo.selectedPMMId,
              [hexlify(info[0]), hexlify(info[1])],
              pmmInfo.sigExpiry,
            ],
          ];
          expect(await router.getCurrentStage(solbtcTradeId[1])).deep.eq(
            STAGE.MAKE_PAYMENT,
          );
          expect(await router.getPMMSelection(solbtcTradeId[1])).deep.eq(
            expectedPMMSelectionInfo,
          );

          //  set back to normal
          await management.connect(admin).setSolver(admin.address, false);
        });

        it("SOLBTC - Should succeed when Solver submits the third trade's pmm selection", async () => {
          const timestamp = await getBlockTimestamp(provider);
          const expiry = BigInt(timestamp + 30 * 60);
          solbtcAmountOut[2] =
            (solbtcRfqInfo[2].minAmountOut as bigint) + parseUnits("5000", 9);
          const selectedPMMId = solbtcPresigns[2][0].pmmId;
          const pmmRecvAddress = solbtcPresigns[2][0].pmmRecvAddress;
          const selectedPMMInfoHash: string = getSelectPMMHash(
            selectedPMMId,
            pmmRecvAddress,
            solbtcTradeInfo[2].toChain[1],
            solbtcTradeInfo[2].toChain[2],
            solbtcAmountOut[2],
            expiry,
          );
          let signature: string = await getSignature(
            accounts[0],
            solbtcTradeId[2],
            selectedPMMInfoHash,
            SignatureType.SelectPMM,
            domain,
          );
          const info: [BytesLike, BytesLike] = [pmmRecvAddress, signature];
          const pmmInfo: CoreTypes.SelectedPMMInfoStruct = {
            amountOut: solbtcAmountOut[2],
            selectedPMMId: selectedPMMId,
            info: info,
            sigExpiry: expiry,
          };

          //  RFQ Info
          const rfqInfoHash: string = getRFQHash(
            solbtcRfqInfo[2].minAmountOut as bigint,
            solbtcRfqInfo[2].tradeTimeout as bigint,
            solbtcAffiliateInfo[2],
          );
          signature = await getSignature(
            solbtcEphemeralL2Wallet[2],
            solbtcTradeId[2],
            rfqInfoHash,
            SignatureType.RFQ,
            domain,
          );
          solbtcRfqInfo[2].rfqInfoSignature = signature;

          //  PMM Selection Info: Selected PMM Info + RFQ Info
          const pmmSelectionInfo: CoreTypes.PMMSelectionStruct = {
            rfqInfo: solbtcRfqInfo[2],
            pmmInfo: pmmInfo,
          };

          const tx = router
            .connect(solver)
            .selectPMM(solbtcTradeId[2], pmmSelectionInfo);
          await expect(tx)
            .to.emit(router, "SelectPMM")
            .withArgs(solver.address, solbtcTradeId[2]);
          await expect(tx)
            .to.emit(solbtc, "SelectedPMM")
            .withArgs(
              await router.getAddress(),
              solver.address,
              solbtcTradeId[2],
              pmmSelectionInfo.pmmInfo.selectedPMMId,
            );

          const expectedPMMSelectionInfo = [
            [
              solbtcRfqInfo[2].minAmountOut,
              solbtcRfqInfo[2].tradeTimeout,
              solbtcRfqInfo[2].rfqInfoSignature,
            ],
            [
              pmmInfo.amountOut,
              pmmInfo.selectedPMMId,
              [hexlify(info[0]), hexlify(info[1])],
              pmmInfo.sigExpiry,
            ],
          ];
          expect(await router.getCurrentStage(solbtcTradeId[2])).deep.eq(
            STAGE.MAKE_PAYMENT,
          );
          expect(await router.getPMMSelection(solbtcTradeId[2])).deep.eq(
            expectedPMMSelectionInfo,
          );
        });
      });
    });

    describe("bundlePayment() functional testing", async () => {
      describe("BTCEVM - bundlePayment() testing", async () => {
        it("BTCEVM - Should revert when bundle payment is empty", async () => {
          const startIdx = BigInt(0);
          const tradeIds: string[] = [];
          const signedAt = BigInt(Math.floor(Date.now() / 1000));
          const infoHash: string = getMakePaymentHash(
            tradeIds,
            signedAt,
            startIdx,
            paymentTxId[0],
          );
          const signature = await getSignature(
            accounts[0],
            btcevmTradeId[0],
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
          ).to.be.revertedWithCustomError(router, "BundlePaymentEmpty");

          expect(await router.getCurrentStage(btcevmTradeId[0])).deep.eq(
            STAGE.MAKE_PAYMENT,
          );
          expect(await router.getSettledPayment(btcevmTradeId[0])).deep.eq(
            EMPTY_SETTLED_PAYMENT,
          );
        });

        it("BTCEVM - Should revert when bundle payment paid for non-recorded trade", async () => {
          const invalidTradeId = keccak256(toUtf8Bytes("Invalid_trade_id"));
          const startIdx = BigInt(0);
          const tradeIds = [btcevmTradeId[0], invalidTradeId];
          const signedAt = BigInt(Math.floor(Date.now() / 1000));
          const infoHash: string = getMakePaymentHash(
            tradeIds,
            signedAt,
            startIdx,
            paymentTxId[0],
          );
          const signature = await getSignature(
            accounts[0],
            btcevmTradeId[0],
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
          ).to.be.revertedWithCustomError(router, "RouteNotFound");

          expect(await router.getCurrentStage(btcevmTradeId[0])).deep.eq(
            STAGE.MAKE_PAYMENT,
          );
          expect(await router.getSettledPayment(btcevmTradeId[0])).deep.eq(
            EMPTY_SETTLED_PAYMENT,
          );
        });

        it("BTCEVM - Should revert when payment bundler pays for trades handled by two different PMMs", async () => {
          //  temporarily set `accounts[0]` as associated account of pmmId2
          await management
            .connect(admin)
            .setPMMAccount(
              btcevmPresigns[1][1].pmmId,
              accounts[0].address,
              true,
            );

          const startIdx = BigInt(0);
          const tradeIds = [btcevmTradeId[0], btcevmTradeId[1]];
          const signedAt = BigInt(Math.floor(Date.now() / 1000));
          const infoHash: string = getMakePaymentHash(
            tradeIds,
            signedAt,
            startIdx,
            paymentTxId[0],
          );
          const signature = await getSignature(
            accounts[0],
            btcevmTradeId[0],
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
            router.connect(accounts[0]).bundlePayment(bundle),
          ).to.be.revertedWithCustomError(router, "InconsistentPMM");

          expect(await router.getCurrentStage(btcevmTradeId[0])).deep.eq(
            STAGE.MAKE_PAYMENT,
          );
          expect(await router.getSettledPayment(btcevmTradeId[0])).deep.eq(
            EMPTY_SETTLED_PAYMENT,
          );
          expect(await router.getCurrentStage(btcevmTradeId[1])).deep.eq(
            STAGE.MAKE_PAYMENT,
          );
          expect(await router.getSettledPayment(btcevmTradeId[1])).deep.eq(
            EMPTY_SETTLED_PAYMENT,
          );

          //  set back to normal
          await management
            .connect(admin)
            .setPMMAccount(
              btcevmPresigns[1][1].pmmId,
              accounts[0].address,
              false,
            );
        });

        it("BTCEVM - Should revert when payment bundler pays for trades of two different types", async () => {
          const startIdx = BigInt(0);
          const tradeIds = [btcevmTradeId[0], evmbtcTradeId[0]];
          const signedAt = BigInt(Math.floor(Date.now() / 1000));
          const infoHash: string = getMakePaymentHash(
            tradeIds,
            signedAt,
            startIdx,
            paymentTxId[0],
          );
          const signature = await getSignature(
            accounts[0],
            btcevmTradeId[0],
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
          ).to.be.revertedWithCustomError(router, "InconsistentCoreType");

          expect(await router.getCurrentStage(btcevmTradeId[0])).deep.eq(
            STAGE.MAKE_PAYMENT,
          );
          expect(await router.getSettledPayment(btcevmTradeId[0])).deep.eq(
            EMPTY_SETTLED_PAYMENT,
          );
          expect(await router.getCurrentStage(evmbtcTradeId[0])).deep.eq(
            STAGE.MAKE_PAYMENT,
          );
          expect(await router.getSettledPayment(evmbtcTradeId[0])).deep.eq(
            EMPTY_SETTLED_PAYMENT,
          );
        });

        it("BTCEVM - Should succeed when a selected PMM calls bundlePayment() to submit paymentTxId - Bundle payment", async () => {
          const startIdx = BigInt(0);
          const tradeIds = [btcevmTradeId[0], btcevmTradeId[2]];
          const signedAt = BigInt(Math.floor(Date.now() / 1000));
          const infoHash: string = getMakePaymentHash(
            tradeIds,
            signedAt,
            startIdx,
            paymentTxId[0],
          );
          const signature = await getSignature(
            accounts[0],
            btcevmTradeId[0],
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
            .withArgs(accounts[0].address, btcevmTradeId[0]);
          await expect(tx)
            .to.emit(btcevm, "MadePayment")
            .withArgs(
              await router.getAddress(),
              accounts[0].address,
              btcevmTradeId[0],
              hexlify(btcevmTradeInfo[2].toChain[1]),
              hexlify(paymentTxId[0]),
              tradeIds,
              startIdx,
            );
          await expect(tx)
            .to.emit(router, "MakePayment")
            .withArgs(accounts[0].address, btcevmTradeId[2]);
          await expect(tx)
            .to.emit(btcevm, "MadePayment")
            .withArgs(
              await router.getAddress(),
              accounts[0].address,
              btcevmTradeId[2],
              hexlify(btcevmTradeInfo[2].toChain[1]),
              hexlify(paymentTxId[0]),
              tradeIds,
              startIdx,
            );

          expect(await router.getCurrentStage(btcevmTradeId[0])).deep.eq(
            STAGE.CONFIRM_PAYMENT,
          );
          expect(await router.getSettledPayment(btcevmTradeId[0])).deep.eq([
            bundlerHash(tradeIds),
            hexlify(paymentTxId[0]),
            EMPTY_BYTES,
            false,
          ]);
          expect(await router.getLastSignedPayment(btcevmTradeId[0])).deep.eq(
            signedAt,
          );
          expect(await router.getCurrentStage(btcevmTradeId[2])).deep.eq(
            STAGE.CONFIRM_PAYMENT,
          );
          expect(await router.getSettledPayment(btcevmTradeId[2])).deep.eq([
            bundlerHash(tradeIds),
            hexlify(paymentTxId[0]),
            EMPTY_BYTES,
            false,
          ]);
          expect(await router.getLastSignedPayment(btcevmTradeId[2])).deep.eq(
            signedAt,
          );
        });

        it("BTCEVM - Should succeed when Solver calls bundlePayment() to submit paymentTxId - Single payment", async () => {
          //  temporarily set "admin" as Solver role
          await management.connect(admin).setSolver(admin.address, true);

          const startIdx = BigInt(0);
          const tradeIds = [btcevmTradeId[1]];
          const signedAt = BigInt(Math.floor(Date.now() / 1000));
          const infoHash: string = getMakePaymentHash(
            tradeIds,
            signedAt,
            startIdx,
            paymentTxId[1],
          );
          const signature = await getSignature(
            accounts[1],
            btcevmTradeId[1],
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
            .withArgs(admin.address, btcevmTradeId[1]);
          await expect(tx)
            .to.emit(btcevm, "MadePayment")
            .withArgs(
              await router.getAddress(),
              admin.address,
              btcevmTradeId[1],
              hexlify(btcevmTradeInfo[1].toChain[1]),
              hexlify(paymentTxId[1]),
              tradeIds,
              startIdx,
            );

          expect(await router.getCurrentStage(btcevmTradeId[1])).deep.eq(
            STAGE.CONFIRM_PAYMENT,
          );
          expect(await router.getSettledPayment(btcevmTradeId[1])).deep.eq([
            bundlerHash(tradeIds),
            hexlify(paymentTxId[1]),
            EMPTY_BYTES,
            false,
          ]);
          expect(await router.getLastSignedPayment(btcevmTradeId[1])).deep.eq(
            signedAt,
          );

          //  set back to normal - "admin" no longer has Solver role
          await management.connect(admin).setSolver(admin.address, false);
        });
      });

      describe("EVMBTC - bundlePayment() testing", async () => {
        it("EVMBTC - Should revert when bundle payment is empty", async () => {
          const startIdx = BigInt(0);
          const tradeIds: string[] = [];
          const signedAt = BigInt(Math.floor(Date.now() / 1000));
          const infoHash: string = getMakePaymentHash(
            tradeIds,
            signedAt,
            startIdx,
            paymentTxId[3],
          );
          const signature = await getSignature(
            accounts[0],
            evmbtcTradeId[0],
            infoHash,
            SignatureType.MakePayment,
            domain,
          );
          const bundle: CoreTypes.BundlePaymentStruct = {
            tradeIds: tradeIds,
            signedAt: signedAt,
            startIdx: startIdx,
            paymentTxId: paymentTxId[3],
            signature: signature,
          };

          await expect(
            router.connect(solver).bundlePayment(bundle),
          ).to.be.revertedWithCustomError(router, "BundlePaymentEmpty");

          expect(await router.getCurrentStage(evmbtcTradeId[0])).deep.eq(
            STAGE.MAKE_PAYMENT,
          );
          expect(await router.getSettledPayment(evmbtcTradeId[0])).deep.eq(
            EMPTY_SETTLED_PAYMENT,
          );
        });

        it("EVMBTC - Should revert when bundle payment paid for non-recorded trade", async () => {
          const invalidTradeId = keccak256(toUtf8Bytes("Invalid_trade_id"));
          const startIdx = BigInt(0);
          const tradeIds = [evmbtcTradeId[0], invalidTradeId];
          const signedAt = BigInt(Math.floor(Date.now() / 1000));
          const infoHash: string = getMakePaymentHash(
            tradeIds,
            signedAt,
            startIdx,
            paymentTxId[3],
          );
          const signature = await getSignature(
            accounts[0],
            evmbtcTradeId[0],
            infoHash,
            SignatureType.MakePayment,
            domain,
          );
          const bundle: CoreTypes.BundlePaymentStruct = {
            tradeIds: tradeIds,
            signedAt: signedAt,
            startIdx: startIdx,
            paymentTxId: paymentTxId[3],
            signature: signature,
          };

          await expect(
            router.connect(solver).bundlePayment(bundle),
          ).to.be.revertedWithCustomError(router, "RouteNotFound");

          expect(await router.getCurrentStage(evmbtcTradeId[0])).deep.eq(
            STAGE.MAKE_PAYMENT,
          );
          expect(await router.getSettledPayment(evmbtcTradeId[0])).deep.eq(
            EMPTY_SETTLED_PAYMENT,
          );
        });

        it("EVMBTC - Should revert when payment bundler pays for trades handled by two different PMMs", async () => {
          //  temporarily set `accounts[0]` as associated account of pmmId2
          await management
            .connect(admin)
            .setPMMAccount(
              evmbtcPresigns[1][1].pmmId,
              accounts[0].address,
              true,
            );

          const startIdx = BigInt(0);
          const tradeIds = [evmbtcTradeId[0], evmbtcTradeId[1]];
          const signedAt = BigInt(Math.floor(Date.now() / 1000));
          const infoHash: string = getMakePaymentHash(
            tradeIds,
            signedAt,
            startIdx,
            paymentTxId[3],
          );
          const signature = await getSignature(
            accounts[0],
            evmbtcTradeId[0],
            infoHash,
            SignatureType.MakePayment,
            domain,
          );
          const bundle: CoreTypes.BundlePaymentStruct = {
            tradeIds: tradeIds,
            signedAt: signedAt,
            startIdx: startIdx,
            paymentTxId: paymentTxId[3],
            signature: signature,
          };

          await expect(
            router.connect(accounts[0]).bundlePayment(bundle),
          ).to.be.revertedWithCustomError(router, "InconsistentPMM");

          expect(await router.getCurrentStage(evmbtcTradeId[0])).deep.eq(
            STAGE.MAKE_PAYMENT,
          );
          expect(await router.getSettledPayment(evmbtcTradeId[0])).deep.eq(
            EMPTY_SETTLED_PAYMENT,
          );
          expect(await router.getCurrentStage(evmbtcTradeId[2])).deep.eq(
            STAGE.MAKE_PAYMENT,
          );
          expect(await router.getSettledPayment(evmbtcTradeId[2])).deep.eq(
            EMPTY_SETTLED_PAYMENT,
          );

          //  set back to normal
          await management
            .connect(admin)
            .setPMMAccount(
              evmbtcPresigns[1][1].pmmId,
              accounts[0].address,
              false,
            );
        });

        it("EVMBTC - Should succeed when Solver Solver calls bundlePayment() to submit paymentTxId - Bundle payment", async () => {
          const startIdx = BigInt(0);
          const tradeIds = [evmbtcTradeId[0], evmbtcTradeId[2]];
          const signedAt = BigInt(Math.floor(Date.now() / 1000));
          const infoHash: string = getMakePaymentHash(
            tradeIds,
            signedAt,
            startIdx,
            paymentTxId[3],
          );
          const signature = await getSignature(
            accounts[0],
            evmbtcTradeId[0],
            infoHash,
            SignatureType.MakePayment,
            domain,
          );
          const bundle: CoreTypes.BundlePaymentStruct = {
            tradeIds: tradeIds,
            signedAt: signedAt,
            startIdx: startIdx,
            paymentTxId: paymentTxId[3],
            signature: signature,
          };

          const tx = router.connect(solver).bundlePayment(bundle);

          await expect(tx)
            .to.emit(router, "MakePayment")
            .withArgs(solver.address, evmbtcTradeId[0]);
          await expect(tx)
            .to.emit(evmbtc, "MadePayment")
            .withArgs(
              await router.getAddress(),
              solver.address,
              evmbtcTradeId[0],
              hexlify(evmbtcTradeInfo[0].toChain[1]),
              hexlify(paymentTxId[3]),
              tradeIds,
              startIdx,
            );

          await expect(tx)
            .to.emit(router, "MakePayment")
            .withArgs(solver.address, evmbtcTradeId[2]);
          await expect(tx)
            .to.emit(evmbtc, "MadePayment")
            .withArgs(
              await router.getAddress(),
              solver.address,
              evmbtcTradeId[2],
              hexlify(evmbtcTradeInfo[2].toChain[1]),
              hexlify(paymentTxId[3]),
              tradeIds,
              startIdx,
            );

          expect(await router.getCurrentStage(evmbtcTradeId[0])).deep.eq(
            STAGE.CONFIRM_PAYMENT,
          );
          expect(await router.getSettledPayment(evmbtcTradeId[0])).deep.eq([
            bundlerHash(tradeIds),
            hexlify(paymentTxId[3]),
            EMPTY_BYTES,
            false,
          ]);
          expect(await router.getLastSignedPayment(evmbtcTradeId[0])).deep.eq(
            signedAt,
          );
          expect(await router.getCurrentStage(evmbtcTradeId[2])).deep.eq(
            STAGE.CONFIRM_PAYMENT,
          );
          expect(await router.getSettledPayment(evmbtcTradeId[2])).deep.eq([
            bundlerHash(tradeIds),
            hexlify(paymentTxId[3]),
            EMPTY_BYTES,
            false,
          ]);
          expect(await router.getLastSignedPayment(evmbtcTradeId[2])).deep.eq(
            signedAt,
          );
        });

        it("EVMBTC - Should succeed when Solver calls bundlePayment() - Single payment", async () => {
          //  temporarily set "admin" as Solver role
          await management.connect(admin).setSolver(admin.address, true);

          const startIdx = BigInt(0);
          const tradeIds = [evmbtcTradeId[1]];
          const signedAt = BigInt(Math.floor(Date.now() / 1000));
          const infoHash: string = getMakePaymentHash(
            tradeIds,
            signedAt,
            startIdx,
            paymentTxId[4],
          );
          const signature = await getSignature(
            accounts[1],
            evmbtcTradeId[1],
            infoHash,
            SignatureType.MakePayment,
            domain,
          );
          const bundle: CoreTypes.BundlePaymentStruct = {
            tradeIds: tradeIds,
            signedAt: signedAt,
            startIdx: startIdx,
            paymentTxId: paymentTxId[4],
            signature: signature,
          };

          const tx = router.connect(admin).bundlePayment(bundle);

          await expect(tx)
            .to.emit(router, "MakePayment")
            .withArgs(admin.address, evmbtcTradeId[1]);
          await expect(tx)
            .to.emit(evmbtc, "MadePayment")
            .withArgs(
              await router.getAddress(),
              admin.address,
              evmbtcTradeId[1],
              hexlify(evmbtcTradeInfo[1].toChain[1]),
              hexlify(paymentTxId[4]),
              tradeIds,
              startIdx,
            );

          expect(await router.getCurrentStage(evmbtcTradeId[1])).deep.eq(
            STAGE.CONFIRM_PAYMENT,
          );
          expect(await router.getSettledPayment(evmbtcTradeId[1])).deep.eq([
            bundlerHash(tradeIds),
            hexlify(paymentTxId[4]),
            EMPTY_BYTES,
            false,
          ]);
          expect(await router.getLastSignedPayment(evmbtcTradeId[1])).deep.eq(
            signedAt,
          );

          //  set back to normal - "admin" has no longer Solver role
          await management.connect(admin).setSolver(admin.address, false);
        });
      });

      describe("BTCSOL - bundlePayment() testing", async () => {
        it("BTCSOL - Should revert when bundle payment is empty", async () => {
          const startIdx = BigInt(0);
          const tradeIds: string[] = [];
          const signedAt = BigInt(Math.floor(Date.now() / 1000));
          const infoHash: string = getMakePaymentHash(
            tradeIds,
            signedAt,
            startIdx,
            paymentTxId[6],
          );
          const signature = await getSignature(
            accounts[0],
            btcsolTradeId[0],
            infoHash,
            SignatureType.MakePayment,
            domain,
          );
          const bundle: CoreTypes.BundlePaymentStruct = {
            tradeIds: tradeIds,
            signedAt: signedAt,
            startIdx: startIdx,
            paymentTxId: paymentTxId[6],
            signature: signature,
          };

          await expect(
            router.connect(solver).bundlePayment(bundle),
          ).to.be.revertedWithCustomError(router, "BundlePaymentEmpty");

          expect(await router.getCurrentStage(btcsolTradeId[0])).deep.eq(
            STAGE.MAKE_PAYMENT,
          );
          expect(await router.getSettledPayment(btcsolTradeId[0])).deep.eq(
            EMPTY_SETTLED_PAYMENT,
          );
        });

        it("BTCSOL - Should revert when bundle payment paid for non-recorded trade", async () => {
          const invalidTradeId = keccak256(toUtf8Bytes("Invalid_trade_id"));
          const startIdx = BigInt(0);
          const tradeIds = [btcsolTradeId[0], invalidTradeId];
          const signedAt = BigInt(Math.floor(Date.now() / 1000));
          const infoHash: string = getMakePaymentHash(
            tradeIds,
            signedAt,
            startIdx,
            paymentTxId[6],
          );
          const signature = await getSignature(
            accounts[0],
            btcsolTradeId[0],
            infoHash,
            SignatureType.MakePayment,
            domain,
          );
          const bundle: CoreTypes.BundlePaymentStruct = {
            tradeIds: tradeIds,
            signedAt: signedAt,
            startIdx: startIdx,
            paymentTxId: paymentTxId[6],
            signature: signature,
          };

          await expect(
            router.connect(solver).bundlePayment(bundle),
          ).to.be.revertedWithCustomError(router, "RouteNotFound");

          expect(await router.getCurrentStage(btcsolTradeId[0])).deep.eq(
            STAGE.MAKE_PAYMENT,
          );
          expect(await router.getSettledPayment(btcsolTradeId[0])).deep.eq(
            EMPTY_SETTLED_PAYMENT,
          );
        });

        it("BTCSOL - Should revert when payment bundler pays for trades handled by two different PMMs", async () => {
          //  temporarily set `accounts[0]` as associated account of pmmId2
          await management
            .connect(admin)
            .setPMMAccount(
              btcsolPresigns[1][1].pmmId,
              accounts[0].address,
              true,
            );

          const startIdx = BigInt(0);
          const tradeIds = [btcsolTradeId[0], btcsolTradeId[1]];
          const signedAt = BigInt(Math.floor(Date.now() / 1000));
          const infoHash: string = getMakePaymentHash(
            tradeIds,
            signedAt,
            startIdx,
            paymentTxId[6],
          );
          const signature = await getSignature(
            accounts[0],
            btcsolTradeId[0],
            infoHash,
            SignatureType.MakePayment,
            domain,
          );
          const bundle: CoreTypes.BundlePaymentStruct = {
            tradeIds: tradeIds,
            signedAt: signedAt,
            startIdx: startIdx,
            paymentTxId: paymentTxId[6],
            signature: signature,
          };

          await expect(
            router.connect(accounts[0]).bundlePayment(bundle),
          ).to.be.revertedWithCustomError(router, "InconsistentPMM");

          expect(await router.getCurrentStage(btcsolTradeId[0])).deep.eq(
            STAGE.MAKE_PAYMENT,
          );
          expect(await router.getSettledPayment(btcsolTradeId[0])).deep.eq(
            EMPTY_SETTLED_PAYMENT,
          );
          expect(await router.getCurrentStage(btcsolTradeId[1])).deep.eq(
            STAGE.MAKE_PAYMENT,
          );
          expect(await router.getSettledPayment(btcsolTradeId[1])).deep.eq(
            EMPTY_SETTLED_PAYMENT,
          );

          //  set back to normal
          await management
            .connect(admin)
            .setPMMAccount(
              btcsolPresigns[1][1].pmmId,
              accounts[0].address,
              false,
            );
        });

        it("BTCSOL - Should revert when payment bundler pays for trades of two different types", async () => {
          const startIdx = BigInt(0);
          const tradeIds = [btcsolTradeId[0], solbtcTradeId[0]];
          const signedAt = BigInt(Math.floor(Date.now() / 1000));
          const infoHash: string = getMakePaymentHash(
            tradeIds,
            signedAt,
            startIdx,
            paymentTxId[6],
          );
          const signature = await getSignature(
            accounts[0],
            btcsolTradeId[0],
            infoHash,
            SignatureType.MakePayment,
            domain,
          );
          const bundle: CoreTypes.BundlePaymentStruct = {
            tradeIds: tradeIds,
            signedAt: signedAt,
            startIdx: startIdx,
            paymentTxId: paymentTxId[6],
            signature: signature,
          };

          await expect(
            router.connect(solver).bundlePayment(bundle),
          ).to.be.revertedWithCustomError(router, "InconsistentCoreType");

          expect(await router.getCurrentStage(btcsolTradeId[0])).deep.eq(
            STAGE.MAKE_PAYMENT,
          );
          expect(await router.getSettledPayment(btcsolTradeId[0])).deep.eq(
            EMPTY_SETTLED_PAYMENT,
          );
          expect(await router.getCurrentStage(solbtcTradeId[0])).deep.eq(
            STAGE.MAKE_PAYMENT,
          );
          expect(await router.getSettledPayment(solbtcTradeId[0])).deep.eq(
            EMPTY_SETTLED_PAYMENT,
          );
        });

        it("BTCSOL - Should succeed when a selected PMM calls bundlePayment() to submit paymentTxId - Bundle payment", async () => {
          const startIdx = BigInt(0);
          const tradeIds = [btcsolTradeId[0], btcsolTradeId[2]];
          const signedAt = BigInt(Math.floor(Date.now() / 1000));
          const infoHash: string = getMakePaymentHash(
            tradeIds,
            signedAt,
            startIdx,
            paymentTxId[6],
          );
          const signature = await getSignature(
            accounts[0],
            btcsolTradeId[0],
            infoHash,
            SignatureType.MakePayment,
            domain,
          );
          const bundle: CoreTypes.BundlePaymentStruct = {
            tradeIds: tradeIds,
            signedAt: signedAt,
            startIdx: startIdx,
            paymentTxId: paymentTxId[6],
            signature: signature,
          };

          const tx = router.connect(accounts[0]).bundlePayment(bundle);

          await expect(tx)
            .to.emit(router, "MakePayment")
            .withArgs(accounts[0].address, btcsolTradeId[0]);
          await expect(tx)
            .to.emit(btcsol, "MadePayment")
            .withArgs(
              await router.getAddress(),
              accounts[0].address,
              btcsolTradeId[0],
              hexlify(btcsolTradeInfo[2].toChain[1]),
              hexlify(paymentTxId[6]),
              tradeIds,
              startIdx,
            );
          await expect(tx)
            .to.emit(router, "MakePayment")
            .withArgs(accounts[0].address, btcsolTradeId[2]);
          await expect(tx)
            .to.emit(btcsol, "MadePayment")
            .withArgs(
              await router.getAddress(),
              accounts[0].address,
              btcsolTradeId[2],
              hexlify(btcsolTradeInfo[2].toChain[1]),
              hexlify(paymentTxId[6]),
              tradeIds,
              startIdx,
            );

          expect(await router.getCurrentStage(btcsolTradeId[0])).deep.eq(
            STAGE.CONFIRM_PAYMENT,
          );
          expect(await router.getSettledPayment(btcsolTradeId[0])).deep.eq([
            bundlerHash(tradeIds),
            hexlify(paymentTxId[6]),
            EMPTY_BYTES,
            false,
          ]);
          expect(await router.getLastSignedPayment(btcsolTradeId[0])).deep.eq(
            signedAt,
          );
          expect(await router.getCurrentStage(btcsolTradeId[2])).deep.eq(
            STAGE.CONFIRM_PAYMENT,
          );
          expect(await router.getSettledPayment(btcsolTradeId[2])).deep.eq([
            bundlerHash(tradeIds),
            hexlify(paymentTxId[6]),
            EMPTY_BYTES,
            false,
          ]);
          expect(await router.getLastSignedPayment(btcsolTradeId[2])).deep.eq(
            signedAt,
          );
        });

        it("BTCSOL - Should succeed when Solver calls bundlePayment() to submit paymentTxId - Single payment", async () => {
          //  temporarily set "admin" as Solver role
          await management.connect(admin).setSolver(admin.address, true);

          const startIdx = BigInt(0);
          const tradeIds = [btcsolTradeId[1]];
          const signedAt = BigInt(Math.floor(Date.now() / 1000));
          const infoHash: string = getMakePaymentHash(
            tradeIds,
            signedAt,
            startIdx,
            paymentTxId[7],
          );
          const signature = await getSignature(
            accounts[1],
            btcsolTradeId[1],
            infoHash,
            SignatureType.MakePayment,
            domain,
          );
          const bundle: CoreTypes.BundlePaymentStruct = {
            tradeIds: tradeIds,
            signedAt: signedAt,
            startIdx: startIdx,
            paymentTxId: paymentTxId[7],
            signature: signature,
          };

          const tx = router.connect(admin).bundlePayment(bundle);

          await expect(tx)
            .to.emit(router, "MakePayment")
            .withArgs(admin.address, btcsolTradeId[1]);
          await expect(tx)
            .to.emit(btcsol, "MadePayment")
            .withArgs(
              await router.getAddress(),
              admin.address,
              btcsolTradeId[1],
              hexlify(btcsolTradeInfo[1].toChain[1]),
              hexlify(paymentTxId[7]),
              tradeIds,
              startIdx,
            );

          expect(await router.getCurrentStage(btcsolTradeId[1])).deep.eq(
            STAGE.CONFIRM_PAYMENT,
          );
          expect(await router.getSettledPayment(btcsolTradeId[1])).deep.eq([
            bundlerHash(tradeIds),
            hexlify(paymentTxId[7]),
            EMPTY_BYTES,
            false,
          ]);
          expect(await router.getLastSignedPayment(btcsolTradeId[1])).deep.eq(
            signedAt,
          );

          //  set back to normal - "admin" no longer has Solver role
          await management.connect(admin).setSolver(admin.address, false);
        });
      });

      describe("SOLBTC - bundlePayment() testing", async () => {
        it("SOLBTC - Should revert when bundle payment is empty", async () => {
          const startIdx = BigInt(0);
          const tradeIds: string[] = [];
          const signedAt = BigInt(Math.floor(Date.now() / 1000));
          const infoHash: string = getMakePaymentHash(
            tradeIds,
            signedAt,
            startIdx,
            paymentTxId[9],
          );
          const signature = await getSignature(
            accounts[0],
            solbtcTradeId[0],
            infoHash,
            SignatureType.MakePayment,
            domain,
          );
          const bundle: CoreTypes.BundlePaymentStruct = {
            tradeIds: tradeIds,
            signedAt: signedAt,
            startIdx: startIdx,
            paymentTxId: paymentTxId[9],
            signature: signature,
          };

          await expect(
            router.connect(solver).bundlePayment(bundle),
          ).to.be.revertedWithCustomError(router, "BundlePaymentEmpty");

          expect(await router.getCurrentStage(solbtcTradeId[0])).deep.eq(
            STAGE.MAKE_PAYMENT,
          );
          expect(await router.getSettledPayment(solbtcTradeId[0])).deep.eq(
            EMPTY_SETTLED_PAYMENT,
          );
        });

        it("SOLBTC - Should revert when bundle payment paid for non-recorded trade", async () => {
          const invalidTradeId = keccak256(toUtf8Bytes("Invalid_trade_id"));
          const startIdx = BigInt(0);
          const tradeIds = [solbtcTradeId[0], invalidTradeId];
          const signedAt = BigInt(Math.floor(Date.now() / 1000));
          const infoHash: string = getMakePaymentHash(
            tradeIds,
            signedAt,
            startIdx,
            paymentTxId[9],
          );
          const signature = await getSignature(
            accounts[0],
            solbtcTradeId[0],
            infoHash,
            SignatureType.MakePayment,
            domain,
          );
          const bundle: CoreTypes.BundlePaymentStruct = {
            tradeIds: tradeIds,
            signedAt: signedAt,
            startIdx: startIdx,
            paymentTxId: paymentTxId[9],
            signature: signature,
          };

          await expect(
            router.connect(solver).bundlePayment(bundle),
          ).to.be.revertedWithCustomError(router, "RouteNotFound");

          expect(await router.getCurrentStage(solbtcTradeId[0])).deep.eq(
            STAGE.MAKE_PAYMENT,
          );
          expect(await router.getSettledPayment(solbtcTradeId[0])).deep.eq(
            EMPTY_SETTLED_PAYMENT,
          );
        });

        it("SOLBTC - Should revert when payment bundler pays for trades handled by two different PMMs", async () => {
          //  temporarily set `accounts[0]` as associated account of pmmId2
          await management
            .connect(admin)
            .setPMMAccount(
              solbtcPresigns[1][1].pmmId,
              accounts[0].address,
              true,
            );

          const startIdx = BigInt(0);
          const tradeIds = [solbtcTradeId[0], solbtcTradeId[1]];
          const signedAt = BigInt(Math.floor(Date.now() / 1000));
          const infoHash: string = getMakePaymentHash(
            tradeIds,
            signedAt,
            startIdx,
            paymentTxId[9],
          );
          const signature = await getSignature(
            accounts[0],
            solbtcTradeId[0],
            infoHash,
            SignatureType.MakePayment,
            domain,
          );
          const bundle: CoreTypes.BundlePaymentStruct = {
            tradeIds: tradeIds,
            signedAt: signedAt,
            startIdx: startIdx,
            paymentTxId: paymentTxId[9],
            signature: signature,
          };

          await expect(
            router.connect(accounts[0]).bundlePayment(bundle),
          ).to.be.revertedWithCustomError(router, "InconsistentPMM");

          expect(await router.getCurrentStage(solbtcTradeId[0])).deep.eq(
            STAGE.MAKE_PAYMENT,
          );
          expect(await router.getSettledPayment(solbtcTradeId[0])).deep.eq(
            EMPTY_SETTLED_PAYMENT,
          );
          expect(await router.getCurrentStage(solbtcTradeId[2])).deep.eq(
            STAGE.MAKE_PAYMENT,
          );
          expect(await router.getSettledPayment(solbtcTradeId[2])).deep.eq(
            EMPTY_SETTLED_PAYMENT,
          );

          //  set back to normal
          await management
            .connect(admin)
            .setPMMAccount(
              solbtcPresigns[1][1].pmmId,
              accounts[0].address,
              false,
            );
        });

        it("SOLBTC - Should succeed when Solver Solver calls bundlePayment() to submit paymentTxId - Bundle payment", async () => {
          const startIdx = BigInt(0);
          const tradeIds = [solbtcTradeId[0], solbtcTradeId[2]];
          const signedAt = BigInt(Math.floor(Date.now() / 1000));
          const infoHash: string = getMakePaymentHash(
            tradeIds,
            signedAt,
            startIdx,
            paymentTxId[9],
          );
          const signature = await getSignature(
            accounts[0],
            solbtcTradeId[0],
            infoHash,
            SignatureType.MakePayment,
            domain,
          );
          const bundle: CoreTypes.BundlePaymentStruct = {
            tradeIds: tradeIds,
            signedAt: signedAt,
            startIdx: startIdx,
            paymentTxId: paymentTxId[9],
            signature: signature,
          };

          const tx = router.connect(solver).bundlePayment(bundle);

          await expect(tx)
            .to.emit(router, "MakePayment")
            .withArgs(solver.address, solbtcTradeId[0]);
          await expect(tx)
            .to.emit(solbtc, "MadePayment")
            .withArgs(
              await router.getAddress(),
              solver.address,
              solbtcTradeId[0],
              hexlify(solbtcTradeInfo[0].toChain[1]),
              hexlify(paymentTxId[9]),
              tradeIds,
              startIdx,
            );

          await expect(tx)
            .to.emit(router, "MakePayment")
            .withArgs(solver.address, solbtcTradeId[2]);
          await expect(tx)
            .to.emit(solbtc, "MadePayment")
            .withArgs(
              await router.getAddress(),
              solver.address,
              solbtcTradeId[2],
              hexlify(solbtcTradeInfo[2].toChain[1]),
              hexlify(paymentTxId[9]),
              tradeIds,
              startIdx,
            );

          expect(await router.getCurrentStage(solbtcTradeId[0])).deep.eq(
            STAGE.CONFIRM_PAYMENT,
          );
          expect(await router.getSettledPayment(solbtcTradeId[0])).deep.eq([
            bundlerHash(tradeIds),
            hexlify(paymentTxId[9]),
            EMPTY_BYTES,
            false,
          ]);
          expect(await router.getLastSignedPayment(solbtcTradeId[0])).deep.eq(
            signedAt,
          );
          expect(await router.getCurrentStage(solbtcTradeId[2])).deep.eq(
            STAGE.CONFIRM_PAYMENT,
          );
          expect(await router.getSettledPayment(solbtcTradeId[2])).deep.eq([
            bundlerHash(tradeIds),
            hexlify(paymentTxId[9]),
            EMPTY_BYTES,
            false,
          ]);
          expect(await router.getLastSignedPayment(solbtcTradeId[2])).deep.eq(
            signedAt,
          );
        });

        it("SOLBTC - Should succeed when Solver calls bundlePayment() - Single payment", async () => {
          //  temporarily set "admin" as Solver role
          await management.connect(admin).setSolver(admin.address, true);

          const startIdx = BigInt(0);
          const tradeIds = [solbtcTradeId[1]];
          const signedAt = BigInt(Math.floor(Date.now() / 1000));
          const infoHash: string = getMakePaymentHash(
            tradeIds,
            signedAt,
            startIdx,
            paymentTxId[10],
          );
          const signature = await getSignature(
            accounts[1],
            solbtcTradeId[1],
            infoHash,
            SignatureType.MakePayment,
            domain,
          );
          const bundle: CoreTypes.BundlePaymentStruct = {
            tradeIds: tradeIds,
            signedAt: signedAt,
            startIdx: startIdx,
            paymentTxId: paymentTxId[10],
            signature: signature,
          };

          const tx = router.connect(admin).bundlePayment(bundle);

          await expect(tx)
            .to.emit(router, "MakePayment")
            .withArgs(admin.address, solbtcTradeId[1]);
          await expect(tx)
            .to.emit(solbtc, "MadePayment")
            .withArgs(
              await router.getAddress(),
              admin.address,
              solbtcTradeId[1],
              hexlify(solbtcTradeInfo[1].toChain[1]),
              hexlify(paymentTxId[10]),
              tradeIds,
              startIdx,
            );

          expect(await router.getCurrentStage(solbtcTradeId[1])).deep.eq(
            STAGE.CONFIRM_PAYMENT,
          );
          expect(await router.getSettledPayment(solbtcTradeId[1])).deep.eq([
            bundlerHash(tradeIds),
            hexlify(paymentTxId[10]),
            EMPTY_BYTES,
            false,
          ]);
          expect(await router.getLastSignedPayment(solbtcTradeId[1])).deep.eq(
            signedAt,
          );

          //  set back to normal - "admin" has no longer Solver role
          await management.connect(admin).setSolver(admin.address, false);
        });
      });
    });

    describe("confirmPayment() functional testing", async () => {
      describe("BTCEVM - confirmPayment() testing", async () => {
        it("BTCEVM - Should succeed when MPC Node submits the first trade's payment confirmation", async () => {
          const pFeeAmount: bigint = (btcevmAmountOut[0] * pFeeRate) / DENOM;
          const aFeeAmount: bigint =
            ((btcevmAffiliateInfo[0].aggregatedValue as bigint) *
              btcevmAmountOut[0]) /
            DENOM;
          const totalAmount: bigint = pFeeAmount + aFeeAmount;
          const paymentAmount: bigint = btcevmAmountOut[0] - totalAmount;
          const infoHash = getConfirmPaymentHash(
            totalAmount,
            paymentAmount,
            btcevmTradeInfo[0].toChain,
            paymentTxId[0],
          );
          const signature: string = await getSignature(
            mpc,
            btcevmTradeId[0],
            infoHash,
            SignatureType.ConfirmPayment,
            domain,
          );

          const tx = router
            .connect(mpcNode1)
            .confirmPayment(btcevmTradeId[0], signature);

          await expect(tx)
            .to.emit(router, "ConfirmPayment")
            .withArgs(mpcNode1.address, btcevmTradeId[0]);
          await expect(tx)
            .to.emit(btcevm, "PaymentConfirmed")
            .withArgs(
              await router.getAddress(),
              mpc.address,
              btcevmTradeId[0],
              hexlify(paymentTxId[0]),
            );

          expect(await router.getCurrentStage(btcevmTradeId[0])).deep.eq(
            STAGE.CONFIRM_SETTLEMENT,
          );
          expect(await router.getSettledPayment(btcevmTradeId[0])).deep.eq([
            bundlerHash([btcevmTradeId[0], btcevmTradeId[2]]),
            hexlify(paymentTxId[0]),
            EMPTY_BYTES,
            true,
          ]);
        });

        it("BTCEVM - Should succeed when MPC Node submits the second trade's payment confirmation", async () => {
          const pFeeAmount: bigint = (btcevmAmountOut[1] * pFeeRate) / DENOM;
          const aFeeAmount: bigint =
            ((btcevmAffiliateInfo[1].aggregatedValue as bigint) *
              btcevmAmountOut[1]) /
            DENOM;
          const totalAmount: bigint = pFeeAmount + aFeeAmount;
          const paymentAmount: bigint = btcevmAmountOut[1] - totalAmount;
          const infoHash = getConfirmPaymentHash(
            totalAmount,
            paymentAmount,
            btcevmTradeInfo[1].toChain,
            paymentTxId[1],
          );
          const signature: string = await getSignature(
            mpc,
            btcevmTradeId[1],
            infoHash,
            SignatureType.ConfirmPayment,
            domain,
          );

          const tx = router
            .connect(mpcNode1)
            .confirmPayment(btcevmTradeId[1], signature);

          await expect(tx)
            .to.emit(router, "ConfirmPayment")
            .withArgs(mpcNode1.address, btcevmTradeId[1]);
          await expect(tx)
            .to.emit(btcevm, "PaymentConfirmed")
            .withArgs(
              await router.getAddress(),
              mpc.address,
              btcevmTradeId[1],
              hexlify(paymentTxId[1]),
            );

          expect(await router.getCurrentStage(btcevmTradeId[1])).deep.eq(
            STAGE.CONFIRM_SETTLEMENT,
          );
          expect(await router.getSettledPayment(btcevmTradeId[1])).deep.eq([
            bundlerHash([btcevmTradeId[1]]),
            hexlify(paymentTxId[1]),
            EMPTY_BYTES,
            true,
          ]);
        });

        it("BTCEVM - Should succeed when MPC Node submits the third trade's payment confirmation", async () => {
          const pFeeAmount: bigint = (btcevmAmountOut[2] * pFeeRate) / DENOM;
          const aFeeAmount: bigint =
            ((btcevmAffiliateInfo[2].aggregatedValue as bigint) *
              btcevmAmountOut[2]) /
            DENOM;
          const totalAmount: bigint = pFeeAmount + aFeeAmount;
          const paymentAmount: bigint = btcevmAmountOut[2] - totalAmount;
          const infoHash = getConfirmPaymentHash(
            totalAmount,
            paymentAmount,
            btcevmTradeInfo[2].toChain,
            paymentTxId[0],
          );
          const signature: string = await getSignature(
            mpc,
            btcevmTradeId[2],
            infoHash,
            SignatureType.ConfirmPayment,
            domain,
          );

          const tx = router
            .connect(mpcNode1)
            .confirmPayment(btcevmTradeId[2], signature);

          await expect(tx)
            .to.emit(router, "ConfirmPayment")
            .withArgs(mpcNode1.address, btcevmTradeId[2]);
          await expect(tx)
            .to.emit(btcevm, "PaymentConfirmed")
            .withArgs(
              await router.getAddress(),
              mpc.address,
              btcevmTradeId[2],
              hexlify(paymentTxId[0]),
            );

          expect(await router.getCurrentStage(btcevmTradeId[2])).deep.eq(
            STAGE.CONFIRM_SETTLEMENT,
          );
          expect(await router.getSettledPayment(btcevmTradeId[2])).deep.eq([
            bundlerHash([btcevmTradeId[0], btcevmTradeId[2]]),
            hexlify(paymentTxId[0]),
            EMPTY_BYTES,
            true,
          ]);
        });
      });

      describe("EVMBTC - confirmPayment() testing", async () => {
        it("EVMBTC - Should succeed when MPC Node submits the first trade's payment confirmation", async () => {
          const infoHash = getConfirmPaymentHash(
            ZERO_VALUE,
            evmbtcAmountOut[0],
            evmbtcTradeInfo[0].toChain,
            paymentTxId[3],
          );
          const signature: string = await getSignature(
            mpc,
            evmbtcTradeId[0],
            infoHash,
            SignatureType.ConfirmPayment,
            domain,
          );

          const tx = router
            .connect(mpcNode1)
            .confirmPayment(evmbtcTradeId[0], signature);

          await expect(tx)
            .to.emit(router, "ConfirmPayment")
            .withArgs(mpcNode1.address, evmbtcTradeId[0]);
          await expect(tx)
            .to.emit(evmbtc, "PaymentConfirmed")
            .withArgs(
              await router.getAddress(),
              mpc.address,
              evmbtcTradeId[0],
              hexlify(paymentTxId[3]),
            );

          expect(await router.getCurrentStage(evmbtcTradeId[0])).deep.eq(
            STAGE.CONFIRM_SETTLEMENT,
          );
          expect(await router.getSettledPayment(evmbtcTradeId[0])).deep.eq([
            bundlerHash([evmbtcTradeId[0], evmbtcTradeId[2]]),
            hexlify(paymentTxId[3]),
            EMPTY_BYTES,
            true,
          ]);
        });

        it("EVMBTC - Should succeed when MPC Node submits the second trade's payment confirmation", async () => {
          const infoHash = getConfirmPaymentHash(
            ZERO_VALUE,
            evmbtcAmountOut[1],
            evmbtcTradeInfo[1].toChain,
            paymentTxId[4],
          );
          const signature: string = await getSignature(
            mpc,
            evmbtcTradeId[1],
            infoHash,
            SignatureType.ConfirmPayment,
            domain,
          );

          const tx = router
            .connect(mpcNode1)
            .confirmPayment(evmbtcTradeId[1], signature);

          await expect(tx)
            .to.emit(router, "ConfirmPayment")
            .withArgs(mpcNode1.address, evmbtcTradeId[1]);
          await expect(tx)
            .to.emit(evmbtc, "PaymentConfirmed")
            .withArgs(
              await router.getAddress(),
              mpc.address,
              evmbtcTradeId[1],
              hexlify(paymentTxId[4]),
            );

          expect(await router.getCurrentStage(evmbtcTradeId[1])).deep.eq(
            STAGE.CONFIRM_SETTLEMENT,
          );
          expect(await router.getSettledPayment(evmbtcTradeId[1])).deep.eq([
            bundlerHash([evmbtcTradeId[1]]),
            hexlify(paymentTxId[4]),
            EMPTY_BYTES,
            true,
          ]);
        });

        it("EVMBTC - Should succeed when MPC Node submits the third trade's payment confirmation", async () => {
          const infoHash = getConfirmPaymentHash(
            ZERO_VALUE,
            evmbtcAmountOut[2],
            evmbtcTradeInfo[2].toChain,
            paymentTxId[3],
          );
          const signature: string = await getSignature(
            mpc,
            evmbtcTradeId[2],
            infoHash,
            SignatureType.ConfirmPayment,
            domain,
          );

          const tx = router
            .connect(mpcNode1)
            .confirmPayment(evmbtcTradeId[2], signature);

          await expect(tx)
            .to.emit(router, "ConfirmPayment")
            .withArgs(mpcNode1.address, evmbtcTradeId[2]);
          await expect(tx)
            .to.emit(evmbtc, "PaymentConfirmed")
            .withArgs(
              await router.getAddress(),
              mpc.address,
              evmbtcTradeId[2],
              hexlify(paymentTxId[3]),
            );

          expect(await router.getCurrentStage(evmbtcTradeId[2])).deep.eq(
            STAGE.CONFIRM_SETTLEMENT,
          );
          expect(await router.getSettledPayment(evmbtcTradeId[2])).deep.eq([
            bundlerHash([evmbtcTradeId[0], evmbtcTradeId[2]]),
            hexlify(paymentTxId[3]),
            EMPTY_BYTES,
            true,
          ]);
        });
      });

      describe("BTCSOL - confirmPayment() testing", async () => {
        it("BTCSOL - Should succeed when MPC Node submits the first trade's payment confirmation", async () => {
          const pFeeAmount: bigint = (btcsolAmountOut[0] * pFeeRate) / DENOM;
          const aFeeAmount: bigint =
            ((btcsolAffiliateInfo[0].aggregatedValue as bigint) *
              btcsolAmountOut[0]) /
            DENOM;
          const totalAmount: bigint = pFeeAmount + aFeeAmount;
          const paymentAmount: bigint = btcsolAmountOut[0] - totalAmount;
          const infoHash = getConfirmPaymentHash(
            totalAmount,
            paymentAmount,
            btcsolTradeInfo[0].toChain,
            paymentTxId[6],
          );
          const signature: string = await getSignature(
            mpc,
            btcsolTradeId[0],
            infoHash,
            SignatureType.ConfirmPayment,
            domain,
          );

          const tx = router
            .connect(mpcNode1)
            .confirmPayment(btcsolTradeId[0], signature);

          await expect(tx)
            .to.emit(router, "ConfirmPayment")
            .withArgs(mpcNode1.address, btcsolTradeId[0]);
          await expect(tx)
            .to.emit(btcsol, "PaymentConfirmed")
            .withArgs(
              await router.getAddress(),
              mpc.address,
              btcsolTradeId[0],
              hexlify(paymentTxId[6]),
            );

          expect(await router.getCurrentStage(btcsolTradeId[0])).deep.eq(
            STAGE.CONFIRM_SETTLEMENT,
          );
          expect(await router.getSettledPayment(btcsolTradeId[0])).deep.eq([
            bundlerHash([btcsolTradeId[0], btcsolTradeId[2]]),
            hexlify(paymentTxId[6]),
            EMPTY_BYTES,
            true,
          ]);
        });

        it("BTCSOL - Should succeed when MPC Node submits the second trade's payment confirmation", async () => {
          const pFeeAmount: bigint = (btcsolAmountOut[1] * pFeeRate) / DENOM;
          const aFeeAmount: bigint =
            ((btcsolAffiliateInfo[1].aggregatedValue as bigint) *
              btcsolAmountOut[1]) /
            DENOM;
          const totalAmount: bigint = pFeeAmount + aFeeAmount;
          const paymentAmount: bigint = btcsolAmountOut[1] - totalAmount;
          const infoHash = getConfirmPaymentHash(
            totalAmount,
            paymentAmount,
            btcsolTradeInfo[1].toChain,
            paymentTxId[7],
          );
          const signature: string = await getSignature(
            mpc,
            btcsolTradeId[1],
            infoHash,
            SignatureType.ConfirmPayment,
            domain,
          );

          const tx = router
            .connect(mpcNode1)
            .confirmPayment(btcsolTradeId[1], signature);

          await expect(tx)
            .to.emit(router, "ConfirmPayment")
            .withArgs(mpcNode1.address, btcsolTradeId[1]);
          await expect(tx)
            .to.emit(btcsol, "PaymentConfirmed")
            .withArgs(
              await router.getAddress(),
              mpc.address,
              btcsolTradeId[1],
              hexlify(paymentTxId[7]),
            );

          expect(await router.getCurrentStage(btcsolTradeId[1])).deep.eq(
            STAGE.CONFIRM_SETTLEMENT,
          );
          expect(await router.getSettledPayment(btcsolTradeId[1])).deep.eq([
            bundlerHash([btcsolTradeId[1]]),
            hexlify(paymentTxId[7]),
            EMPTY_BYTES,
            true,
          ]);
        });

        it("BTCSOL - Should succeed when MPC Node submits the third trade's payment confirmation", async () => {
          const pFeeAmount: bigint = (btcsolAmountOut[2] * pFeeRate) / DENOM;
          const aFeeAmount: bigint =
            ((btcsolAffiliateInfo[2].aggregatedValue as bigint) *
              btcsolAmountOut[2]) /
            DENOM;
          const totalAmount: bigint = pFeeAmount + aFeeAmount;
          const paymentAmount: bigint = btcsolAmountOut[2] - totalAmount;
          const infoHash = getConfirmPaymentHash(
            totalAmount,
            paymentAmount,
            btcsolTradeInfo[2].toChain,
            paymentTxId[6],
          );
          const signature: string = await getSignature(
            mpc,
            btcsolTradeId[2],
            infoHash,
            SignatureType.ConfirmPayment,
            domain,
          );

          const tx = router
            .connect(mpcNode1)
            .confirmPayment(btcsolTradeId[2], signature);

          await expect(tx)
            .to.emit(router, "ConfirmPayment")
            .withArgs(mpcNode1.address, btcsolTradeId[2]);
          await expect(tx)
            .to.emit(btcsol, "PaymentConfirmed")
            .withArgs(
              await router.getAddress(),
              mpc.address,
              btcsolTradeId[2],
              hexlify(paymentTxId[6]),
            );

          expect(await router.getCurrentStage(btcsolTradeId[2])).deep.eq(
            STAGE.CONFIRM_SETTLEMENT,
          );
          expect(await router.getSettledPayment(btcsolTradeId[2])).deep.eq([
            bundlerHash([btcsolTradeId[0], btcsolTradeId[2]]),
            hexlify(paymentTxId[6]),
            EMPTY_BYTES,
            true,
          ]);
        });
      });

      describe("SOLBTC - confirmPayment() testing", async () => {
        it("SOLBTC - Should succeed when MPC Node submits the first trade's payment confirmation", async () => {
          const infoHash = getConfirmPaymentHash(
            ZERO_VALUE,
            solbtcAmountOut[0],
            solbtcTradeInfo[0].toChain,
            paymentTxId[9],
          );
          const signature: string = await getSignature(
            mpc,
            solbtcTradeId[0],
            infoHash,
            SignatureType.ConfirmPayment,
            domain,
          );

          const tx = router
            .connect(mpcNode1)
            .confirmPayment(solbtcTradeId[0], signature);

          await expect(tx)
            .to.emit(router, "ConfirmPayment")
            .withArgs(mpcNode1.address, solbtcTradeId[0]);
          await expect(tx)
            .to.emit(solbtc, "PaymentConfirmed")
            .withArgs(
              await router.getAddress(),
              mpc.address,
              solbtcTradeId[0],
              hexlify(paymentTxId[9]),
            );

          expect(await router.getCurrentStage(solbtcTradeId[0])).deep.eq(
            STAGE.CONFIRM_SETTLEMENT,
          );
          expect(await router.getSettledPayment(solbtcTradeId[0])).deep.eq([
            bundlerHash([solbtcTradeId[0], solbtcTradeId[2]]),
            hexlify(paymentTxId[9]),
            EMPTY_BYTES,
            true,
          ]);
        });

        it("SOLBTC - Should succeed when MPC Node submits the second trade's payment confirmation", async () => {
          const infoHash = getConfirmPaymentHash(
            ZERO_VALUE,
            solbtcAmountOut[1],
            solbtcTradeInfo[1].toChain,
            paymentTxId[10],
          );
          const signature: string = await getSignature(
            mpc,
            solbtcTradeId[1],
            infoHash,
            SignatureType.ConfirmPayment,
            domain,
          );

          const tx = router
            .connect(mpcNode1)
            .confirmPayment(solbtcTradeId[1], signature);

          await expect(tx)
            .to.emit(router, "ConfirmPayment")
            .withArgs(mpcNode1.address, solbtcTradeId[1]);
          await expect(tx)
            .to.emit(solbtc, "PaymentConfirmed")
            .withArgs(
              await router.getAddress(),
              mpc.address,
              solbtcTradeId[1],
              hexlify(paymentTxId[10]),
            );

          expect(await router.getCurrentStage(solbtcTradeId[1])).deep.eq(
            STAGE.CONFIRM_SETTLEMENT,
          );
          expect(await router.getSettledPayment(solbtcTradeId[1])).deep.eq([
            bundlerHash([solbtcTradeId[1]]),
            hexlify(paymentTxId[10]),
            EMPTY_BYTES,
            true,
          ]);
        });

        it("SOLBTC - Should succeed when MPC Node submits the third trade's payment confirmation", async () => {
          const infoHash = getConfirmPaymentHash(
            ZERO_VALUE,
            solbtcAmountOut[2],
            solbtcTradeInfo[2].toChain,
            paymentTxId[9],
          );
          const signature: string = await getSignature(
            mpc,
            solbtcTradeId[2],
            infoHash,
            SignatureType.ConfirmPayment,
            domain,
          );

          const tx = router
            .connect(mpcNode1)
            .confirmPayment(solbtcTradeId[2], signature);

          await expect(tx)
            .to.emit(router, "ConfirmPayment")
            .withArgs(mpcNode1.address, solbtcTradeId[2]);
          await expect(tx)
            .to.emit(solbtc, "PaymentConfirmed")
            .withArgs(
              await router.getAddress(),
              mpc.address,
              solbtcTradeId[2],
              hexlify(paymentTxId[9]),
            );

          expect(await router.getCurrentStage(solbtcTradeId[2])).deep.eq(
            STAGE.CONFIRM_SETTLEMENT,
          );
          expect(await router.getSettledPayment(solbtcTradeId[2])).deep.eq([
            bundlerHash([solbtcTradeId[0], solbtcTradeId[2]]),
            hexlify(paymentTxId[9]),
            EMPTY_BYTES,
            true,
          ]);
        });
      });
    });

    describe("confirmSettlement() functional testing", async () => {
      describe("BTCEVM - confirmSettlement() testing", async () => {
        it("BTCEVM - Should succeed when MPC Node submits the first trade's settlement confirmation", async () => {
          const infoHash: string = getConfirmSettlementHash(
            ZERO_VALUE,
            releaseTxHash[0],
          );
          const signature: string = await getSignature(
            mpc,
            btcevmTradeId[0],
            infoHash,
            SignatureType.ConfirmSettlement,
            domain,
          );

          const tx = router
            .connect(mpcNode1)
            .confirmSettlement(btcevmTradeId[0], releaseTxHash[0], signature);

          await expect(tx)
            .to.emit(router, "ConfirmSettlement")
            .withArgs(mpcNode1.address, btcevmTradeId[0]);
          await expect(tx)
            .to.emit(btcevm, "SettlementConfirmed")
            .withArgs(
              await router.getAddress(),
              mpc.address,
              btcevmTradeId[0],
              hexlify(releaseTxHash[0]),
            );

          expect(await router.getCurrentStage(btcevmTradeId[0])).deep.eq(
            STAGE.COMPLETE,
          );
          expect(await router.getSettledPayment(btcevmTradeId[0])).deep.eq([
            bundlerHash([btcevmTradeId[0], btcevmTradeId[2]]),
            hexlify(paymentTxId[0]),
            hexlify(releaseTxHash[0]),
            true,
          ]);
        });

        it("BTCEVM - Should succeed when MPC Node submits the second trade's settlement confirmation", async () => {
          const infoHash: string = getConfirmSettlementHash(
            ZERO_VALUE,
            releaseTxHash[1],
          );
          const signature: string = await getSignature(
            mpc,
            btcevmTradeId[1],
            infoHash,
            SignatureType.ConfirmSettlement,
            domain,
          );

          const tx = router
            .connect(mpcNode1)
            .confirmSettlement(btcevmTradeId[1], releaseTxHash[1], signature);

          await expect(tx)
            .to.emit(router, "ConfirmSettlement")
            .withArgs(mpcNode1.address, btcevmTradeId[1]);
          await expect(tx)
            .to.emit(btcevm, "SettlementConfirmed")
            .withArgs(
              await router.getAddress(),
              mpc.address,
              btcevmTradeId[1],
              hexlify(releaseTxHash[1]),
            );

          expect(await router.getCurrentStage(btcevmTradeId[1])).deep.eq(
            STAGE.COMPLETE,
          );
          expect(await router.getSettledPayment(btcevmTradeId[1])).deep.eq([
            bundlerHash([btcevmTradeId[1]]),
            hexlify(paymentTxId[1]),
            hexlify(releaseTxHash[1]),
            true,
          ]);
        });

        it("BTCEVM - Should succeed when MPC Node submits the third trade's settlement confirmation", async () => {
          const infoHash: string = getConfirmSettlementHash(
            ZERO_VALUE,
            releaseTxHash[2],
          );
          const signature: string = await getSignature(
            mpc,
            btcevmTradeId[2],
            infoHash,
            SignatureType.ConfirmSettlement,
            domain,
          );

          const tx = router
            .connect(mpcNode1)
            .confirmSettlement(btcevmTradeId[2], releaseTxHash[2], signature);

          await expect(tx)
            .to.emit(router, "ConfirmSettlement")
            .withArgs(mpcNode1.address, btcevmTradeId[2]);
          await expect(tx)
            .to.emit(btcevm, "SettlementConfirmed")
            .withArgs(
              await router.getAddress(),
              mpc.address,
              btcevmTradeId[2],
              hexlify(releaseTxHash[2]),
            );

          expect(await router.getCurrentStage(btcevmTradeId[2])).deep.eq(
            STAGE.COMPLETE,
          );
          expect(await router.getSettledPayment(btcevmTradeId[2])).deep.eq([
            bundlerHash([btcevmTradeId[0], btcevmTradeId[2]]),
            hexlify(paymentTxId[0]),
            hexlify(releaseTxHash[2]),
            true,
          ]);
        });
      });

      describe("EVMBTC - confirmSettlement() testing", async () => {
        it("EVMBTC - Should succeed when MPC Node submits the first trade's settlement confirmation", async () => {
          const infoHash: string = getConfirmSettlementHash(
            evmbtcPFeeAmount[0] + evmbtcAFeeAmount[0],
            releaseTxHash[3],
          );
          const signature: string = await getSignature(
            mpc,
            evmbtcTradeId[0],
            infoHash,
            SignatureType.ConfirmSettlement,
            domain,
          );

          const tx = router
            .connect(mpcNode1)
            .confirmSettlement(evmbtcTradeId[0], releaseTxHash[3], signature);

          await expect(tx)
            .to.emit(router, "ConfirmSettlement")
            .withArgs(mpcNode1.address, evmbtcTradeId[0]);
          await expect(tx)
            .to.emit(evmbtc, "SettlementConfirmed")
            .withArgs(
              await router.getAddress(),
              mpc.address,
              evmbtcTradeId[0],
              hexlify(releaseTxHash[3]),
            );

          expect(await router.getCurrentStage(evmbtcTradeId[0])).deep.eq(
            STAGE.COMPLETE,
          );
          expect(await router.getSettledPayment(evmbtcTradeId[0])).deep.eq([
            bundlerHash([evmbtcTradeId[0], evmbtcTradeId[2]]),
            hexlify(paymentTxId[3]),
            hexlify(releaseTxHash[3]),
            true,
          ]);
        });

        it("EVMBTC - Should succeed when MPC Node submits the second trade's settlement confirmation", async () => {
          const infoHash: string = getConfirmSettlementHash(
            evmbtcPFeeAmount[1] + evmbtcAFeeAmount[1],
            releaseTxHash[4],
          );
          const signature: string = await getSignature(
            mpc,
            evmbtcTradeId[1],
            infoHash,
            SignatureType.ConfirmSettlement,
            domain,
          );

          const tx = router
            .connect(mpcNode1)
            .confirmSettlement(evmbtcTradeId[1], releaseTxHash[4], signature);

          await expect(tx)
            .to.emit(router, "ConfirmSettlement")
            .withArgs(mpcNode1.address, evmbtcTradeId[1]);
          await expect(tx)
            .to.emit(evmbtc, "SettlementConfirmed")
            .withArgs(
              await router.getAddress(),
              mpc.address,
              evmbtcTradeId[1],
              hexlify(releaseTxHash[4]),
            );

          expect(await router.getCurrentStage(evmbtcTradeId[1])).deep.eq(
            STAGE.COMPLETE,
          );
          expect(await router.getSettledPayment(evmbtcTradeId[1])).deep.eq([
            bundlerHash([evmbtcTradeId[1]]),
            hexlify(paymentTxId[4]),
            hexlify(releaseTxHash[4]),
            true,
          ]);
        });

        it("EVMBTC - Should succeed when MPC Node submits the third trade's settlement confirmation", async () => {
          const infoHash: string = getConfirmSettlementHash(
            evmbtcPFeeAmount[2] + evmbtcAFeeAmount[2],
            releaseTxHash[5],
          );
          const signature: string = await getSignature(
            mpc,
            evmbtcTradeId[2],
            infoHash,
            SignatureType.ConfirmSettlement,
            domain,
          );

          const tx = router
            .connect(mpcNode1)
            .confirmSettlement(evmbtcTradeId[2], releaseTxHash[5], signature);

          await expect(tx)
            .to.emit(router, "ConfirmSettlement")
            .withArgs(mpcNode1.address, evmbtcTradeId[2]);
          await expect(tx)
            .to.emit(evmbtc, "SettlementConfirmed")
            .withArgs(
              await router.getAddress(),
              mpc.address,
              evmbtcTradeId[2],
              hexlify(releaseTxHash[5]),
            );

          expect(await router.getCurrentStage(evmbtcTradeId[2])).deep.eq(
            STAGE.COMPLETE,
          );
          expect(await router.getSettledPayment(evmbtcTradeId[2])).deep.eq([
            bundlerHash([evmbtcTradeId[0], evmbtcTradeId[2]]),
            hexlify(paymentTxId[3]),
            hexlify(releaseTxHash[5]),
            true,
          ]);
        });
      });

      describe("BTCSOL - confirmSettlement() testing", async () => {
        it("BTCSOL - Should succeed when MPC Node submits the first trade's settlement confirmation", async () => {
          const infoHash: string = getConfirmSettlementHash(
            ZERO_VALUE,
            releaseTxHash[6],
          );
          const signature: string = await getSignature(
            mpc,
            btcsolTradeId[0],
            infoHash,
            SignatureType.ConfirmSettlement,
            domain,
          );

          const tx = router
            .connect(mpcNode1)
            .confirmSettlement(btcsolTradeId[0], releaseTxHash[6], signature);

          await expect(tx)
            .to.emit(router, "ConfirmSettlement")
            .withArgs(mpcNode1.address, btcsolTradeId[0]);
          await expect(tx)
            .to.emit(btcsol, "SettlementConfirmed")
            .withArgs(
              await router.getAddress(),
              mpc.address,
              btcsolTradeId[0],
              hexlify(releaseTxHash[6]),
            );

          expect(await router.getCurrentStage(btcsolTradeId[0])).deep.eq(
            STAGE.COMPLETE,
          );
          expect(await router.getSettledPayment(btcsolTradeId[0])).deep.eq([
            bundlerHash([btcsolTradeId[0], btcsolTradeId[2]]),
            hexlify(paymentTxId[6]),
            hexlify(releaseTxHash[6]),
            true,
          ]);
        });

        it("BTCSOL - Should succeed when MPC Node submits the second trade's settlement confirmation", async () => {
          const infoHash: string = getConfirmSettlementHash(
            ZERO_VALUE,
            releaseTxHash[7],
          );
          const signature: string = await getSignature(
            mpc,
            btcsolTradeId[1],
            infoHash,
            SignatureType.ConfirmSettlement,
            domain,
          );

          const tx = router
            .connect(mpcNode1)
            .confirmSettlement(btcsolTradeId[1], releaseTxHash[7], signature);

          await expect(tx)
            .to.emit(router, "ConfirmSettlement")
            .withArgs(mpcNode1.address, btcsolTradeId[1]);
          await expect(tx)
            .to.emit(btcsol, "SettlementConfirmed")
            .withArgs(
              await router.getAddress(),
              mpc.address,
              btcsolTradeId[1],
              hexlify(releaseTxHash[7]),
            );

          expect(await router.getCurrentStage(btcsolTradeId[1])).deep.eq(
            STAGE.COMPLETE,
          );
          expect(await router.getSettledPayment(btcsolTradeId[1])).deep.eq([
            bundlerHash([btcsolTradeId[1]]),
            hexlify(paymentTxId[7]),
            hexlify(releaseTxHash[7]),
            true,
          ]);
        });

        it("BTCSOL - Should succeed when MPC Node submits the third trade's settlement confirmation", async () => {
          const infoHash: string = getConfirmSettlementHash(
            ZERO_VALUE,
            releaseTxHash[8],
          );
          const signature: string = await getSignature(
            mpc,
            btcsolTradeId[2],
            infoHash,
            SignatureType.ConfirmSettlement,
            domain,
          );

          const tx = router
            .connect(mpcNode1)
            .confirmSettlement(btcsolTradeId[2], releaseTxHash[8], signature);

          await expect(tx)
            .to.emit(router, "ConfirmSettlement")
            .withArgs(mpcNode1.address, btcsolTradeId[2]);
          await expect(tx)
            .to.emit(btcsol, "SettlementConfirmed")
            .withArgs(
              await router.getAddress(),
              mpc.address,
              btcsolTradeId[2],
              hexlify(releaseTxHash[8]),
            );

          expect(await router.getCurrentStage(btcsolTradeId[2])).deep.eq(
            STAGE.COMPLETE,
          );
          expect(await router.getSettledPayment(btcsolTradeId[2])).deep.eq([
            bundlerHash([btcsolTradeId[0], btcsolTradeId[2]]),
            hexlify(paymentTxId[6]),
            hexlify(releaseTxHash[8]),
            true,
          ]);
        });
      });

      describe("SOLBTC - confirmSettlement() testing", async () => {
        it("SOLBTC - Should succeed when MPC Node submits the first trade's settlement confirmation", async () => {
          const infoHash: string = getConfirmSettlementHash(
            solbtcPFeeAmount[0] + solbtcAFeeAmount[0],
            releaseTxHash[9],
          );
          const signature: string = await getSignature(
            mpc,
            solbtcTradeId[0],
            infoHash,
            SignatureType.ConfirmSettlement,
            domain,
          );

          const tx = router
            .connect(mpcNode1)
            .confirmSettlement(solbtcTradeId[0], releaseTxHash[9], signature);

          await expect(tx)
            .to.emit(router, "ConfirmSettlement")
            .withArgs(mpcNode1.address, solbtcTradeId[0]);
          await expect(tx)
            .to.emit(solbtc, "SettlementConfirmed")
            .withArgs(
              await router.getAddress(),
              mpc.address,
              solbtcTradeId[0],
              hexlify(releaseTxHash[9]),
            );

          expect(await router.getCurrentStage(solbtcTradeId[0])).deep.eq(
            STAGE.COMPLETE,
          );
          expect(await router.getSettledPayment(solbtcTradeId[0])).deep.eq([
            bundlerHash([solbtcTradeId[0], solbtcTradeId[2]]),
            hexlify(paymentTxId[9]),
            hexlify(releaseTxHash[9]),
            true,
          ]);
        });

        it("SOLBTC - Should succeed when MPC Node submits the second trade's settlement confirmation", async () => {
          const infoHash: string = getConfirmSettlementHash(
            solbtcPFeeAmount[1] + solbtcAFeeAmount[1],
            releaseTxHash[10],
          );
          const signature: string = await getSignature(
            mpc,
            solbtcTradeId[1],
            infoHash,
            SignatureType.ConfirmSettlement,
            domain,
          );

          const tx = router
            .connect(mpcNode1)
            .confirmSettlement(solbtcTradeId[1], releaseTxHash[10], signature);

          await expect(tx)
            .to.emit(router, "ConfirmSettlement")
            .withArgs(mpcNode1.address, solbtcTradeId[1]);
          await expect(tx)
            .to.emit(solbtc, "SettlementConfirmed")
            .withArgs(
              await router.getAddress(),
              mpc.address,
              solbtcTradeId[1],
              hexlify(releaseTxHash[10]),
            );

          expect(await router.getCurrentStage(solbtcTradeId[1])).deep.eq(
            STAGE.COMPLETE,
          );
          expect(await router.getSettledPayment(solbtcTradeId[1])).deep.eq([
            bundlerHash([solbtcTradeId[1]]),
            hexlify(paymentTxId[10]),
            hexlify(releaseTxHash[10]),
            true,
          ]);
        });

        it("SOLBTC - Should succeed when MPC Node submits the third trade's settlement confirmation", async () => {
          const infoHash: string = getConfirmSettlementHash(
            solbtcPFeeAmount[2] + solbtcAFeeAmount[2],
            releaseTxHash[11],
          );
          const signature: string = await getSignature(
            mpc,
            solbtcTradeId[2],
            infoHash,
            SignatureType.ConfirmSettlement,
            domain,
          );

          const tx = router
            .connect(mpcNode1)
            .confirmSettlement(solbtcTradeId[2], releaseTxHash[11], signature);

          await expect(tx)
            .to.emit(router, "ConfirmSettlement")
            .withArgs(mpcNode1.address, solbtcTradeId[2]);
          await expect(tx)
            .to.emit(solbtc, "SettlementConfirmed")
            .withArgs(
              await router.getAddress(),
              mpc.address,
              solbtcTradeId[2],
              hexlify(releaseTxHash[11]),
            );

          expect(await router.getCurrentStage(solbtcTradeId[2])).deep.eq(
            STAGE.COMPLETE,
          );
          expect(await router.getSettledPayment(solbtcTradeId[2])).deep.eq([
            bundlerHash([solbtcTradeId[0], solbtcTradeId[2]]),
            hexlify(paymentTxId[9]),
            hexlify(releaseTxHash[11]),
            true,
          ]);
        });
      });
    });
  });

  describe("Query Core Handler and its type via Router", async () => {
    describe("getHandler() functional testing", async () => {
      it("Should be able to retrieve info with an invalid Route - Un-registered fromChain", async () => {
        const invalidFromChain = toUtf8Bytes("Invalid_from_chain");
        expect(
          await router.getHandler(
            invalidFromChain,
            btcevmTradeInfo[0].toChain[1],
          ),
        ).deep.eq([ZeroAddress, ""]);
      });

      it("Should be able to retrieve info with an invalid Route - Un-registered toChain", async () => {
        const invalidToChain = toUtf8Bytes("Invalid_to_chain");
        expect(
          await router.getHandler(
            btcevmTradeInfo[0].fromChain[1],
            invalidToChain,
          ),
        ).deep.eq([ZeroAddress, ""]);
      });

      it("Should succeed when querying Core Handler info with a valid fromChain and toChain - BTCEVM", async () => {
        expect(
          await router.getHandler(
            btcevmTradeInfo[0].fromChain[1],
            btcevmTradeInfo[0].toChain[1],
          ),
        ).deep.eq([await btcevm.getAddress(), "BTCEVM"]);
      });

      it("Should succeed when querying Core Handler info with a valid fromChain and toChain - EVMBTC", async () => {
        expect(
          await router.getHandler(
            evmbtcTradeInfo[0].fromChain[1],
            evmbtcTradeInfo[0].toChain[1],
          ),
        ).deep.eq([await evmbtc.getAddress(), "EVMBTC"]);
      });
    });

    describe("getHandlerOf() functional testing", async () => {
      it("Should be able to retrieve info with an invalid tradeId", async () => {
        const invalidTradeId = keccak256(toUtf8Bytes("Invalid_Trade_Id"));
        expect(await router.getHandlerOf(invalidTradeId)).deep.eq([
          ZeroAddress,
          "",
        ]);
      });

      it("Should succeed when querying Core Handler info with a valid tradeId - BTCEVM", async () => {
        expect(await router.getHandlerOf(btcevmTradeId[0])).deep.eq([
          await btcevm.getAddress(),
          "BTCEVM",
        ]);
      });

      it("Should succeed when querying Core Handler info with a valid tradeId - EVMBTC", async () => {
        expect(await router.getHandlerOf(evmbtcTradeId[0])).deep.eq([
          await evmbtc.getAddress(),
          "EVMBTC",
        ]);
      });
    });
  });

  describe("Query Management's settings via Router", async () => {
    describe("isValidNetwork() functional testing", async () => {
      it("Should be able to check whether networkId is valid", async () => {
        const validNetworkId = btcevmTradeInfo[0].fromChain[1];
        expect(await management.isValidNetwork(validNetworkId)).deep.eq(true);
        expect(await router.isValidNetwork(validNetworkId)).deep.eq(true);
      });

      it("Should be able to check whether networkId is invalid", async () => {
        const invalidNetworkId = toUtf8Bytes("Invalid_network_id");
        expect(await management.isValidNetwork(invalidNetworkId)).deep.eq(
          false,
        );
        expect(await router.isValidNetwork(invalidNetworkId)).deep.eq(false);
      });
    });

    describe("isValidToken() functional testing", async () => {
      it("Should be able to check one tokenId is valid", async () => {
        const validNetworkId = btcevmTradeInfo[0].fromChain[1];
        const validTokenId = btcevmTradeInfo[0].fromChain[2];
        expect(
          await management.isValidToken(validNetworkId, validTokenId),
        ).deep.eq(true);
        expect(await router.isValidToken(validNetworkId, validTokenId)).deep.eq(
          true,
        );
      });

      it("Should be able to check one tokenId is invalid - NetworkId invalid and TokenId valid", async () => {
        const validTokenId = btcevmTradeInfo[0].fromChain[2];
        const invalidNetworkId = toUtf8Bytes("Invalid_network_id");
        expect(
          await management.isValidToken(invalidNetworkId, validTokenId),
        ).deep.eq(false);
        expect(
          await router.isValidToken(invalidNetworkId, validTokenId),
        ).deep.eq(false);
      });

      it("Should be able to check one tokenId is invalid - NetworkId valid and TokenId invalid", async () => {
        const validNetworkId = btcevmTradeInfo[0].fromChain[1];
        const invalidTokenId = toUtf8Bytes("Invalid_token_id");
        expect(
          await management.isValidToken(validNetworkId, invalidTokenId),
        ).deep.eq(false);
        expect(
          await router.isValidToken(validNetworkId, invalidTokenId),
        ).deep.eq(false);
      });
    });

    describe("isSolver() functional testing", async () => {
      it("Should be able to check whether one account has the Solver role", async () => {
        expect(await management.solvers(solver.address)).deep.eq(true);
        expect(await router.isSolver(solver.address)).deep.eq(true);

        expect(await management.solvers(admin.address)).deep.eq(false);
        expect(await router.isSolver(admin.address)).deep.eq(false);
      });
    });

    describe("isMPCNode() functional testing", async () => {
      it("Should be able to check whether an account is the MPC Node's associated account", async () => {
        expect(await management.mpcNodes(solver.address)).deep.eq(false);
        expect(await router.isMPCNode(solver.address)).deep.eq(false);

        expect(await management.mpcNodes(mpcNode1.address)).deep.eq(true);
        expect(await router.isMPCNode(mpcNode1.address)).deep.eq(true);

        expect(await management.mpcNodes(mpcNode2.address)).deep.eq(true);
        expect(await router.isMPCNode(mpcNode2.address)).deep.eq(true);
      });
    });

    describe("isValidPMM() functional testing", async () => {
      it("Should be able to check whether one pmmId is a valid registered PMM", async () => {
        const validPmmId = btcevmPresigns[0][0].pmmId;
        expect(await management.isValidPMM(validPmmId)).deep.eq(true);
        expect(await router.isValidPMM(validPmmId)).deep.eq(true);

        const invalidPmmId = keccak256(toUtf8Bytes("Invalid_PMM_ID"));
        expect(await management.isValidPMM(invalidPmmId)).deep.eq(false);
        expect(await router.isValidPMM(invalidPmmId)).deep.eq(false);
      });
    });

    describe("isValidPMMAccount() functional testing", async () => {
      it("Should be able to check whether an account is the PMM's associated account", async () => {
        const pmmId = btcevmPresigns[0][0].pmmId;
        expect(await management.isValidPMMAccount(pmmId, accounts[0])).deep.eq(
          true,
        );
        expect(await management.isValidPMMAccount(pmmId, accounts[1])).deep.eq(
          false,
        );

        expect(await router.isValidPMMAccount(pmmId, accounts[0])).deep.eq(
          true,
        );
        expect(await router.isValidPMMAccount(pmmId, accounts[1])).deep.eq(
          false,
        );
      });
    });

    describe("isValidPubkey() functional testing", async () => {
      it("Should be able to check whether one pubkey is a valid one", async () => {
        let networkId = btcevmTradeInfo[0].fromChain[1];
        const pubkey = mpc.signingKey.compressedPublicKey;
        expect(await management.isValidPubkey(networkId, pubkey)).deep.eq(true);
        expect(await router.isValidPubkey(networkId, pubkey)).deep.eq(true);

        const invalidPubkey = btcevmScriptInfo[0].depositInfo[2]; // `userEphemeralKey`
        expect(
          await management.isValidPubkey(networkId, invalidPubkey),
        ).deep.eq(false);
        expect(await router.isValidPubkey(networkId, invalidPubkey)).deep.eq(
          false,
        );
      });
    });

    describe("isSuspended() functional testing", async () => {
      it("Should be able to check whether one stage is suspended - OPERATING Mode", async () => {
        expect(await router.getProtocolState()).deep.eq(Status.OPERATING);

        expect(await router.isSuspended(STAGE.SUBMIT)).deep.eq(false);
        expect(await router.isSuspended(STAGE.CONFIRM_DEPOSIT)).deep.eq(false);
        expect(await router.isSuspended(STAGE.SELECT_PMM)).deep.eq(false);
        expect(await router.isSuspended(STAGE.MAKE_PAYMENT)).deep.eq(false);
        expect(await router.isSuspended(STAGE.CONFIRM_PAYMENT)).deep.eq(false);
        expect(await router.isSuspended(STAGE.CONFIRM_SETTLEMENT)).deep.eq(
          false,
        );
      });

      it("Should be able to check whether one stage is suspended - SUSPEND Mode", async () => {
        await management.connect(admin).suspend();
        expect(await router.getProtocolState()).deep.eq(Status.SUSPENDED);

        expect(await router.isSuspended(STAGE.SUBMIT)).deep.eq(true);
        expect(await router.isSuspended(STAGE.CONFIRM_DEPOSIT)).deep.eq(true);
        expect(await router.isSuspended(STAGE.SELECT_PMM)).deep.eq(true);
        expect(await router.isSuspended(STAGE.MAKE_PAYMENT)).deep.eq(false);
        expect(await router.isSuspended(STAGE.CONFIRM_PAYMENT)).deep.eq(false);
        expect(await router.isSuspended(STAGE.CONFIRM_SETTLEMENT)).deep.eq(
          false,
        );

        //  set back to normal
        await management.connect(admin).resume();
      });

      it("Should be able to check whether one stage is suspended - SHUTDOWN Mode", async () => {
        await management.connect(admin).shutdown();
        expect(await router.getProtocolState()).deep.eq(Status.SHUTDOWN);

        expect(await router.isSuspended(STAGE.SUBMIT)).deep.eq(true);
        expect(await router.isSuspended(STAGE.CONFIRM_DEPOSIT)).deep.eq(true);
        expect(await router.isSuspended(STAGE.SELECT_PMM)).deep.eq(true);
        expect(await router.isSuspended(STAGE.MAKE_PAYMENT)).deep.eq(true);
        expect(await router.isSuspended(STAGE.CONFIRM_PAYMENT)).deep.eq(true);
        expect(await router.isSuspended(STAGE.CONFIRM_SETTLEMENT)).deep.eq(
          true,
        );

        //  set back to normal
        await management.connect(admin).resume();
      });
    });

    describe("getManagementOwner() functional testing", async () => {
      it("Should be able to query the Management contract's Owner via Router", async () => {
        const owner = await management.owner();

        expect(await router.getManagementOwner()).deep.eq(owner);
      });
    });

    describe("getProtocolState() functional testing", async () => {
      it("Should be able to query protocol's status via Router", async () => {
        expect(await router.getProtocolState()).deep.eq(Status.OPERATING);

        //  change to `Suspend` state
        await management.connect(admin).suspend();
        expect(await router.getProtocolState()).deep.eq(Status.SUSPENDED);

        //  set back to normal
        await management.connect(admin).resume();
        expect(await router.getProtocolState()).deep.eq(Status.OPERATING);
      });
    });

    describe("getPFeeRate() functional testing", async () => {
      it("Should be able to query a current protocol fee rate via Router", async () => {
        const feeRate = await management.pFeeRate();

        expect(await router.getPFeeRate()).deep.eq(feeRate);
      });
    });

    describe("getLatestMPCInfo() functional testing", async () => {
      it("Should be able to query the latest MPC's pubkeys info for one networkId via Router", async () => {
        const networkId = btcevmTradeInfo[0].fromChain[1];
        const mpcInfo = await management.getLatestMPCInfo(networkId);
        expect(mpcInfo).not.eq([
          ZeroAddress,
          BigInt(0),
          EMPTY_BYTES,
          EMPTY_BYTES,
        ]);

        expect(await router.getLatestMPCInfo(networkId)).deep.eq(mpcInfo);
      });
    });

    describe("getMPCInfo() functional testing", async () => {
      it("Should be able to retrieve a full MPC's pubkeys info via Router", async () => {
        const networkId = evmbtcTradeInfo[0].fromChain[1];
        const pubkey = mpc.signingKey.compressedPublicKey;
        const mpcInfo = await management.getMPCInfo(networkId, pubkey);
        expect(mpcInfo).not.eq([
          ZeroAddress,
          BigInt(0),
          EMPTY_BYTES,
          EMPTY_BYTES,
        ]);

        expect(await router.getMPCInfo(networkId, pubkey)).deep.eq(mpcInfo);
      });
    });

    describe("numOfSupportedTokens() functional testing", async () => {
      it("Should be able to query a number of supported tokens via Router", async () => {
        const num = await management.numOfSupportedTokens();
        expect(await router.numOfSupportedTokens()).deep.eq(num);
      });
    });

    describe("getTokens() functional testing", async () => {
      it("Should be able to retrieve a supported token list via Router", async () => {
        const fromIdx = BigInt(0);
        const numOfSupportedTokens = await management.numOfSupportedTokens();
        const list = await management.getTokens(fromIdx, numOfSupportedTokens);
        expect(await router.getTokens(fromIdx, numOfSupportedTokens)).deep.eq(
          list,
        );
      });
    });

    describe("numOfPMMAccounts() functional testing", async () => {
      it("Should be able to retrieve a number of associated accounts of one registered pmmId", async () => {
        const pmmId = btcevmPresigns[0][0].pmmId;
        const numOfAccounts = await management.numOfPMMAccounts(pmmId);

        expect(await router.numOfPMMAccounts(pmmId)).deep.eq(numOfAccounts);
      });

      it("Should be able to retrieve a number of associated accounts of un-registered pmmId", async () => {
        const pmmId = keccak256(toUtf8Bytes("Invalid_PMM_ID"));
        const numOfAccounts = await management.numOfPMMAccounts(pmmId);
        expect(numOfAccounts).deep.eq(0);

        expect(await router.numOfPMMAccounts(pmmId)).deep.eq(numOfAccounts);
      });
    });

    describe("getPMMAccounts() functional testing", async () => {
      it("Should be able to retrieve associated accounts of a registered PMM", async () => {
        const pmmId = btcevmPresigns[0][0].pmmId;
        const fromIdx = BigInt(0);
        const toIdx = await router.numOfPMMAccounts(pmmId);
        const list = await management.getPMMAccounts(pmmId, fromIdx, toIdx);

        expect(await router.getPMMAccounts(pmmId, fromIdx, toIdx)).deep.eq(
          list,
        );
      });

      it("Should be able to retrieve associated accounts of un-registered PMM - Empty list", async () => {
        //  @dev: When `_numOfPMMAccounts(pmmId) == 0`, a contract returns an empty list
        //  Thus, it won't revert when `toIdx` goes out of range
        const pmmId = keccak256(toUtf8Bytes("Invalid_PMM_ID"));
        const fromIdx = BigInt(0);
        const toIdx = BigInt(1);
        const numOfAccounts = await router.numOfPMMAccounts(pmmId);
        expect(numOfAccounts).lessThan(toIdx);
        const list = await management.getPMMAccounts(pmmId, fromIdx, toIdx);
        expect(list).deep.eq([]);

        expect(await router.getPMMAccounts(pmmId, fromIdx, toIdx)).deep.eq(
          list,
        );
      });
    });
  });
});
