import { expect } from "chai";
import { ethers, network } from "hardhat";
import {
  ZeroAddress,
  keccak256,
  toUtf8Bytes,
  TypedDataDomain,
  AbiCoder,
  getAddress,
  ZeroHash,
} from "ethers";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";
import { time, takeSnapshot } from "@nomicfoundation/hardhat-network-helpers";

import {
  Protocol,
  Protocol__factory,
  NativeVault,
  NativeVault__factory,
} from "../../typechain-types";
import { IBaseVault } from "../../typechain-types/contracts/asset-chain/NativeVault";
import { ITypes as CoreTypes } from "../../typechain-types/contracts/utils/Core";
import { WETH9_ABI, WETH9_BYTECODE } from "../clone-token/ethereum/weth9/weth9";
import { getAffiliateInfo, getTradeInfo } from "../../sample-data/evmbtc";
import getTradeId from "../../scripts/utils/others/getTradeId";
import {
  getPresignSignature,
  getSettlementSignature,
} from "../../scripts/utils/signatures/getSignature";
import { getPresignHash } from "../../scripts/utils/signatures/getInfoHash";

const Zero = BigInt(0);
const DENOM = BigInt(10_000);
const pFeeRate = BigInt(25);
const EMPTY_TRADE_HASH = ZeroHash;
const abiCoder = AbiCoder.defaultAbiCoder();

async function adjustTime(nextTimestamp: number): Promise<void> {
  await time.increaseTo(nextTimestamp);
}

function hashOf(data: IBaseVault.TradeDetailStruct): string {
  const tradeHash: string = keccak256(
    abiCoder.encode(
      ["uint256", "uint64", "address", "address", "address"],
      Object.values(data),
    ),
  );

  return tradeHash;
}

describe("NativeVault Contract Testing", () => {
  let admin: HardhatEthersSigner,
    solver: HardhatEthersSigner,
    mpc: HardhatEthersSigner,
    mpcNode: HardhatEthersSigner,
    pmm: HardhatEthersSigner,
    ephemeralAssetKey: HardhatEthersSigner,
    ephemeralL2Key: HardhatEthersSigner;
  let accounts: HardhatEthersSigner[];

  let protocol: Protocol, clone: Protocol, vault: NativeVault;
  let weth9: any, domain: TypedDataDomain;
  let tradeInfo: CoreTypes.TradeInfoStruct[] = [];
  let affiliate: CoreTypes.AffiliateStruct[] = [];
  let tradeDetail: IBaseVault.TradeDetailStruct[] = [];
  let tradeInput: IBaseVault.TradeInputStruct[] = [];
  let sessionId: bigint[] = [];
  let tradeId: string[] = [];
  let ephemeralL2Address: string;

  const weth9Addr = "0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14";
  const provider = ethers.provider;
  const fromChain = "ethereum-sepolia";
  const fromToken = "native";

  before(async () => {
    await network.provider.request({
      method: "hardhat_reset",
      params: [],
    });

    [
      admin,
      solver,
      mpc,
      mpcNode,
      pmm,
      ephemeralAssetKey,
      ephemeralL2Key,
      ...accounts
    ] = await ethers.getSigners();

    //  Deploy Wrapped ETH (WETH9) contract
    await ethers.provider.send("hardhat_setCode", [weth9Addr, WETH9_BYTECODE]);
    weth9 = new ethers.Contract(weth9Addr, WETH9_ABI, provider);

    //  Deploy Protocol contract
    const Protocol = (await ethers.getContractFactory(
      "Protocol",
      admin,
    )) as Protocol__factory;
    protocol = await Protocol.deploy(admin.address, admin.address);
    clone = await Protocol.deploy(admin.address, admin.address);

    //  Deploy Vault contract
    const NativeVault = (await ethers.getContractFactory(
      "NativeVault",
      admin,
    )) as NativeVault__factory;
    vault = await NativeVault.deploy(await protocol.getAddress(), weth9Addr);

    //  Prepare TradeInfo and TradeId
    for (let i = 0; i < 4; i++) {
      sessionId.push(BigInt(keccak256(toUtf8Bytes(crypto.randomUUID()))));
      tradeInfo.push(getTradeInfo(fromChain, fromToken, accounts[i].address));
      affiliate.push(getAffiliateInfo());
      tradeId.push(getTradeId(sessionId[i], solver.address, tradeInfo[i]));
      tradeDetail.push({
        amount: tradeInfo[i].amountIn,
        timeout: BigInt(Math.floor(Date.now() / 1000) + (24 + i) * 3600),
        mpc: mpc.address,
        ephemeralAssetAddress: ephemeralAssetKey.address,
        refundAddress: getAddress(tradeInfo[i].fromChain[0].toString()),
      });
      tradeInput.push({
        sessionId: sessionId[i],
        solver: solver.address,
        tradeInfo: tradeInfo[i],
      });
    }
    ephemeralL2Address = ephemeralL2Key.address;

    const contractDomain: TypedDataDomain = await vault.eip712Domain();
    domain = {
      name: contractDomain.name,
      version: contractDomain.version,
      chainId: contractDomain.chainId,
      verifyingContract: contractDomain.verifyingContract,
    };
  });

  it("Should be able to check the initialized settings of Vault contract", async () => {
    expect(await vault.WRAPPED_TOKEN()).deep.equal(weth9Addr);
    expect(await vault.protocol()).deep.equal(await protocol.getAddress());
  });

  describe("setProtocol() functional testing", async () => {
    it("Should revert when Non-Owner tries to set new Protocol contract", async () => {
      expect(await vault.protocol()).deep.equal(await protocol.getAddress());

      await expect(
        vault.connect(accounts[0]).setProtocol(accounts[0].address),
      ).to.be.revertedWithCustomError(vault, "Unauthorized");

      expect(await vault.protocol()).deep.equal(await protocol.getAddress());
    });

    it("Should revert when Owner sets 0x0 as Protocol contract", async () => {
      expect(await vault.protocol()).deep.equal(await protocol.getAddress());

      await expect(
        vault.connect(admin).setProtocol(ZeroAddress),
      ).to.be.revertedWithCustomError(vault, "AddressZero");

      expect(await vault.protocol()).deep.equal(await protocol.getAddress());
    });

    it("Should succeed when Owner sets new Protocol contract", async () => {
      expect(await vault.protocol()).deep.equal(await protocol.getAddress());

      const newProtocol = await clone.getAddress();
      const tx = vault.connect(admin).setProtocol(newProtocol);
      await expect(tx)
        .to.emit(vault, "ProtocolUpdated")
        .withArgs(admin.address, newProtocol);

      expect(await vault.protocol()).deep.equal(newProtocol);
    });

    it("Should succeed when Owner sets back to previous Protocol contract", async () => {
      const currentProtocol = await clone.getAddress();
      const prevProtocol = await protocol.getAddress();

      expect(await vault.protocol()).deep.equal(currentProtocol);

      const tx = vault.connect(admin).setProtocol(prevProtocol);
      await expect(tx)
        .to.emit(vault, "ProtocolUpdated")
        .withArgs(admin.address, prevProtocol);

      expect(await vault.protocol()).deep.equal(prevProtocol);
    });
  });

  describe("deposit() functional testing", async () => {
    it("Should revert when User tries to deposit, but fromUserAddress not match with msg.sender", async () => {
      const vaultAddress = await vault.getAddress();
      const balance = await provider.getBalance(vaultAddress);

      await expect(
        vault
          .connect(accounts[1])
          .deposit(ephemeralL2Address, tradeInput[0], tradeDetail[0], {
            value: tradeDetail[0].amount,
          }),
      ).to.be.revertedWithCustomError(vault, "Unauthorized");

      expect(await provider.getBalance(vaultAddress)).deep.eq(balance);
    });

    it("Should revert when User tries to deposit, but timeout is invalid", async () => {
      const block = await provider.getBlockNumber();
      const timestamp = (await provider.getBlock(block))?.timestamp as number;
      const invalidTimeout = Number(timestamp) - 1;
      const invalidTradeDetail = structuredClone(tradeDetail[0]);
      invalidTradeDetail.timeout = BigInt(invalidTimeout);

      const vaultAddress = await vault.getAddress();
      const balance = await provider.getBalance(vaultAddress);

      await expect(
        vault
          .connect(accounts[0])
          .deposit(ephemeralL2Address, tradeInput[0], invalidTradeDetail, {
            value: invalidTradeDetail.amount,
          }),
      ).to.be.revertedWithCustomError(vault, "InvalidTimeout");

      expect(await provider.getBalance(vaultAddress)).deep.eq(balance);
    });

    it("Should revert when User tries to deposit, but amount = 0", async () => {
      const invalidTradeInfo = structuredClone(tradeInfo[0]);
      invalidTradeInfo.amountIn = Zero;
      const invalidTradeDetail = structuredClone(tradeDetail[0]);
      invalidTradeDetail.amount = Zero;
      const invalidTradeInput = structuredClone(tradeInput[0]);
      invalidTradeInput.tradeInfo = invalidTradeInfo;

      const vaultAddress = await vault.getAddress();
      const balance = await provider.getBalance(vaultAddress);

      await expect(
        vault
          .connect(accounts[0])
          .deposit(ephemeralL2Address, invalidTradeInput, invalidTradeDetail, {
            value: invalidTradeDetail.amount,
          }),
      ).to.be.revertedWithCustomError(vault, "InvalidDepositAmount");

      expect(await provider.getBalance(vaultAddress)).deep.eq(balance);
    });

    it("Should revert when User tries to deposit, but `amount` and `amountIn`, specified in the TradeDetail and TradeInfo, not matched", async () => {
      const invalidTradeDetail = structuredClone(tradeDetail[0]);
      invalidTradeDetail.amount = (tradeInfo[0].amountIn as bigint) - BigInt(1);

      const vaultAddress = await vault.getAddress();
      const balance = await provider.getBalance(vaultAddress);

      await expect(
        vault
          .connect(accounts[0])
          .deposit(ephemeralL2Address, tradeInput[0], invalidTradeDetail, {
            value: invalidTradeDetail.amount,
          }),
      ).to.be.revertedWithCustomError(vault, "InvalidDepositAmount");

      expect(await provider.getBalance(vaultAddress)).deep.eq(balance);
    });

    it("Should revert when User tries to deposit, but msg.value not matched the `amount`", async () => {
      const vaultAddress = await vault.getAddress();
      const balance = await provider.getBalance(vaultAddress);

      await expect(
        vault
          .connect(accounts[0])
          .deposit(ephemeralL2Address, tradeInput[0], tradeDetail[0], {
            value: (tradeDetail[0].amount as bigint) - BigInt(1),
          }),
      ).to.be.revertedWithCustomError(vault, "InvalidDepositAmount");

      expect(await provider.getBalance(vaultAddress)).deep.eq(balance);
    });

    it("Should revert when User tries to deposit, but provided mpcAddresss is 0x0", async () => {
      const invalidTradeDetail = structuredClone(tradeDetail[0]);
      invalidTradeDetail.mpc = ZeroAddress;

      const vaultAddress = await vault.getAddress();
      const balance = await provider.getBalance(vaultAddress);

      await expect(
        vault
          .connect(accounts[0])
          .deposit(ephemeralL2Address, tradeInput[0], invalidTradeDetail, {
            value: invalidTradeDetail.amount,
          }),
      ).to.be.revertedWithCustomError(vault, "AddressZero");

      expect(await provider.getBalance(vaultAddress)).deep.eq(balance);
    });

    it("Should revert when User tries to deposit, but provided ephemeralAssetAddress is 0x0", async () => {
      const invalidTradeDetail = structuredClone(tradeDetail[0]);
      invalidTradeDetail.ephemeralAssetAddress = ZeroAddress;

      const vaultAddress = await vault.getAddress();
      const balance = await provider.getBalance(vaultAddress);

      await expect(
        vault
          .connect(accounts[0])
          .deposit(ephemeralL2Address, tradeInput[0], invalidTradeDetail, {
            value: invalidTradeDetail.amount,
          }),
      ).to.be.revertedWithCustomError(vault, "AddressZero");

      expect(await provider.getBalance(vaultAddress)).deep.eq(balance);
    });

    it("Should revert when User tries to deposit, but provided refundAddress is 0x0", async () => {
      const invalidTradeDetail = structuredClone(tradeDetail[0]);
      invalidTradeDetail.refundAddress = ZeroAddress;

      const vaultAddress = await vault.getAddress();
      const balance = await provider.getBalance(vaultAddress);

      await expect(
        vault
          .connect(accounts[0])
          .deposit(ephemeralL2Address, tradeInput[0], invalidTradeDetail, {
            value: invalidTradeDetail.amount,
          }),
      ).to.be.revertedWithCustomError(vault, "AddressZero");

      expect(await provider.getBalance(vaultAddress)).deep.eq(balance);
    });

    it("Should succeed when User deposits fund with valid parameters", async () => {
      const amount = tradeDetail[0].amount;
      const tx = vault
        .connect(accounts[0])
        .deposit(ephemeralL2Address, tradeInput[0], tradeDetail[0], {
          value: amount,
        });

      await expect(tx).changeEtherBalances(
        [accounts[0].address, await vault.getAddress()],
        [-amount, amount],
      );
      await expect(tx).to.emit(vault, "Deposited").withArgs(
        tradeId[0],
        accounts[0].address,
        ZeroAddress, //  Native coin: 0x0
        ephemeralL2Address,
        Object.values(tradeDetail[0]),
      );

      expect(await vault.getTradeHash(tradeId[0])).deep.eq(
        hashOf(tradeDetail[0]),
      );
    });

    it("Should succeed when User makes another deposit", async () => {
      const amount = tradeDetail[1].amount;

      const tx = vault
        .connect(accounts[1])
        .deposit(ephemeralL2Address, tradeInput[1], tradeDetail[1], {
          value: amount,
        });

      await expect(tx).changeEtherBalances(
        [accounts[1].address, await vault.getAddress()],
        [-amount, amount],
      );
      await expect(tx).to.emit(vault, "Deposited").withArgs(
        tradeId[1],
        accounts[1].address,
        ZeroAddress, //  Native coin: 0x0
        ephemeralL2Address,
        Object.values(tradeDetail[1]),
      );

      expect(await vault.getTradeHash(tradeId[1])).deep.eq(
        hashOf(tradeDetail[1]),
      );
    });

    it("Should succeed when User makes another deposit", async () => {
      const amount = tradeDetail[2].amount;

      const tx = vault
        .connect(accounts[2])
        .deposit(ephemeralL2Address, tradeInput[2], tradeDetail[2], {
          value: amount,
        });

      await expect(tx).changeEtherBalances(
        [accounts[2].address, await vault.getAddress()],
        [-amount, amount],
      );
      await expect(tx).to.emit(vault, "Deposited").withArgs(
        tradeId[2],
        accounts[2].address,
        ZeroAddress, //  Native coin: 0x0
        ephemeralL2Address,
        Object.values(tradeDetail[2]),
      );

      expect(await vault.getTradeHash(tradeId[2])).deep.eq(
        hashOf(tradeDetail[2]),
      );
    });

    it("Should succeed when User makes another deposit", async () => {
      const amount = tradeDetail[3].amount;

      const tx = vault
        .connect(accounts[3])
        .deposit(ephemeralL2Address, tradeInput[3], tradeDetail[3], {
          value: amount,
        });

      await expect(tx).changeEtherBalances(
        [accounts[3].address, await vault.getAddress()],
        [-amount, amount],
      );
      await expect(tx).to.emit(vault, "Deposited").withArgs(
        tradeId[3],
        accounts[3].address,
        ZeroAddress, //  Native coin: 0x0
        ephemeralL2Address,
        Object.values(tradeDetail[3]),
      );

      expect(await vault.getTradeHash(tradeId[3])).deep.eq(
        hashOf(tradeDetail[3]),
      );
    });

    it("Should revert when User makes a duplicated deposit", async () => {
      const newTradeDetail = structuredClone(tradeDetail[0]);
      newTradeDetail.timeout = BigInt(
        Math.floor(Date.now() / 1000) + 24 * 3600,
      );

      const vaultAddress = await vault.getAddress();
      const balance = await provider.getBalance(vaultAddress);
      const lastHash = await vault.getTradeHash(tradeId[0]);

      await expect(
        vault
          .connect(accounts[0])
          .deposit(ephemeralL2Address, tradeInput[0], newTradeDetail, {
            value: newTradeDetail.amount,
          }),
      ).to.be.revertedWithCustomError(vault, "DuplicatedDeposit");

      expect(await provider.getBalance(vaultAddress)).deep.eq(balance);
      expect(await vault.getTradeHash(tradeId[0])).deep.eq(lastHash);
    });
  });

  describe("settlement() functional testing", async () => {
    it("Should revert when MPC Nodes tries to settle non-existed tradeId", async () => {
      //  Prepare presign
      const invalidTradeId = keccak256(toUtf8Bytes("Invalid_trade_id"));
      const presignInfoHash: string = getPresignHash(
        pmm.address,
        tradeInfo[0].amountIn as bigint,
      );
      const presign = await getPresignSignature(
        ephemeralAssetKey,
        tradeId[0],
        presignInfoHash,
        domain,
      );

      //  Prepare mpcSignature
      const pFeeAmount = ((tradeInfo[0].amountIn as bigint) * pFeeRate) / DENOM;
      const aFeeAmount =
        (BigInt(affiliate[0].aggregatedValue) * BigInt(tradeInfo[0].amountIn)) /
        DENOM;
      const totalFee = pFeeAmount + aFeeAmount;
      const mpcSignature = await getSettlementSignature(
        mpc,
        totalFee,
        presign,
        domain,
      );

      const vaultAddress = await vault.getAddress();
      const balance = await provider.getBalance(vaultAddress);
      const lastHash = await vault.getTradeHash(tradeId[0]);

      //  @dev: When `tradeId` is not recorded, hash of trade detail wouldn't match
      await expect(
        vault
          .connect(mpcNode)
          .settlement(
            invalidTradeId,
            totalFee,
            pmm.address,
            tradeDetail[0],
            presign,
            mpcSignature,
          ),
      ).to.be.revertedWithCustomError(vault, "TradeDetailNotMatched");

      expect(await provider.getBalance(vaultAddress)).deep.eq(balance);
      expect(await vault.getTradeHash(tradeId[0])).deep.eq(lastHash);
    });

    it("Should revert when MPC Nodes tries to settle the tradeId, but timeout has passed", async () => {
      const block = await provider.getBlockNumber();
      const timestamp = (await provider.getBlock(block))?.timestamp as number;
      const exceedTimeout = Number(tradeDetail[0].timeout) + 1;

      //  take a snapshot before increasing block.timestamp
      const snapshot = await takeSnapshot();
      if (timestamp < exceedTimeout) await adjustTime(exceedTimeout);

      //  Prepare presign
      const presignInfoHash: string = getPresignHash(
        pmm.address,
        tradeInfo[0].amountIn as bigint,
      );
      const presign = await getPresignSignature(
        ephemeralAssetKey,
        tradeId[0],
        presignInfoHash,
        domain,
      );

      //  Prepare mpcSignature
      const pFeeAmount = ((tradeInfo[0].amountIn as bigint) * pFeeRate) / DENOM;
      const aFeeAmount =
        (BigInt(affiliate[0].aggregatedValue) * BigInt(tradeInfo[0].amountIn)) /
        DENOM;
      const totalFee = pFeeAmount + aFeeAmount;
      const mpcSignature = await getSettlementSignature(
        mpc,
        totalFee,
        presign,
        domain,
      );

      const vaultAddress = await vault.getAddress();
      const balance = await provider.getBalance(vaultAddress);
      const lastHash = await vault.getTradeHash(tradeId[0]);

      await expect(
        vault
          .connect(mpcNode)
          .settlement(
            tradeId[0],
            totalFee,
            pmm.address,
            tradeDetail[0],
            presign,
            mpcSignature,
          ),
      ).to.be.revertedWithCustomError(vault, "Timeout");

      expect(await provider.getBalance(vaultAddress)).deep.eq(balance);
      expect(await vault.getTradeHash(tradeId[0])).deep.eq(lastHash);

      //  set back to normal
      await snapshot.restore();
    });

    it("Should revert when MPC Nodes settles the tradeId, but presign is invalid - Invalid signer", async () => {
      //  Prepare presign
      const presignInfoHash: string = getPresignHash(
        pmm.address,
        tradeInfo[0].amountIn as bigint,
      );
      const presign = await getPresignSignature(
        mpcNode, //  wrong signer. Should be ephemeralAssetKey
        tradeId[0],
        presignInfoHash,
        domain,
      );

      //  Prepare mpcSignature
      const pFeeAmount = ((tradeInfo[0].amountIn as bigint) * pFeeRate) / DENOM;
      const aFeeAmount =
        (BigInt(affiliate[0].aggregatedValue) * BigInt(tradeInfo[0].amountIn)) /
        DENOM;
      const totalFee = pFeeAmount + aFeeAmount;
      const mpcSignature = await getSettlementSignature(
        mpc,
        totalFee,
        presign,
        domain,
      );

      const vaultAddress = await vault.getAddress();
      const balance = await provider.getBalance(vaultAddress);
      const lastHash = await vault.getTradeHash(tradeId[0]);

      await expect(
        vault
          .connect(mpcNode)
          .settlement(
            tradeId[0],
            totalFee,
            pmm.address,
            tradeDetail[0],
            presign,
            mpcSignature,
          ),
      ).to.be.revertedWithCustomError(vault, "InvalidPresign");

      expect(await provider.getBalance(vaultAddress)).deep.eq(balance);
      expect(await vault.getTradeHash(tradeId[0])).deep.eq(lastHash);
    });

    it("Should revert when MPC Nodes settles the tradeId, but presign is invalid - Un-matched tradeId", async () => {
      //  Prepare presign
      const presignInfoHash: string = getPresignHash(
        pmm.address,
        tradeInfo[0].amountIn as bigint,
      );
      const presign = await getPresignSignature(
        ephemeralAssetKey,
        tradeId[1], // un-matched tradeId. Should be tradeId[0]
        presignInfoHash,
        domain,
      );

      //  Prepare mpcSignature
      const pFeeAmount = ((tradeInfo[0].amountIn as bigint) * pFeeRate) / DENOM;
      const aFeeAmount =
        (BigInt(affiliate[0].aggregatedValue) * BigInt(tradeInfo[0].amountIn)) /
        DENOM;
      const totalFee = pFeeAmount + aFeeAmount;
      const mpcSignature = await getSettlementSignature(
        mpc,
        totalFee,
        presign,
        domain,
      );

      const vaultAddress = await vault.getAddress();
      const balance = await provider.getBalance(vaultAddress);
      const lastHash1 = await vault.getTradeHash(tradeId[0]);
      const lastHash2 = await vault.getTradeHash(tradeId[1]);

      await expect(
        vault
          .connect(mpcNode)
          .settlement(
            tradeId[0],
            totalFee,
            pmm.address,
            tradeDetail[0],
            presign,
            mpcSignature,
          ),
      ).to.be.revertedWithCustomError(vault, "InvalidPresign");

      expect(await provider.getBalance(vaultAddress)).deep.eq(balance);
      expect(await vault.getTradeHash(tradeId[0])).deep.eq(lastHash1);
      expect(await vault.getTradeHash(tradeId[1])).deep.eq(lastHash2);
    });

    it("Should revert when MPC Nodes settles the tradeId, but presign is invalid - Un-matched toAddress", async () => {
      //  Prepare presign
      const presignInfoHash: string = getPresignHash(
        pmm.address,
        tradeInfo[0].amountIn as bigint,
      );
      const presign = await getPresignSignature(
        ephemeralAssetKey,
        tradeId[0],
        presignInfoHash,
        domain,
      );

      //  Prepare mpcSignature
      const pFeeAmount = ((tradeInfo[0].amountIn as bigint) * pFeeRate) / DENOM;
      const aFeeAmount =
        (BigInt(affiliate[0].aggregatedValue) * BigInt(tradeInfo[0].amountIn)) /
        DENOM;
      const totalFee = pFeeAmount + aFeeAmount;
      const mpcSignature = await getSettlementSignature(
        mpc,
        totalFee,
        presign,
        domain,
      );

      const vaultAddress = await vault.getAddress();
      const balance = await provider.getBalance(vaultAddress);
      const lastHash = await vault.getTradeHash(tradeId[0]);

      await expect(
        vault.connect(mpcNode).settlement(
          tradeId[0],
          totalFee,
          mpcNode.address, //  un-matched pmmRecvAddress
          tradeDetail[0],
          presign,
          mpcSignature,
        ),
      ).to.be.revertedWithCustomError(vault, "InvalidPresign");

      expect(await provider.getBalance(vaultAddress)).deep.eq(balance);
      expect(await vault.getTradeHash(tradeId[0])).deep.eq(lastHash);
    });

    it("Should revert when MPC Nodes settles the tradeId, but presign is invalid - Un-matched amount", async () => {
      //  Prepare presign
      const presignInfoHash: string = getPresignHash(
        pmm.address,
        (tradeInfo[0].amountIn as bigint) - BigInt(1), //   un-matched amount
      );
      const presign = await getPresignSignature(
        ephemeralAssetKey,
        tradeId[0],
        presignInfoHash,
        domain,
      );

      //  Prepare mpcSignature
      const pFeeAmount = ((tradeInfo[0].amountIn as bigint) * pFeeRate) / DENOM;
      const aFeeAmount =
        (BigInt(affiliate[0].aggregatedValue) * BigInt(tradeInfo[0].amountIn)) /
        DENOM;
      const totalFee = pFeeAmount + aFeeAmount;
      const mpcSignature = await getSettlementSignature(
        mpc,
        totalFee,
        presign,
        domain,
      );

      const vaultAddress = await vault.getAddress();
      const balance = await provider.getBalance(vaultAddress);
      const lastHash = await vault.getTradeHash(tradeId[0]);

      await expect(
        vault
          .connect(mpcNode)
          .settlement(
            tradeId[0],
            totalFee,
            pmm.address,
            tradeDetail[0],
            presign,
            mpcSignature,
          ),
      ).to.be.revertedWithCustomError(vault, "InvalidPresign");

      expect(await provider.getBalance(vaultAddress)).deep.eq(balance);
      expect(await vault.getTradeHash(tradeId[0])).deep.eq(lastHash);
    });

    it("Should revert when MPC Nodes settles the tradeId, but presign is invalid - Wrong domain - Wrong name", async () => {
      //  create wrong domain EIP-712
      const wrongDomain: TypedDataDomain = {
        ...domain,
        name: "Invalid Contract Name",
      };

      //  Prepare presign
      const presignInfoHash: string = getPresignHash(
        pmm.address,
        tradeInfo[0].amountIn as bigint,
      );
      const presign = await getPresignSignature(
        ephemeralAssetKey,
        tradeId[0],
        presignInfoHash,
        wrongDomain,
      );

      //  Prepare mpcSignature
      const pFeeAmount = ((tradeInfo[0].amountIn as bigint) * pFeeRate) / DENOM;
      const aFeeAmount =
        (BigInt(affiliate[0].aggregatedValue) * BigInt(tradeInfo[0].amountIn)) /
        DENOM;
      const totalFee = pFeeAmount + aFeeAmount;
      const mpcSignature = await getSettlementSignature(
        mpc,
        totalFee,
        presign,
        domain,
      );

      const vaultAddress = await vault.getAddress();
      const balance = await provider.getBalance(vaultAddress);
      const lastHash = await vault.getTradeHash(tradeId[0]);

      await expect(
        vault
          .connect(mpcNode)
          .settlement(
            tradeId[0],
            totalFee,
            pmm.address,
            tradeDetail[0],
            presign,
            mpcSignature,
          ),
      ).to.be.revertedWithCustomError(vault, "InvalidPresign");

      expect(await provider.getBalance(vaultAddress)).deep.eq(balance);
      expect(await vault.getTradeHash(tradeId[0])).deep.eq(lastHash);
    });

    it("Should revert when MPC Nodes settles the tradeId, but presign is invalid - Wrong domain - Wrong version", async () => {
      //  create wrong domain eip-712
      const wrongDomain: TypedDataDomain = {
        ...domain,
        version: "Wrong Version",
      };

      //  Prepare presign
      const presignInfoHash: string = getPresignHash(
        pmm.address,
        tradeInfo[0].amountIn as bigint,
      );
      const presign = await getPresignSignature(
        ephemeralAssetKey,
        tradeId[0],
        presignInfoHash,
        wrongDomain,
      );

      //  Prepare mpcSignature
      const pFeeAmount = ((tradeInfo[0].amountIn as bigint) * pFeeRate) / DENOM;
      const aFeeAmount =
        (BigInt(affiliate[0].aggregatedValue) * BigInt(tradeInfo[0].amountIn)) /
        DENOM;
      const totalFee = pFeeAmount + aFeeAmount;
      const mpcSignature = await getSettlementSignature(
        mpc,
        totalFee,
        presign,
        domain,
      );

      const vaultAddress = await vault.getAddress();
      const balance = await provider.getBalance(vaultAddress);
      const lastHash = await vault.getTradeHash(tradeId[0]);

      await expect(
        vault
          .connect(mpcNode)
          .settlement(
            tradeId[0],
            totalFee,
            pmm.address,
            tradeDetail[0],
            presign,
            mpcSignature,
          ),
      ).to.be.revertedWithCustomError(vault, "InvalidPresign");

      expect(await provider.getBalance(vaultAddress)).deep.eq(balance);
      expect(await vault.getTradeHash(tradeId[0])).deep.eq(lastHash);
    });

    it("Should revert when MPC Nodes settles the tradeId, but presign is invalid - Wrong domain - Wrong chainId", async () => {
      //  create wrong domain eip-712
      const wrongDomain: TypedDataDomain = {
        ...domain,
        chainId: (domain.chainId as bigint) + BigInt(1),
      };

      //  Prepare presign
      const presignInfoHash: string = getPresignHash(
        pmm.address,
        tradeInfo[0].amountIn as bigint,
      );
      const presign = await getPresignSignature(
        ephemeralAssetKey,
        tradeId[0],
        presignInfoHash,
        wrongDomain,
      );

      //  Prepare mpcSignature
      const pFeeAmount = ((tradeInfo[0].amountIn as bigint) * pFeeRate) / DENOM;
      const aFeeAmount =
        (BigInt(affiliate[0].aggregatedValue) * BigInt(tradeInfo[0].amountIn)) /
        DENOM;
      const totalFee = pFeeAmount + aFeeAmount;
      const mpcSignature = await getSettlementSignature(
        mpc,
        totalFee,
        presign,
        domain,
      );

      const vaultAddress = await vault.getAddress();
      const balance = await provider.getBalance(vaultAddress);
      const lastHash = await vault.getTradeHash(tradeId[0]);

      await expect(
        vault
          .connect(mpcNode)
          .settlement(
            tradeId[0],
            totalFee,
            pmm.address,
            tradeDetail[0],
            presign,
            mpcSignature,
          ),
      ).to.be.revertedWithCustomError(vault, "InvalidPresign");

      expect(await provider.getBalance(vaultAddress)).deep.eq(balance);
      expect(await vault.getTradeHash(tradeId[0])).deep.eq(lastHash);
    });

    it("Should revert when MPC Nodes settles the tradeId, but presign is invalid - Wrong domain - Wrong address", async () => {
      //  create wrong domain eip-712
      const wrongDomain: TypedDataDomain = {
        ...domain,
        verifyingContract: mpcNode.address,
      };

      //  Prepare presign
      const presignInfoHash: string = getPresignHash(
        pmm.address,
        tradeInfo[0].amountIn as bigint,
      );
      const presign = await getPresignSignature(
        ephemeralAssetKey,
        tradeId[0],
        presignInfoHash,
        wrongDomain,
      );

      //  Prepare mpcSignature
      const pFeeAmount = ((tradeInfo[0].amountIn as bigint) * pFeeRate) / DENOM;
      const aFeeAmount =
        (BigInt(affiliate[0].aggregatedValue) * BigInt(tradeInfo[0].amountIn)) /
        DENOM;
      const totalFee = pFeeAmount + aFeeAmount;
      const mpcSignature = await getSettlementSignature(
        mpc,
        totalFee,
        presign,
        domain,
      );

      const vaultAddress = await vault.getAddress();
      const balance = await provider.getBalance(vaultAddress);
      const lastHash = await vault.getTradeHash(tradeId[0]);

      await expect(
        vault
          .connect(mpcNode)
          .settlement(
            tradeId[0],
            totalFee,
            pmm.address,
            tradeDetail[0],
            presign,
            mpcSignature,
          ),
      ).to.be.revertedWithCustomError(vault, "InvalidPresign");

      expect(await provider.getBalance(vaultAddress)).deep.eq(balance);
      expect(await vault.getTradeHash(tradeId[0])).deep.eq(lastHash);
    });

    it("Should revert when MPC Nodes settles the tradeId, but mpcSignature is invalid - Invalid signer", async () => {
      //  Prepare presign
      const presignInfoHash: string = getPresignHash(
        pmm.address,
        tradeInfo[0].amountIn as bigint,
      );
      const presign = await getPresignSignature(
        ephemeralAssetKey,
        tradeId[0],
        presignInfoHash,
        domain,
      );

      //  Prepare mpcSignature
      const pFeeAmount = ((tradeInfo[0].amountIn as bigint) * pFeeRate) / DENOM;
      const aFeeAmount =
        (BigInt(affiliate[0].aggregatedValue) * BigInt(tradeInfo[0].amountIn)) /
        DENOM;
      const totalFee = pFeeAmount + aFeeAmount;
      const mpcSignature = await getSettlementSignature(
        mpcNode, //  invalid signer. Should be mpc
        totalFee,
        presign,
        domain,
      );

      const vaultAddress = await vault.getAddress();
      const balance = await provider.getBalance(vaultAddress);
      const lastHash = await vault.getTradeHash(tradeId[0]);

      await expect(
        vault
          .connect(mpcNode)
          .settlement(
            tradeId[0],
            totalFee,
            pmm.address,
            tradeDetail[0],
            presign,
            mpcSignature,
          ),
      ).to.be.revertedWithCustomError(vault, "InvalidMPCSign");

      expect(await provider.getBalance(vaultAddress)).deep.eq(balance);
      expect(await vault.getTradeHash(tradeId[0])).deep.eq(lastHash);
    });

    it("Should revert when MPC Nodes settles the tradeId, but mpcSignature is invalid - Un-matched totalFee", async () => {
      //  Prepare presign
      const presignInfoHash: string = getPresignHash(
        pmm.address,
        tradeInfo[0].amountIn as bigint,
      );
      const presign = await getPresignSignature(
        ephemeralAssetKey,
        tradeId[0],
        presignInfoHash,
        domain,
      );

      //  Prepare mpcSignature
      const pFeeAmount = ((tradeInfo[0].amountIn as bigint) * pFeeRate) / DENOM;
      const aFeeAmount =
        (BigInt(affiliate[0].aggregatedValue) * BigInt(tradeInfo[0].amountIn)) /
        DENOM;
      const totalFee = pFeeAmount + aFeeAmount;
      const mpcSignature = await getSettlementSignature(
        mpc,
        totalFee,
        presign,
        domain,
      );

      const vaultAddress = await vault.getAddress();
      const balance = await provider.getBalance(vaultAddress);
      const lastHash = await vault.getTradeHash(tradeId[0]);

      await expect(
        vault.connect(mpcNode).settlement(
          tradeId[0],
          totalFee - BigInt(1), //  un-matched totalFee
          pmm.address,
          tradeDetail[0],
          presign,
          mpcSignature,
        ),
      ).to.be.revertedWithCustomError(vault, "InvalidMPCSign");

      expect(await provider.getBalance(vaultAddress)).deep.eq(balance);
      expect(await vault.getTradeHash(tradeId[0])).deep.eq(lastHash);
    });

    it("Should revert when MPC Nodes settles the tradeId, but mpcSignature is invalid - Un-matched presign", async () => {
      //  Prepare presign
      const presignInfoHash: string = getPresignHash(
        pmm.address,
        tradeInfo[0].amountIn as bigint,
      );
      const presign = await getPresignSignature(
        ephemeralAssetKey,
        tradeId[0],
        presignInfoHash,
        domain,
      );
      const anotherInfoHash: string = getPresignHash(
        pmm.address,
        tradeInfo[1].amountIn as bigint,
      );
      const anotherPresign: string = await getPresignSignature(
        ephemeralAssetKey,
        tradeId[1],
        anotherInfoHash,
        domain,
      );

      //  Prepare mpcSignature
      const pFeeAmount = ((tradeInfo[0].amountIn as bigint) * pFeeRate) / DENOM;
      const aFeeAmount =
        (BigInt(affiliate[0].aggregatedValue) * BigInt(tradeInfo[0].amountIn)) /
        DENOM;
      const totalFee = pFeeAmount + aFeeAmount;
      const mpcSignature = await getSettlementSignature(
        mpc,
        totalFee,
        anotherPresign,
        domain,
      );

      const vaultAddress = await vault.getAddress();
      const balance = await provider.getBalance(vaultAddress);
      const lastHash = await vault.getTradeHash(tradeId[0]);

      await expect(
        vault
          .connect(mpcNode)
          .settlement(
            tradeId[0],
            totalFee,
            pmm.address,
            tradeDetail[0],
            presign,
            mpcSignature,
          ),
      ).to.be.revertedWithCustomError(vault, "InvalidMPCSign");

      expect(await provider.getBalance(vaultAddress)).deep.eq(balance);
      expect(await vault.getTradeHash(tradeId[0])).deep.eq(lastHash);
    });

    it("Should revert when MPC Nodes settles the tradeId, but mpcSignature is invalid - Wrong domain - Wrong name", async () => {
      //  create wrong domain eip-712
      const wrongDomain: TypedDataDomain = {
        ...domain,
        name: "Invalid Contract Name",
      };

      //  Prepare presign
      const presignInfoHash: string = getPresignHash(
        pmm.address,
        tradeInfo[0].amountIn as bigint,
      );
      const presign = await getPresignSignature(
        ephemeralAssetKey,
        tradeId[0],
        presignInfoHash,
        domain,
      );

      //  Prepare mpcSignature
      const pFeeAmount = ((tradeInfo[0].amountIn as bigint) * pFeeRate) / DENOM;
      const aFeeAmount =
        (BigInt(affiliate[0].aggregatedValue) * BigInt(tradeInfo[0].amountIn)) /
        DENOM;
      const totalFee = pFeeAmount + aFeeAmount;
      const mpcSignature = await getSettlementSignature(
        mpc,
        totalFee,
        presign,
        wrongDomain,
      );

      const vaultAddress = await vault.getAddress();
      const balance = await provider.getBalance(vaultAddress);
      const lastHash = await vault.getTradeHash(tradeId[0]);

      await expect(
        vault
          .connect(mpcNode)
          .settlement(
            tradeId[0],
            totalFee,
            pmm.address,
            tradeDetail[0],
            presign,
            mpcSignature,
          ),
      ).to.be.revertedWithCustomError(vault, "InvalidMPCSign");

      expect(await provider.getBalance(vaultAddress)).deep.eq(balance);
      expect(await vault.getTradeHash(tradeId[0])).deep.eq(lastHash);
    });

    it("Should revert when MPC Nodes settles the tradeId, but mpcSignature is invalid - Wrong domain - Wrong version", async () => {
      //  create wrong domain eip-712
      const wrongDomain: TypedDataDomain = {
        ...domain,
        version: "Invalid Version",
      };

      //  Prepare presign
      const presignInfoHash: string = getPresignHash(
        pmm.address,
        tradeInfo[0].amountIn as bigint,
      );
      const presign = await getPresignSignature(
        ephemeralAssetKey,
        tradeId[0],
        presignInfoHash,
        domain,
      );

      //  Prepare mpcSignature
      const pFeeAmount = ((tradeInfo[0].amountIn as bigint) * pFeeRate) / DENOM;
      const aFeeAmount =
        (BigInt(affiliate[0].aggregatedValue) * BigInt(tradeInfo[0].amountIn)) /
        DENOM;
      const totalFee = pFeeAmount + aFeeAmount;
      const mpcSignature = await getSettlementSignature(
        mpc,
        totalFee,
        presign,
        wrongDomain,
      );

      const vaultAddress = await vault.getAddress();
      const balance = await provider.getBalance(vaultAddress);
      const lastHash = await vault.getTradeHash(tradeId[0]);

      await expect(
        vault
          .connect(mpcNode)
          .settlement(
            tradeId[0],
            totalFee,
            pmm.address,
            tradeDetail[0],
            presign,
            mpcSignature,
          ),
      ).to.be.revertedWithCustomError(vault, "InvalidMPCSign");

      expect(await provider.getBalance(vaultAddress)).deep.eq(balance);
      expect(await vault.getTradeHash(tradeId[0])).deep.eq(lastHash);
    });

    it("Should revert when MPC Nodes settles the tradeId, but mpcSignature is invalid - Wrong domain - Wrong chainId", async () => {
      //  create wrong domain eip-712
      const wrongDomain: TypedDataDomain = {
        ...domain,
        chainId: (domain.chainId as bigint) + BigInt(1),
      };

      //  Prepare presign
      const presignInfoHash: string = getPresignHash(
        pmm.address,
        tradeInfo[0].amountIn as bigint,
      );
      const presign = await getPresignSignature(
        ephemeralAssetKey,
        tradeId[0],
        presignInfoHash,
        domain,
      );

      //  Prepare mpcSignature
      const pFeeAmount = ((tradeInfo[0].amountIn as bigint) * pFeeRate) / DENOM;
      const aFeeAmount =
        (BigInt(affiliate[0].aggregatedValue) * BigInt(tradeInfo[0].amountIn)) /
        DENOM;
      const totalFee = pFeeAmount + aFeeAmount;
      const mpcSignature = await getSettlementSignature(
        mpc,
        totalFee,
        presign,
        wrongDomain,
      );

      const vaultAddress = await vault.getAddress();
      const balance = await provider.getBalance(vaultAddress);
      const lastHash = await vault.getTradeHash(tradeId[0]);

      await expect(
        vault
          .connect(mpcNode)
          .settlement(
            tradeId[0],
            totalFee,
            pmm.address,
            tradeDetail[0],
            presign,
            mpcSignature,
          ),
      ).to.be.revertedWithCustomError(vault, "InvalidMPCSign");

      expect(await provider.getBalance(vaultAddress)).deep.eq(balance);
      expect(await vault.getTradeHash(tradeId[0])).deep.eq(lastHash);
    });

    it("Should revert when MPC Nodes settles the tradeId, but mpcSignature is invalid - Wrong domain - Wrong address", async () => {
      //  create wrong domain eip-712
      const wrongDomain: TypedDataDomain = {
        ...domain,
        verifyingContract: mpcNode.address,
      };

      //  Prepare presign
      const presignInfoHash: string = getPresignHash(
        pmm.address,
        tradeInfo[0].amountIn as bigint,
      );
      const presign = await getPresignSignature(
        ephemeralAssetKey,
        tradeId[0],
        presignInfoHash,
        domain,
      );

      //  Prepare mpcSignature
      const pFeeAmount = ((tradeInfo[0].amountIn as bigint) * pFeeRate) / DENOM;
      const aFeeAmount =
        (BigInt(affiliate[0].aggregatedValue) * BigInt(tradeInfo[0].amountIn)) /
        DENOM;
      const totalFee = pFeeAmount + aFeeAmount;
      const mpcSignature = await getSettlementSignature(
        mpc,
        totalFee,
        presign,
        wrongDomain,
      );

      const vaultAddress = await vault.getAddress();
      const balance = await provider.getBalance(vaultAddress);
      const lastHash = await vault.getTradeHash(tradeId[0]);

      await expect(
        vault
          .connect(mpcNode)
          .settlement(
            tradeId[0],
            totalFee,
            pmm.address,
            tradeDetail[0],
            presign,
            mpcSignature,
          ),
      ).to.be.revertedWithCustomError(vault, "InvalidMPCSign");

      expect(await provider.getBalance(vaultAddress)).deep.eq(balance);
      expect(await vault.getTradeHash(tradeId[0])).deep.eq(lastHash);
    });

    it("Should succeed when MPC Nodes finalize one trade by calling settlement()", async () => {
      //  Prepare presign
      const presignInfoHash: string = getPresignHash(
        pmm.address,
        tradeInfo[0].amountIn as bigint,
      );
      const presign = await getPresignSignature(
        ephemeralAssetKey,
        tradeId[0],
        presignInfoHash,
        domain,
      );

      //  Prepare mpcSignature
      const pFeeAmount = ((tradeInfo[0].amountIn as bigint) * pFeeRate) / DENOM;
      const aFeeAmount =
        (BigInt(affiliate[0].aggregatedValue) * BigInt(tradeInfo[0].amountIn)) /
        DENOM;
      const totalFee = pFeeAmount + aFeeAmount;
      const mpcSignature = await getSettlementSignature(
        mpc,
        totalFee,
        presign,
        domain,
      );
      const vaultAddress = await vault.getAddress();
      const pFeeAddress = await protocol.pFeeAddr();
      const amount: bigint = tradeInfo[0].amountIn as bigint;

      const tx = vault
        .connect(mpcNode)
        .settlement(
          tradeId[0],
          totalFee,
          pmm.address,
          tradeDetail[0],
          presign,
          mpcSignature,
        );

      await expect(tx)
        .to.emit(vault, "Settled")
        .withArgs(
          tradeId[0],
          ZeroAddress, //  Native coin 0x0
          pmm.address, // toAddress
          mpcNode.address, //  operator
          amount - totalFee, //  amount after fee
          pFeeAddress,
          totalFee,
        );
      await expect(tx).changeEtherBalances(
        [vaultAddress, pFeeAddress],
        [-amount, totalFee],
      );
      await expect(tx).changeTokenBalance(
        weth9,
        pmm.address,
        amount - totalFee,
      );
      expect(await vault.getTradeHash(tradeId[0])).deep.eq(EMPTY_TRADE_HASH);
    });

    it("Should succeed when MPC Nodes settles another tradeId", async () => {
      //  Prepare presign
      const presignInfoHash: string = getPresignHash(
        pmm.address,
        tradeInfo[1].amountIn as bigint,
      );
      const presign = await getPresignSignature(
        ephemeralAssetKey,
        tradeId[1],
        presignInfoHash,
        domain,
      );

      //  Prepare mpcSignature
      const pFeeAmount = ((tradeInfo[1].amountIn as bigint) * pFeeRate) / DENOM;
      const aFeeAmount =
        (BigInt(affiliate[1].aggregatedValue) * BigInt(tradeInfo[1].amountIn)) /
        DENOM;
      const totalFee = pFeeAmount + aFeeAmount;
      const mpcSignature = await getSettlementSignature(
        mpc,
        totalFee,
        presign,
        domain,
      );
      const vaultAddress = await vault.getAddress();
      const pFeeAddress = await protocol.pFeeAddr();
      const amount: bigint = tradeInfo[1].amountIn as bigint;

      const tx = vault
        .connect(mpcNode)
        .settlement(
          tradeId[1],
          totalFee,
          pmm.address,
          tradeDetail[1],
          presign,
          mpcSignature,
        );

      await expect(tx)
        .to.emit(vault, "Settled")
        .withArgs(
          tradeId[1],
          ZeroAddress, //  Native coin 0x0
          pmm.address, // toAddress
          mpcNode.address, //  operator
          amount - totalFee, //  amount after fee
          pFeeAddress,
          totalFee,
        );
      await expect(tx).changeEtherBalances(
        [vaultAddress, pFeeAddress],
        [-amount, totalFee],
      );
      await expect(tx).changeTokenBalance(
        weth9,
        pmm.address,
        amount - totalFee,
      );
      expect(await vault.getTradeHash(tradeId[1])).deep.eq(EMPTY_TRADE_HASH);
    });

    it("Should revert when MPC Nodes finalizes the trade that has been settled", async () => {
      //  Prepare presign
      const presignInfoHash: string = getPresignHash(
        pmm.address,
        tradeInfo[0].amountIn as bigint,
      );
      const presign = await getPresignSignature(
        ephemeralAssetKey,
        tradeId[0],
        presignInfoHash,
        domain,
      );

      //  Prepare mpcSignature
      const pFeeAmount = ((tradeInfo[0].amountIn as bigint) * pFeeRate) / DENOM;
      const aFeeAmount =
        (BigInt(affiliate[0].aggregatedValue) * BigInt(tradeInfo[0].amountIn)) /
        DENOM;
      const totalFee = pFeeAmount + aFeeAmount;
      const mpcSignature = await getSettlementSignature(
        mpc,
        totalFee,
        presign,
        domain,
      );

      const vaultAddress = await vault.getAddress();
      const balance = await provider.getBalance(vaultAddress);

      //  @dev: When `tradeId` is finalized, contract would delete the storage
      //  that saves the hash of trade detail. Thus, it likely fails with `TradeDetailNotMatched`
      await expect(
        vault
          .connect(mpcNode)
          .settlement(
            tradeId[0],
            totalFee,
            pmm.address,
            tradeDetail[0],
            presign,
            mpcSignature,
          ),
      ).to.be.revertedWithCustomError(vault, "TradeDetailNotMatched");

      expect(await provider.getBalance(vaultAddress)).deep.eq(balance);
      expect(await vault.getTradeHash(tradeId[0])).deep.eq(EMPTY_TRADE_HASH);
    });
  });

  describe("claim() functional testing", async () => {
    it("Should revert when User tries to get a refund, but not yet timeout", async () => {
      const vaultAddress = await vault.getAddress();
      const balance = await provider.getBalance(vaultAddress);
      const lastHash = await vault.getTradeHash(tradeId[2]);

      await expect(
        vault.connect(accounts[2]).claim(tradeId[2], tradeDetail[2]),
      ).to.be.revertedWithCustomError(vault, "ClaimNotAvailable");

      expect(await provider.getBalance(vaultAddress)).deep.eq(balance);
      expect(await vault.getTradeHash(tradeId[2])).deep.eq(lastHash);
    });

    it("Should revert when User claims a refund for non-existence tradeId", async () => {
      const vaultAddress = await vault.getAddress();
      const balance = await provider.getBalance(vaultAddress);
      const invalidTradeId = keccak256(toUtf8Bytes("Invalid_trade_id"));

      //  @dev: When `tradeId` is not recorded, hash of trade detail wouldn't match
      await expect(
        vault.connect(accounts[2]).claim(invalidTradeId, tradeDetail[2]),
      ).to.be.revertedWithCustomError(vault, "TradeDetailNotMatched");

      expect(await provider.getBalance(vaultAddress)).deep.eq(balance);
    });

    it("Should succeed when User gets a refund after timeout - Self claim", async () => {
      const block = await provider.getBlockNumber();
      const timestamp = (await provider.getBlock(block))?.timestamp as number;
      const exceedTimeout = Number(tradeDetail[2].timeout) + 1;
      if (timestamp < exceedTimeout) await adjustTime(exceedTimeout);

      const refundAddress = accounts[2].address;
      const amount = tradeInfo[2].amountIn;
      //  @dev:
      //  The function claim() has no constraint on the "caller"
      //  Anyone can call to transfer the refund, and contract will transfer
      //  the `amount` to `refundAddress` that is specified and hashed
      //  in the hash of trade detail when `tradeId` is initialized
      const tx = vault.connect(accounts[2]).claim(tradeId[2], tradeDetail[2]);

      await expect(tx).to.emit(vault, "Claimed").withArgs(
        tradeId[2],
        ZeroAddress, //  Native coin 0x0
        refundAddress, // refundAddress
        accounts[2].address, //  operator
        amount,
      );
      await expect(tx).changeEtherBalances(
        [await vault.getAddress(), refundAddress],
        [-amount, amount],
      );
      expect(await vault.getTradeHash(tradeId[2])).deep.eq(EMPTY_TRADE_HASH);
    });

    it("Should succeed when User gets another refund after timeout - By the MPC Node", async () => {
      const block = await provider.getBlockNumber();
      const timestamp = (await provider.getBlock(block))?.timestamp as number;
      const exceedTimeout = Number(tradeDetail[3].timeout) + 1;
      if (timestamp < exceedTimeout) await adjustTime(exceedTimeout);

      const refundAddress = accounts[3].address;
      const amount = tradeInfo[3].amountIn;
      //  @dev:
      //  The function claim() has no constraint on the "caller"
      //  Anyone can call to transfer the refund, and contract will transfer
      //  the `amount` to `refundAddress` that is specified and hashed
      //  in the hash of trade detail when `tradeId` is initialized
      const tx = vault.connect(mpcNode).claim(tradeId[3], tradeDetail[3]);

      await expect(tx).to.emit(vault, "Claimed").withArgs(
        tradeId[3],
        ZeroAddress, //  Native coin 0x0
        refundAddress, // refundAddress
        mpcNode.address, //  operator
        amount,
      );
      await expect(tx).changeEtherBalances(
        [await vault.getAddress(), refundAddress],
        [-amount, amount],
      );
      expect(await vault.getTradeHash(tradeId[3])).deep.eq(EMPTY_TRADE_HASH);
    });

    it("Should revert when User tries to get a refund, but tradeId already claimed", async () => {
      const block = await provider.getBlockNumber();
      const timestamp = (await provider.getBlock(block))?.timestamp as number;
      const timeout = Number(tradeDetail[3].timeout);
      if (timestamp < timeout) await adjustTime(timeout);

      const vaultAddress = await vault.getAddress();
      const balance = await provider.getBalance(vaultAddress);

      //  @dev: When `tradeId` is claimed, contract would delete the storage
      //  that saves the hash of trade detail. Thus, it likely fails with `TradeDetailNotMatched`
      await expect(
        vault.connect(accounts[3]).claim(tradeId[3], tradeDetail[3]),
      ).to.be.revertedWithCustomError(vault, "TradeDetailNotMatched");

      expect(await provider.getBalance(vaultAddress)).deep.eq(balance);
      expect(await vault.getTradeHash(tradeId[3])).deep.eq(EMPTY_TRADE_HASH);
    });
  });
});
