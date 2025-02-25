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
  toBeHex,
} from "ethers";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";
import { time, takeSnapshot } from "@nomicfoundation/hardhat-network-helpers";
import { HardhatEthersProvider } from "@nomicfoundation/hardhat-ethers/internal/hardhat-ethers-provider";

import {
  Protocol,
  Protocol__factory,
  TokenVault,
  TokenVault__factory,
} from "../../typechain-types";
import { IBaseVault } from "../../typechain-types/contracts/asset-chain/NativeVault";
import { ITypes as CoreTypes } from "../../typechain-types/contracts/utils/Core";
import {
  TETHER_ABI,
  TETHER_BYTECODE,
} from "../clone-token/ethereum/usdt/tether";
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

async function getBlockTimestamp(provider: HardhatEthersProvider) {
  const block = await provider.getBlockNumber();
  const timestamp = (await provider.getBlock(block))?.timestamp as number;

  return timestamp;
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

describe("TokenVault-USDT Contract Testing", () => {
  let admin: HardhatEthersSigner,
    solver: HardhatEthersSigner,
    mpc: HardhatEthersSigner,
    mpcNode: HardhatEthersSigner,
    pmm: HardhatEthersSigner,
    ephemeralAssetKey: HardhatEthersSigner,
    ephemeralL2Key: HardhatEthersSigner;
  let accounts: HardhatEthersSigner[];

  let protocol: Protocol, clone: Protocol, vault: TokenVault;
  let usdt: any, domain: TypedDataDomain;
  let tradeInfo: CoreTypes.TradeInfoStruct[] = [];
  let affiliate: CoreTypes.AffiliateStruct[] = [];
  let tradeDetail: IBaseVault.TradeDetailStruct[] = [];
  let tradeInput: IBaseVault.TradeInputStruct[] = [];
  let sessionId: bigint[] = [];
  let tradeId: string[] = [];
  let totalFee: bigint[] = [];
  let ephemeralL2Address: string;

  const provider = ethers.provider;
  const fromChain = "ethereum";
  let fromToken;
  const usdtAddr = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
  const decimals = 6;
  const initSupply = ethers.parseUnits("1000000000000", decimals);

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

    //  Deploy Tether USD (usdt) contract (bytecode copied from Etherscan.io)
    await ethers.provider.send("hardhat_setCode", [usdtAddr, TETHER_BYTECODE]);
    usdt = new ethers.Contract(usdtAddr, TETHER_ABI, provider);
    await ethers.provider.send("hardhat_setStorageAt", [
      usdtAddr,
      "0x0000000000000000000000000000000000000000000000000000000000000000",
      toBeHex(admin.address, 32),
    ]);
    fromToken = await usdt.getAddress();

    //  Deploy Protocol contract
    const Protocol = (await ethers.getContractFactory(
      "Protocol",
      admin,
    )) as Protocol__factory;
    protocol = await Protocol.deploy(admin.address, admin.address);
    clone = await Protocol.deploy(admin.address, admin.address);

    //  Deploy Vault contract
    const TokenVault = (await ethers.getContractFactory(
      "TokenVault",
      admin,
    )) as TokenVault__factory;
    vault = await TokenVault.deploy(
      await protocol.getAddress(),
      await usdt.getAddress(),
    );

    //  Prepare TradeInfo and TradeId
    for (let i = 0; i < 4; i++) {
      sessionId.push(BigInt(keccak256(toUtf8Bytes(crypto.randomUUID()))));
      tradeInfo.push(
        getTradeInfo(fromChain, fromToken, accounts[i].address, decimals),
      );
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

      const pFeeAmount = ((tradeInfo[i].amountIn as bigint) * pFeeRate) / DENOM;
      const aFeeAmount =
        (BigInt(affiliate[i].aggregatedValue) * BigInt(tradeInfo[i].amountIn)) /
        DENOM;
      totalFee.push(pFeeAmount + aFeeAmount);
    }
    ephemeralL2Address = ephemeralL2Key.address;

    const contractDomain: TypedDataDomain = await vault.eip712Domain();
    domain = {
      name: contractDomain.name,
      version: contractDomain.version,
      chainId: contractDomain.chainId,
      verifyingContract: contractDomain.verifyingContract,
    };

    //  issue "initSupply" to "admin"
    await usdt.connect(admin).issue(initSupply);
  });

  it("Should be able to check the initialized settings of Vault contract", async () => {
    expect(await vault.LOCKING_TOKEN()).deep.equal(await usdt.getAddress());
    expect(await vault.protocol()).deep.equal(await protocol.getAddress());
    expect(await usdt.owner()).deep.eq(admin.address);
    expect(await usdt.totalSupply()).deep.eq(initSupply);
    expect(await usdt.balanceOf(admin.address)).deep.eq(initSupply);
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
      const vaultBalance = await usdt.balanceOf(vaultAddress);
      const userBalance = await usdt.balanceOf(accounts[0].address);

      await expect(
        vault
          .connect(accounts[1])
          .deposit(ephemeralL2Address, tradeInput[0], tradeDetail[0]),
      ).to.be.revertedWithCustomError(vault, "Unauthorized");

      expect(await usdt.balanceOf(vaultAddress)).deep.eq(vaultBalance);
      expect(await usdt.balanceOf(accounts[0].address)).deep.eq(userBalance);
    });

    it("Should revert when User tries to deposit, but timeout is invalid", async () => {
      const timestamp = await getBlockTimestamp(provider);
      const invalidTimeout = Number(timestamp) - 1;
      const invalidTradeDetail = structuredClone(tradeDetail[0]);
      invalidTradeDetail.timeout = BigInt(invalidTimeout);

      const vaultAddress = await vault.getAddress();
      const vaultBalance = await usdt.balanceOf(vaultAddress);
      const userBalance = await usdt.balanceOf(accounts[0].address);

      await expect(
        vault
          .connect(accounts[0])
          .deposit(ephemeralL2Address, tradeInput[0], invalidTradeDetail),
      ).to.be.revertedWithCustomError(vault, "InvalidTimeout");

      expect(await usdt.balanceOf(vaultAddress)).deep.eq(vaultBalance);
      expect(await usdt.balanceOf(accounts[0].address)).deep.eq(userBalance);
    });

    it("Should revert when User tries to deposit, but amount = 0", async () => {
      const invalidTradeDetail = structuredClone(tradeDetail[0]);
      invalidTradeDetail.amount = Zero;
      const invalidTradeInput = structuredClone(tradeInput[0]);
      invalidTradeInput.tradeInfo.amountIn = Zero;

      const vaultAddress = await vault.getAddress();
      const vaultBalance = await usdt.balanceOf(vaultAddress);
      const userBalance = await usdt.balanceOf(accounts[0].address);

      await expect(
        vault
          .connect(accounts[0])
          .deposit(ephemeralL2Address, invalidTradeInput, invalidTradeDetail),
      ).to.be.revertedWithCustomError(vault, "InvalidDepositAmount");

      expect(await usdt.balanceOf(vaultAddress)).deep.eq(vaultBalance);
      expect(await usdt.balanceOf(accounts[0].address)).deep.eq(userBalance);
    });

    it("Should revert when User tries to deposit, but `amount` and `amountIn`, specified in the TradeDetail and TradeInfo, not matched", async () => {
      const invalidTradeDetail = structuredClone(tradeDetail[0]);
      invalidTradeDetail.amount = (tradeInfo[0].amountIn as bigint) - BigInt(1);

      const vaultAddress = await vault.getAddress();
      const vaultBalance = await usdt.balanceOf(vaultAddress);
      const userBalance = await usdt.balanceOf(accounts[0].address);

      await expect(
        vault
          .connect(accounts[0])
          .deposit(ephemeralL2Address, tradeInput[0], invalidTradeDetail),
      ).to.be.revertedWithCustomError(vault, "InvalidDepositAmount");

      expect(await usdt.balanceOf(vaultAddress)).deep.eq(vaultBalance);
      expect(await usdt.balanceOf(accounts[0].address)).deep.eq(userBalance);
    });

    it("Should revert when User tries to deposit, but provided mpcAddresss is 0x0", async () => {
      const invalidTradeDetail = structuredClone(tradeDetail[0]);
      invalidTradeDetail.mpc = ZeroAddress;

      const vaultAddress = await vault.getAddress();
      const vaultBalance = await usdt.balanceOf(vaultAddress);
      const userBalance = await usdt.balanceOf(accounts[0].address);

      await expect(
        vault
          .connect(accounts[0])
          .deposit(ephemeralL2Address, tradeInput[0], invalidTradeDetail),
      ).to.be.revertedWithCustomError(vault, "AddressZero");

      expect(await usdt.balanceOf(vaultAddress)).deep.eq(vaultBalance);
      expect(await usdt.balanceOf(accounts[0].address)).deep.eq(userBalance);
    });

    it("Should revert when User tries to deposit, but provided ephemeralAssetAddress is 0x0", async () => {
      const invalidTradeDetail = structuredClone(tradeDetail[0]);
      invalidTradeDetail.ephemeralAssetAddress = ZeroAddress;

      const vaultAddress = await vault.getAddress();
      const vaultBalance = await usdt.balanceOf(vaultAddress);
      const userBalance = await usdt.balanceOf(accounts[0].address);

      await expect(
        vault
          .connect(accounts[0])
          .deposit(ephemeralL2Address, tradeInput[0], invalidTradeDetail),
      ).to.be.revertedWithCustomError(vault, "AddressZero");

      expect(await usdt.balanceOf(vaultAddress)).deep.eq(vaultBalance);
      expect(await usdt.balanceOf(accounts[0].address)).deep.eq(userBalance);
    });

    it("Should revert when User tries to deposit, but provided refundAddress is 0x0", async () => {
      const invalidTradeDetail = structuredClone(tradeDetail[0]);
      invalidTradeDetail.refundAddress = ZeroAddress;

      const vaultAddress = await vault.getAddress();
      const vaultBalance = await usdt.balanceOf(vaultAddress);
      const userBalance = await usdt.balanceOf(accounts[0].address);

      await expect(
        vault
          .connect(accounts[0])
          .deposit(ephemeralL2Address, tradeInput[0], invalidTradeDetail),
      ).to.be.revertedWithCustomError(vault, "AddressZero");

      expect(await usdt.balanceOf(vaultAddress)).deep.eq(vaultBalance);
      expect(await usdt.balanceOf(accounts[0].address)).deep.eq(userBalance);
    });

    it("Should revert when User tries to deposit, but insufficient balance - Zero balance", async () => {
      const vaultAddress = await vault.getAddress();
      const vaultBalance = await usdt.balanceOf(vaultAddress);
      const userBalance = await usdt.balanceOf(accounts[0].address);

      await expect(
        vault
          .connect(accounts[0])
          .deposit(ephemeralL2Address, tradeInput[0], tradeDetail[0]),
      ).to.be.revertedWithoutReason();

      expect(await usdt.balanceOf(vaultAddress)).deep.eq(vaultBalance);
      expect(await usdt.balanceOf(accounts[0].address)).deep.eq(userBalance);
    });

    it("Should revert when User tries to deposit, but insufficient balance", async () => {
      //  Try to add some funds, but insufficient
      const amount: bigint = tradeInfo[0].amountIn as bigint;
      await usdt
        .connect(admin)
        .transfer(accounts[0].address, amount - BigInt(1));
      expect(await usdt.balanceOf(accounts[0].address)).lessThan(amount);

      const vaultAddress = await vault.getAddress();
      const vaultBalance = await usdt.balanceOf(vaultAddress);
      const userBalance = await usdt.balanceOf(accounts[0].address);

      await expect(
        vault
          .connect(accounts[0])
          .deposit(ephemeralL2Address, tradeInput[0], tradeDetail[0]),
      ).to.be.revertedWithoutReason();

      expect(await usdt.balanceOf(vaultAddress)).deep.eq(vaultBalance);
      expect(await usdt.balanceOf(accounts[0].address)).deep.eq(userBalance);
    });

    it("Should revert when User tries to deposit, but insufficient allowance", async () => {
      //  Try to add more funds
      const amount: bigint = tradeInfo[0].amountIn as bigint;
      const vaultAddress = await vault.getAddress();
      await usdt.connect(admin).transfer(accounts[0].address, amount);
      expect(await usdt.balanceOf(accounts[0].address)).greaterThan(amount);
      expect(await usdt.allowance(accounts[0].address, vaultAddress)).lessThan(
        amount,
      );

      const vaultBalance = await usdt.balanceOf(vaultAddress);
      const userBalance = await usdt.balanceOf(accounts[0].address);

      await expect(
        vault
          .connect(accounts[0])
          .deposit(ephemeralL2Address, tradeInput[0], tradeDetail[0]),
      ).to.be.revertedWithoutReason();

      expect(await usdt.balanceOf(vaultAddress)).deep.eq(vaultBalance);
      expect(await usdt.balanceOf(accounts[0].address)).deep.eq(userBalance);
    });

    it("Should succeed when User deposits fund with valid parameters", async () => {
      //  approve `amount` of allowance
      const amount: bigint = tradeInfo[0].amountIn as bigint;
      const vaultAddress = await vault.getAddress();
      await usdt.connect(accounts[0]).approve(vaultAddress, amount);

      const tx = vault
        .connect(accounts[0])
        .deposit(ephemeralL2Address, tradeInput[0], tradeDetail[0]);

      await expect(tx).changeTokenBalances(
        usdt,
        [accounts[0].address, vaultAddress],
        [-amount, amount],
      );
      await expect(tx)
        .to.emit(vault, "Deposited")
        .withArgs(
          tradeId[0],
          accounts[0].address,
          usdtAddr,
          ephemeralL2Address,
          Object.values(tradeDetail[0]),
        );

      expect(await vault.getTradeHash(tradeId[0])).deep.eq(
        hashOf(tradeDetail[0]),
      );
    });

    it("Should succeed when User makes another deposit", async () => {
      //  add funds and approve `amount` of allowance
      const amount: bigint = tradeInfo[1].amountIn as bigint;
      const vaultAddress = await vault.getAddress();
      await usdt.connect(admin).transfer(accounts[1].address, amount);
      await usdt.connect(accounts[1]).approve(vaultAddress, amount);

      const tx = vault
        .connect(accounts[1])
        .deposit(ephemeralL2Address, tradeInput[1], tradeDetail[1]);

      await expect(tx).changeTokenBalances(
        usdt,
        [accounts[1].address, vaultAddress],
        [-amount, amount],
      );
      await expect(tx)
        .to.emit(vault, "Deposited")
        .withArgs(
          tradeId[1],
          accounts[1].address,
          usdtAddr,
          ephemeralL2Address,
          Object.values(tradeDetail[1]),
        );

      expect(await vault.getTradeHash(tradeId[1])).deep.eq(
        hashOf(tradeDetail[1]),
      );
    });

    it("Should succeed when User makes another deposit", async () => {
      //  add funds and approve `amount` of allowance
      const amount: bigint = tradeInfo[2].amountIn as bigint;
      const vaultAddress = await vault.getAddress();
      await usdt.connect(admin).transfer(accounts[2].address, amount);
      await usdt.connect(accounts[2]).approve(vaultAddress, amount);

      const tx = vault
        .connect(accounts[2])
        .deposit(ephemeralL2Address, tradeInput[2], tradeDetail[2]);

      await expect(tx).changeTokenBalances(
        usdt,
        [accounts[2].address, vaultAddress],
        [-amount, amount],
      );
      await expect(tx)
        .to.emit(vault, "Deposited")
        .withArgs(
          tradeId[2],
          accounts[2].address,
          usdtAddr,
          ephemeralL2Address,
          Object.values(tradeDetail[2]),
        );

      expect(await vault.getTradeHash(tradeId[2])).deep.eq(
        hashOf(tradeDetail[2]),
      );
    });

    it("Should succeed when User makes another deposit", async () => {
      //  add funds and approve `amount` of allowance
      const amount: bigint = tradeInfo[3].amountIn as bigint;
      const vaultAddress = await vault.getAddress();
      await usdt.connect(admin).transfer(accounts[3].address, amount);
      await usdt.connect(accounts[3]).approve(vaultAddress, amount);

      const tx = vault
        .connect(accounts[3])
        .deposit(ephemeralL2Address, tradeInput[3], tradeDetail[3]);

      await expect(tx).changeTokenBalances(
        usdt,
        [accounts[3].address, vaultAddress],
        [-amount, amount],
      );
      await expect(tx)
        .to.emit(vault, "Deposited")
        .withArgs(
          tradeId[3],
          accounts[3].address,
          usdtAddr,
          ephemeralL2Address,
          Object.values(tradeDetail[3]),
        );

      expect(await vault.getTradeHash(tradeId[3])).deep.eq(
        hashOf(tradeDetail[3]),
      );
    });

    it("Should revert when User makes a duplicated deposit", async () => {
      const amount: bigint = tradeInfo[0].amountIn as bigint;
      const newTradeDetail = structuredClone(tradeDetail[0]);
      newTradeDetail.timeout = BigInt(
        Math.floor(Date.now() / 1000) + 24 * 3600,
      );

      //  add funds, and set approval
      const vaultAddress = await vault.getAddress();
      await usdt.connect(admin).transfer(accounts[0].address, amount);
      await usdt.connect(accounts[0]).approve(vaultAddress, amount);

      const vaultBalance = await usdt.balanceOf(vaultAddress);
      const userBalance = await usdt.balanceOf(accounts[0].address);
      const lastHash = await vault.getTradeHash(tradeId[0]);

      await expect(
        vault
          .connect(accounts[0])
          .deposit(ephemeralL2Address, tradeInput[0], newTradeDetail),
      ).to.be.revertedWithCustomError(vault, "DuplicatedDeposit");

      expect(await usdt.balanceOf(vaultAddress)).deep.eq(vaultBalance);
      expect(await usdt.balanceOf(accounts[0].address)).deep.eq(userBalance);
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
      const mpcSignature = await getSettlementSignature(
        mpc,
        totalFee[0],
        presign,
        domain,
      );

      const lashHash = await vault.getTradeHash(tradeId[0]);
      const vaultAddress = await vault.getAddress();
      const vaultBalance = await usdt.balanceOf(vaultAddress);
      const pmmBalance = await usdt.balanceOf(pmm.address);

      //  @dev: When `tradeId` is not recorded, hash of trade detail wouldn't match
      await expect(
        vault
          .connect(mpcNode)
          .settlement(
            invalidTradeId,
            totalFee[0],
            pmm.address,
            tradeDetail[0],
            presign,
            mpcSignature,
          ),
      ).to.be.revertedWithCustomError(vault, "TradeDetailNotMatched");

      expect(await usdt.balanceOf(vaultAddress)).deep.eq(vaultBalance);
      expect(await usdt.balanceOf(pmm.address)).deep.eq(pmmBalance);
      expect(await vault.getTradeHash(tradeId[0])).deep.eq(lashHash);
    });

    it("Should revert when MPC Nodes tries to settle the tradeId, but timeout has passed", async () => {
      const timestamp = await getBlockTimestamp(provider);
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
      const mpcSignature = await getSettlementSignature(
        mpc,
        totalFee[0],
        presign,
        domain,
      );

      const lashHash = await vault.getTradeHash(tradeId[0]);
      const vaultAddress = await vault.getAddress();
      const vaultBalance = await usdt.balanceOf(vaultAddress);
      const pmmBalance = await usdt.balanceOf(pmm.address);

      await expect(
        vault
          .connect(mpcNode)
          .settlement(
            tradeId[0],
            totalFee[0],
            pmm.address,
            tradeDetail[0],
            presign,
            mpcSignature,
          ),
      ).to.be.revertedWithCustomError(vault, "Timeout");

      expect(await usdt.balanceOf(vaultAddress)).deep.eq(vaultBalance);
      expect(await usdt.balanceOf(pmm.address)).deep.eq(pmmBalance);
      expect(await vault.getTradeHash(tradeId[0])).deep.eq(lashHash);

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
      const mpcSignature = await getSettlementSignature(
        mpc,
        totalFee[0],
        presign,
        domain,
      );

      const lashHash = await vault.getTradeHash(tradeId[0]);
      const vaultAddress = await vault.getAddress();
      const vaultBalance = await usdt.balanceOf(vaultAddress);
      const pmmBalance = await usdt.balanceOf(pmm.address);

      await expect(
        vault
          .connect(mpcNode)
          .settlement(
            tradeId[0],
            totalFee[0],
            pmm.address,
            tradeDetail[0],
            presign,
            mpcSignature,
          ),
      ).to.be.revertedWithCustomError(vault, "InvalidPresign");

      expect(await usdt.balanceOf(vaultAddress)).deep.eq(vaultBalance);
      expect(await usdt.balanceOf(pmm.address)).deep.eq(pmmBalance);
      expect(await vault.getTradeHash(tradeId[0])).deep.eq(lashHash);
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
      const mpcSignature = await getSettlementSignature(
        mpc,
        totalFee[0],
        presign,
        domain,
      );

      const lashHash1 = await vault.getTradeHash(tradeId[0]);
      const lashHash2 = await vault.getTradeHash(tradeId[1]);
      const vaultAddress = await vault.getAddress();
      const vaultBalance = await usdt.balanceOf(vaultAddress);
      const pmmBalance = await usdt.balanceOf(pmm.address);

      await expect(
        vault
          .connect(mpcNode)
          .settlement(
            tradeId[0],
            totalFee[0],
            pmm.address,
            tradeDetail[0],
            presign,
            mpcSignature,
          ),
      ).to.be.revertedWithCustomError(vault, "InvalidPresign");

      expect(await usdt.balanceOf(vaultAddress)).deep.eq(vaultBalance);
      expect(await usdt.balanceOf(pmm.address)).deep.eq(pmmBalance);
      expect(await vault.getTradeHash(tradeId[0])).deep.eq(lashHash1);
      expect(await vault.getTradeHash(tradeId[1])).deep.eq(lashHash2);
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
      const mpcSignature = await getSettlementSignature(
        mpc,
        totalFee[0],
        presign,
        domain,
      );

      const lashHash = await vault.getTradeHash(tradeId[0]);
      const vaultAddress = await vault.getAddress();
      const vaultBalance = await usdt.balanceOf(vaultAddress);
      const pmmBalance = await usdt.balanceOf(pmm.address);

      await expect(
        vault.connect(mpcNode).settlement(
          tradeId[0],
          totalFee[0],
          mpcNode.address, //  un-matched pmmRecvAddress
          tradeDetail[0],
          presign,
          mpcSignature,
        ),
      ).to.be.revertedWithCustomError(vault, "InvalidPresign");

      expect(await usdt.balanceOf(vaultAddress)).deep.eq(vaultBalance);
      expect(await usdt.balanceOf(pmm.address)).deep.eq(pmmBalance);
      expect(await vault.getTradeHash(tradeId[0])).deep.eq(lashHash);
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
      const mpcSignature = await getSettlementSignature(
        mpc,
        totalFee[0],
        presign,
        domain,
      );

      const lashHash = await vault.getTradeHash(tradeId[0]);
      const vaultAddress = await vault.getAddress();
      const vaultBalance = await usdt.balanceOf(vaultAddress);
      const pmmBalance = await usdt.balanceOf(pmm.address);

      await expect(
        vault
          .connect(mpcNode)
          .settlement(
            tradeId[0],
            totalFee[0],
            pmm.address,
            tradeDetail[0],
            presign,
            mpcSignature,
          ),
      ).to.be.revertedWithCustomError(vault, "InvalidPresign");

      expect(await usdt.balanceOf(vaultAddress)).deep.eq(vaultBalance);
      expect(await usdt.balanceOf(pmm.address)).deep.eq(pmmBalance);
      expect(await vault.getTradeHash(tradeId[0])).deep.eq(lashHash);
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
      const mpcSignature = await getSettlementSignature(
        mpc,
        totalFee[0],
        presign,
        domain,
      );

      const lashHash = await vault.getTradeHash(tradeId[0]);
      const vaultAddress = await vault.getAddress();
      const vaultBalance = await usdt.balanceOf(vaultAddress);
      const pmmBalance = await usdt.balanceOf(pmm.address);

      await expect(
        vault
          .connect(mpcNode)
          .settlement(
            tradeId[0],
            totalFee[0],
            pmm.address,
            tradeDetail[0],
            presign,
            mpcSignature,
          ),
      ).to.be.revertedWithCustomError(vault, "InvalidPresign");

      expect(await usdt.balanceOf(vaultAddress)).deep.eq(vaultBalance);
      expect(await usdt.balanceOf(pmm.address)).deep.eq(pmmBalance);
      expect(await vault.getTradeHash(tradeId[0])).deep.eq(lashHash);
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
      const mpcSignature = await getSettlementSignature(
        mpc,
        totalFee[0],
        presign,
        domain,
      );

      const lashHash = await vault.getTradeHash(tradeId[0]);
      const vaultAddress = await vault.getAddress();
      const vaultBalance = await usdt.balanceOf(vaultAddress);
      const pmmBalance = await usdt.balanceOf(pmm.address);

      await expect(
        vault
          .connect(mpcNode)
          .settlement(
            tradeId[0],
            totalFee[0],
            pmm.address,
            tradeDetail[0],
            presign,
            mpcSignature,
          ),
      ).to.be.revertedWithCustomError(vault, "InvalidPresign");

      expect(await usdt.balanceOf(vaultAddress)).deep.eq(vaultBalance);
      expect(await usdt.balanceOf(pmm.address)).deep.eq(pmmBalance);
      expect(await vault.getTradeHash(tradeId[0])).deep.eq(lashHash);
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
      const mpcSignature = await getSettlementSignature(
        mpc,
        totalFee[0],
        presign,
        domain,
      );

      const lashHash = await vault.getTradeHash(tradeId[0]);
      const vaultAddress = await vault.getAddress();
      const vaultBalance = await usdt.balanceOf(vaultAddress);
      const pmmBalance = await usdt.balanceOf(pmm.address);

      await expect(
        vault
          .connect(mpcNode)
          .settlement(
            tradeId[0],
            totalFee[0],
            pmm.address,
            tradeDetail[0],
            presign,
            mpcSignature,
          ),
      ).to.be.revertedWithCustomError(vault, "InvalidPresign");

      expect(await usdt.balanceOf(vaultAddress)).deep.eq(vaultBalance);
      expect(await usdt.balanceOf(pmm.address)).deep.eq(pmmBalance);
      expect(await vault.getTradeHash(tradeId[0])).deep.eq(lashHash);
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
      const mpcSignature = await getSettlementSignature(
        mpc,
        totalFee[0],
        presign,
        domain,
      );

      const lashHash = await vault.getTradeHash(tradeId[0]);
      const vaultAddress = await vault.getAddress();
      const vaultBalance = await usdt.balanceOf(vaultAddress);
      const pmmBalance = await usdt.balanceOf(pmm.address);

      await expect(
        vault
          .connect(mpcNode)
          .settlement(
            tradeId[0],
            totalFee[0],
            pmm.address,
            tradeDetail[0],
            presign,
            mpcSignature,
          ),
      ).to.be.revertedWithCustomError(vault, "InvalidPresign");

      expect(await usdt.balanceOf(vaultAddress)).deep.eq(vaultBalance);
      expect(await usdt.balanceOf(pmm.address)).deep.eq(pmmBalance);
      expect(await vault.getTradeHash(tradeId[0])).deep.eq(lashHash);
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
      const mpcSignature = await getSettlementSignature(
        mpcNode, //  invalid signer. Should be mpc
        totalFee[0],
        presign,
        domain,
      );

      const lashHash = await vault.getTradeHash(tradeId[0]);
      const vaultAddress = await vault.getAddress();
      const vaultBalance = await usdt.balanceOf(vaultAddress);
      const pmmBalance = await usdt.balanceOf(pmm.address);

      await expect(
        vault
          .connect(mpcNode)
          .settlement(
            tradeId[0],
            totalFee[0],
            pmm.address,
            tradeDetail[0],
            presign,
            mpcSignature,
          ),
      ).to.be.revertedWithCustomError(vault, "InvalidMPCSign");

      expect(await usdt.balanceOf(vaultAddress)).deep.eq(vaultBalance);
      expect(await usdt.balanceOf(pmm.address)).deep.eq(pmmBalance);
      expect(await vault.getTradeHash(tradeId[0])).deep.eq(lashHash);
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
      const mpcSignature = await getSettlementSignature(
        mpc,
        totalFee[0],
        presign,
        domain,
      );

      const lashHash = await vault.getTradeHash(tradeId[0]);
      const vaultAddress = await vault.getAddress();
      const vaultBalance = await usdt.balanceOf(vaultAddress);
      const pmmBalance = await usdt.balanceOf(pmm.address);

      await expect(
        vault.connect(mpcNode).settlement(
          tradeId[0],
          totalFee[0] - BigInt(1), //  un-matched totalFee
          pmm.address,
          tradeDetail[0],
          presign,
          mpcSignature,
        ),
      ).to.be.revertedWithCustomError(vault, "InvalidMPCSign");

      expect(await usdt.balanceOf(vaultAddress)).deep.eq(vaultBalance);
      expect(await usdt.balanceOf(pmm.address)).deep.eq(pmmBalance);
      expect(await vault.getTradeHash(tradeId[0])).deep.eq(lashHash);
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
      const mpcSignature = await getSettlementSignature(
        mpc,
        totalFee[0],
        anotherPresign,
        domain,
      );

      const lashHash = await vault.getTradeHash(tradeId[0]);
      const vaultAddress = await vault.getAddress();
      const vaultBalance = await usdt.balanceOf(vaultAddress);
      const pmmBalance = await usdt.balanceOf(pmm.address);

      await expect(
        vault
          .connect(mpcNode)
          .settlement(
            tradeId[0],
            totalFee[0],
            pmm.address,
            tradeDetail[0],
            presign,
            mpcSignature,
          ),
      ).to.be.revertedWithCustomError(vault, "InvalidMPCSign");

      expect(await usdt.balanceOf(vaultAddress)).deep.eq(vaultBalance);
      expect(await usdt.balanceOf(pmm.address)).deep.eq(pmmBalance);
      expect(await vault.getTradeHash(tradeId[0])).deep.eq(lashHash);
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
      const mpcSignature = await getSettlementSignature(
        mpc,
        totalFee[0],
        presign,
        wrongDomain,
      );

      const lashHash = await vault.getTradeHash(tradeId[0]);
      const vaultAddress = await vault.getAddress();
      const vaultBalance = await usdt.balanceOf(vaultAddress);
      const pmmBalance = await usdt.balanceOf(pmm.address);

      await expect(
        vault
          .connect(mpcNode)
          .settlement(
            tradeId[0],
            totalFee[0],
            pmm.address,
            tradeDetail[0],
            presign,
            mpcSignature,
          ),
      ).to.be.revertedWithCustomError(vault, "InvalidMPCSign");

      expect(await usdt.balanceOf(vaultAddress)).deep.eq(vaultBalance);
      expect(await usdt.balanceOf(pmm.address)).deep.eq(pmmBalance);
      expect(await vault.getTradeHash(tradeId[0])).deep.eq(lashHash);
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
      const mpcSignature = await getSettlementSignature(
        mpc,
        totalFee[0],
        presign,
        wrongDomain,
      );

      const lashHash = await vault.getTradeHash(tradeId[0]);
      const vaultAddress = await vault.getAddress();
      const vaultBalance = await usdt.balanceOf(vaultAddress);
      const pmmBalance = await usdt.balanceOf(pmm.address);

      await expect(
        vault
          .connect(mpcNode)
          .settlement(
            tradeId[0],
            totalFee[0],
            pmm.address,
            tradeDetail[0],
            presign,
            mpcSignature,
          ),
      ).to.be.revertedWithCustomError(vault, "InvalidMPCSign");

      expect(await usdt.balanceOf(vaultAddress)).deep.eq(vaultBalance);
      expect(await usdt.balanceOf(pmm.address)).deep.eq(pmmBalance);
      expect(await vault.getTradeHash(tradeId[0])).deep.eq(lashHash);
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
      const mpcSignature = await getSettlementSignature(
        mpc,
        totalFee[0],
        presign,
        wrongDomain,
      );

      const lashHash = await vault.getTradeHash(tradeId[0]);
      const vaultAddress = await vault.getAddress();
      const vaultBalance = await usdt.balanceOf(vaultAddress);
      const pmmBalance = await usdt.balanceOf(pmm.address);

      await expect(
        vault
          .connect(mpcNode)
          .settlement(
            tradeId[0],
            totalFee[0],
            pmm.address,
            tradeDetail[0],
            presign,
            mpcSignature,
          ),
      ).to.be.revertedWithCustomError(vault, "InvalidMPCSign");

      expect(await usdt.balanceOf(vaultAddress)).deep.eq(vaultBalance);
      expect(await usdt.balanceOf(pmm.address)).deep.eq(pmmBalance);
      expect(await vault.getTradeHash(tradeId[0])).deep.eq(lashHash);
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
      const mpcSignature = await getSettlementSignature(
        mpc,
        totalFee[0],
        presign,
        wrongDomain,
      );

      const lashHash = await vault.getTradeHash(tradeId[0]);
      const vaultAddress = await vault.getAddress();
      const vaultBalance = await usdt.balanceOf(vaultAddress);
      const pmmBalance = await usdt.balanceOf(pmm.address);

      await expect(
        vault
          .connect(mpcNode)
          .settlement(
            tradeId[0],
            totalFee[0],
            pmm.address,
            tradeDetail[0],
            presign,
            mpcSignature,
          ),
      ).to.be.revertedWithCustomError(vault, "InvalidMPCSign");

      expect(await usdt.balanceOf(vaultAddress)).deep.eq(vaultBalance);
      expect(await usdt.balanceOf(pmm.address)).deep.eq(pmmBalance);
      expect(await vault.getTradeHash(tradeId[0])).deep.eq(lashHash);
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
      const mpcSignature = await getSettlementSignature(
        mpc,
        totalFee[0],
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
          totalFee[0],
          pmm.address,
          tradeDetail[0],
          presign,
          mpcSignature,
        );

      await expect(tx)
        .to.emit(vault, "Settled")
        .withArgs(
          tradeId[0],
          usdtAddr,
          pmm.address, // toAddress
          mpcNode.address, //  operator
          amount - totalFee[0], //  amount after fee
          pFeeAddress,
          totalFee[0],
        );
      await expect(tx).changeTokenBalances(
        usdt,
        [vaultAddress, pmm.address, pFeeAddress],
        [-amount, amount - totalFee[0], totalFee[0]],
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
      const mpcSignature = await getSettlementSignature(
        mpc,
        totalFee[1],
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
          totalFee[1],
          pmm.address,
          tradeDetail[1],
          presign,
          mpcSignature,
        );

      await expect(tx)
        .to.emit(vault, "Settled")
        .withArgs(
          tradeId[1],
          usdtAddr,
          pmm.address, // toAddress
          mpcNode.address, //  operator
          amount - totalFee[1], //  amount after fee
          pFeeAddress,
          totalFee[1],
        );
      await expect(tx).changeTokenBalances(
        usdt,
        [vaultAddress, pmm.address, pFeeAddress],
        [-amount, amount - totalFee[1], totalFee[1]],
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
      const mpcSignature = await getSettlementSignature(
        mpc,
        totalFee[0],
        presign,
        domain,
      );

      const vaultAddress = await vault.getAddress();
      const vaultBalance = await usdt.balanceOf(vaultAddress);
      const pmmBalance = await usdt.balanceOf(pmm.address);

      //  @dev: When `tradeId` is finalized, contract would delete the storage
      //  that saves the hash of trade detail. Thus, it likely fails with `TradeDetailNotMatched`
      await expect(
        vault
          .connect(mpcNode)
          .settlement(
            tradeId[0],
            totalFee[0],
            pmm.address,
            tradeDetail[0],
            presign,
            mpcSignature,
          ),
      ).to.be.revertedWithCustomError(vault, "TradeDetailNotMatched");

      expect(await usdt.balanceOf(vaultAddress)).deep.eq(vaultBalance);
      expect(await usdt.balanceOf(pmm.address)).deep.eq(pmmBalance);
      expect(await vault.getTradeHash(tradeId[0])).deep.eq(EMPTY_TRADE_HASH);
    });
  });

  describe("claim() functional testing", async () => {
    it("Should revert when User tries to get a refund, but not yet timeout", async () => {
      const lashHash = await vault.getTradeHash(tradeId[2]);
      const vaultAddress = await vault.getAddress();
      const vaultBalance = await usdt.balanceOf(vaultAddress);
      const userBalance = await usdt.balanceOf(tradeDetail[2].refundAddress);

      await expect(
        vault.connect(accounts[2]).claim(tradeId[2], tradeDetail[2]),
      ).to.be.revertedWithCustomError(vault, "ClaimNotAvailable");

      expect(await usdt.balanceOf(vaultAddress)).deep.eq(vaultBalance);
      expect(await usdt.balanceOf(tradeDetail[2].refundAddress)).deep.eq(
        userBalance,
      );
      expect(await vault.getTradeHash(tradeId[2])).deep.eq(lashHash);
    });

    it("Should revert when User claims a refund for non-existence tradeId", async () => {
      const vaultAddress = await vault.getAddress();
      const vaultBalance = await usdt.balanceOf(vaultAddress);
      const invalidTradeId = keccak256(toUtf8Bytes("Invalid_trade_id"));

      //  @dev: When `tradeId` is not recorded, hash of trade detail wouldn't match
      await expect(
        vault.connect(accounts[2]).claim(invalidTradeId, tradeDetail[2]),
      ).to.be.revertedWithCustomError(vault, "TradeDetailNotMatched");

      expect(await usdt.balanceOf(vaultAddress)).deep.eq(vaultBalance);
    });

    it("Should succeed when User gets a refund after timeout - Self claim", async () => {
      const timestamp = await getBlockTimestamp(provider);
      const exceedTimeout = Number(tradeDetail[2].timeout) + 1;
      if (timestamp < exceedTimeout) await adjustTime(exceedTimeout);

      const refundAddress = tradeDetail[2].refundAddress;
      const amount = tradeInfo[2].amountIn;
      //  @dev:
      //  The function claim() has no constraint on the "caller"
      //  Anyone can call to transfer the refund, and contract will transfer
      //  the `amount` to `refundAddress` that is specified and hashed
      //  in the hash of trade detail when `tradeId` is initialized
      const tx = vault.connect(accounts[2]).claim(tradeId[2], tradeDetail[2]);

      await expect(tx).to.emit(vault, "Claimed").withArgs(
        tradeId[2],
        usdtAddr,
        refundAddress, // refundAddress
        accounts[2].address, //  operator
        amount,
      );
      await expect(tx).changeTokenBalances(
        usdt,
        [await vault.getAddress(), refundAddress],
        [-amount, amount],
      );
      expect(await vault.getTradeHash(tradeId[2])).deep.eq(EMPTY_TRADE_HASH);
    });

    it("Should succeed when User gets another refund after timeout - By the MPC Node", async () => {
      const timestamp = await getBlockTimestamp(provider);
      const exceedTimeout = Number(tradeDetail[3].timeout) + 1;
      if (timestamp < exceedTimeout) await adjustTime(exceedTimeout);

      const refundAddress = tradeDetail[3].refundAddress;
      const amount = tradeInfo[3].amountIn;
      //  @dev:
      //  The function claim() has no constraint on the "caller"
      //  Anyone can call to transfer the refund, and contract will transfer
      //  the `amount` to `refundAddress` that is specified and hashed
      //  in the hash of trade detail when `tradeId` is initialized
      const tx = vault.connect(mpcNode).claim(tradeId[3], tradeDetail[3]);

      await expect(tx).to.emit(vault, "Claimed").withArgs(
        tradeId[3],
        usdtAddr,
        refundAddress, // refundAddress
        mpcNode.address, //  operator
        amount,
      );
      await expect(tx).changeTokenBalances(
        usdt,
        [await vault.getAddress(), refundAddress],
        [-amount, amount],
      );
      expect(await vault.getTradeHash(tradeId[3])).deep.eq(EMPTY_TRADE_HASH);
    });

    it("Should revert when User tries to get a refund, but tradeId already claimed", async () => {
      const timestamp = await getBlockTimestamp(provider);
      const timeout = Number(tradeDetail[3].timeout);
      if (timestamp < timeout) await adjustTime(timeout);

      const refundAddress = tradeDetail[3].refundAddress;
      const vaultAddress = await vault.getAddress();
      const vaultBalance = await usdt.balanceOf(vaultAddress);
      const userBalance = await usdt.balanceOf(refundAddress);

      //  @dev: When `tradeId` is claimed, contract would delete the storage
      //  that saves the hash of trade detail. Thus, it likely fails with `TradeDetailNotMatched`
      await expect(
        vault.connect(accounts[3]).claim(tradeId[3], tradeDetail[3]),
      ).to.be.revertedWithCustomError(vault, "TradeDetailNotMatched");

      expect(await usdt.balanceOf(vaultAddress)).deep.eq(vaultBalance);
      expect(await usdt.balanceOf(refundAddress)).deep.eq(userBalance);
      expect(await vault.getTradeHash(tradeId[3])).deep.eq(EMPTY_TRADE_HASH);
    });
  });
});
