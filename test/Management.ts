import { expect } from "chai";
import { ethers, network } from "hardhat";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";
import {
  keccak256,
  toUtf8Bytes,
  computeAddress,
  hexlify,
  Wallet,
} from "ethers";
import { Keypair, PublicKey } from "@solana/web3.js";

import { Management, Management__factory } from "../typechain-types";
import { ITypes as ManagementTypes } from "../typechain-types/contracts/Management";
import { getMPCPubkey } from "../scripts/utils/bitcoin/btc";
import { genSolanaKP } from "../scripts/utils/solana/sol";
import { randomTxId } from "../sample-data/utils";

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
}

const Zero = BigInt(0);
const ZeroAddress = ethers.ZeroAddress;
const EMPTY_BYTES = hexlify("0x");
const EMPTY_INFO = [ZeroAddress, Zero, EMPTY_BYTES, EMPTY_BYTES];
const MAX_UINT64 = BigInt("18446744073709551615");
const provider = ethers.provider;

const btcChain = "bitcoin-testnet";
const evmChain = "ethereum-sepolia";
const solChain = "solana-devnet";

const btcTestnet: ManagementTypes.TokenInfoStruct = {
  info: [
    toUtf8Bytes("native"), // tokenId
    toUtf8Bytes(btcChain), // networkId
    toUtf8Bytes("BTC"), // symbol
    toUtf8Bytes("https://example.com"),
    toUtf8Bytes("Bitcoin (BTC) - Bitcoin Testnet Token"),
  ],
  decimals: BigInt(8),
};

const ethTestnet: ManagementTypes.TokenInfoStruct = {
  info: [
    toUtf8Bytes("native"), // tokenId
    toUtf8Bytes(evmChain), // networkId
    toUtf8Bytes("ETH"), // symbol
    toUtf8Bytes("https://example.com"),
    toUtf8Bytes("Ethereum (ETH) - Ethereum Sepolia Testnet Token"),
  ],
  decimals: BigInt(18),
};

const solTestnet: ManagementTypes.TokenInfoStruct = {
  info: [
    toUtf8Bytes("native"), // tokenId
    toUtf8Bytes(solChain), // networkId
    toUtf8Bytes("SOL"), // symbol
    toUtf8Bytes("https://example.com"),
    toUtf8Bytes("Solana (SOL) - Solana Devnet Token"),
  ],
  decimals: BigInt(9),
};

describe("Management Contract Testing", () => {
  let admin: HardhatEthersSigner;
  let solver: HardhatEthersSigner, newSolver: HardhatEthersSigner;
  let mpcNode1: HardhatEthersSigner, mpcNode2: HardhatEthersSigner;
  let accounts: HardhatEthersSigner[];

  let management: Management;
  const pFeeRate: bigint = BigInt(50);

  const prevExpireTime = BigInt(0);
  let mpcInfo: ManagementTypes.MPCInfoStruct;

  before(async () => {
    await network.provider.request({
      method: "hardhat_reset",
      params: [],
    });

    [admin, solver, newSolver, mpcNode1, mpcNode2, ...accounts] =
      await ethers.getSigners();

    //  Deploy Management contract
    const Management = (await ethers.getContractFactory(
      "Management",
      admin,
    )) as Management__factory;
    management = await Management.deploy(admin.address, pFeeRate);
  });

  it("Should be able to check the initialized settings of Management contract", async () => {
    expect(await management.owner()).deep.equal(admin.address);
    expect(await management.pFeeRate()).deep.equal(pFeeRate);
  });

  describe("setFeeRate() functional testing", async () => {
    it("Should revert when Non-Owner tries to update protocol's fee rate", async () => {
      const newFeeRate = BigInt(30);
      expect(await management.pFeeRate()).deep.equal(pFeeRate);

      await expect(
        management.connect(accounts[0]).setFeeRate(newFeeRate),
      ).to.be.revertedWithCustomError(management, "OwnableUnauthorizedAccount");

      expect(await management.pFeeRate()).deep.equal(pFeeRate);
    });

    it("Should succeed when Owner updates pFeeRate = 0", async () => {
      expect(await management.pFeeRate()).deep.equal(pFeeRate);

      await management.connect(admin).setFeeRate(0);

      expect(await management.pFeeRate()).deep.equal(0);
    });

    it("Should succeed when Owner updates another value of the protocol's fee rate", async () => {
      const newFeeRate = BigInt(30);
      expect(await management.pFeeRate()).deep.equal(0);

      await management.connect(admin).setFeeRate(newFeeRate);

      expect(await management.pFeeRate()).deep.equal(newFeeRate);
    });
  });

  describe("setSolver() functional testing", async () => {
    it("Should revert when Non-Owner tries to set one account as Solver", async () => {
      expect(await management.solvers(accounts[0].address)).deep.eq(false);

      await expect(
        management.connect(accounts[0]).setSolver(accounts[0].address, true),
      ).to.be.revertedWithCustomError(management, "OwnableUnauthorizedAccount");

      expect(await management.solvers(accounts[0].address)).deep.eq(false);
    });

    it("Should succeed when Owner sets 0x00 as Solver", async () => {
      expect(await management.solvers(ZeroAddress)).deep.eq(false);

      const tx = management.connect(admin).setSolver(ZeroAddress, true);
      await expect(tx)
        .to.emit(management, "UpdatedSolver")
        .withArgs(ZeroAddress, true);

      expect(await management.solvers(ZeroAddress)).deep.eq(true);
    });

    it("Should succeed when Owner sets one account as Solver", async () => {
      expect(await management.solvers(solver.address)).deep.eq(false);

      const tx = management.connect(admin).setSolver(solver.address, true);
      await expect(tx)
        .to.emit(management, "UpdatedSolver")
        .withArgs(solver.address, true);

      expect(await management.solvers(solver.address)).deep.eq(true);
    });

    it("Should succeed when Owner sets another account as Solver", async () => {
      expect(await management.solvers(newSolver.address)).deep.eq(false);

      const tx = management.connect(admin).setSolver(newSolver.address, true);
      await expect(tx)
        .to.emit(management, "UpdatedSolver")
        .withArgs(newSolver.address, true);

      expect(await management.solvers(newSolver.address)).deep.eq(true);
    });

    it("Should revert when Owner sets one account, as Solver, that already registered", async () => {
      expect(await management.solvers(solver.address)).deep.eq(true);

      await expect(
        management.connect(admin).setSolver(solver.address, true),
      ).to.be.revertedWithCustomError(management, "RegisteredAlready");

      expect(await management.solvers(solver.address)).deep.eq(true);
    });

    it("Should revert when Non-Owner tries to remove a current Solver", async () => {
      expect(await management.solvers(solver.address)).deep.eq(true);

      await expect(
        management.connect(accounts[0]).setSolver(solver.address, false),
      ).to.be.revertedWithCustomError(management, "OwnableUnauthorizedAccount");

      expect(await management.solvers(solver.address)).deep.eq(true);
    });

    it("Should succeed when Owner removes the Solver (0x00)", async () => {
      expect(await management.solvers(ZeroAddress)).deep.eq(true);

      const tx = management.connect(admin).setSolver(ZeroAddress, false);
      await expect(tx)
        .to.emit(management, "UpdatedSolver")
        .withArgs(ZeroAddress, false);

      expect(await management.solvers(ZeroAddress)).deep.eq(false);
    });

    it("Should succeed when Owner removes one Solver", async () => {
      expect(await management.solvers(solver.address)).deep.eq(true);

      const tx = management.connect(admin).setSolver(solver.address, false);
      await expect(tx)
        .to.emit(management, "UpdatedSolver")
        .withArgs(solver.address, false);

      expect(await management.solvers(solver.address)).deep.eq(false);
    });

    it("Should revert when Owner removes the Solver that already unregistered", async () => {
      expect(await management.solvers(solver.address)).deep.eq(false);

      await expect(
        management.connect(admin).setSolver(solver.address, false),
      ).to.be.revertedWithCustomError(management, "UnregisteredAlready");

      expect(await management.solvers(solver.address)).deep.eq(false);
    });

    it("Should succeed when Owner removes another Solver", async () => {
      expect(await management.solvers(newSolver.address)).deep.eq(true);

      const tx = management.connect(admin).setSolver(newSolver.address, false);
      await expect(tx)
        .to.emit(management, "UpdatedSolver")
        .withArgs(newSolver.address, false);

      expect(await management.solvers(newSolver.address)).deep.eq(false);
    });
  });

  describe("setMPCNode() functional testing", async () => {
    it("Should revert when Non-Owner tries to set MPC Nod's associated account", async () => {
      expect(await management.mpcNodes(mpcNode1.address)).deep.eq(false);

      await expect(
        management.connect(accounts[0]).setMPCNode(mpcNode1.address, true),
      ).to.be.revertedWithCustomError(management, "OwnableUnauthorizedAccount");

      expect(await management.mpcNodes(mpcNode1.address)).deep.eq(false);
    });

    it("Should succeed when Owner sets 0x00 as MPC Node's associated account", async () => {
      expect(await management.mpcNodes(ZeroAddress)).deep.eq(false);

      const tx = management.connect(admin).setMPCNode(ZeroAddress, true);
      await expect(tx)
        .to.emit(management, "UpdatedMPCNode")
        .withArgs(ZeroAddress, true);

      expect(await management.mpcNodes(ZeroAddress)).deep.eq(true);
    });

    it("Should succeed when Owner sets MPC Node's associated account", async () => {
      expect(await management.mpcNodes(mpcNode1.address)).deep.eq(false);

      const tx = management.connect(admin).setMPCNode(mpcNode1.address, true);
      await expect(tx)
        .to.emit(management, "UpdatedMPCNode")
        .withArgs(mpcNode1.address, true);

      expect(await management.mpcNodes(mpcNode1.address)).deep.eq(true);
    });

    it("Should succeed when Owner sets another MPC Node's associated account", async () => {
      expect(await management.mpcNodes(mpcNode2.address)).deep.eq(false);

      const tx = management.connect(admin).setMPCNode(mpcNode2.address, true);
      await expect(tx)
        .to.emit(management, "UpdatedMPCNode")
        .withArgs(mpcNode2.address, true);

      expect(await management.mpcNodes(mpcNode2.address)).deep.eq(true);
    });

    it("Should revert when Owner sets one account that was registered as MPC Node's associated account", async () => {
      expect(await management.mpcNodes(mpcNode1.address)).deep.eq(true);

      await expect(
        management.connect(admin).setMPCNode(mpcNode1.address, true),
      ).to.be.revertedWithCustomError(management, "RegisteredAlready");

      expect(await management.mpcNodes(mpcNode1.address)).deep.eq(true);
    });

    it("Should revert when Non-Owner tries to remove MPC Node's associated account", async () => {
      expect(await management.mpcNodes(mpcNode1.address)).deep.eq(true);

      await expect(
        management.connect(accounts[0]).setMPCNode(mpcNode1.address, false),
      ).to.be.revertedWithCustomError(management, "OwnableUnauthorizedAccount");

      expect(await management.mpcNodes(mpcNode1.address)).deep.eq(true);
    });

    it("Should succeed when Owner removes the MPC Node's associated account (0x00)", async () => {
      expect(await management.mpcNodes(ZeroAddress)).deep.eq(true);

      const tx = management.connect(admin).setMPCNode(ZeroAddress, false);
      await expect(tx)
        .to.emit(management, "UpdatedMPCNode")
        .withArgs(ZeroAddress, false);

      expect(await management.mpcNodes(ZeroAddress)).deep.eq(false);
    });

    it("Should succeed when Owner removes the MPC Node's associated account", async () => {
      expect(await management.mpcNodes(mpcNode1.address)).deep.eq(true);

      const tx = management.connect(admin).setMPCNode(mpcNode1.address, false);
      await expect(tx)
        .to.emit(management, "UpdatedMPCNode")
        .withArgs(mpcNode1.address, false);

      expect(await management.mpcNodes(mpcNode1.address)).deep.eq(false);
    });

    it("Should revert when Owner removes MPC Node's associated account that was unregistered", async () => {
      expect(await management.mpcNodes(mpcNode1.address)).deep.eq(false);

      await expect(
        management.connect(admin).setMPCNode(mpcNode1.address, false),
      ).to.be.revertedWithCustomError(management, "UnregisteredAlready");

      expect(await management.mpcNodes(mpcNode1.address)).deep.eq(false);
    });

    it("Should succeed when Owner removes another MPC Node's associated account", async () => {
      expect(await management.mpcNodes(mpcNode2.address)).deep.eq(true);

      const tx = management.connect(admin).setMPCNode(mpcNode2.address, false);
      await expect(tx)
        .to.emit(management, "UpdatedMPCNode")
        .withArgs(mpcNode2.address, false);

      expect(await management.mpcNodes(mpcNode2.address)).deep.eq(false);
    });
  });

  describe("setPMM() functional testing", async () => {
    it("Should revert when Non-Owner tries to register the PMM", async () => {
      const pmmId = keccak256(toUtf8Bytes("PMM Identification 1"));

      expect(await management.isValidPMM(pmmId)).deep.eq(false);
      expect(
        await management.isValidPMMAccount(pmmId, accounts[0].address),
      ).deep.eq(false);

      await expect(
        management.connect(accounts[0]).setPMM(pmmId, accounts[0].address),
      ).to.be.revertedWithCustomError(management, "OwnableUnauthorizedAccount");

      expect(await management.isValidPMM(pmmId)).deep.eq(false);
      expect(
        await management.isValidPMMAccount(pmmId, accounts[0].address),
      ).deep.eq(false);
    });

    it("Should revert when Owner attemps to register the PMM with its associated account = 0x0", async () => {
      const pmmId = keccak256(toUtf8Bytes("PMM Identification 1"));

      expect(await management.isValidPMM(pmmId)).deep.eq(false);

      await expect(
        management.connect(admin).setPMM(pmmId, ZeroAddress),
      ).to.be.revertedWithCustomError(management, "AddressZero");

      expect(await management.isValidPMM(pmmId)).deep.eq(false);
    });

    it("Should succeed when Owner registers the PMM and its associated account", async () => {
      const pmmId = keccak256(toUtf8Bytes("PMM Identification 1"));

      expect(await management.isValidPMM(pmmId)).deep.eq(false);
      expect(
        await management.isValidPMMAccount(pmmId, accounts[0].address),
      ).deep.eq(false);

      const tx = management.connect(admin).setPMM(pmmId, accounts[0].address);
      await expect(tx).to.emit(management, "UpdatedPMM").withArgs(pmmId, true);
      await expect(tx)
        .to.emit(management, "UpdatedPMMAccount")
        .withArgs(pmmId, accounts[0].address, true);

      expect(await management.isValidPMM(pmmId)).deep.eq(true);
      expect(
        await management.isValidPMMAccount(pmmId, accounts[0].address),
      ).deep.eq(true);
    });

    it("Should succeed when Owner registers another PMM and its associated account", async () => {
      const pmmId = keccak256(toUtf8Bytes("PMM Identification 2"));

      expect(await management.isValidPMM(pmmId)).deep.eq(false);
      expect(
        await management.isValidPMMAccount(pmmId, accounts[2].address),
      ).deep.eq(false);

      const tx = management.connect(admin).setPMM(pmmId, accounts[2].address);
      await expect(tx).to.emit(management, "UpdatedPMM").withArgs(pmmId, true);
      await expect(tx)
        .to.emit(management, "UpdatedPMMAccount")
        .withArgs(pmmId, accounts[2].address, true);

      expect(await management.isValidPMM(pmmId)).deep.eq(true);
      expect(
        await management.isValidPMMAccount(pmmId, accounts[2].address),
      ).deep.eq(true);
    });

    it("Should revert when Owner attempts to register the PMM that was registered", async () => {
      const pmmId = keccak256(toUtf8Bytes("PMM Identification 1"));

      expect(await management.isValidPMM(pmmId)).deep.eq(true);
      const numOfAccounts = await management.numOfPMMAccounts(pmmId);
      expect(numOfAccounts).deep.eq(1);

      await expect(
        management.connect(admin).setPMM(pmmId, accounts[1].address),
      ).to.be.revertedWithCustomError(management, "RegisteredAlready");

      expect(await management.isValidPMM(pmmId)).deep.eq(true);
      expect(await management.numOfPMMAccounts(pmmId)).deep.eq(numOfAccounts);
    });

    it("Should succeed when Owner registers another PMM and its associated account", async () => {
      const pmmId = keccak256(toUtf8Bytes("PMM Identification 3"));

      expect(await management.isValidPMM(pmmId)).deep.eq(false);
      expect(
        await management.isValidPMMAccount(pmmId, accounts[3].address),
      ).deep.eq(false);

      const tx = management.connect(admin).setPMM(pmmId, accounts[3].address);
      await expect(tx).to.emit(management, "UpdatedPMM").withArgs(pmmId, true);
      await expect(tx)
        .to.emit(management, "UpdatedPMMAccount")
        .withArgs(pmmId, accounts[3].address, true);

      expect(await management.isValidPMM(pmmId)).deep.eq(true);
      expect(
        await management.isValidPMMAccount(pmmId, accounts[3].address),
      ).deep.eq(true);
    });
  });

  describe("setPMMAccount() functional testing", async () => {
    it("Should revert when Non-Owner attempts to add a PMM's associated account", async () => {
      const pmmId = keccak256(toUtf8Bytes("PMM Identification 1"));
      const associatedAccount = accounts[1].address;

      expect(
        await management.isValidPMMAccount(pmmId, associatedAccount),
      ).deep.eq(false);
      const numOfAccounts = await management.numOfPMMAccounts(pmmId);

      await expect(
        management
          .connect(accounts[0])
          .setPMMAccount(pmmId, associatedAccount, true),
      ).to.be.revertedWithCustomError(management, "OwnableUnauthorizedAccount");

      expect(
        await management.isValidPMMAccount(pmmId, associatedAccount),
      ).deep.eq(false);
      expect(await management.numOfPMMAccounts(pmmId)).deep.eq(numOfAccounts);
    });

    it("Should revert when Owner attempts to add 0x00 as PMM's associated account", async () => {
      const pmmId = keccak256(toUtf8Bytes("PMM Identification 1"));
      const associatedAccount = ZeroAddress;

      const numOfAccounts = await management.numOfPMMAccounts(pmmId);

      await expect(
        management.connect(admin).setPMMAccount(pmmId, associatedAccount, true),
      ).to.be.revertedWithCustomError(management, "AddressZero");

      expect(await management.numOfPMMAccounts(pmmId)).deep.eq(numOfAccounts);
    });

    it("Should revert when Owner attempts to add an associated account for un-registered PMM", async () => {
      const pmmId = keccak256(toUtf8Bytes("PMM Identification 4"));
      const associatedAccount = accounts[1].address;

      expect(await management.isValidPMM(pmmId)).deep.eq(false);
      expect(
        await management.isValidPMMAccount(pmmId, associatedAccount),
      ).deep.eq(false);
      const numOfAccounts = await management.numOfPMMAccounts(pmmId);
      expect(numOfAccounts).deep.eq(0);

      await expect(
        management.connect(admin).setPMMAccount(pmmId, associatedAccount, true),
      ).to.be.revertedWithCustomError(management, "PMMNotRegistered");

      expect(await management.isValidPMM(pmmId)).deep.eq(false);
      expect(
        await management.isValidPMMAccount(pmmId, associatedAccount),
      ).deep.eq(false);
      expect(await management.numOfPMMAccounts(pmmId)).deep.eq(numOfAccounts);
    });

    it("Should revert when Owner attempts to add an associated account for one PMM, but account already added", async () => {
      const pmmId = keccak256(toUtf8Bytes("PMM Identification 1"));
      const associatedAccount = accounts[0].address;

      expect(
        await management.isValidPMMAccount(pmmId, associatedAccount),
      ).deep.eq(true);
      const numOfAccounts = await management.numOfPMMAccounts(pmmId);

      await expect(
        management.connect(admin).setPMMAccount(pmmId, associatedAccount, true),
      ).to.be.revertedWithCustomError(management, "RegisteredAlready");

      expect(
        await management.isValidPMMAccount(pmmId, associatedAccount),
      ).deep.eq(true);
      expect(await management.numOfPMMAccounts(pmmId)).deep.eq(numOfAccounts);
    });

    it("Should succeed when Owner adds an associated account for one PMM", async () => {
      const pmmId = keccak256(toUtf8Bytes("PMM Identification 1"));
      const associatedAccount = accounts[1].address;

      expect(
        await management.isValidPMMAccount(pmmId, associatedAccount),
      ).deep.eq(false);
      const numOfAccounts = await management.numOfPMMAccounts(pmmId);

      const tx = management
        .connect(admin)
        .setPMMAccount(pmmId, associatedAccount, true);

      await expect(tx)
        .to.emit(management, "UpdatedPMMAccount")
        .withArgs(pmmId, associatedAccount, true);

      expect(
        await management.isValidPMMAccount(pmmId, associatedAccount),
      ).deep.eq(true);
      expect(await management.numOfPMMAccounts(pmmId)).deep.eq(
        numOfAccounts + BigInt(1),
      );
    });

    it("Should revert when Non-Owner attempts to remove one PMM's associated account", async () => {
      const pmmId = keccak256(toUtf8Bytes("PMM Identification 1"));
      const associatedAccount = accounts[0].address;

      expect(
        await management.isValidPMMAccount(pmmId, associatedAccount),
      ).deep.eq(true);
      const numOfAccounts = await management.numOfPMMAccounts(pmmId);

      await expect(
        management
          .connect(accounts[0])
          .setPMMAccount(pmmId, associatedAccount, false),
      ).to.be.revertedWithCustomError(management, "OwnableUnauthorizedAccount");

      expect(
        await management.isValidPMMAccount(pmmId, associatedAccount),
      ).deep.eq(true);
      expect(await management.numOfPMMAccounts(pmmId)).deep.eq(numOfAccounts);
    });

    it("Should revert when Owner attempts to remove associated account for un-registered PMM", async () => {
      const pmmId = keccak256(toUtf8Bytes("PMM Identification 4"));
      const associatedAccount = accounts[1].address;

      expect(await management.isValidPMM(pmmId)).deep.eq(false);
      expect(
        await management.isValidPMMAccount(pmmId, associatedAccount),
      ).deep.eq(false);
      const numOfAccounts = await management.numOfPMMAccounts(pmmId);
      expect(numOfAccounts).deep.eq(0);

      await expect(
        management
          .connect(admin)
          .setPMMAccount(pmmId, associatedAccount, false),
      ).to.be.revertedWithCustomError(management, "PMMNotRegistered");

      expect(await management.isValidPMM(pmmId)).deep.eq(false);
      expect(
        await management.isValidPMMAccount(pmmId, associatedAccount),
      ).deep.eq(false);
      expect(await management.numOfPMMAccounts(pmmId)).deep.eq(numOfAccounts);
    });

    it("Should succeed when Owner removes an associated account for one PMM - PMM still valid after removing", async () => {
      const pmmId = keccak256(toUtf8Bytes("PMM Identification 1"));
      const associatedAccount = accounts[0].address;

      expect(
        await management.isValidPMMAccount(pmmId, associatedAccount),
      ).deep.eq(true);
      const numOfAccounts = await management.numOfPMMAccounts(pmmId);

      const tx = management
        .connect(admin)
        .setPMMAccount(pmmId, associatedAccount, false);

      await expect(tx)
        .to.emit(management, "UpdatedPMMAccount")
        .withArgs(pmmId, associatedAccount, false);

      //  @dev: When removing PMM's associated account, it `numOfAccounts = 0`
      //  `pmmId` will be invalid. However, `numOfAccount = 1`
      //  => pmmId is still valid.
      expect(await management.isValidPMM(pmmId)).deep.eq(true);
      expect(
        await management.isValidPMMAccount(pmmId, associatedAccount),
      ).deep.eq(false);
      expect(await management.numOfPMMAccounts(pmmId)).deep.eq(
        numOfAccounts - BigInt(1),
      );
    });

    it("Should revert when Owner removes an associated account for one PMM, but account already removed", async () => {
      const pmmId = keccak256(toUtf8Bytes("PMM Identification 1"));
      const associatedAccount = accounts[0].address;

      expect(
        await management.isValidPMMAccount(pmmId, associatedAccount),
      ).deep.eq(false);
      const numOfAccounts = await management.numOfPMMAccounts(pmmId);

      await expect(
        management
          .connect(admin)
          .setPMMAccount(pmmId, associatedAccount, false),
      ).to.be.revertedWithCustomError(management, "UnregisteredAlready");

      expect(
        await management.isValidPMMAccount(pmmId, associatedAccount),
      ).deep.eq(false);
      expect(await management.numOfPMMAccounts(pmmId)).deep.eq(numOfAccounts);
    });

    it("Should succeed when Owner removes an associated account for one PMM - PMM invalid after removing", async () => {
      const pmmId = keccak256(toUtf8Bytes("PMM Identification 3"));
      const associatedAccount = accounts[3].address;

      expect(
        await management.isValidPMMAccount(pmmId, associatedAccount),
      ).deep.eq(true);
      const numOfAccounts = await management.numOfPMMAccounts(pmmId);
      expect(numOfAccounts).deep.eq(1);

      const tx = management
        .connect(admin)
        .setPMMAccount(pmmId, associatedAccount, false);

      await expect(tx)
        .to.emit(management, "UpdatedPMMAccount")
        .withArgs(pmmId, associatedAccount, false);

      expect(await management.isValidPMM(pmmId)).deep.eq(false);
      expect(
        await management.isValidPMMAccount(pmmId, associatedAccount),
      ).deep.eq(false);
      expect(await management.numOfPMMAccounts(pmmId)).deep.eq(
        numOfAccounts - BigInt(1),
      );
    });

    it("Should succeed when Owner registers PMM and its associated account after removing accounts", async () => {
      const pmmId = keccak256(toUtf8Bytes("PMM Identification 3"));

      expect(await management.isValidPMM(pmmId)).deep.eq(false);
      expect(
        await management.isValidPMMAccount(pmmId, accounts[3].address),
      ).deep.eq(false);

      const tx = management.connect(admin).setPMM(pmmId, accounts[3].address);
      await expect(tx).to.emit(management, "UpdatedPMM").withArgs(pmmId, true);
      await expect(tx)
        .to.emit(management, "UpdatedPMMAccount")
        .withArgs(pmmId, accounts[3].address, true);

      expect(await management.isValidPMM(pmmId)).deep.eq(true);
      expect(
        await management.isValidPMMAccount(pmmId, accounts[3].address),
      ).deep.eq(true);
    });
  });

  describe("removePMM() functional testing", async () => {
    it("Should revert when Non-Owner attempts to remove one PMM", async () => {
      const pmmId = keccak256(toUtf8Bytes("PMM Identification 1"));

      expect(await management.isValidPMM(pmmId)).deep.eq(true);
      const numOfAccounts = await management.numOfPMMAccounts(pmmId);

      await expect(
        management.connect(accounts[0]).removePMM(pmmId),
      ).to.be.revertedWithCustomError(management, "OwnableUnauthorizedAccount");

      expect(await management.isValidPMM(pmmId)).deep.eq(true);
      expect(await management.numOfPMMAccounts(pmmId)).deep.eq(numOfAccounts);
    });

    it("Should revert when Owner removes un-registered PMM", async () => {
      const pmmId = keccak256(toUtf8Bytes("PMM Identification 4"));

      expect(await management.isValidPMM(pmmId)).deep.eq(false);

      await expect(
        management.connect(admin).removePMM(pmmId),
      ).to.be.revertedWithCustomError(management, "UnregisteredAlready");

      expect(await management.isValidPMM(pmmId)).deep.eq(false);
    });

    it("Should succeed when Owner removes one PMM", async () => {
      const pmmId = keccak256(toUtf8Bytes("PMM Identification 1"));

      expect(await management.isValidPMM(pmmId)).deep.eq(true);
      const numOfAccounts = await management.numOfPMMAccounts(pmmId);

      const tx = management.connect(admin).removePMM(pmmId);

      await expect(tx).to.emit(management, "UpdatedPMM").withArgs(pmmId, false);
      expect(await management.isValidPMM(pmmId)).deep.eq(false);
      expect(await management.numOfPMMAccounts(pmmId)).deep.eq(
        numOfAccounts - numOfAccounts,
      );
    });

    it("Should succeed when Owner removes another PMM", async () => {
      const pmmId = keccak256(toUtf8Bytes("PMM Identification 2"));

      expect(await management.isValidPMM(pmmId)).deep.eq(true);
      const numOfAccounts = await management.numOfPMMAccounts(pmmId);

      const tx = management.connect(admin).removePMM(pmmId);

      await expect(tx).to.emit(management, "UpdatedPMM").withArgs(pmmId, false);
      expect(await management.isValidPMM(pmmId)).deep.eq(false);
      expect(await management.numOfPMMAccounts(pmmId)).deep.eq(
        numOfAccounts - numOfAccounts,
      );
    });

    it("Should succeed when Owner registers PMM and its associated account after removing", async () => {
      const pmmId = keccak256(toUtf8Bytes("PMM Identification 1"));

      expect(await management.isValidPMM(pmmId)).deep.eq(false);
      expect(
        await management.isValidPMMAccount(pmmId, accounts[1].address),
      ).deep.eq(false);

      const tx = management.connect(admin).setPMM(pmmId, accounts[1].address);
      await expect(tx).to.emit(management, "UpdatedPMM").withArgs(pmmId, true);
      await expect(tx)
        .to.emit(management, "UpdatedPMMAccount")
        .withArgs(pmmId, accounts[1].address, true);

      expect(await management.isValidPMM(pmmId)).deep.eq(true);
      expect(
        await management.isValidPMMAccount(pmmId, accounts[1].address),
      ).deep.eq(true);
    });
  });

  describe("setToken() and removeToken() functional testing", async () => {
    it("Should revert when Non-Owner tries to register Token", async () => {
      expect(await management.numOfSupportedTokens()).deep.eq(0);
      expect(await management.isValidNetwork(btcTestnet.info[1])).deep.eq(
        false,
      );
      expect(
        await management.isValidToken(btcTestnet.info[1], btcTestnet.info[0]),
      ).deep.eq(false);

      await expect(
        management.connect(accounts[0]).setToken(btcTestnet),
      ).to.be.revertedWithCustomError(management, "OwnableUnauthorizedAccount");

      expect(await management.numOfSupportedTokens()).deep.eq(0);
      expect(await management.isValidNetwork(btcTestnet.info[1])).deep.eq(
        false,
      );
      expect(
        await management.isValidToken(btcTestnet.info[1], btcTestnet.info[0]),
      ).deep.eq(false);
    });

    it("Should succeed when Owner registers one Token", async () => {
      const numOfSupportedTokens = await management.numOfSupportedTokens();
      expect(await management.isValidNetwork(btcTestnet.info[1])).deep.eq(
        false,
      );
      expect(
        await management.isValidToken(btcTestnet.info[1], btcTestnet.info[0]),
      ).deep.eq(false);

      const tx = management.connect(admin).setToken(btcTestnet);
      await expect(tx)
        .to.emit(management, "UpdatedToken")
        .withArgs(
          hexlify(btcTestnet.info[1]),
          hexlify(btcTestnet.info[0]),
          true,
        );

      expect(await management.numOfSupportedTokens()).deep.eq(
        numOfSupportedTokens + BigInt(1),
      );
      expect(await management.isValidNetwork(btcTestnet.info[1])).deep.eq(true);
      expect(
        await management.isValidToken(btcTestnet.info[1], btcTestnet.info[0]),
      ).deep.eq(true);
    });

    it("Should succeed when Owner registers another Token", async () => {
      const numOfSupportedTokens = await management.numOfSupportedTokens();
      expect(await management.isValidNetwork(ethTestnet.info[1])).deep.eq(
        false,
      );
      expect(
        await management.isValidToken(ethTestnet.info[1], ethTestnet.info[0]),
      ).deep.eq(false);

      const tx = management.connect(admin).setToken(ethTestnet);
      await expect(tx)
        .to.emit(management, "UpdatedToken")
        .withArgs(
          hexlify(ethTestnet.info[1]),
          hexlify(ethTestnet.info[0]),
          true,
        );

      expect(await management.numOfSupportedTokens()).deep.eq(
        numOfSupportedTokens + BigInt(1),
      );
      expect(await management.isValidNetwork(ethTestnet.info[1])).deep.eq(true);
      expect(
        await management.isValidToken(ethTestnet.info[1], ethTestnet.info[0]),
      ).deep.eq(true);
    });

    it("Should succeed when Owner updates TokenInfo of a supported token", async () => {
      const newInfo = structuredClone(btcTestnet);
      newInfo.info[3] = toUtf8Bytes("https://example.com/newlink");

      //  get first tokenInfo => fromIdx = 0, toIdx = 1
      const fromIdx = BigInt(0);
      const toIdx = BigInt(1);

      let firstToken = (await management.getTokens(fromIdx, toIdx))[0];
      const numOfSupportedTokens = await management.numOfSupportedTokens();
      expect(await management.isValidNetwork(btcTestnet.info[1])).deep.eq(true);
      expect(
        await management.isValidToken(btcTestnet.info[1], btcTestnet.info[0]),
      ).deep.eq(true);
      expect(firstToken.info[3]).deep.eq(hexlify(btcTestnet.info[3]));

      await management.connect(admin).setToken(newInfo);

      firstToken = (await management.getTokens(fromIdx, toIdx))[0];
      expect(await management.numOfSupportedTokens()).deep.eq(
        numOfSupportedTokens,
      );
      expect(await management.isValidNetwork(btcTestnet.info[1])).deep.eq(true);
      expect(
        await management.isValidToken(btcTestnet.info[1], btcTestnet.info[0]),
      ).deep.eq(true);
      expect(firstToken.info[3]).deep.eq(hexlify(newInfo.info[3]));
    });

    it("Should revert when Non-Owner tries to remove a registered token", async () => {
      const numOfSupportedTokens = await management.numOfSupportedTokens();
      expect(await management.isValidNetwork(btcTestnet.info[1])).deep.eq(true);
      expect(
        await management.isValidToken(btcTestnet.info[1], btcTestnet.info[0]),
      ).deep.eq(true);

      await expect(
        management
          .connect(accounts[0])
          .removeToken(btcTestnet.info[1], btcTestnet.info[0]),
      ).to.be.revertedWithCustomError(management, "OwnableUnauthorizedAccount");

      expect(await management.numOfSupportedTokens()).deep.eq(
        numOfSupportedTokens,
      );
      expect(await management.isValidNetwork(btcTestnet.info[1])).deep.eq(true);
      expect(
        await management.isValidToken(btcTestnet.info[1], btcTestnet.info[0]),
      ).deep.eq(true);
    });

    it("Should revert when Owner removes a non-supported token", async () => {
      const numOfSupportedTokens = await management.numOfSupportedTokens();
      expect(await management.isValidNetwork(solTestnet.info[1])).deep.eq(
        false,
      );
      expect(
        await management.isValidToken(solTestnet.info[1], solTestnet.info[0]),
      ).deep.eq(false);

      await expect(
        management
          .connect(admin)
          .removeToken(solTestnet.info[1], solTestnet.info[0]),
      ).to.be.revertedWithCustomError(management, "UnregisteredAlready");

      expect(await management.numOfSupportedTokens()).deep.eq(
        numOfSupportedTokens,
      );
      expect(await management.isValidNetwork(solTestnet.info[1])).deep.eq(
        false,
      );
      expect(
        await management.isValidToken(solTestnet.info[1], solTestnet.info[0]),
      ).deep.eq(false);
    });

    it("Should succeed when Owner removes a supported token", async () => {
      const numOfSupportedTokens = await management.numOfSupportedTokens();
      expect(await management.isValidNetwork(btcTestnet.info[1])).deep.eq(true);
      expect(
        await management.isValidToken(btcTestnet.info[1], btcTestnet.info[0]),
      ).deep.eq(true);

      const tx = management
        .connect(admin)
        .removeToken(btcTestnet.info[1], btcTestnet.info[0]);
      await expect(tx)
        .to.emit(management, "UpdatedToken")
        .withArgs(btcTestnet.info[1], btcTestnet.info[0], false);

      expect(await management.numOfSupportedTokens()).deep.eq(
        numOfSupportedTokens - BigInt(1),
      );
      expect(await management.isValidNetwork(btcTestnet.info[1])).deep.eq(
        false,
      );
      expect(
        await management.isValidToken(btcTestnet.info[1], btcTestnet.info[0]),
      ).deep.eq(false);
    });

    it("Should succeed when Owner removes another supported Token", async () => {
      const numOfSupportedTokens = await management.numOfSupportedTokens();
      expect(await management.isValidNetwork(ethTestnet.info[1])).deep.eq(true);
      expect(
        await management.isValidToken(ethTestnet.info[1], ethTestnet.info[0]),
      ).deep.eq(true);

      const tx = management
        .connect(admin)
        .removeToken(ethTestnet.info[1], ethTestnet.info[0]);
      await expect(tx)
        .to.emit(management, "UpdatedToken")
        .withArgs(ethTestnet.info[1], ethTestnet.info[0], false);

      expect(await management.numOfSupportedTokens()).deep.eq(
        numOfSupportedTokens - BigInt(1),
      );
      expect(await management.isValidNetwork(ethTestnet.info[1])).deep.eq(
        false,
      );
      expect(
        await management.isValidToken(ethTestnet.info[1], ethTestnet.info[0]),
      ).deep.eq(false);
    });

    it("Should succeed when Owner registers the token that was removed", async () => {
      const numOfSupportedTokens = await management.numOfSupportedTokens();
      expect(await management.isValidNetwork(btcTestnet.info[1])).deep.eq(
        false,
      );
      expect(
        await management.isValidToken(btcTestnet.info[1], btcTestnet.info[0]),
      ).deep.eq(false);

      const tx = management.connect(admin).setToken(btcTestnet);
      await expect(tx)
        .to.emit(management, "UpdatedToken")
        .withArgs(
          hexlify(btcTestnet.info[1]),
          hexlify(btcTestnet.info[0]),
          true,
        );

      expect(await management.numOfSupportedTokens()).deep.eq(
        numOfSupportedTokens + BigInt(1),
      );
      expect(await management.isValidNetwork(btcTestnet.info[1])).deep.eq(true);
      expect(
        await management.isValidToken(btcTestnet.info[1], btcTestnet.info[0]),
      ).deep.eq(true);
    });
  });

  describe("setMPCInfo() and revokeMPCKey() functional testing", async () => {
    it("Should revert when Non-Owner tries to set MPC's pubkeys info", async () => {
      const networkId = toUtf8Bytes(btcChain);
      const mpcPubkey = hexlify(
        "0x0221ce35ecda1078a291f6a431ad40f5df237d2b46792a4bcf738e1a6ac7442abe",
      );
      const mpcAddress = computeAddress(mpcPubkey);
      mpcInfo = {
        mpcL2Address: mpcAddress,
        expireTime: MAX_UINT64,
        mpcL2Pubkey: mpcPubkey,
        mpcAssetPubkey: mpcPubkey, //  For Bitcoin, `mpcAssetPubkey` = `mpcL2Pubkey`
      };

      expect(await management.isValidPubkey(networkId, mpcPubkey)).deep.eq(
        false,
      );
      expect(await management.getLatestMPCInfo(networkId)).deep.eq(EMPTY_INFO);

      await expect(
        management
          .connect(accounts[0])
          .setMPCInfo(networkId, mpcInfo, prevExpireTime),
      ).to.be.revertedWithCustomError(management, "OwnableUnauthorizedAccount");

      expect(await management.isValidPubkey(networkId, mpcPubkey)).deep.eq(
        false,
      );
      expect(await management.getLatestMPCInfo(networkId)).deep.eq(EMPTY_INFO);
    });

    it("Should succeed when Owner registers MPC's pubkeys info for one networkId", async () => {
      const networkId = toUtf8Bytes(btcChain);
      const mpcPubkey = hexlify(
        "0x0221ce35ecda1078a291f6a431ad40f5df237d2b46792a4bcf738e1a6ac7442abe",
      );
      const mpcAddress = computeAddress(mpcPubkey);
      mpcInfo = {
        mpcL2Address: mpcAddress,
        expireTime: MAX_UINT64,
        mpcL2Pubkey: mpcPubkey,
        mpcAssetPubkey: mpcPubkey, //  For Bitcoin, `mpcAssetPubkey` = `mpcL2Pubkey`
      };

      expect(await management.isValidPubkey(networkId, mpcPubkey)).deep.eq(
        false,
      );
      expect(await management.getLatestMPCInfo(networkId)).deep.eq(EMPTY_INFO);

      const tx = management
        .connect(admin)
        .setMPCInfo(networkId, mpcInfo, prevExpireTime);
      await expect(tx)
        .to.emit(management, "UpdatedMPCInfo")
        .withArgs(
          mpcInfo.mpcL2Address,
          mpcInfo.mpcL2Pubkey,
          mpcInfo.mpcAssetPubkey,
          networkId,
        );

      const expectMPCInfo = [
        mpcInfo.mpcL2Address,
        MAX_UINT64,
        mpcInfo.mpcL2Pubkey,
        mpcInfo.mpcAssetPubkey,
      ];
      expect(await management.isValidPubkey(networkId, mpcPubkey)).deep.eq(
        true,
      );
      expect(await management.getLatestMPCInfo(networkId)).deep.eq(
        expectMPCInfo,
      );
    });

    it("Should revert when Owner updates MPC's pubkey info, but key's expiring time already expired", async () => {
      const block = await provider.getBlockNumber();
      const timestamp = (await provider.getBlock(block))?.timestamp as number;

      const networkId = toUtf8Bytes(btcChain);
      const prevMPCPubkey = hexlify(
        "0x0221ce35ecda1078a291f6a431ad40f5df237d2b46792a4bcf738e1a6ac7442abe",
      );
      const mpcPubkey = hexlify(
        "0x03461f5b1bc170b0562c78754129948a47268f4a2a4feed3f1996909adbe979151",
      );
      const mpcAddress = computeAddress(mpcPubkey);
      mpcInfo = {
        mpcL2Address: mpcAddress,
        expireTime: BigInt(timestamp - 1),
        mpcL2Pubkey: mpcPubkey,
        mpcAssetPubkey: mpcPubkey, //  For Bitcoin, `mpcAssetPubkey` = `mpcL2Pubkey`
      };

      expect(await management.isValidPubkey(networkId, prevMPCPubkey)).deep.eq(
        true,
      );
      expect(await management.isValidPubkey(networkId, mpcPubkey)).deep.eq(
        false,
      );
      const lastInfo = await management.getLatestMPCInfo(networkId);

      await expect(
        management
          .connect(admin)
          .setMPCInfo(networkId, mpcInfo, prevExpireTime),
      ).to.be.revertedWithCustomError(management, "AlreadyExpired");

      expect(await management.isValidPubkey(networkId, prevMPCPubkey)).deep.eq(
        true,
      );
      expect(await management.isValidPubkey(networkId, mpcPubkey)).deep.eq(
        false,
      );
      expect(await management.getLatestMPCInfo(networkId)).deep.eq(lastInfo);
    });

    it("Should succeed when Owner updates MPC's pubkeys info for one networkId", async () => {
      //  @dev: In this scenario, another MPC's pubkeys will be set for `btcChain`
      //  the previous MPC's pubkeys are still valid until `newExpireTime`
      const block = await provider.getBlockNumber();
      const timestamp = (await provider.getBlock(block))?.timestamp as number;
      const newExpireTime = BigInt(timestamp + 60 * 60); //  prepare for another test case

      const networkId = toUtf8Bytes(btcChain);
      const prevMPCPubkey = hexlify(
        "0x0221ce35ecda1078a291f6a431ad40f5df237d2b46792a4bcf738e1a6ac7442abe",
      );
      const prevMPCAddress = computeAddress(prevMPCPubkey);
      const mpcPubkey = hexlify(
        "0x03461f5b1bc170b0562c78754129948a47268f4a2a4feed3f1996909adbe979151",
      );
      const mpcAddress = computeAddress(mpcPubkey);
      mpcInfo = {
        mpcL2Address: mpcAddress,
        expireTime: MAX_UINT64,
        mpcL2Pubkey: mpcPubkey,
        mpcAssetPubkey: mpcPubkey, //  For Bitcoin, `mpcAssetPubkey` = `mpcL2Pubkey`
      };

      expect(await management.isValidPubkey(networkId, prevMPCPubkey)).deep.eq(
        true,
      );
      expect(await management.isValidPubkey(networkId, mpcPubkey)).deep.eq(
        false,
      );
      expect(await management.getLatestMPCInfo(networkId)).deep.eq([
        prevMPCAddress,
        MAX_UINT64,
        prevMPCPubkey,
        prevMPCPubkey,
      ]);

      const tx = management
        .connect(admin)
        .setMPCInfo(networkId, mpcInfo, newExpireTime);
      await expect(tx)
        .to.emit(management, "UpdatedMPCInfo")
        .withArgs(
          mpcInfo.mpcL2Address,
          mpcInfo.mpcL2Pubkey,
          mpcInfo.mpcAssetPubkey,
          networkId,
        );

      const expectMPCInfo = [
        mpcInfo.mpcL2Address,
        MAX_UINT64,
        mpcInfo.mpcL2Pubkey,
        mpcInfo.mpcAssetPubkey,
      ];
      expect(await management.isValidPubkey(networkId, prevMPCPubkey)).deep.eq(
        true,
      );
      expect(await management.isValidPubkey(networkId, mpcPubkey)).deep.eq(
        true,
      );
      expect(await management.getLatestMPCInfo(networkId)).deep.eq(
        expectMPCInfo,
      );
    });

    it("Should revert when Owner registers MPC's pubkey info for non-supported networkId", async () => {
      const networkId = toUtf8Bytes(solChain);
      expect(await management.isValidNetwork(networkId)).deep.eq(false);

      const mpcAssetKP: Keypair = genSolanaKP(getMPCPubkey().slice(0, 64));
      const mpcAssetPubkey: PublicKey = mpcAssetKP.publicKey;
      const mpcPubkey = hexlify(
        "0x0221ce35ecda1078a291f6a431ad40f5df237d2b46792a4bcf738e1a6ac7442abe",
      );
      const mpcAddress = computeAddress(mpcPubkey);
      mpcInfo = {
        mpcL2Address: mpcAddress,
        expireTime: MAX_UINT64,
        mpcL2Pubkey: mpcPubkey,
        mpcAssetPubkey: mpcAssetPubkey.toBytes(), //  For Solana, `mpcAssetPubkey` != `mpcL2Pubkey`
      };

      expect(await management.isValidPubkey(networkId, mpcPubkey)).deep.eq(
        false,
      );
      expect(await management.getLatestMPCInfo(networkId)).deep.eq(EMPTY_INFO);

      await expect(
        management
          .connect(admin)
          .setMPCInfo(networkId, mpcInfo, prevExpireTime),
      ).to.be.revertedWithCustomError(management, "NetworkNotFound");

      expect(await management.isValidPubkey(networkId, mpcPubkey)).deep.eq(
        false,
      );
      expect(await management.getLatestMPCInfo(networkId)).deep.eq(EMPTY_INFO);
    });

    it("Should succeed when Owner registers MPC's pubkeys info for another networkId", async () => {
      //  register `solChain`
      const networkId = toUtf8Bytes(solChain);
      await management.connect(admin).setToken(solTestnet);
      expect(await management.isValidNetwork(networkId)).deep.eq(true);

      const mpcAssetKP: Keypair = genSolanaKP(getMPCPubkey().slice(0, 64));
      const mpcAssetPubkey: PublicKey = mpcAssetKP.publicKey;
      const mpcPubkey = hexlify(
        "0x0221ce35ecda1078a291f6a431ad40f5df237d2b46792a4bcf738e1a6ac7442abe",
      );
      const mpcAddress = computeAddress(mpcPubkey);
      mpcInfo = {
        mpcL2Address: mpcAddress,
        expireTime: MAX_UINT64,
        mpcL2Pubkey: mpcPubkey,
        mpcAssetPubkey: hexlify(mpcAssetPubkey.toBytes()), //  For Solana, `mpcAssetPubkey` != `mpcL2Pubkey`
      };

      expect(await management.isValidPubkey(networkId, mpcPubkey)).deep.eq(
        false,
      );
      expect(await management.getLatestMPCInfo(networkId)).deep.eq(EMPTY_INFO);

      const tx = management
        .connect(admin)
        .setMPCInfo(networkId, mpcInfo, prevExpireTime);
      await expect(tx)
        .to.emit(management, "UpdatedMPCInfo")
        .withArgs(
          mpcInfo.mpcL2Address,
          mpcInfo.mpcL2Pubkey,
          mpcInfo.mpcAssetPubkey,
          networkId,
        );

      const expectMPCInfo = [
        mpcInfo.mpcL2Address,
        MAX_UINT64,
        mpcInfo.mpcL2Pubkey,
        mpcInfo.mpcAssetPubkey,
      ];
      expect(await management.isValidPubkey(networkId, mpcPubkey)).deep.eq(
        true,
      );
      expect(await management.getLatestMPCInfo(networkId)).deep.eq(
        expectMPCInfo,
      );
    });

    it("Should revert when Non-Owner attempts to revoke the MPC's key for a networkId", async () => {
      const networkId = toUtf8Bytes(btcChain);
      const mpcPubkey = hexlify(
        "0x03461f5b1bc170b0562c78754129948a47268f4a2a4feed3f1996909adbe979151",
      );

      expect(await management.isValidPubkey(networkId, mpcPubkey)).deep.eq(
        true,
      );
      const lastInfo = await management.getLatestMPCInfo(networkId);

      await expect(
        management.connect(accounts[0]).revokeMPCKey(networkId, mpcPubkey),
      ).to.be.revertedWithCustomError(management, "OwnableUnauthorizedAccount");

      expect(await management.isValidPubkey(networkId, mpcPubkey)).deep.eq(
        true,
      );
      expect(await management.getLatestMPCInfo(networkId)).deep.eq(lastInfo);
    });

    it("Should revert when Owner attempts to revoke MPC's key for a non-supported networkId", async () => {
      //  @dev: `evmChain` already removed and `pubkey` for that `networkId` not yet registered
      const networkId = toUtf8Bytes(evmChain);
      expect(await management.isValidNetwork(networkId)).deep.eq(false);

      const mpcPubkey = hexlify(
        "0x03461f5b1bc170b0562c78754129948a47268f4a2a4feed3f1996909adbe979151",
      );

      expect(await management.isValidPubkey(networkId, mpcPubkey)).deep.eq(
        false,
      );
      const lastInfo = await management.getLatestMPCInfo(networkId);
      expect(lastInfo).deep.eq(EMPTY_INFO);

      await expect(
        management.connect(admin).revokeMPCKey(networkId, mpcPubkey),
      ).to.be.revertedWithCustomError(management, "InvalidPubkey");

      expect(await management.isValidPubkey(networkId, mpcPubkey)).deep.eq(
        false,
      );
      expect(await management.getLatestMPCInfo(networkId)).deep.eq(lastInfo);
    });

    it("Should revert when Owner attempts to revoke MPC's key for a un-registered key", async () => {
      //  @dev: `btcChain` is registered with MPC's pubkeys
      const networkId = toUtf8Bytes(btcChain);
      expect(await management.isValidNetwork(networkId)).deep.eq(true);

      //  generate a random mpcPubkey
      const mpcPubkey = new Wallet(randomTxId(), provider).signingKey
        .compressedPublicKey;

      expect(await management.isValidPubkey(networkId, mpcPubkey)).deep.eq(
        false,
      );
      const lastInfo = await management.getLatestMPCInfo(networkId);

      await expect(
        management.connect(admin).revokeMPCKey(networkId, mpcPubkey),
      ).to.be.revertedWithCustomError(management, "InvalidPubkey");

      expect(await management.isValidPubkey(networkId, mpcPubkey)).deep.eq(
        false,
      );
      expect(await management.getLatestMPCInfo(networkId)).deep.eq(lastInfo);
    });

    it("Should succeed when Owner revoke the MPC's key for one networkId - Valid Key but not latest", async () => {
      //  @dev: MPC's pubkey already updated by another one, but not yet expired.
      //  revokeMPCKey() will set `expireTime` to 0 to completely deactivate it.
      const networkId = toUtf8Bytes(btcChain);
      const mpcPubkey = hexlify(
        "0x0221ce35ecda1078a291f6a431ad40f5df237d2b46792a4bcf738e1a6ac7442abe",
      );
      expect(await management.isValidPubkey(networkId, mpcPubkey)).deep.eq(
        true,
      );

      expect(
        (await management.getMPCInfo(networkId, mpcPubkey)).expireTime,
      ).greaterThan(0);

      const tx = management.connect(admin).revokeMPCKey(networkId, mpcPubkey);

      await expect(tx)
        .to.emit(management, "RevokedMPCKey")
        .withArgs(networkId, mpcPubkey);

      expect(
        (await management.getMPCInfo(networkId, mpcPubkey)).expireTime,
      ).deep.eq(0);
    });

    it("Should succeed when Owner revoke the latest MPC's key for one networkId", async () => {
      const networkId = toUtf8Bytes(btcChain);
      const mpcPubkey = hexlify(
        "0x03461f5b1bc170b0562c78754129948a47268f4a2a4feed3f1996909adbe979151",
      );
      expect(await management.isValidPubkey(networkId, mpcPubkey)).deep.eq(
        true,
      );
      expect(
        (await management.getLatestMPCInfo(networkId)).mpcAssetPubkey,
      ).deep.eq(mpcPubkey);
      expect(
        (await management.getLatestMPCInfo(networkId)).mpcL2Pubkey,
      ).deep.eq(mpcPubkey);

      expect(
        (await management.getMPCInfo(networkId, mpcPubkey)).expireTime,
      ).greaterThan(0);

      const tx = management.connect(admin).revokeMPCKey(networkId, mpcPubkey);

      await expect(tx)
        .to.emit(management, "RevokedMPCKey")
        .withArgs(networkId, mpcPubkey);

      expect(await management.isValidPubkey(networkId, mpcPubkey)).deep.eq(
        false,
      );
      expect(
        (await management.getMPCInfo(networkId, mpcPubkey)).expireTime,
      ).deep.eq(0);
    });

    it("Should revert when Owner revokes the MPC's key that already revoked", async () => {
      const networkId = toUtf8Bytes(btcChain);
      const mpcPubkey = hexlify(
        "0x03461f5b1bc170b0562c78754129948a47268f4a2a4feed3f1996909adbe979151",
      );

      expect(await management.isValidPubkey(networkId, mpcPubkey)).deep.eq(
        false,
      );
      const lastInfo = await management.getMPCInfo(networkId, mpcPubkey);
      expect(lastInfo.expireTime).deep.eq(0);

      await expect(
        management.connect(admin).revokeMPCKey(networkId, mpcPubkey),
      ).to.be.revertedWithCustomError(management, "MPCKeyAlreadyRevoked");

      expect(await management.isValidPubkey(networkId, mpcPubkey)).deep.eq(
        false,
      );
      expect(await management.getMPCInfo(networkId, mpcPubkey)).deep.eq(
        lastInfo,
      );
    });
  });

  describe("suspend() functional testing", async () => {
    it("Should revert when Non-Owner tries to set suspension", async () => {
      expect(await management.state()).deep.eq(Status.OPERATING);

      await expect(
        management.connect(accounts[0]).suspend(),
      ).to.be.revertedWithCustomError(management, "OwnableUnauthorizedAccount");

      expect(await management.state()).deep.eq(Status.OPERATING);
    });

    it("Should succeed when Owner suspends the protocol", async () => {
      expect(await management.state()).deep.eq(Status.OPERATING);

      const tx = management.connect(admin).suspend();
      await expect(tx).to.emit(management, "Suspended").withArgs(admin.address);

      expect(await management.state()).deep.eq(Status.SUSPENDED);

      //  should also verify `isSuspend()` functional testing
      //  During `Suspension` state:
      //  - `submitTrade`, `confirmDeposit` and `selectPMM` are suspended
      //  - `makePayment`, `confirmPayment` and `confirmSettlement` continue to operate normally
      expect(await management.isSuspended(STAGE.SUBMIT)).deep.eq(true);
      expect(await management.isSuspended(STAGE.CONFIRM_DEPOSIT)).deep.eq(true);
      expect(await management.isSuspended(STAGE.SELECT_PMM)).deep.eq(true);
      expect(await management.isSuspended(STAGE.MAKE_PAYMENT)).deep.eq(false);
      expect(await management.isSuspended(STAGE.CONFIRM_PAYMENT)).deep.eq(
        false,
      );
      expect(await management.isSuspended(STAGE.CONFIRM_SETTLEMENT)).deep.eq(
        false,
      );
    });
  });

  describe("shutdown() functional testing", async () => {
    it("Should revert when Non-Owner tries to set shutdown", async () => {
      expect(await management.state()).deep.eq(Status.SUSPENDED);

      await expect(
        management.connect(accounts[0]).shutdown(),
      ).to.be.revertedWithCustomError(management, "OwnableUnauthorizedAccount");

      expect(await management.state()).deep.eq(Status.SUSPENDED);
    });

    it("Should succeed when Owner shutdowns the protocol", async () => {
      expect(await management.state()).deep.eq(Status.SUSPENDED);

      const tx = management.connect(admin).shutdown();
      await expect(tx).to.emit(management, "Shutdown").withArgs(admin.address);

      expect(await management.state()).deep.eq(Status.SHUTDOWN);

      //  should also verify `isSuspend()` functional testing
      //  During `Shutdown` state:
      //  - `submitTrade`, `confirmDeposit` and `selectPMM` are stopped
      //  - `makePayment`, `confirmPayment` and `confirmSettlement` are also stopped
      expect(await management.isSuspended(STAGE.SUBMIT)).deep.eq(true);
      expect(await management.isSuspended(STAGE.CONFIRM_DEPOSIT)).deep.eq(true);
      expect(await management.isSuspended(STAGE.SELECT_PMM)).deep.eq(true);
      expect(await management.isSuspended(STAGE.MAKE_PAYMENT)).deep.eq(true);
      expect(await management.isSuspended(STAGE.CONFIRM_PAYMENT)).deep.eq(true);
      expect(await management.isSuspended(STAGE.CONFIRM_SETTLEMENT)).deep.eq(
        true,
      );
    });
  });

  describe("resume() functional testing", async () => {
    it("Should revert when Non-Owner tries to resume the Protocol", async () => {
      expect(await management.state()).deep.eq(Status.SHUTDOWN);

      await expect(
        management.connect(accounts[0]).resume(),
      ).to.be.revertedWithCustomError(management, "OwnableUnauthorizedAccount");

      expect(await management.state()).deep.eq(Status.SHUTDOWN);
    });

    it("Should succeed when Owner resumes the protocol", async () => {
      expect(await management.state()).deep.eq(Status.SHUTDOWN);

      const tx = management.connect(admin).resume();
      await expect(tx).to.emit(management, "Resume").withArgs(admin.address);

      expect(await management.state()).deep.eq(Status.OPERATING);

      //  should also verify `isSuspend()` functional testing
      //  During `OPERATING` state:
      //  - `submitTrade`, `confirmDeposit` and `selectPMM` works normally
      //  - `makePayment`, `confirmPayment` and `confirmSettlement` also works normally
      expect(await management.isSuspended(STAGE.SUBMIT)).deep.eq(false);
      expect(await management.isSuspended(STAGE.CONFIRM_DEPOSIT)).deep.eq(
        false,
      );
      expect(await management.isSuspended(STAGE.SELECT_PMM)).deep.eq(false);
      expect(await management.isSuspended(STAGE.MAKE_PAYMENT)).deep.eq(false);
      expect(await management.isSuspended(STAGE.CONFIRM_PAYMENT)).deep.eq(
        false,
      );
      expect(await management.isSuspended(STAGE.CONFIRM_SETTLEMENT)).deep.eq(
        false,
      );
    });
  });
});
