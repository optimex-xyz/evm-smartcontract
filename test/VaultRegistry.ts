import { expect } from "chai";
import { ethers, network } from "hardhat";
import { hexlify, toUtf8Bytes, ZeroAddress } from "ethers";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";

import {
  Management,
  Management__factory,
  VaultRegistry,
  VaultRegistry__factory,
} from "../typechain-types";
import { ITypes } from "../typechain-types/contracts/Management";

describe("VaultRegistry Contract Testing", () => {
  let admin: HardhatEthersSigner;
  let accounts: HardhatEthersSigner[];

  let management: Management, clone: Management;
  let registry: VaultRegistry;

  const pFeeRate: bigint = BigInt(50);
  const evmChain = toUtf8Bytes("base-sepolia");
  const token: ITypes.TokenInfoStruct = {
    info: [
      toUtf8Bytes("native"), // tokenId
      evmChain, // networkId
      toUtf8Bytes("ETH"), // symbol
      toUtf8Bytes("https://example.com"),
      toUtf8Bytes("Ethereum (ETH) - Sepolia Base Token"),
    ],
    decimals: BigInt(18),
  };

  before(async () => {
    await network.provider.request({
      method: "hardhat_reset",
      params: [],
    });

    [admin, ...accounts] = await ethers.getSigners();

    //  Deploy Management contract
    const Management = (await ethers.getContractFactory(
      "Management",
      admin,
    )) as Management__factory;
    management = await Management.deploy(admin.address, pFeeRate);
    clone = await Management.deploy(admin.address, pFeeRate);

    //  Deploy VaultRegistry contract
    const Registry = (await ethers.getContractFactory(
      "VaultRegistry",
      admin,
    )) as VaultRegistry__factory;
    registry = await Registry.deploy(await management.getAddress());

    await management.connect(admin).setToken(token);
  });

  it("Should be able to check the initialized settings of registry contract", async () => {
    expect(await registry.management()).deep.equal(
      await management.getAddress(),
    );
  });

  describe("setManagement() functional testing", async () => {
    it("Should revert when Unauthorized client, a arbitrary account, tries to update new Management contract", async () => {
      expect(await registry.management()).deep.equal(
        await management.getAddress(),
      );

      await expect(
        registry.connect(accounts[0]).setManagement(accounts[0].address),
      ).to.be.revertedWithCustomError(registry, "Unauthorized");

      expect(await registry.management()).deep.equal(
        await management.getAddress(),
      );
    });

    it("Should revert when Owner updates 0x0 as a new address of Management contract", async () => {
      expect(await registry.management()).deep.equal(
        await management.getAddress(),
      );

      await expect(
        registry.connect(admin).setManagement(ZeroAddress),
      ).to.be.revertedWithCustomError(registry, "AddressZero");

      expect(await registry.management()).deep.equal(
        await management.getAddress(),
      );
    });

    it("Should succeed when Owner updates a new address of Management contract", async () => {
      expect(await registry.management()).deep.equal(
        await management.getAddress(),
      );

      await registry.connect(admin).setManagement(await clone.getAddress());

      expect(await registry.management()).deep.equal(await clone.getAddress());
    });

    it("Should succeed when Owner changes back to previous Management contract", async () => {
      expect(await registry.management()).deep.equal(await clone.getAddress());

      await registry
        .connect(admin)
        .setManagement(await management.getAddress());

      expect(await registry.management()).deep.equal(
        await management.getAddress(),
      );
    });
  });

  describe("setVault() functional testing", async () => {
    it("Should revert when Non-Owner tries to set Vault of one token", async () => {
      expect(await registry.getVault(evmChain, token.info[0])).deep.eq(
        ZeroAddress,
      );

      await expect(
        registry
          .connect(accounts[0])
          .setVault(accounts[0].address, evmChain, token.info[0]),
      ).to.be.revertedWithCustomError(registry, "Unauthorized");

      expect(await registry.getVault(evmChain, token.info[0])).deep.eq(
        ZeroAddress,
      );
    });

    it("Should revert when Owner calls to set Vault of one token, but Vault is 0x0", async () => {
      await expect(
        registry.connect(admin).setVault(ZeroAddress, evmChain, token.info[0]),
      ).to.be.revertedWithCustomError(registry, "AddressZero");
    });

    it("Should revert when Owner sets Vault of one token, but token not supported", async () => {
      const invalidTokenId = toUtf8Bytes("Invalid_token_id");
      expect(await registry.getVault(evmChain, invalidTokenId)).deep.eq(
        ZeroAddress,
      );

      await expect(
        registry
          .connect(admin)
          .setVault(accounts[0].address, evmChain, invalidTokenId),
      ).to.be.revertedWithCustomError(registry, "TokenNotSupported");

      expect(await registry.getVault(evmChain, invalidTokenId)).deep.eq(
        ZeroAddress,
      );
    });

    it("Should succeed when Owner calls to set Vault of one chain", async () => {
      const vault = accounts[0].address;
      expect(await registry.getVault(evmChain, token.info[0])).deep.eq(
        ZeroAddress,
      );

      const tx = registry
        .connect(admin)
        .setVault(vault, evmChain, token.info[0]);

      await expect(tx)
        .to.emit(registry, "AssetVaultUpdated")
        .withArgs(
          admin.address,
          ZeroAddress,
          vault,
          hexlify(evmChain),
          hexlify(token.info[0]),
        );

      expect(await registry.getVault(evmChain, token.info[0])).deep.eq(vault);
    });

    it("Should succeed when Owner calls to update Vault of one chain", async () => {
      const previousVault = accounts[0].address;
      const newVault = accounts[1].address;
      expect(await registry.getVault(evmChain, token.info[0])).deep.eq(
        previousVault,
      );

      const tx = registry
        .connect(admin)
        .setVault(newVault, evmChain, token.info[0]);

      await expect(tx)
        .to.emit(registry, "AssetVaultUpdated")
        .withArgs(
          admin.address,
          previousVault,
          newVault,
          hexlify(evmChain),
          hexlify(token.info[0]),
        );

      expect(await registry.getVault(evmChain, token.info[0])).deep.eq(
        newVault,
      );
    });
  });

  describe("removeVault() functional testing", async () => {
    it("Should revert when Non-Owner tries to remove Vault", async () => {
      const currentVault = await registry.getVault(evmChain, token.info[0]);

      await expect(
        registry.connect(accounts[0]).removeVault(evmChain, token.info[0]),
      ).to.be.revertedWithCustomError(registry, "Unauthorized");

      expect(await registry.getVault(evmChain, token.info[0])).deep.eq(
        currentVault,
      );
    });

    it("Should revert when Owner removes non-existed Vault - NetworkId not existed", async () => {
      const invalidNetworkId = toUtf8Bytes("Invalid_network_id");

      await expect(
        registry.connect(admin).removeVault(invalidNetworkId, token.info[0]),
      ).to.be.revertedWithCustomError(registry, "VaultNotFound");
    });

    it("Should revert when Owner removes non-existed Vault - TokenId not existed", async () => {
      const invalidTokenId = toUtf8Bytes("Invalid_token_id");

      await expect(
        registry.connect(admin).removeVault(evmChain, invalidTokenId),
      ).to.be.revertedWithCustomError(registry, "VaultNotFound");
    });

    it("Should succeed when Owner removes Vault", async () => {
      const currentVault = accounts[1].address;
      expect(await registry.getVault(evmChain, token.info[0])).deep.eq(
        currentVault,
      );

      const tx = registry.connect(admin).removeVault(evmChain, token.info[0]);

      await expect(tx)
        .to.emit(registry, "AssetVaultUpdated")
        .withArgs(
          admin.address,
          currentVault,
          ZeroAddress,
          hexlify(evmChain),
          hexlify(token.info[0]),
        );

      expect(await registry.getVault(evmChain, token.info[0])).deep.eq(
        ZeroAddress,
      );
    });
  });
});
