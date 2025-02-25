import { expect } from "chai";
import { ethers, network } from "hardhat";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";
import { ZeroAddress } from "ethers";

import { Protocol, Protocol__factory } from "../../typechain-types";

describe("Protocol Contract Testing", () => {
  let admin: HardhatEthersSigner, accounts: HardhatEthersSigner[];
  let pFeeAddr1: HardhatEthersSigner, pFeeAddr2: HardhatEthersSigner;

  let protocol: Protocol;

  before(async () => {
    await network.provider.request({
      method: "hardhat_reset",
      params: [],
    });

    [admin, pFeeAddr1, pFeeAddr2, ...accounts] = await ethers.getSigners();

    //  Deploy Protocol contract
    const Protocol = (await ethers.getContractFactory(
      "Protocol",
      admin,
    )) as Protocol__factory;
    protocol = await Protocol.deploy(admin.address, pFeeAddr1);
  });

  it("Should be able to check the initialized settings of Protocol contract", async () => {
    expect(await protocol.owner()).deep.equal(admin.address);
    expect(await protocol.pFeeAddr()).deep.equal(pFeeAddr1.address);
  });

  describe("setPFeeAddress() functional testing", async () => {
    it("Should revert when Non-Owner tries to set pFeeAddress", async () => {
      expect(await protocol.pFeeAddr()).deep.equal(pFeeAddr1.address);

      await expect(
        protocol.connect(accounts[0]).setPFeeAddress(accounts[0].address),
      ).to.be.revertedWithCustomError(protocol, "OwnableUnauthorizedAccount");

      expect(await protocol.pFeeAddr()).deep.equal(pFeeAddr1.address);
    });

    it("Should revert when Owner sets 0x0 as pFeeAddress", async () => {
      expect(await protocol.pFeeAddr()).deep.equal(pFeeAddr1.address);

      await expect(
        protocol.connect(admin).setPFeeAddress(ZeroAddress),
      ).to.be.revertedWithCustomError(protocol, "AddressZero");

      expect(await protocol.pFeeAddr()).deep.equal(pFeeAddr1.address);
    });

    it("Should succeed when Owner sets pFeeAddress", async () => {
      expect(await protocol.pFeeAddr()).deep.equal(pFeeAddr1.address);

      const tx = protocol.connect(admin).setPFeeAddress(pFeeAddr2.address);
      await expect(tx)
        .to.emit(protocol, "PFeeAddressUpdated")
        .withArgs(admin.address, pFeeAddr2.address);

      expect(await protocol.pFeeAddr()).deep.equal(pFeeAddr2.address);
    });

    it("Should succeed when Owner sets back to previous pFeeAddress", async () => {
      expect(await protocol.pFeeAddr()).deep.equal(pFeeAddr2.address);

      const tx = protocol.connect(admin).setPFeeAddress(pFeeAddr1.address);
      await expect(tx)
        .to.emit(protocol, "PFeeAddressUpdated")
        .withArgs(admin.address, pFeeAddr1.address);

      expect(await protocol.pFeeAddr()).deep.equal(pFeeAddr1.address);
    });
  });
});
