import { expect } from "chai";
import { ethers, network } from "hardhat";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";
import {
  keccak256,
  parseEther,
  parseUnits,
  toUtf8Bytes,
  ZeroAddress,
} from "ethers";

import {
  Protocol,
  Protocol__factory,
  Payment,
  Payment__factory,
  Token20,
  Token20__factory,
} from "../../typechain-types";

const provider = ethers.provider;

describe("Payment Contract Testing", () => {
  let admin: HardhatEthersSigner, accounts: HardhatEthersSigner[];
  let pFeeAddr1: HardhatEthersSigner, pFeeAddr2: HardhatEthersSigner;

  let protocol: Protocol, clone: Protocol;
  let payment: Payment, weth: Token20;

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
    clone = await Protocol.deploy(admin.address, pFeeAddr1);

    //  Deploy Payment contract
    const Payment = (await ethers.getContractFactory(
      "Payment",
      admin,
    )) as Payment__factory;
    payment = await Payment.deploy(await protocol.getAddress());

    //  Deploy `WETH` contract
    const WETH = (await ethers.getContractFactory(
      "Token20",
      admin,
    )) as Token20__factory;
    weth = await WETH.deploy("Wrapped ETH", "WETH");
  });

  it("Should be able to check the initialized settings of Payment contract", async () => {
    expect(await payment.protocol()).deep.equal(await protocol.getAddress());
  });

  describe("setProtocol() functional testing", async () => {
    it("Should revert when Non-Owner tries to set new Protocol contract", async () => {
      expect(await payment.protocol()).deep.equal(await protocol.getAddress());

      await expect(
        payment.connect(accounts[0]).setProtocol(accounts[0].address),
      ).to.be.revertedWithCustomError(payment, "Unauthorized");

      expect(await payment.protocol()).deep.equal(await protocol.getAddress());
    });

    it("Should revert when Owner sets 0x0 as Protocol contract", async () => {
      expect(await payment.protocol()).deep.equal(await protocol.getAddress());

      await expect(
        payment.connect(admin).setProtocol(ZeroAddress),
      ).to.be.revertedWithCustomError(protocol, "AddressZero");

      expect(await payment.protocol()).deep.equal(await protocol.getAddress());
    });

    it("Should succeed when Owner sets new Protocol contract", async () => {
      expect(await payment.protocol()).deep.equal(await protocol.getAddress());

      const newProtocol = await clone.getAddress();
      const tx = payment.connect(admin).setProtocol(newProtocol);
      await expect(tx)
        .to.emit(payment, "ProtocolUpdated")
        .withArgs(admin.address, newProtocol);

      expect(await payment.protocol()).deep.equal(newProtocol);
    });

    it("Should succeed when Owner sets back to previous Protocol contract", async () => {
      const currentProtocol = await clone.getAddress();
      const prevProtocol = await protocol.getAddress();

      expect(await payment.protocol()).deep.equal(currentProtocol);

      const tx = payment.connect(admin).setProtocol(prevProtocol);
      await expect(tx)
        .to.emit(payment, "ProtocolUpdated")
        .withArgs(admin.address, prevProtocol);

      expect(await payment.protocol()).deep.equal(prevProtocol);
    });
  });

  describe("Transfer native coin directly to contract", async () => {
    it("Should revert when Account transfers native coins to the Payment contract", async () => {
      const balance = await provider.getBalance(await payment.getAddress());

      await expect(
        admin.sendTransaction({
          to: await payment.getAddress(),
          value: parseEther("5.0"),
        }),
      ).to.be.revertedWithoutReason();

      expect(await provider.getBalance(await payment.getAddress())).deep.eq(
        balance,
      );
    });
  });

  describe("payment() functional testing", async () => {
    it("Should revert when Account makes a payment, but deadline is exceeded - Native coin", async () => {
      const balance = await provider.getBalance(accounts[5].address);
      const block = await provider.getBlockNumber();
      const timestamp = (await provider.getBlock(block))?.timestamp as number;
      const invalidDeadline = Number(timestamp) - 1;
      const deadline: bigint = BigInt(invalidDeadline); //  exceed deadline

      const tradeId = keccak256(toUtf8Bytes("first_tradeId"));
      const toUser = accounts[5].address;
      const amount = parseUnits("100", "ether");
      const totalFee = parseUnits("0.5", "ether");

      await expect(
        payment
          .connect(accounts[0])
          .payment(tradeId, ZeroAddress, toUser, amount, totalFee, deadline, {
            value: amount,
          }),
      ).to.be.revertedWithCustomError(payment, "DeadlineExceeded");

      expect(await provider.getBalance(accounts[5].address)).deep.eq(balance);
    });

    it("Should revert when Account makes a payment, but deadline is exceeded - ERC20", async () => {
      const fromBalance = await weth.balanceOf(accounts[0].address);
      const toBalance = await weth.balanceOf(accounts[5].address);
      const block = await provider.getBlockNumber();
      const timestamp = (await provider.getBlock(block))?.timestamp as number;
      const invalidDeadline = Number(timestamp) - 1;
      const deadline: bigint = BigInt(invalidDeadline); //  exceed deadline

      const tradeId = keccak256(toUtf8Bytes("first_tradeId"));
      const toUser = accounts[5].address;
      const token = await weth.getAddress();
      const amount = parseUnits("100", "ether");
      const totalFee = parseUnits("0.5", "ether");

      await expect(
        payment
          .connect(accounts[0])
          .payment(tradeId, token, toUser, amount, totalFee, deadline),
      ).to.be.revertedWithCustomError(payment, "DeadlineExceeded");

      expect(await weth.balanceOf(accounts[0].address)).deep.eq(fromBalance);
      expect(await weth.balanceOf(accounts[5].address)).deep.eq(toBalance);
    });

    it("Should revert when Account makes a payment, but amount is zero - Native coin", async () => {
      const balance = await provider.getBalance(accounts[5].address);
      const deadline: bigint = BigInt(Math.floor(Date.now() / 1000) + 15 * 60); //  deadline = 15mins

      const tradeId = keccak256(toUtf8Bytes("first_tradeId"));
      const toUser = accounts[5].address;
      const amount = BigInt(0);
      const totalFee = BigInt(0);

      await expect(
        payment
          .connect(accounts[0])
          .payment(tradeId, ZeroAddress, toUser, amount, totalFee, deadline, {
            value: amount,
          }),
      ).to.be.revertedWithCustomError(payment, "InvalidPaymentAmount");

      expect(await provider.getBalance(accounts[5].address)).deep.eq(balance);
    });

    it("Should revert when Account makes a payment, but amount is zero - ERC20", async () => {
      const fromBalance = await weth.balanceOf(accounts[0].address);
      const toBalance = await weth.balanceOf(accounts[5].address);
      const deadline: bigint = BigInt(Math.floor(Date.now() / 1000) + 15 * 60); //  deadline = 15mins

      const tradeId = keccak256(toUtf8Bytes("first_tradeId"));
      const toUser = accounts[5].address;
      const token = await weth.getAddress();
      const amount = BigInt(0);
      const totalFee = BigInt(0);

      await expect(
        payment
          .connect(accounts[0])
          .payment(tradeId, token, toUser, amount, totalFee, deadline),
      ).to.be.revertedWithCustomError(payment, "InvalidPaymentAmount");

      expect(await weth.balanceOf(accounts[0].address)).deep.eq(fromBalance);
      expect(await weth.balanceOf(accounts[5].address)).deep.eq(toBalance);
    });

    it("Should revert when Account makes a payment, but amount <= totalFee - Native coin", async () => {
      const balance = await provider.getBalance(accounts[5].address);
      const deadline: bigint = BigInt(Math.floor(Date.now() / 1000) + 15 * 60); //  deadline = 15mins

      const tradeId = keccak256(toUtf8Bytes("first_tradeId"));
      const toUser = accounts[5].address;
      const totalFee = parseUnits("0.5", "ether");
      const amount = totalFee - BigInt(1);

      await expect(
        payment
          .connect(accounts[0])
          .payment(tradeId, ZeroAddress, toUser, amount, totalFee, deadline, {
            value: amount,
          }),
      ).to.be.revertedWithCustomError(payment, "InvalidPaymentAmount");

      expect(await provider.getBalance(accounts[5].address)).deep.eq(balance);
    });

    it("Should revert when Account makes a payment, but amount <= totalFee - ERC20", async () => {
      const fromBalance = await weth.balanceOf(accounts[0].address);
      const toBalance = await weth.balanceOf(accounts[5].address);
      const deadline: bigint = BigInt(Math.floor(Date.now() / 1000) + 15 * 60); //  deadline = 15mins

      const tradeId = keccak256(toUtf8Bytes("first_tradeId"));
      const toUser = accounts[5].address;
      const token = await weth.getAddress();
      const totalFee = parseUnits("0.5", "ether");
      const amount = totalFee - BigInt(1);

      await expect(
        payment
          .connect(accounts[0])
          .payment(tradeId, token, toUser, amount, totalFee, deadline),
      ).to.be.revertedWithCustomError(payment, "InvalidPaymentAmount");

      expect(await weth.balanceOf(accounts[0].address)).deep.eq(fromBalance);
      expect(await weth.balanceOf(accounts[5].address)).deep.eq(toBalance);
    });

    it("Should revert when Account makes a payment with un-matching msg.value and amount - Native coin", async () => {
      const balance = await provider.getBalance(accounts[5].address);
      const deadline: bigint = BigInt(Math.floor(Date.now() / 1000) + 15 * 60); //  deadline = 15mins

      const tradeId = keccak256(toUtf8Bytes("first_tradeId"));
      const toUser = accounts[5].address;
      const amount = parseUnits("100", "ether");
      const totalFee = parseUnits("0.5", "ether");

      await expect(
        payment
          .connect(accounts[0])
          .payment(tradeId, ZeroAddress, toUser, amount, totalFee, deadline, {
            value: amount - BigInt(1),
          }),
      ).to.be.revertedWithCustomError(payment, "NativeCoinNotMatched");

      expect(await provider.getBalance(accounts[5].address)).deep.eq(balance);
    });

    it("Should revert when Account makes a payment, but toUser = 0x0 - Native coin", async () => {
      const tradeId = keccak256(toUtf8Bytes("first_tradeId"));
      const amount = parseUnits("100", "ether");
      const totalFee = parseUnits("0.5", "ether");
      const deadline: bigint = BigInt(Math.floor(Date.now() / 1000) + 15 * 60); //  deadline = 15mins

      await expect(
        payment
          .connect(accounts[0])
          .payment(
            tradeId,
            ZeroAddress,
            ZeroAddress,
            amount,
            totalFee,
            deadline,
            {
              value: amount,
            },
          ),
      ).to.be.revertedWithCustomError(payment, "AddressZero");
    });

    it("Should revert when Account makes a payment, but toUser = 0x0 - ERC20", async () => {
      const balance = await weth.balanceOf(accounts[0].address);
      const deadline: bigint = BigInt(Math.floor(Date.now() / 1000) + 15 * 60); //  deadline = 15mins

      const tradeId = keccak256(toUtf8Bytes("first_tradeId"));
      const token = await weth.getAddress();
      const amount = parseUnits("100", "ether");
      const totalFee = parseUnits("0.5", "ether");

      await expect(
        payment
          .connect(accounts[0])
          .payment(tradeId, token, ZeroAddress, amount, totalFee, deadline),
      ).to.be.revertedWithCustomError(payment, "AddressZero");

      expect(await weth.balanceOf(accounts[0].address)).deep.eq(balance);
    });

    it("Should revert when Account makes a payment, but insufficient allowance - ERC20", async () => {
      const fromBalance = await weth.balanceOf(accounts[0].address);
      const toBalance = await weth.balanceOf(accounts[5].address);
      const deadline: bigint = BigInt(Math.floor(Date.now() / 1000) + 15 * 60); //  deadline = 15mins

      const tradeId = keccak256(toUtf8Bytes("first_tradeId"));
      const toUser = accounts[5].address;
      const token = await weth.getAddress();
      const amount = parseUnits("100", "ether");
      const totalFee = parseUnits("0.5", "ether");

      await expect(
        payment
          .connect(accounts[0])
          .payment(tradeId, token, toUser, amount, totalFee, deadline),
      ).to.be.revertedWithCustomError(weth, "ERC20InsufficientAllowance");

      expect(await weth.balanceOf(accounts[0].address)).deep.eq(fromBalance);
      expect(await weth.balanceOf(accounts[5].address)).deep.eq(toBalance);
    });

    it("Should revert when Account makes a payment, but insufficient balance - ERC20", async () => {
      const fromBalance = await weth.balanceOf(accounts[0].address);
      const toBalance = await weth.balanceOf(accounts[5].address);
      const deadline: bigint = BigInt(Math.floor(Date.now() / 1000) + 15 * 60); //  deadline = 15mins

      const tradeId = keccak256(toUtf8Bytes("first_tradeId"));
      const toUser = accounts[5].address;
      const token = await weth.getAddress();
      const amount = parseUnits("100", "ether");
      const totalFee = parseUnits("0.5", "ether");

      //  approve an allowance
      await weth
        .connect(accounts[0])
        .approve(await payment.getAddress(), amount);

      await expect(
        payment
          .connect(accounts[0])
          .payment(tradeId, token, toUser, amount, totalFee, deadline),
      ).to.be.revertedWithCustomError(weth, "ERC20InsufficientBalance");

      expect(await weth.balanceOf(accounts[0].address)).deep.eq(fromBalance);
      expect(await weth.balanceOf(accounts[5].address)).deep.eq(toBalance);
    });

    it("Should succeed when Account makes a payment - Native coin", async () => {
      const tradeId = keccak256(toUtf8Bytes("first_tradeId"));
      const toUser = accounts[5].address;
      const amount = parseUnits("100", "ether");
      const totalFee = parseUnits("0.5", "ether");
      const deadline: bigint = BigInt(Math.floor(Date.now() / 1000) + 15 * 60); //  deadline = 15mins

      const tx = payment
        .connect(accounts[0])
        .payment(tradeId, ZeroAddress, toUser, amount, totalFee, deadline, {
          value: amount,
        });

      await expect(tx)
        .to.emit(payment, "PaymentTransferred")
        .withArgs(
          tradeId,
          accounts[0].address,
          toUser,
          pFeeAddr1,
          ZeroAddress,
          amount - totalFee,
          totalFee,
        );
      await expect(tx).changeEtherBalances(
        [accounts[0].address, toUser, pFeeAddr1],
        [-amount, amount - totalFee, totalFee],
      );
    });

    it("Should succeed when Account makes a payment - ERC20", async () => {
      const tradeId = keccak256(toUtf8Bytes("second_tradeId"));
      const toUser = accounts[5].address;
      const token = await weth.getAddress();
      const amount = parseUnits("500", "ether");
      const totalFee = parseUnits("2.5", "ether");
      const deadline: bigint = BigInt(Math.floor(Date.now() / 1000) + 15 * 60); //  deadline = 15mins

      //  mint amount to `accounts[0]`, and set allowance
      await weth.connect(admin).mint(accounts[0].address, amount);
      await weth
        .connect(accounts[0])
        .approve(await payment.getAddress(), amount);

      const tx = payment
        .connect(accounts[0])
        .payment(tradeId, token, toUser, amount, totalFee, deadline);

      await expect(tx)
        .to.emit(payment, "PaymentTransferred")
        .withArgs(
          tradeId,
          accounts[0].address,
          toUser,
          pFeeAddr1,
          token,
          amount - totalFee,
          totalFee,
        );
      await expect(tx).changeTokenBalances(
        weth,
        [accounts[0].address, toUser, pFeeAddr1],
        [-amount, amount - totalFee, totalFee],
      );
    });

    it("Should succeed when Account makes a payment with totalFee = 0 - Native coin", async () => {
      const tradeId = keccak256(toUtf8Bytes("3rd_tradeId"));
      const toUser = accounts[5].address;
      const amount = parseUnits("100", "ether");
      const totalFee = BigInt(0);
      const deadline: bigint = BigInt(Math.floor(Date.now() / 1000) + 15 * 60); //  deadline = 15mins

      const tx = payment
        .connect(accounts[0])
        .payment(tradeId, ZeroAddress, toUser, amount, totalFee, deadline, {
          value: amount,
        });

      await expect(tx)
        .to.emit(payment, "PaymentTransferred")
        .withArgs(
          tradeId,
          accounts[0].address,
          toUser,
          pFeeAddr1,
          ZeroAddress,
          amount - totalFee,
          totalFee,
        );
      await expect(tx).changeEtherBalances(
        [accounts[0].address, toUser, pFeeAddr1],
        [-amount, amount - totalFee, totalFee],
      );
    });

    it("Should succeed when Account makes a payment with totalFee = 0 - ERC20", async () => {
      const tradeId = keccak256(toUtf8Bytes("4th_tradeId"));
      const toUser = accounts[5].address;
      const token = await weth.getAddress();
      const amount = parseUnits("500", "ether");
      const totalFee = BigInt(0);
      const deadline: bigint = BigInt(Math.floor(Date.now() / 1000) + 15 * 60); //  deadline = 15mins

      //  mint amount to `accounts[0]`, and set allowance
      await weth.connect(admin).mint(accounts[0].address, amount);
      await weth
        .connect(accounts[0])
        .approve(await payment.getAddress(), amount);

      const tx = payment
        .connect(accounts[0])
        .payment(tradeId, token, toUser, amount, totalFee, deadline);

      await expect(tx)
        .to.emit(payment, "PaymentTransferred")
        .withArgs(
          tradeId,
          accounts[0].address,
          toUser,
          pFeeAddr1,
          token,
          amount - totalFee,
          totalFee,
        );
      await expect(tx).changeTokenBalances(
        weth,
        [accounts[0].address, toUser, pFeeAddr1],
        [-amount, amount - totalFee, totalFee],
      );
    });
  });
});
