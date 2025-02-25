// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

/// Authentication Errors
error Unauthorized();

/// Authorization (Signature) Errors
error InvalidPresign();
error InvalidMPCSign();

/// Parameters Errors
error AddressZero();
error InvalidDepositAmount();
error NativeCoinNotMatched();
error InvalidTimeout();
error InvalidPaymentAmount();
error DuplicatedDeposit();
error TradeDetailNotMatched();

/// Timeout Errors
error Timeout();
error ClaimNotAvailable();
error DeadlineExceeded();
