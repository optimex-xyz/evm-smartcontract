// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

/// Authentication Errors
error Unauthorized();

/// Registration Errors
error PMMNotRegistered();
error InvalidMPCAssetPubkey();
error NetworkNotFound();
error RegisteredAlready();
error UnregisteredAlready();
error RouteNotSupported();
error TokenNotSupported();

/// Authorization (Signature) Errors
error InvalidRFQSign();
error InvalidPMMSign();
error InvalidMPCSign();

/// Parameters Errors
error AddressZero();
error InvalidTradeId();
error InvalidTimeout();
error PMMAddrNotMatched();
error InsufficientQuoteAmount();
error InvalidPMMSelection();
error VaultAddrNotMatched();
error RouteNotFound();
error OutOfRange();
error InvalidPaymentIdLength();
error InconsistentPMM();
error InconsistentCoreType();
error BundlePaymentEmpty();
error OutdatedSignature();
error VaultNotFound();
error InvalidPubkey();
error AlreadyExpired();
error MPCKeyAlreadyRevoked();
error ExceededAffiliateFeeLimit();

/// Stage or Timeout Errors
error DeadlineExceeded();
error InvalidProcedureState(uint256 expectedStage, uint256 currentStage);
error SignatureExpired();
error InSuspension();
error UpdateNotAllowed();
