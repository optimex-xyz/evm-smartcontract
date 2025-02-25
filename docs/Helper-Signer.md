#### Overview

The `Signer` contract functions as a helper within the `PetaFi Protocol`, providing utilities for recovering the address of the signer based on distinct message types. Each function is designed to validate and recover signatures for specific transaction actions, ensuring protocol integrity.

#### Key Components and Descriptions

1.  Signature Domain:
    - The contract uses `EIP-712` standard for domain separation in hashing and signing messages, allowing for secure signature verification.
2.  Signatures and Hashes:
    - Utilizes `infoHash` to provide a flexible mechanism for adjusting parameter information.
    - `_DEPOSIT_CONFIRMATION`:
      - Description: Hash identifier for confirming deposits within the protocol.
      - Hashing mechanism:
        - `keccak256("ConfirmDeposit(bytes32 tradeId,bytes32 infoHash)")`
        - `infoHash = keccak256(abi.encode(depositHash, depositTxId))`
    - `_SELECTION`
      - Description: Identifier for the PMM (Post-Match Making) selection action.
      - Hashing mechanism:
        - `keccak256("Selection(bytes32 tradeId,bytes32 infoHash)")`
        - `infoHash = keccak256(abi.encode(pmmId, pmmRecvAddr, toChain, toToken, amountOut, expiry))`
    - `_RFQ_AUTHENTICATION`:
      - Description: Unique identifier for RFQ (Request For Quote) authentication.
      - Hashing mechanism:
        - `keccak256("Authentication(bytes32 tradeId,bytes32 infoHash)")`
        - `infoHash = keccak256(abi.encode(minAmountOut, tradeTimeout, affiliateInfo))`
    - `_MAKE_PAYMENT`:
      - Description: Identifier for making payment announcements within the protocol.
      - Hashing mechanism:
        - `keccak256("MakePayment(bytes32 infoHash)")`
        - `infoHash = keccak256(abi.encode(signedAt, startIdx, bundlerHash, paymentTxId))`
        - `bundlerHash = keccak256(abi.encode(tradeIds))`
    - `_PAYMENT_CONFIRMATION`:
      - Description: Identifier for confirming payment actions.
      - Hashing mechanism:
        - `keccak256("ConfirmPayment(bytes32 tradeId,bytes32 infoHash)")`
        - `infoHash = keccak256(abi.encode(paymentHash, paymentTxId))`
        - `paymentHash = keccak256(abi.encode(totalFee, paymentAmount, toUserAddress, toChain, toToken))`
        - Note: The total fee amount is charged on the EVM-compatible or Solana network side.
          - For BTC->EVM and BTC->SOL: The total fee is paid by the selected PMM, so `totalFee != 0` when the MPC confirms payment.
          - For EVM->BTC and SOL->BTC: The total fee is charged when the MPC settles the trade, meaning `totalFee = 0` at this stage.
    - `_SETTLEMENT_CONFIRMATION`:
      - Description: Used for settlement confirmation signature recovery.
      - Hashing mechanism:
        - `keccak256("ConfirmSettlement(bytes32 tradeId,bytes32 infoHash)")`
        - `infoHash = keccak256(abi.encode(totalFee, releaseTxId))`
        - Note: The total fee amount is charged on the EVM-compatible or Solana network side.
          - For BTC->EVM and BTC->SOL: The total fee is paid and confirmed by the MPC at the previous stage, so `totalFee = 0` at this stage.
          - For EVM->BTC and SOL->BTC: The total fee is charged when the MPC settles the trade, so `totalFee != 0` at this stage.

#### Functions Documentation

1.  `function getDepositConfirmationSigner(bytes32 tradeId, bytes32 infoHash, bytes signature)`
    - Purpose: Recovers the signer address for a deposit confirmation message.
    - Parameters:
      - `tradeId` (bytes32):
        - Description: The trade identifier.
        - Type: `bytes32`
      - `infoHash` (bytes32):
        - Description: Hash containing transaction details.
        - Type: `bytes32`
      - `signature`: - Description: Signature to recover the `signer` from. - Type: `bytes`
    - Returns: Address of the `signer`.
2.  `function getRFQSigner(bytes32 tradeId, bytes32 infoHash, bytes signature)`
    - Purpose: Recovers the signer address for RFQ authentication.
    - Parameters:
      - `tradeId` (bytes32):
        - Description: Trade identifier for the RFQ.
        - Type: `bytes32`
      - `infoHash` (bytes32):
        - Description: Encodes `minAmountOut` and `tradeTimeout`.
        - Type: `bytes32`
      - `signature`
        - Description: The signature for authentication.
        - Type: `bytes`
    - Returns: Address of the `signer`.
3.  `function getPMMSelectionSigner(bytes32 tradeId, bytes32 infoHash, bytes signature)`
    - Purpose: Recovers the signer for PMM selection messages.
    - Parameters:
      - `tradeId`:
        - Description: Trade identifier.
        - Type: `bytes32`
      - `infoHash`:
        - Description: Encodes selection details.
        - Type: `bytes32`
      - `signature`:
        - Description: Signature to recover the signer.
        - Type: `bytes`
    - Returns: Address of the `signer`.
4.  `function getMakePaymentSigner(bytes32 infoHash, bytes signature)`
    - Purpose: Retrieves the signer for a payment announcement message.
    - Parameters:
      - `infoHash`:
        - Description: Encodes transaction details, including the transaction ID, bundler hash, and trade identifiers.
        - Type: `bytes32`
      - `signature`:
        - Description: Signature for recovery.
        - Type: `bytes`
    - Returns: Address of the `signer`.
5.  `function getPaymentConfirmationSigner(bytes32 tradeId, bytes32 infoHash, bytes signature)`
    - Purpose: Recovers signer for payment confirmation messages.
    - Parameters:
      - `tradeId`:
        - Description: Trade identifier.
        - Type: `bytes32`
      - `infoHash`:
        - Description: Encodes paymentHash and paymentTxId.
        - Type: `bytes32`
      - `signature`:
        - Description: Signature to recover the signer.
        - Type: `bytes32`
    - Returns: Address of the `signer`.
6.  `function getSettlementConfirmationSigner(bytes32 tradeId, bytes32 infoHash, bytes signature)`
    - Purpose: Retrieves the signer for settlement confirmation messages.
    - Parameters:
      - `tradeId`:
        - Description: Trade identifier.
        - Type: `bytes32`
      - `infoHash`:
        - Description: Encodes transaction release details.
        - Type: `bytes32`
      - `signature`:
        - Description: Signature to verify.
        - Type: `bytes`
    - Returns: Address of the `signer`.
