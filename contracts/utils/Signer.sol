// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/***********************************************************************************************************
                          =========== PetaFi ===========
    @title Signer contract                               
    @dev This contract functions as the helper contract within the PetaFi Protocol.
    - Recovers the `signer` of each signature based on its type.
************************************************************************************************************/

contract Signer is EIP712 {
    using ECDSA for bytes32;

    /************************************************************************************************

    _DEPOSIT_CONFIRMATION = keccak256("ConfirmDeposit(bytes32 tradeId,bytes32 infoHash)")

        - infoHash = keccak256(abi.encode(depositHash, depositTxId))
        - depositHash = keccak256(abi.encode(amountIn, fromUser, fromChain, fromToken, depositFromList))

    *************************************************************************************************/
    bytes32 private constant _DEPOSIT_CONFIRMATION =
        0x713a35f0afe60bce1fa69e3c973dd1570d270f1ed93a58eb4e9fa6738d061efb;

    /************************************************************************************************

    _SELECTION = keccak256("Selection(bytes32 tradeId,bytes32 infoHash)")

        - infoHash = keccak256(abi.encode(pmmId, pmmRecvAddr, toChain, toToken, amountOut, expiry))

    *************************************************************************************************/
    bytes32 private constant _SELECTION =
        0x1391abf39f0c135805e524996c345904996b6f28aae73274d15bb75644485eaf;

    /************************************************************************************************

    _RFQ_AUTHENTICATION = keccak256("Authentication(bytes32 tradeId,bytes32 infoHash)")

        - infoHash = keccak256(abi.encode(minAmountOut, tradeTimeout, affiliateInfo))

    *************************************************************************************************/
    bytes32 private constant _RFQ_AUTHENTICATION =
        0xf8cc740ef5291dc502037942be67c8528c9eaddd8872e0695961837dbb91e320;

    /************************************************************************************************

    _MAKE_PAYMENT = keccak256("MakePayment(bytes32 infoHash)")
        
        - infoHash = keccak256(abi.encode(signedAt, startIdx, bundlerHash, paymentTxId))
        - bundlerHash = keccak256(abi.encode(tradeIds))

    *************************************************************************************************/
    bytes32 private constant _MAKE_PAYMENT =
        0x98d28255b6ea627095877d2c50ce87fe98d9957886fcbd34bb3a42a63e7f465d;

    /************************************************************************************************

    _PAYMENT_CONFIRMATION = keccak256("ConfirmPayment(bytes32 tradeId,bytes32 infoHash)")
        - infoHash = keccak256(abi.encode(paymentHash, paymentTxId))

    - BTC -> EVM and BTC -> SOL: totalFee != 0
    - EVM -> BTC and SOL -> BTC: totalFee = 0
        - paymentHash = keccak256(
            abi.encode(totalFee, paymentAmount, toUserAddress, toChain, toToken))

    *************************************************************************************************/
    bytes32 private constant _PAYMENT_CONFIRMATION =
        0x9ac26de0577f54ed5178d21ab09db1bf06ff4d122ff860b5198b43d5fe7c96d0;

    /************************************************************************************************

    _SETTLEMENT_CONFIRMATION = keccak256("ConfirmSettlement(bytes32 tradeId,bytes32 infoHash)")

    - BTC -> EVM and BTC -> SOL: totalFee = 0
    - EVM -> BTC and SOL -> BTC: totalFee != 0
        - infoHash = keccak256(abi.encode(totalFee, releaseTxId))

    *************************************************************************************************/
    bytes32 private constant _SETTLEMENT_CONFIRMATION =
        0x6372c563a871900a9e4754f2f2eb0b45457c6aedaad14fda8e2327cbcf67829a;

    constructor() EIP712("PetaFi", "Version 1") {}

    /**
        @notice Recovers the signer of the deposit confirmation signature
        @param tradeId The unique identifier assigned to a trade.
        @param infoHash The hash representing additional information related to the deposit confirmation.
        @param signature The signature provided by the sender.
        @return signer The address of the signer.
    */
    function getDepositConfirmationSigner(
        bytes32 tradeId,
        bytes32 infoHash,
        bytes calldata signature
    ) external view returns (address signer) {
        signer = _hashTypedDataV4(
            keccak256(abi.encode(_DEPOSIT_CONFIRMATION, tradeId, infoHash))
        ).recover(signature);
    }

    /**
        @notice Recovers the signer of the RFQ (Request for Quote) authentication signature
        @param tradeId The unique identifier assigned to a trade.
        @param infoHash The hash representing additional information related to the RFQ authentication.
        @param signature The signature provided by the sender.
        @return signer The address of the signer.
    */
    function getRFQSigner(
        bytes32 tradeId,
        bytes32 infoHash,
        bytes calldata signature
    ) external view returns (address signer) {
        signer = _hashTypedDataV4(
            keccak256(abi.encode(_RFQ_AUTHENTICATION, tradeId, infoHash))
        ).recover(signature);
    }

    /**
        @notice Recovers the signer of the PMM's selection
        @param tradeId The unique identifier assigned to a trade.
        @param infoHash The hash representing additional information related to the PMM selection.
        @param signature The signature provided by the sender.
        @return signer The address of the signer.
    */
    function getPMMSelectionSigner(
        bytes32 tradeId,
        bytes32 infoHash,
        bytes calldata signature
    ) external view returns (address signer) {
        signer = _hashTypedDataV4(
            keccak256(abi.encode(_SELECTION, tradeId, infoHash))
        ).recover(signature);
    }

    /**
        @notice Recovers the signer of the make payment signature
        @param infoHash The hash representing additional information related to the payment.
        @param signature The signature provided by the sender.
        @return signer The address of the signer.
    */
    function getMakePaymentSigner(
        bytes32 infoHash,
        bytes calldata signature
    ) external view returns (address signer) {
        signer = _hashTypedDataV4(
            keccak256(abi.encode(_MAKE_PAYMENT, infoHash))
        ).recover(signature);
    }

    /**
        @notice Recovers the signer of the payment confirmation signature
        @param tradeId The unique identifier assigned to a trade.
        @param infoHash The hash representing additional information related to the payment confirmation.
        @param signature The signature provided by the sender.
        @return signer The address of the signer.
    */
    function getPaymentConfirmationSigner(
        bytes32 tradeId,
        bytes32 infoHash,
        bytes calldata signature
    ) external view returns (address signer) {
        signer = _hashTypedDataV4(
            keccak256(abi.encode(_PAYMENT_CONFIRMATION, tradeId, infoHash))
        ).recover(signature);
    }

    /**
        @notice Recovers the signer of the settlement confirmation signature
        @param tradeId The unique identifier assigned to a trade.
        @param infoHash The hash representing additional information related to the settlement confirmation.
        @param signature The signature provided by the sender.
        @return signer The address of the signer.
    */
    function getSettlementConfirmationSigner(
        bytes32 tradeId,
        bytes32 infoHash,
        bytes calldata signature
    ) external view returns (address signer) {
        signer = _hashTypedDataV4(
            keccak256(abi.encode(_SETTLEMENT_CONFIRMATION, tradeId, infoHash))
        ).recover(signature);
    }
}
