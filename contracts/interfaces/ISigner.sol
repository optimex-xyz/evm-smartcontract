// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

interface ISigner {
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
        bytes memory signature
    ) external view returns (address signer);

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
    ) external view returns (address signer);

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
    ) external view returns (address signer);

    /**
        @notice Recovers the signer of the make payment signature
        @param infoHash The hash representing additional information related to the payment.
        @param signature The signature provided by the sender.
        @return signer The address of the signer.
    */
    function getMakePaymentSigner(
        bytes32 infoHash,
        bytes calldata signature
    ) external view returns (address signer);

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
    ) external view returns (address signer);

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
    ) external view returns (address signer);
}
