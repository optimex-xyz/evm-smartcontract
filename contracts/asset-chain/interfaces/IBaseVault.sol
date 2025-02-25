// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "../../interfaces/ITypes.sol";

interface IBaseVault {
    struct TradeDetail {
        uint256 amount;
        uint64 timeout; //  a.k.a `scriptTimeout` in the PetaFi Protocol
        address mpc;
        address ephemeralAssetAddress; //  address derived from `ephemeralAssetPubkey`
        address refundAddress;
    }

    struct TradeInput {
        uint256 sessionId;
        address solver;
        ITypes.TradeInfo tradeInfo;
    }

    /**
        @notice Emitted when a depositor successfully deposits the trade funds into the Vault contract.
        @param tradeId The unique identifier of the trade.
        @param depositor The address of the entity depositing the funds.
        @param token The address of the token being deposited.
        @param ephemeralL2Address The address used to sign `rfqInfo` in the PetaFi Protocol.
        @param detail A struct containing the trade details.
        @dev Related function: `deposit()`.
    */
    event Deposited(
        bytes32 indexed tradeId,
        address indexed depositor,
        address indexed token,
        address ephemeralL2Address,
        TradeDetail detail
    );

    /**
        @notice Emitted when the MPC successfully settles the trade.
        @param tradeId The unique identifier of the trade.
        @param token The address of the token used for settlement.
        @param to The recipient address receiving the settled amount.
        @param operator The address of the entity executing the settlement.
        @param settledAmount The amount transferred to the recipient after deducting fees.
        @param pFeeAddress The address receiving the protocol fee.
        @param totalFeeAmount The total fee amount deducted from the settlement.
        @dev Related function: `settlement()`.
    */
    event Settled(
        bytes32 indexed tradeId,
        address indexed token,
        address indexed to,
        address operator,
        uint256 settledAmount,
        address pFeeAddress,
        uint256 totalFeeAmount
    );

    /**
        @notice Emitted when locked funds are successfully transferred back to the `refundAddress`.
        @param tradeId The unique identifier of the trade.
        @param token The address of the token being refunded.
        @param to The recipient address receiving the refunded amount.
        @param operator The address of the entity executing the refund.
        @param amount The amount refunded to the recipient.
        @dev Related function: `claim()`.
    */
    event Claimed(
        bytes32 indexed tradeId,
        address indexed token,
        address indexed to,
        address operator,
        uint256 amount
    );

    /**
        @notice Retrieves the hash of the trade details for a given `tradeId`.
        @param tradeId The unique identifier assigned to a trade.
        @return tradeHash The hash of the `TradeDetail` object associated with the given `tradeId`.
    */
    function getTradeHash(
        bytes32 tradeId
    ) external view returns (bytes32 tradeHash);

    /**
        @notice Transfers the specified `amount` to `toAddress` to finalize the trade identified by `tradeId`.
        @dev Can only be executed if `block.timestamp <= timeout`.
        @param tradeId The unique identifier assigned to a trade.
        @param totalFee The total fee amount deducted from the settlement.
        @param toAddress The address of the selected PMM (`pmmRecvAddress`).
        @param detail The trade details, including relevant trade parameters.
        @param presign The pre-signature signed by `ephemeralAssetAddress`.
        @param mpcSignature The MPC's signature authorizing the settlement.
    */
    function settlement(
        bytes32 tradeId,
        uint256 totalFee,
        address toAddress,
        TradeDetail calldata detail,
        bytes calldata presign,
        bytes calldata mpcSignature
    ) external;

    /**
        @notice Transfers the locked funds to the `refundAddress` for the specified trade.
        @dev Can only be claimed if `block.timestamp > timeout`
        @param tradeId The unique identifier assigned to the trade.
        @param detail The trade details, including relevant trade parameters.
    */
    function claim(bytes32 tradeId, TradeDetail calldata detail) external;
}
