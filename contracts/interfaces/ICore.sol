// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "../interfaces/ITypes.sol";

interface ICore is ITypes {
    /** 
        @notice Retrieve the maximum allowable affiliate fee rate, expressed in basis points (bps)
        @dev This value defines an upper limit on the affiliate fee rate that can be applied to a trade,
            preventing excessive affiliate fees
        @return The maximum affiliate fee rate as a `uint256`.
    */
    function maxAffiliateFeeRate() external view returns (uint256);

    /** 
        @notice Retrieve the type of `Core Handler` contract.
        @dev This function returns a string that indicates the type of the contract 
            providing clarity on the contract's role. It is an abstract function
            that should be implemented in derived contracts to specify the handler type.
        @return A string representing the type of Core Handler, e.g., `BTCEVM`, `EVMBTC`.
    */
    function typeOfHandler() external view returns (string memory);

    /** 
        @notice Query the current stage of the trade identified by `tradeId`.
        @dev This function retrieves the current stage of the specified trade from the 
            `_currentStages` mapping. It helps track the trade's progress and ensures 
            that it proceeds through the correct stages sequentially.
        @param tradeId The unique ID assigned to one trade.
        @return The current stage of the trade, represented as an integer.
    */
    function currentStage(bytes32 tradeId) external view returns (uint256);

    /** 
        @notice Query the most recent timestamp when the `paymentTxId` was signed 
            for the trade identified by `tradeId`.
        @dev This function retrieves the timestamp of when the payment transaction ID 
            was last signed, allowing to track replacement for the specified trade.
            It is useful for ensuring timely updates and preventing unexpected replacement.
        @param tradeId The unique ID assigned to one trade.
        @return The most recent timestamp when the `paymentTxId` was signed.
    */
    function lastSignedPayment(bytes32 tradeId) external view returns (uint64);

    /** 
        @notice Retrieves the FeeDetails struct associated with the specified `tradeId`.
        @dev Returns detailed fee information, including protocol and affiliate fee rates and amounts, for a given trade.
        @param tradeId The unique identifier assigned to one trade.
        @return The FeeDetails struct containing the trade's fee breakdown.
    */
    function feeDetails(
        bytes32 tradeId
    ) external view returns (FeeDetails memory);

    /** 
        @notice Retrieves the Affiliate struct associated with the specified `tradeId`.
        @dev Provides affiliate information, including the aggregated affiliate fee rate and other relevant details.
        @param tradeId The unique identifier assigned to one trade.
        @return The Affiliate struct containing the trade's affiliate details.
    */
    function affiliate(
        bytes32 tradeId
    ) external view returns (Affiliate memory);

    /** 
        @notice Query the TradeData struct associated with the specified `tradeId`.
        @dev This function returns the data associated with the given `tradeId`. 
        @param tradeId The unique identifier assigned to one trade.
        @return The TradeData struct containing detailed trade information.
    */
    function trade(bytes32 tradeId) external view returns (TradeData memory);

    /** 
        @notice Query the list of Presign submissions for the specified `tradeId`.
        @dev This function returns an array of presignatures' info associated with the given `tradeId`.
        @param tradeId The unique identifier assigned to one trade.
        @return An array of Presign structs.
    */
    function presign(bytes32 tradeId) external view returns (Presign[] memory);

    /** 
        @notice Query the confirmed list of deposited addresses associated with the specified `tradeId`.
        @dev This function returns a list of addresses that have been confirmed as deposited 
            for a specific trade.
        @param tradeId The unique identifier assigned to one trade.
        @return An array of addresses that have been confirmed as deposited for the trade.
    */
    function depositAddressList(
        bytes32 tradeId
    ) external view returns (bytes[] memory);

    /** 
        @notice Query the SettledPayment struct associated with the specified `tradeId`.
        @dev This function returns the details of the settled payment for a specific trade. 
        @param tradeId The unique identifier assigned to one trade.
        @return The settled payment details for the trade.
    */
    function settledPayment(
        bytes32 tradeId
    ) external view returns (SettledPayment memory);

    /** 
        @notice Query the PMMSelection struct associated with the specified `tradeId`.
        @dev This function returns the selected PMM's selection proof, including 
            the RFQ information, for the trade. 
        @param tradeId The unique identifier assigned to one trade.
        @return The struct containing the PMM selection information for the trade.
    */
    function pmmSelection(
        bytes32 tradeId
    ) external view returns (PMMSelection memory);

    /** 
        @notice Submits trade data, affiliate information and presigns.
        @dev Caller must be the `Router` contract, and the `requester` has the `Solver` role.
        @param requester The Solver's address submitting the trade information.
        @param tradeId The unique identifier assigned to the trade.
        @param tradeData The trade data, including relevant information such as trade details, involved networks, and amounts.
        @param affiliateInfo A struct containing affiliate details.
        @param presignList The presign information, involved in the trade, supporting the settlement.
    */
    function submitTrade(
        address requester,
        bytes32 tradeId,
        TradeData calldata tradeData,
        Affiliate calldata affiliateInfo,
        Presign[] calldata presignList
    ) external;

    /** 
        @notice Submit the deposit confirmation.
        @dev Caller must be the `Router` contract, and the `requester` must be authorized MPC Node's account.
        @param requester The authorized MPC Node's account submitting the deposit confirmation.
        @param tradeId The unique identifier assigned to the trade.
        @param signature The signature, provided by MPC threshold keys, confirming the deposit.
        @param depositFromList A list of addresses that transferred the `amountIn` to the designated vault.
    */
    function confirmDeposit(
        address requester,
        bytes32 tradeId,
        bytes calldata signature,
        bytes[] memory depositFromList
    ) external;

    /** 
        @notice Select the PMM winner for a specific trade.
        @dev Caller must be `Router` contract, and the `requester` has a Solver role.
        @param requester The Solver's address submitting the PMM selection.
        @param tradeId The unique identifier assigned to the trade.
        @param info The PMM selection data, which includes proof of the selected PMM and Request for Quote (RFQ) information.
    */
    function selectPMM(
        address requester,
        bytes32 tradeId,
        PMMSelection calldata info
    ) external;

    /** 
        @notice Allows the selected PMM to publicly announce that payment has been transferred to the User.
        @dev Caller must be the `Router` contract, and `requester` must be either `Solver` or a selected `PMM`.
        @param requester Either `Solver` or a selected PMM making the payment announcement.
        @param indexOfTrade The index of the `tradeId` within the bundle.
        @param bundle The `BundlePayment` struct contains the payment transaction ID and related details.
        @return bytes32 The unique identifier assigned to the PMM.
    */
    function makePayment(
        address requester,
        uint256 indexOfTrade,
        BundlePayment calldata bundle
    ) external returns (bytes32);

    /** 
        @notice Submit confirmation that payment has been received.
        @dev Caller must be the `Router` contract, and the `requester` must be an authorized MPC Node's account.
        @param requester The authorized MPC Node's account submitting the payment confirmation.
        @param tradeId The unique identifier assigned to the trade for which payment is being confirmed.
        @param signature The signature provided by the `MPC Node` using their threshold key to confirm the payment.
    */
    function confirmPayment(
        address requester,
        bytes32 tradeId,
        bytes calldata signature
    ) external;

    /** 
        @notice Submit confirmation of a settlement for a trade.
        @dev Caller must be the `Router` contract, and the `requester` must be an authorized MPC Node's account. 
        @param requester The authorized MPC Node's account submitting the settlement confirmation.
        @param tradeId The unique identifier assigned to the trade for which the settlement is being confirmed.
        @param releaseTxId The transaction ID of the released settlement on the source network.
        @param signature The signature provided by the `MPC Node` using their threshold key to confirm the settlement.
    */
    function confirmSettlement(
        address requester,
        bytes32 tradeId,
        bytes calldata releaseTxId,
        bytes calldata signature
    ) external;
}
