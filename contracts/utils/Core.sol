// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "../interfaces/IManagement.sol";
import "../interfaces/ISigner.sol";
import "../interfaces/ITypes.sol";
import "../interfaces/IRouter.sol";
import "./Errors.sol";

/*****************************************************************************************
    @title Core contract (Abstract)                             
    @dev This contract defines the fundamental interfaces for the Core Handler contracts 
        used in the Protocol. Core handlers facilitate the exchange of assets across
        multiple networks and are responsible for handling various trade operations,
        including deposits, payments, and settlement confirmations
    @dev The following Core Handler contracts are supported:
    - BTCEVM: Supports trades/swaps from Bitcoin Network to EVM Compatible Networks.
    - EVMBTC: Supports trades/swaps from EVM Compatible Networks to Bitcoin Network.
    - BTCSOL: Supports trades/swaps from Bitcoin Network to Solana Network.
    - SOLBTC: Supports trades/swaps from Solana Network to Bitcoin Network.
******************************************************************************************/

abstract contract Core is ITypes {
    uint256 internal constant DENOM = 10_000;

    uint256 internal constant ZERO_VALUE = 0;

    /// An upper limit of the affiliate fee rate (bps)
    uint256 public maxAffiliateFeeRate;

    /// Address of Router contract
    IRouter public router;

    /// Tracks the procedure of each trade identified by `tradeId`
    mapping(bytes32 => uint256) internal _currentStages;

    /// Records the most recent timestamp when the `paymentTxId` was signed for the specified `tradeId`
    mapping(bytes32 => uint64) internal _lastSignedPayment;

    /// Tracks the address of the `solver` associated with a particular `tradeId`
    mapping(bytes32 => address) internal _tradeToSolver;

    /// A list of fee details associated with a particular `tradeId`
    mapping(bytes32 => FeeDetails) internal _feeDetails;

    /// A list of settled payment's info associated with a particular `tradeId`
    mapping(bytes32 => SettledPayment) internal _settledPayments;

    /// Stores Trade Data for each `tradeId`
    mapping(bytes32 => TradeData) internal _trades;

    /// Stores affiliate-related information for each `tradeId`
    mapping(bytes32 => Affiliate) internal _affiliates;

    /// Stores a confirmed list of deposited addresses for each `tradeId`
    mapping(bytes32 => bytes[]) internal _depositAddressList;

    /// Stores full details of Presign information for each `tradeId`
    mapping(bytes32 => Presign[]) internal _presigns;

    /// Stores the PMM selection details for each `tradeId`
    mapping(bytes32 => PMMSelection) internal _pmmSelection;

    /// A mapping that tracks the index of the involved PMMs for each `tradeId`
    mapping(bytes32 => mapping(bytes32 => uint256)) internal _tradeToPMMIndex;

    /// Tracks whether the `paymentTxId` in the bundle payment has been confirmed by the MPC for any trade
    mapping(bytes => bool) internal _paymentTxConfirmed;

    /**
        @notice Emitted when a `Solver` successfully submits trade.
        @param forwarder The Router's address forwarding the trade info.
        @param solver The Solver's address submitting the info.
        @param tradeId The unique identifier for the trade.
        @param network The unique identifier of the source network.
        @param depositTxId The transaction ID of the deposit.
        @dev Relate function: submitTrade().
    */
    event TradeInfoSubmitted(
        address indexed forwarder,
        address indexed solver,
        bytes32 indexed tradeId,
        bytes network,
        bytes depositTxId
    );

    /**
        @notice Emitted when the `MPC` successfully submits a deposit confirmation for a trade.
        @dev Triggered by the function `confirmDeposit()`.
        @param forwarder The Router's address forwarding the deposit confirmation.
        @param mpc The MPC's address confirming the deposit.
        @param tradeId The unique identifier for the trade.
        @param totalFeeRate The total fee rate (protocol and aggregate affiliate) associated with the trade.
        @dev Related function: confirmDeposit()
    */
    event DepositConfirmed(
        address indexed forwarder,
        address indexed mpc,
        bytes32 indexed tradeId,
        uint256 totalFeeRate
    );

    /**
        @notice Emitted when a `Solver` successfully submits the PMM selection for a trade.
        @param forwarder The Router's address forwarding the PMM selection submission.
        @param solver The Solver's address selecting the PMM.
        @param tradeId The unique identifier for the trade.
        @param selectedPMMId The unique identifier of the selected PMM.
        @dev Relate function: selectPMM()
    */
    event SelectedPMM(
        address indexed forwarder,
        address indexed solver,
        bytes32 indexed tradeId,
        bytes32 selectedPMMId
    );

    /**
        @notice Emitted when either `Solver` or a selected PMM submits a payment transaction id.
        @param forwarder The Router's address forwarding the request submission.
        @param operator Either Solver or a selected PMM submitting the make payment.
        @param tradeId The unique identifier for the trade.
        @param network The unique identifier of network associated with the payment.
        @param paymentTxId The transaction ID of the payment.
        @param bundle An array of tradeIds paid by the payment.
        @param startIdx The starting index for the payment bundle within the paymentTxId.
        @dev Relate function: makePayment()
    */
    event MadePayment(
        address indexed forwarder,
        address indexed operator,
        bytes32 indexed tradeId,
        bytes network,
        bytes paymentTxId,
        bytes32[] bundle,
        uint256 startIdx
    );

    /**
        @notice Emitted when the `MPC` successfully confirms a payment for a trade.
        @param forwarder The Router's address forwarding the payment confirmation.
        @param mpc The MPC's address confirming the payment.
        @param tradeId The unique identifier for the trade.
        @param paymentTxId The transaction ID of the payment.
        @dev Relate function: confirmPayment()
    */
    event PaymentConfirmed(
        address indexed forwarder,
        address indexed mpc,
        bytes32 indexed tradeId,
        bytes paymentTxId
    );

    /**
        @notice Emitted when the `MPC` successfully confirms the settlement for a trade.
        @param forwarder The Router's address forwarding the settlement confirmation.
        @param mpc The MPC's address confirming the settlement.
        @param tradeId The unique identifier for the trade.
        @param releaseTxId The transaction ID representing the settlement release.
        @dev Relate function: confirmSettlement()
     */
    event SettlementConfirmed(
        address indexed forwarder,
        address indexed mpc,
        bytes32 indexed tradeId,
        bytes releaseTxId
    );

    modifier onlyManagementOwner() {
        if (msg.sender != _management().owner()) revert Unauthorized();
        _;
    }

    modifier onlySolver(address requester) {
        if (msg.sender != address(router) || !_management().solvers(requester))
            revert Unauthorized();
        _;
    }

    modifier onlyMPCNode(address requester) {
        if (msg.sender != address(router) || !_management().mpcNodes(requester))
            revert Unauthorized();
        _;
    }

    modifier notAddressZero(address checkingAddress) {
        if (checkingAddress == address(0)) revert AddressZero();
        _;
    }

    modifier isSuspended(STAGE stage) {
        if (_management().isSuspended(stage)) revert InSuspension();
        _;
    }

    /** 
        @notice Retrieve the type of `Core Handler` contract.
        @dev This function returns a string that indicates the type of the contract 
            providing clarity on the contract's role. It is an abstract function
            that should be implemented in derived contracts to specify the handler type.
        @return A string representing the type of Core Handler, e.g., `BTCEVM`, `EVMBTC`.
    */
    function typeOfHandler() external view virtual returns (string memory);

    /** 
        @notice Query the current stage of the trade identified by `tradeId`.
        @dev This function retrieves the current stage of the specified trade from the 
            `_currentStages` mapping. It helps track the trade's progress and ensures 
            that it proceeds through the correct stages sequentially.
        @param tradeId The unique ID assigned to one trade.
        @return The current stage of the trade, represented as an integer.
    */
    function currentStage(bytes32 tradeId) external view returns (uint256) {
        return _currentStages[tradeId];
    }

    /** 
        @notice Query the most recent timestamp when the `paymentTxId` was signed 
            for the trade identified by `tradeId`.
        @dev This function retrieves the timestamp of when the payment transaction ID 
            was last signed, allowing to track replacement for the specified trade.
            It is useful for ensuring timely updates and preventing unexpected replacement.
        @param tradeId The unique ID assigned to one trade.
        @return The most recent timestamp when the `paymentTxId` was signed.
    */
    function lastSignedPayment(bytes32 tradeId) external view returns (uint64) {
        return _lastSignedPayment[tradeId];
    }

    /** 
        @notice Retrieves the FeeDetails struct associated with the specified `tradeId`.
        @dev Returns detailed fee information, including protocol and affiliate fee rates and amounts, for a given trade.
        @param tradeId The unique identifier assigned to one trade.
        @return The FeeDetails struct containing the trade's fee breakdown.
    */
    function feeDetails(
        bytes32 tradeId
    ) external view returns (FeeDetails memory) {
        return _feeDetails[tradeId];
    }

    /** 
        @notice Retrieves the Affiliate struct associated with the specified `tradeId`.
        @dev Provides affiliate information, including the aggregated affiliate fee rate and other relevant details.
        @param tradeId The unique identifier assigned to one trade.
        @return The Affiliate struct containing the trade's affiliate details.
    */
    function affiliate(
        bytes32 tradeId
    ) external view returns (Affiliate memory) {
        return _affiliates[tradeId];
    }

    /** 
        @notice Query the TradeData struct associated with the specified `tradeId`.
        @dev This function returns the data associated with the given `tradeId`. 
        @param tradeId The unique identifier assigned to one trade.
        @return The TradeData struct containing detailed trade information.
    */
    function trade(bytes32 tradeId) external view returns (TradeData memory) {
        return _trades[tradeId];
    }

    /** 
        @notice Query the list of Presign submissions for the specified `tradeId`.
        @dev This function returns an array of presignatures' info associated with the given `tradeId`.
        @param tradeId The unique identifier assigned to one trade.
        @return An array of Presign structs.
    */
    function presign(bytes32 tradeId) external view returns (Presign[] memory) {
        return _presigns[tradeId];
    }

    /** 
        @notice Query the confirmed list of deposited addresses associated with the specified `tradeId`.
        @dev This function returns a list of addresses that have been confirmed as deposited 
            for a specific trade.
        @param tradeId The unique identifier assigned to one trade.
        @return An array of addresses that have been confirmed as deposited for the trade.
    */
    function depositAddressList(
        bytes32 tradeId
    ) external view returns (bytes[] memory) {
        return _depositAddressList[tradeId];
    }

    /** 
        @notice Query the SettledPayment struct associated with the specified `tradeId`.
        @dev This function returns the details of the settled payment for a specific trade. 
        @param tradeId The unique identifier assigned to one trade.
        @return The settled payment details for the trade.
    */
    function settledPayment(
        bytes32 tradeId
    ) external view returns (SettledPayment memory) {
        return _settledPayments[tradeId];
    }

    /** 
        @notice Query the PMMSelection struct associated with the specified `tradeId`.
        @dev This function returns the selected PMM's selection proof, including 
            the RFQ information, for the trade. 
        @param tradeId The unique identifier assigned to one trade.
        @return The struct containing the PMM selection information for the trade.
    */
    function pmmSelection(
        bytes32 tradeId
    ) external view returns (PMMSelection memory) {
        return _pmmSelection[tradeId];
    }

    /**
        @notice Updates the Router contract address.
        @dev Caller must be the `Owner` of the current Management contract.
        @param newRouter The address of the new Router contract.
    */
    function setRouter(
        address newRouter
    ) external onlyManagementOwner notAddressZero(newRouter) {
        router = IRouter(newRouter);
    }

    /**
        @notice Updates the maximum allowable affiliate fee rate.
        @dev Caller must be the `Owner` of the current Management contract.
        @param newRate The new maximum affiliate fee rate, expressed in basis points (bps).
    */
    function setMaxAffiliateFeeRate(
        uint256 newRate
    ) external onlyManagementOwner {
        maxAffiliateFeeRate = newRate;
    }

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
    ) external virtual;

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
        bytes memory signature,
        bytes[] memory depositFromList
    ) external virtual;

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
    ) external virtual;

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
        BundlePayment memory bundle
    ) external virtual returns (bytes32);

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
    ) external virtual;

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
    ) external virtual;

    function _isValidPMMSignature(bytes32 pmmId, address signer) internal view {
        if (!_management().isValidPMMAccount(pmmId, signer))
            revert InvalidPMMSign();
    }

    function _isValidMPCSignature(
        address signer,
        bytes memory networkId,
        bytes memory mpcAssetPubkey
    ) internal view {
        MPCInfo memory info = _management().getMPCInfo(
            networkId,
            mpcAssetPubkey
        );
        if (signer != info.mpcL2Address) revert InvalidMPCSign();
    }

    function _signer() internal view returns (ISigner) {
        return ISigner(router.SIGNER());
    }

    function _management() internal view returns (IManagement) {
        return IManagement(router.management());
    }

    function _isMatched(
        bytes memory data1,
        bytes calldata data2
    ) internal pure returns (bool) {
        return keccak256(data1) == keccak256(data2);
    }

    function _validateStage(
        bytes32 tradeId,
        STAGE expectedStage
    ) internal view {
        uint256 stage = _currentStages[tradeId];
        if (
            (expectedStage == STAGE.MAKE_PAYMENT &&
                stage != uint256(STAGE.MAKE_PAYMENT) &&
                stage != uint256(STAGE.CONFIRM_PAYMENT)) ||
            (expectedStage != STAGE.MAKE_PAYMENT &&
                stage != uint256(expectedStage))
        ) revert InvalidProcedureState(uint256(expectedStage), stage);
    }

    function _validateStageAndTimeout(
        bytes32 tradeId,
        uint256 timeout,
        STAGE expectedStage
    ) internal view returns (uint256 currentTime) {
        currentTime = block.timestamp;
        _validateStage(tradeId, expectedStage);
        if (currentTime >= timeout) revert DeadlineExceeded();
    }
}
