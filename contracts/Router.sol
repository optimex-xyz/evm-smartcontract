// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./interfaces/IManagement.sol";
import "./interfaces/ICore.sol";
import "./utils/Errors.sol";

/***********************************************************************************************************
    @title Router contract                               
    @dev This contract functions as the helper contract within the Protocol.
    - Manages routes between chains (e.g., "fromChain" -> "toChain").
    - Facilitates multiple actor types (`Solver`, `PMM`, `MPC`) in sending requests to the appropriate handler contract.
    - Enables fetching of `tradeId` data from the correct handler contract.
    - Supports fetching Protocol's settings.
************************************************************************************************************/

contract Router is ITypes {
    /// Address of Signer contract
    address public immutable SIGNER;

    /// Address of Management contract
    IManagement public management;

    /// Mapping of chain pair hashes to their routing Core contracts
    /// keccak256(fromChain, toChain) => routing Core contract address
    mapping(bytes32 => address) private _routes;

    /// Mapping of trade IDs to their associated Core contracts
    mapping(bytes32 => address) private _tradeIdToCore;

    /// Tracks version numbers for Core contracts
    mapping(address => uint256) public version;

    /**
        @dev Emitted when the owner of Management sets a new routing Core contract.
        @param core Address of the Core contract.
        @param version Version of the Core contract.
        @param fromChain Source chain in bytes format.
        @param toChain Destination chain in bytes format.
        @dev Related function: setRoute()
    */
    event UpdatedRoute(
        address indexed core,
        uint256 indexed version,
        bytes fromChain,
        bytes toChain
    );

    /**
        @dev Emitted when a `Solver` successfully submits one trade.
        @param solver Address of the Solver submitting the information.
        @param tradeId Identifier of the trade.
        @dev Related function: submitTrade()
    */
    event SubmitTradeInfo(address indexed solver, bytes32 indexed tradeId);

    /**
        @dev Emitted when the authorized `MPC Node` successfully submits a deposit confirmation.
        @param mpc Address of the authorized MPC Node submitting the confirmation.
        @param tradeId Identifier of the trade.
        @param pFeeRate Protocol fee rate.
        @param aFeeRate Aggregated affiliate fee rate.
        @param list List of addressess that transfer `amountIn` to a designated vault.
        @dev Related function: confirmDeposit()
    */
    event ConfirmDeposit(
        address indexed mpc,
        bytes32 indexed tradeId,
        uint256 pFeeRate,
        uint256 aFeeRate,
        bytes[] list
    );

    /**
        @dev Emitted when a `Solver` successfully selects the PMM for a trade.
        @param solver Address of the Solver making the selection.
        @param tradeId Identifier of the trade.
        @dev Related function: selectPMM()
    */
    event SelectPMM(address indexed solver, bytes32 indexed tradeId);

    /**
        @dev Emitted when a `Solver` or a selected `PMM` submits the payment's transaction ID (single or bundled).
        @param operator Address of the operator (either Solver or a selected PMM) submitting the transaction ID.
        @param tradeId Identifier of the trade.
        @dev Related function: bundlePayment()
    */
    event MakePayment(address indexed operator, bytes32 indexed tradeId);

    /**
        @dev Emitted when an authorized `MPC Node` successfully submits a payment confirmation.
        @param mpc Address of the authorized MPC Node submitting the confirmation.
        @param tradeId Identifier of the trade.
        @dev Related function: confirmPayment()
    */
    event ConfirmPayment(address indexed mpc, bytes32 indexed tradeId);

    /**
        @dev Emitted when the authorized `MPC Node` successfully submits a settlement confirmation.
        @param mpc Address of the authorized MPC Node submitting the confirmation.
        @param tradeId Identifier of the trade.
        @dev Related function: confirmSettlement()
    */
    event ConfirmSettlement(address indexed mpc, bytes32 indexed tradeId);

    modifier onlyManagementOwner() {
        if (msg.sender != management.owner()) revert Unauthorized();
        _;
    }

    modifier notAddressZero(address checkingAddress) {
        if (checkingAddress == address(0)) revert AddressZero();
        _;
    }

    modifier isExisted(bytes32 tradeId) {
        if (_tradeIdToCore[tradeId] == address(0)) revert RouteNotFound();
        _;
    }

    constructor(IManagement management_, address signer) {
        management = management_;
        SIGNER = signer;
    }

    /**
        @notice Updates the address of the Management contract.
        @dev Caller must be the `Owner` of the current Management contract.
        @param newManagement The new Management contract's address.
    */
    function setManagement(
        address newManagement
    ) external onlyManagementOwner notAddressZero(newManagement) {
        management = IManagement(newManagement);
    }

    /**
        @notice Sets a routing Core contract to handle trades from `fromChain` to `toChain`.
        @dev Caller must be the `Owner` of the current Management contract.
        @param core The address of the Core contract.
        @param fromChain A unique identifier assigned to the source network (in bytes format).
        @param toChain A unique identifier assigned to the destination network (in bytes format).
    */
    function setRoute(
        address core,
        bytes calldata fromChain,
        bytes calldata toChain
    ) external onlyManagementOwner notAddressZero(core) {
        /// Ensure `fromChain` and `toChain` are supported networks
        if (!isValidNetwork(fromChain) || !isValidNetwork(toChain))
            revert RouteNotSupported();

        /// Prevent duplicate registration of the same Core contract for this route
        bytes32 routingHash = keccak256(abi.encode(fromChain, toChain));
        address routingCore = _routes[routingHash];
        if (routingCore == core) revert RegisteredAlready();

        /// Update storage with the new Core contract and increment its version
        uint256 versionNo = version[routingCore];
        version[core] = versionNo + 1;
        _routes[routingHash] = core;

        emit UpdatedRoute(core, versionNo + 1, fromChain, toChain);
    }

    /**
        @notice Retrieves the Core Handler for a specific route defined by `fromChain` and `toChain`.
        @param fromChain A unique identifier assigned to the source network (in bytes format).
        @param toChain A unique identifier assigned to the destination network (in bytes format).
        @return handler The address of the Core Handler (returns `address(0)` if not registered).
        @return handlerType A string representing the type of handler (empty if `handler` is `address(0)`).
    */
    function getHandler(
        bytes calldata fromChain,
        bytes calldata toChain
    ) external view returns (address handler, string memory handlerType) {
        bytes32 routingHash = keccak256(abi.encode(fromChain, toChain));
        handler = _routes[routingHash];
        if (handler == address(0)) handlerType = "";
        else handlerType = ICore(handler).typeOfHandler();
    }

    /**
        @notice Retrieves the Core Handler contract associated with a specific `tradeId`.
        @param tradeId The unique identifier of the trade.
        @return handler The address of the Core Handler (returns `address(0)` if not recorded).
        @return handlerType A string representing the type of handler (empty if `handler` is not recorded).
    */
    function getHandlerOf(
        bytes32 tradeId
    ) external view returns (address handler, string memory handlerType) {
        handler = _tradeIdToCore[tradeId];
        if (handler == address(0)) handlerType = "";
        else handlerType = ICore(handler).typeOfHandler();
    }

    /*****************************************************************************************
                              Management Interaction
      - Supports sending following requests to the Management contract
          - isValidNetwork / isValidToken / isSolver
          - isMPCNode / isValidPMM / isValidPMMAccount
          - isValidPubkey / isSuspended / getManagementOwner
          - getProtocolState / getPFeeRate / getLatestMPCInfo
          - getMPCInfo / numOfSupportedTokens / getTokens
          - numOfPMMAccounts / getPMMAccounts
    ******************************************************************************************/

    /**
        @notice Checks whether the given `networkId` is currently supported.
        @dev A `networkId` is considered supported if it has at least one supported `tokenId`.
        @param networkId The unique identifier assigned to a network.
        @return A boolean value indicating whether the `networkId` is supported.
    */
    function isValidNetwork(
        bytes calldata networkId
    ) public view returns (bool) {
        return management.isValidNetwork(networkId);
    }

    /**
        @notice Checks whether the given `tokenId` of the specified `networkId` is currently supported.
        @param networkId The unique identifier assigned to a network.
        @param tokenId The unique identifier assigned to a token within the `networkId`.
        @return A boolean value indicating whether the `tokenId` is supported for the specified `networkId`.
    */
    function isValidToken(
        bytes calldata networkId,
        bytes calldata tokenId
    ) external view returns (bool) {
        return management.isValidToken(networkId, tokenId);
    }

    /**
        @notice Checks if the specified `account` is currently assigned as a `Solver`.
        @param account The address to validate.
        @return A boolean value indicating whether the `account` is assigned as a `Solver`.
    */
    function isSolver(address account) external view returns (bool) {
        return management.solvers(account);
    }

    /**
        @notice Checks if the specified `account` is currently set as a MPC Node's associated account.
        @param account The address to validate.
        @return A boolean value indicating whether the `account` is associated with an MPC Node.
    */
    function isMPCNode(address account) external view returns (bool) {
        return management.mpcNodes(account);
    }

    /**
        @notice Checks whether the specified PMM is registered.
        @param pmmId The unique identifier of the PMM to validate.
        @return A boolean value indicating whether the PMM is registered.
    */
    function isValidPMM(bytes32 pmmId) external view returns (bool) {
        return management.isValidPMM(pmmId);
    }

    /**
        @notice Checks whether the specified `account` is registered as a PMM's associated account.
        @param pmmId The unique identifier given to one PMM.
        @param account The address to validate.
        @return A boolean value indicating whether the `account` is a PMM's associated account.
    */
    function isValidPMMAccount(
        bytes32 pmmId,
        address account
    ) external view returns (bool) {
        return management.isValidPMMAccount(pmmId, account);
    }

    /**
        @notice Validates whether the specified `pubkey` is registered and not expired on the given `networkId`.
        @param networkId The unique identifier assigned to a network.
        @param pubkey The `mpcAssetPubkey` or `mpcL2Pubkey` to validate.
        @return A boolean value indicating whether the `pubkey` is valid (registered and not expired).
    */
    function isValidPubkey(
        bytes calldata networkId,
        bytes calldata pubkey
    ) external view returns (bool) {
        return management.isValidPubkey(networkId, pubkey);
    }

    /**
        @notice Checks whether the specified `stage` is currently suspended.
        @param stage The `STAGE` enum value representing the stage to check.
        @return A boolean value indicating whether the `stage` is suspended.
    */
    function isSuspended(STAGE stage) external view returns (bool) {
        return management.isSuspended(stage);
    }

    /**
        @notice Retrieves the current `Owner` of the Management contract.
        @return The current Owner's address
    */
    function getManagementOwner() external view returns (address) {
        return management.owner();
    }

    /**
        @notice Retrieves the current state of the Protocol.
        @return The state of the protocol as a `uint256`:
            - 0: OPERATING
            - 1: SUSPENDED
            - 2: SHUTDOWN
    */
    function getProtocolState() external view returns (uint256) {
        return management.state();
    }

    /**
        @notice Retrieves the current `pFeeRate` setting from the Management contract.
        @return The current protocol fee rate (`pFeeRate`) as a `uint256`.
        @dev
        - If `pFeeRate` is updated after a trade is submitted, the `tradeId` will use the 
            `pFeeRate` that was in effect at the time of submission.
        - To check the fee details applied to a specific `tradeId`, use the `getFeeDetails` function instead.
    */
    function getPFeeRate() external view returns (uint256) {
        return management.pFeeRate();
    }

    /**
        @notice Retrieves the most recent MPC's public keys associated with a specific `networkId`.
        @param networkId The unique identifier given to a network.
        @return The latest details of the MPC's public keys for the given `networkId`.
    */
    function getLatestMPCInfo(
        bytes calldata networkId
    ) external view returns (MPCInfo memory) {
        return management.getLatestMPCInfo(networkId);
    }

    /**
        @notice Retrieves the MPC information associated with a given `networkId` and `pubkey`.
        @param networkId The unique identifier for the network.
        @param pubkey The `mpcL2Pubkey` or `mpcAssetPubkey` to query.
        @return info The details of the MPC's public keys for the given parameters.
    */
    function getMPCInfo(
        bytes calldata networkId,
        bytes calldata pubkey
    ) external view returns (MPCInfo memory info) {
        return management.getMPCInfo(networkId, pubkey);
    }

    /**
        @notice Retrieves the total number of tokens currently supported by the Protocol.
        @return The total number of supported tokens as a `uint256`.
    */
    function numOfSupportedTokens() external view returns (uint256) {
        return management.numOfSupportedTokens();
    }

    /**
        @notice Retrieves a list of token information within the specified index range.
        @param fromIdx The starting index of the range (inclusive).
        @param toIdx The ending index of the range (exclusive).
        @return list An array of the tokens' details in the specified range.
    */
    function getTokens(
        uint256 fromIdx,
        uint256 toIdx
    ) external view returns (ITypes.TokenInfo[] memory list) {
        return management.getTokens(fromIdx, toIdx);
    }

    /**
        @notice Retrieves the total number of accounts associated with a specific `PMM`.
        @param pmmId The unique identifier of the `PMM`.
        @return The total number of PMM's associated accounts as a `uint256`.
    */
    function numOfPMMAccounts(bytes32 pmmId) external view returns (uint256) {
        return management.numOfPMMAccounts(pmmId);
    }

    /** 
        @notice Queries a list of associated accounts for a given `pmmId` within the specified range.
        @param pmmId The unique identifier assigned to a `PMM`.
        @param fromIdx The starting index (inclusive).
        @param toIdx The ending index (exclusive).
        @return list A list of associated accounts within the specified range.
    */
    function getPMMAccounts(
        bytes32 pmmId,
        uint256 fromIdx,
        uint256 toIdx
    ) external view returns (address[] memory list) {
        return management.getPMMAccounts(pmmId, fromIdx, toIdx);
    }

    /*****************************************************************************************
                              Core Contract Interaction
      - Supports sending following requests to Core Handler Contracts
          - getCurrentStage / getTradeData / getPresigns / getAffiliateInfo
          - getPMMSelection / getFeeDetails / getSettledPayment
          - getDepositAddressList / getLastSignedPayment / getMaxAffiliateFeeRate
          - submitTrade / confirmDeposit / selectPMM 
          - makePayment / confirmPayment / confirmSettlement
    ******************************************************************************************/

    /**
        @notice Retrieves the current stage of a specific trade.
        @param tradeId The unique identifier assigned to the trade.
        @return The current stage of the trade as a `uint256`.
    */
    function getCurrentStage(bytes32 tradeId) external view returns (uint256) {
        return _core(tradeId).currentStage(tradeId);
    }

    /**
        @notice Retrieves the trade data for a specific trade.
        @param tradeId The unique identifier assigned to the trade.
        @return A `TradeData` struct containing the details of the trade.
    */
    function getTradeData(
        bytes32 tradeId
    ) external view returns (TradeData memory) {
        return _core(tradeId).trade(tradeId);
    }

    /**
        @notice Retrieves the presign submissions for a specific trade.
        @param tradeId The unique identifier assigned to the trade.
        @return An array of `Presign` structs containing presign information for the trade.
    */
    function getPresigns(
        bytes32 tradeId
    ) external view returns (Presign[] memory) {
        return _core(tradeId).presign(tradeId);
    }

    /** 
        @notice Retrieves the Affiliate struct associated with the specified `tradeId`.
        @param tradeId The unique identifier assigned to one trade.
        @return The Affiliate struct containing the trade's affiliate details.
    */
    function getAffiliateInfo(
        bytes32 tradeId
    ) external view returns (Affiliate memory) {
        return _core(tradeId).affiliate(tradeId);
    }

    /**
        @notice Retrieves the PMM selection proof for a specific trade.
        @param tradeId The unique identifier assigned to the trade.
        @return A `PMMSelection` struct containing the PMM selection details for the trade.
    */
    function getPMMSelection(
        bytes32 tradeId
    ) external view returns (PMMSelection memory) {
        return _core(tradeId).pmmSelection(tradeId);
    }

    /**
        @notice Retrieves the FeeDetails struct associated with the specified `tradeId`.
        @param tradeId The unique identifier assigned to the trade.
        @return The FeeDetails struct containing the trade's fee breakdown.
    */
    function getFeeDetails(
        bytes32 tradeId
    ) external view returns (FeeDetails memory) {
        return _core(tradeId).feeDetails(tradeId);
    }

    /**
        @notice Retrieves the settled payment information for a specific trade.
        @param tradeId The unique identifier assigned to the trade.
        @return A `SettledPayment` struct containing details of the settled payment for the trade.
    */
    function getSettledPayment(
        bytes32 tradeId
    ) external view returns (SettledPayment memory) {
        return _core(tradeId).settledPayment(tradeId);
    }

    /** 
        @notice Retrieves the list of confirmed deposit addresses for a specific trade.
        @param tradeId The unique identifier assigned to the trade.
        @return A bytes array containing the confirmed deposit addresses for the trade.
    */
    function getDepositAddressList(
        bytes32 tradeId
    ) external view returns (bytes[] memory) {
        return _core(tradeId).depositAddressList(tradeId);
    }

    /** 
        @notice Retrieves the last timestamp when the `paymentTxId` was signed for updating.
        @param tradeId The unique identifier assigned to the trade.
        @return The timestamp when the `paymentTxId` was last signed for update.
    */
    function getLastSignedPayment(
        bytes32 tradeId
    ) external view returns (uint64) {
        return _core(tradeId).lastSignedPayment(tradeId);
    }

    /**
        @notice Retrieves the current maximum allowable affiliate fee rate for a given route `fromChain` and `toChain`.
        @dev Reverts with `RouteNotSupported` if no handler is found for the given route.
        @param fromChain A unique identifier assigned to the source network (in bytes format).
        @param toChain A unique identifier assigned to the destination network (in bytes format).
        @return The maximum affiliate fee rate as a `uint256`, expressed in basis points (bps).
    */
    function getMaxAffiliateFeeRate(
        bytes calldata fromChain,
        bytes calldata toChain
    ) external view returns (uint256) {
        bytes32 routingHash = keccak256(abi.encode(fromChain, toChain));
        address handler = _routes[routingHash];
        if (handler == address(0)) revert RouteNotSupported();

        return ICore(handler).maxAffiliateFeeRate();
    }

    /** 
        @notice Submits trade data and presigns for a specific trade.
        @dev Caller must have the `Solver` role. The Core handler contract will validate this.
        @param tradeId The unique identifier assigned to the trade.
        @param tradeData A struct containing the trade information.
        @param affiliateInfo A struct containing affiliate details.
        @param presignList The presign information involved in the trade.
    */
    function submitTrade(
        bytes32 tradeId,
        TradeData calldata tradeData,
        Affiliate calldata affiliateInfo,
        Presign[] calldata presignList
    ) external {
        bytes32 routingHash = keccak256(
            abi.encode(
                tradeData.tradeInfo.fromChain[1],
                tradeData.tradeInfo.toChain[1]
            )
        );
        address core = _routes[routingHash];
        if (core == address(0)) revert RouteNotSupported();

        /// map `tradeId` -> Core contract
        _tradeIdToCore[tradeId] = core;

        /// emit event before calling Core contract
        address sender = msg.sender;
        emit SubmitTradeInfo(sender, tradeId);

        ICore(core).submitTrade(
            sender,
            tradeId,
            tradeData,
            affiliateInfo,
            presignList
        );
    }

    /** 
        @notice Confirms the deposit for a specific trade.
        @dev Caller must be MPC Node's associated account. The Core contract will validate this.
        @param tradeId The unique identifier assigned to the trade.
        @param signature The signature provided by MPC's threshold key.
        @param depositFromList The list of addresses that transferred `amountIn` to a designated vault.
    */
    function confirmDeposit(
        bytes32 tradeId,
        bytes calldata signature,
        bytes[] calldata depositFromList
    ) external {
        /// emit event before calling Core contract
        address sender = msg.sender;

        _core(tradeId).confirmDeposit(
            sender,
            tradeId,
            signature,
            depositFromList
        );

        //  get Protocol Fee and depositFromList
        ICore core = _core(tradeId);
        FeeDetails memory details = core.feeDetails(tradeId);
        bytes[] memory list = core.depositAddressList(tradeId);

        emit ConfirmDeposit(
            sender,
            tradeId,
            details.pFeeRate,
            details.aFeeRate,
            list
        );
    }

    /** 
        @notice Selects the PMM winner for a specific trade.
        @dev Caller must have the `Solver` role. The Core contract will validate this.
        @param tradeId The unique identifier assigned to the trade.
        @param info The struct containing the selected PMM's proof and RFQ information.
    */
    function selectPMM(
        bytes32 tradeId,
        PMMSelection calldata info
    ) external isExisted(tradeId) {
        /// emit event before calling Core contract
        address sender = msg.sender;
        emit SelectPMM(sender, tradeId);

        _core(tradeId).selectPMM(sender, tradeId, info);
    }

    /** 
        @notice Announces that a PMM has made a payment transfer to the User via `Solver`.
        @dev Caller must be either `Solver` or a selected PMM. This constraint is validated by the Core handler contract.
        @param bundle The `BundlePayment` struct containing the following:
            - `tradeIds`: An array of bytes32 values representing the list of tradeIds being paid by the `paymentTxId`.
            - `signedAt`: A timestamp representing when the payment is signed by the selected PMM.
            - `startIdx`: A starting index of sub-transactions within the `paymentTxId`.
            - `paymentTxId`: The payment transaction identifier.
            - `signature`: A signature signed by the selected PMM.
    */
    function bundlePayment(BundlePayment calldata bundle) external {
        address sender = msg.sender;
        uint256 len = bundle.tradeIds.length;
        if (len == 0) revert BundlePaymentEmpty();

        /// Variables to ensure consistency across PMM ID and Core Type
        bytes32 pmmId;
        string memory coreType;
        for (uint256 i; i < len; i++) {
            bytes32 tradeId = bundle.tradeIds[i];
            address core = _tradeIdToCore[tradeId];
            if (core == address(0)) revert RouteNotFound();

            /// Emit event before interacting with the Core contract
            emit MakePayment(sender, tradeId);
            bytes32 id = ICore(core).makePayment(sender, i, bundle);

            if (i == 0) {
                coreType = ICore(core).typeOfHandler();
                pmmId = id;
            } else {
                /// Ensure all tradeIds belong to the same PMM and Core type
                if (pmmId != id) revert InconsistentPMM();
                if (
                    keccak256(bytes(coreType)) !=
                    keccak256(bytes(ICore(core).typeOfHandler()))
                ) revert InconsistentCoreType();
            }
        }
    }

    /** 
        @notice Submits a confirmation for a payment.
        @dev Caller must be an MPC Node's associated account. This constraint is validated by the Core handler contract.
        @param tradeId The unique identifier assigned to the trade.
        @param signature The signature provided by MPC's threshold key.
    */
    function confirmPayment(
        bytes32 tradeId,
        bytes calldata signature
    ) external isExisted(tradeId) {
        /// emit event before calling Core contract
        address sender = msg.sender;
        emit ConfirmPayment(sender, tradeId);

        _core(tradeId).confirmPayment(sender, tradeId, signature);
    }

    /** 
        @notice Submits a confirmation for the settlement of a trade.
        @dev Caller must be an MPC Node's associated account. The Core contract will validate this.
        @param tradeId The unique identifier assigned to the trade.
        @param releaseTxId The released transaction ID (on the Source Network).
        @param signature The signature provided by MPC's threshold key.
    */
    function confirmSettlement(
        bytes32 tradeId,
        bytes calldata releaseTxId,
        bytes calldata signature
    ) external isExisted(tradeId) {
        /// emit event before calling Core contract
        address sender = msg.sender;
        emit ConfirmSettlement(sender, tradeId);

        _core(tradeId).confirmSettlement(
            sender,
            tradeId,
            releaseTxId,
            signature
        );
    }

    function _core(bytes32 tradeId) private view returns (ICore) {
        /// @dev: If `tradeId` not found, it returns 0x0
        /// thus, calling a function is likely reverted
        return ICore(_tradeIdToCore[tradeId]);
    }
}
