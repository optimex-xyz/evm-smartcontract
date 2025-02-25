// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./utils/Core.sol";

/**************************************************************************************
                          =========== PetaFi ===========
    @title BTCEVM contract                               
    @dev This contract facilitates trades and swaps from the Bitcoin network to 
        EVM-compatible networks.
    - Tracks the current stage of each trade.
    - Enforces authentication restrictions based on trade progression.
    - Records submitted proofs for each stage.
***************************************************************************************/
contract BTCEVM is Core {
    constructor(IRouter router_) {
        router = router_;
    }

    /**
        @notice Retrieves the contract type identifier.
        @return A string representing the contract type ("BTCEVM").
    */
    function typeOfHandler() external pure override returns (string memory) {
        return "BTCEVM";
    }

    /** 
        @notice Submits trade data, affiliate information and presigns.
        @dev Caller must be the `Router` contract. Cannot modify the trade once submitted.
        @param requester The Solver's address.
        @param tradeId The unique identifier assigned to the trade.
        @param tradeData A struct containing the trade information.
        @param affiliateInfo A struct containing affiliate details.
        @param presignList The presign data associated with the trade.
    */
    function submitTrade(
        address requester,
        bytes32 tradeId,
        TradeData calldata tradeData,
        Affiliate calldata affiliateInfo,
        Presign[] calldata presignList
    ) external override onlySolver(requester) isSuspended(STAGE.SUBMIT) {
        {
            /// Validate `tradeId` and `scriptTimeout`
            /// `tradeId` is derived as: hash(sessionId, solver.address, tradeInfo)
            _validateStage(tradeId, STAGE.SUBMIT);
            bytes32 expectedTradeId = sha256(
                abi.encode(tradeData.sessionId, requester, tradeData.tradeInfo)
            );
            if (tradeId != expectedTradeId) revert InvalidTradeId();
            if (block.timestamp >= tradeData.scriptInfo.scriptTimeout)
                revert InvalidTimeout();
        }

        /// Validate `tokenPairInfo`
        /// The source and destination chains and tokens must be whitelisted
        IManagement management = _management();
        if (
            !management.isValidToken(
                tradeData.tradeInfo.fromChain[1],
                tradeData.tradeInfo.fromChain[2]
            ) ||
            !management.isValidToken(
                tradeData.tradeInfo.toChain[1],
                tradeData.tradeInfo.toChain[2]
            )
        ) revert TokenNotSupported();

        /// Verify mpcAssetPubkey validity
        /// @dev: `mpcAssetPubkey` is validated (registered and not expired) when a trade is initially submitted.
        /// After this stage, the key remains valid until the trade is finalized
        /// regardless of any changes (e.g., expiration)
        if (
            !management.isValidPubkey(
                tradeData.tradeInfo.fromChain[1],
                tradeData.scriptInfo.depositInfo[3]
            )
        ) revert InvalidMPCAssetPubkey();

        {
            /// Store the index of involved PMMs in a mapping
            /// The index of `pmmId` is incremented by 1
            /// @dev:
            /// - Ensures `pmmId` is already registered
            /// - Presign validity is verified by MPC
            uint256 len = presignList.length;
            bytes32 pmmId;
            for (uint256 i; i < len; i++) {
                pmmId = presignList[i].pmmId;
                if (!management.isValidPMM(pmmId)) revert PMMNotRegistered();

                /// save to storage
                _presigns[tradeId].push(presignList[i]);
                _tradeToPMMIndex[tradeId][pmmId] = i + 1;
            }
        }

        /// Affiliate information is verified at the `selectPMM` stage, where
        /// `rfqInfo` contains the user's signature, including the affiliate details, ensuring
        /// user awareness of the aggregated affiliate fee
        /// At this step, the contract only verifies that it does not exceed the upper limit
        if (affiliateInfo.aggregatedValue > maxAffiliateFeeRate)
            revert ExceededAffiliateFeeLimit();

        /// Advances the trade stage and stores relevant data
        /// @dev The current `pFeeRate` setting is snapshotted and applied to `tradeId` until finalization
        /// The `pFeeAmount` and `aFeeAmount` will be determined at the `selectPMM` stage
        _currentStages[tradeId]++;
        _trades[tradeId] = tradeData;
        _tradeToSolver[tradeId] = requester; //  map `solver` -> `tradeId`
        _feeDetails[tradeId].pFeeRate = uint128(management.pFeeRate());
        _feeDetails[tradeId].aFeeRate = uint128(affiliateInfo.aggregatedValue);
        _affiliates[tradeId] = affiliateInfo;

        emit TradeInfoSubmitted(
            msg.sender,
            requester,
            tradeId,
            tradeData.tradeInfo.fromChain[1],
            tradeData.scriptInfo.depositInfo[1]
        );
    }

    /** 
        @notice Confirms the deposit for a trade.
        @dev Caller must be the `Router` contract. Cannot modify the confirmation once submitted.
        @param requester The authorized MPC Node's address.
        @param tradeId The unique identifier assigned to the trade.
        @param signature The signature generated using MPC's threshold key.
        @param depositFromList The list of addresses that transferred `amountIn` to a designated vault.
    */
    function confirmDeposit(
        address requester,
        bytes32 tradeId,
        bytes memory signature,
        bytes[] memory depositFromList
    )
        external
        override
        onlyMPCNode(requester)
        isSuspended(STAGE.CONFIRM_DEPOSIT)
    {
        /// Ensure the trade is at the correct stage
        TradeData memory tradeData = _trades[tradeId];
        _validateStage(tradeId, STAGE.CONFIRM_DEPOSIT);

        /// Validate the signature
        bytes32 depositHash = keccak256(
            abi.encode(
                tradeData.tradeInfo.amountIn,
                tradeData.tradeInfo.fromChain,
                depositFromList
            )
        );
        address signer = _signer().getDepositConfirmationSigner(
            tradeId,
            keccak256(
                abi.encode(depositHash, tradeData.scriptInfo.depositInfo[1])
            ),
            signature
        );
        _isValidMPCSignature(
            signer,
            tradeData.tradeInfo.fromChain[1],
            tradeData.scriptInfo.depositInfo[3]
        );

        /// Advance trade stage and store `depositFromList`
        _currentStages[tradeId]++;
        _depositAddressList[tradeId] = depositFromList;

        FeeDetails memory details = _feeDetails[tradeId];
        emit DepositConfirmed(
            msg.sender,
            signer,
            tradeId,
            details.pFeeRate + details.aFeeRate
        );
    }

    /** 
        @notice Selects the winning PMM for the specified trade.
        @dev Caller must be the `Router` contract. Cannot modify the information once submitted.
        @param requester The Solver's address.
        @param tradeId The unique identifier assigned to the trade.
        @param info The struct containing the selected PMM’s proof and RFQ details.
    */
    function selectPMM(
        address requester,
        bytes32 tradeId,
        PMMSelection calldata info
    ) external override onlySolver(requester) isSuspended(STAGE.SELECT_PMM) {
        /// Ensure the requester is the same Solver who submitted the trade
        address expectedSolver = _tradeToSolver[tradeId];
        if (requester != expectedSolver) revert Unauthorized();

        /// Ensure the followings:
        /// - `tradeTimeout` has not expired
        /// - `tradeTimeout` cannot exceed `scriptTimeout`
        /// - Provided pmm's signature has not expired
        /// - A selected PMM is included in the presign
        TradeData memory tradeData = _trades[tradeId];
        {
            uint256 currentTime = _validateStageAndTimeout(
                tradeId,
                info.rfqInfo.tradeTimeout,
                STAGE.SELECT_PMM
            );
            if (info.rfqInfo.tradeTimeout > tradeData.scriptInfo.scriptTimeout)
                revert InvalidTimeout();
            if (info.pmmInfo.sigExpiry < currentTime) revert SignatureExpired();

            uint256 index = _tradeToPMMIndex[tradeId][
                info.pmmInfo.selectedPMMId
            ];
            if (index == 0) revert InvalidPMMSelection();
            if (
                !_isMatched(
                    _presigns[tradeId][index - 1].pmmRecvAddress,
                    info.pmmInfo.info[0]
                )
            ) revert PMMAddrNotMatched();
        }

        /// @dev: For BTC->EVM, the fee is charged on the EVM side
        /// Calculate `pFeeAmount` (protocol) and `aFeeAmount` (affiliate), then validate that
        /// `amountOut` - `totalFee` >= `minAmountOut`
        FeeDetails memory details = _feeDetails[tradeId];
        uint256 pFeeAmount = (info.pmmInfo.amountOut * details.pFeeRate) /
            DENOM;
        uint256 aFeeAmount = (info.pmmInfo.amountOut * details.aFeeRate) /
            DENOM;
        uint256 totalFeeAmount = pFeeAmount + aFeeAmount;
        if (info.pmmInfo.amountOut - totalFeeAmount < info.rfqInfo.minAmountOut)
            revert InsufficientQuoteAmount();

        /// Validate the selected PMM's signature
        bytes32 infoHash = keccak256(
            abi.encode(
                info.pmmInfo.selectedPMMId, // pmmId
                info.pmmInfo.info[0], //  pmmRecvAddress
                tradeData.tradeInfo.toChain[1], // toChain
                tradeData.tradeInfo.toChain[2], // toToken
                info.pmmInfo.amountOut,
                info.pmmInfo.sigExpiry
            )
        );
        ISigner helper = _signer();
        address signer = helper.getPMMSelectionSigner(
            tradeId,
            infoHash,
            info.pmmInfo.info[1]
        );
        _isValidPMMSignature(info.pmmInfo.selectedPMMId, signer);

        /// Validate the RFQ signature provided by the User
        signer = helper.getRFQSigner(
            tradeId,
            keccak256(
                abi.encode(
                    info.rfqInfo.minAmountOut,
                    info.rfqInfo.tradeTimeout,
                    _affiliates[tradeId]
                )
            ),
            info.rfqInfo.rfqInfoSignature
        );
        if (signer != tradeData.scriptInfo.userEphemeralL2Address)
            revert InvalidRFQSign();

        /// increase `currentStage` and store data
        details.totalAmount = totalFeeAmount;
        details.pFeeAmount = pFeeAmount;
        details.aFeeAmount = aFeeAmount;
        _currentStages[tradeId]++;
        _pmmSelection[tradeId] = info;
        _feeDetails[tradeId] = details;

        emit SelectedPMM(
            msg.sender,
            requester,
            tradeId,
            info.pmmInfo.selectedPMMId
        );
    }

    /**
        @notice Allows the selected PMM to publicly announce that payment has been transferred to the user.
        @dev Caller must be the `Router` contract.
        @dev The submission/update is permitted only if all `tradeIds` in the bundle 
            are still in the `MAKE_PAYMENT` or `CONFIRM_PAYMENT` state.
        @param requester Either `Solver` or the `PMM` selected in the previous stage.
        @param indexOfTrade The index of the `tradeId` within the bundle.
        @param bundle The `BundlePayment` struct containing trade details.
        @return pmmId The identifier of the selected PMM.
    */
    function makePayment(
        address requester,
        uint256 indexOfTrade,
        BundlePayment memory bundle
    )
        external
        override
        isSuspended(STAGE.MAKE_PAYMENT)
        returns (bytes32 pmmId)
    {
        /// Ensure the function is being requested by either a `Solver` or `PMM`
        /// - For `PMM`, it must be the one selected in the previous stage
        /// - For `Solver`, it must be the entity that submitted the `tradeId`
        address sender = msg.sender;
        bytes32 tradeId = bundle.tradeIds[indexOfTrade];
        pmmId = _pmmSelection[tradeId].pmmInfo.selectedPMMId;
        {
            IManagement management = _management();
            bool isSolver = management.solvers(requester) &&
                requester == _tradeToSolver[tradeId];
            bool isPMM = management.isValidPMMAccount(pmmId, requester);
            if (sender != address(router)) revert Unauthorized();
            if (!isSolver && !isPMM) revert Unauthorized();
        }
        /// Prevent DoS attacks and conflicting overwrites
        if (bundle.paymentTxId.length == 0) revert InvalidPaymentIdLength();
        if (bundle.signedAt < _lastSignedPayment[tradeId])
            revert OutdatedSignature();

        /// Cannot announce payment once `scriptTimeout` has been reached
        /// @dev: Ensure the update is allowed only if all `tradeIds` in the bundle
        /// are still in one of the following states:
        /// - `MAKE_PAYMENT`
        /// - `CONFIRM_PAYMENT`
        TradeData memory tradeData = _trades[tradeId];
        _validateStageAndTimeout(
            tradeId,
            tradeData.scriptInfo.scriptTimeout,
            STAGE.MAKE_PAYMENT
        );
        bytes memory lastPaymentTxId = _settledPayments[tradeId].paymentTxId;
        if (_paymentTxConfirmed[lastPaymentTxId]) revert UpdateNotAllowed();

        /// Validate PMM's signature
        bytes32 bundlerHash = keccak256(abi.encode(bundle.tradeIds));
        {
            address signer = _signer().getMakePaymentSigner(
                keccak256(
                    abi.encode(
                        bundle.signedAt,
                        bundle.startIdx,
                        bundlerHash,
                        bundle.paymentTxId
                    )
                ),
                bundle.signature
            );
            _isValidPMMSignature(
                _pmmSelection[tradeId].pmmInfo.selectedPMMId,
                signer
            );
        }

        /// update `currentStage`, and `_lastSignedPayment`
        /// and store `paymentTxId` (marked as `isConfirmed = false`)
        _currentStages[tradeId] = uint256(STAGE.CONFIRM_PAYMENT);
        _lastSignedPayment[tradeId] = bundle.signedAt;
        _settledPayments[tradeId].paymentTxId = bundle.paymentTxId;
        _settledPayments[tradeId].bundlerHash = bundlerHash;

        emit MadePayment(
            sender,
            requester,
            tradeId,
            tradeData.tradeInfo.toChain[1],
            bundle.paymentTxId,
            bundle.tradeIds,
            bundle.startIdx
        );
    }

    /**
        @notice Submits a payment confirmation for a trade.
        @dev Caller must be the `Router` contract. Cannot modify the confirmation once submitted.
        @param requester The authorized `MPC Node`.
        @param tradeId The unique identifier of the trade.
        @param signature The signature provided by the MPC's threshold key.
    */
    function confirmPayment(
        address requester,
        bytes32 tradeId,
        bytes calldata signature
    )
        external
        override
        onlyMPCNode(requester)
        isSuspended(STAGE.CONFIRM_PAYMENT)
    {
        /// Ensure the trade is at the correct stage and has not timeout
        TradeData memory tradeData = _trades[tradeId];
        PMMSelection memory info = _pmmSelection[tradeId];
        _validateStageAndTimeout(
            tradeId,
            tradeData.scriptInfo.scriptTimeout,
            STAGE.CONFIRM_PAYMENT
        );

        /// Validate signature
        address signer;
        bytes32 paymentHash;
        {
            uint256 totalFeeAmount = _feeDetails[tradeId].totalAmount;
            paymentHash = keccak256(
                abi.encode(
                    totalFeeAmount,
                    info.pmmInfo.amountOut - totalFeeAmount,
                    tradeData.tradeInfo.toChain
                )
            );
        }
        bytes memory paymentTxId = _settledPayments[tradeId].paymentTxId;
        signer = _signer().getPaymentConfirmationSigner(
            tradeId,
            keccak256(abi.encode(paymentHash, paymentTxId)),
            signature
        );
        _isValidMPCSignature(
            signer,
            tradeData.tradeInfo.fromChain[1],
            tradeData.scriptInfo.depositInfo[3]
        );

        /// Advance trade stage and mark the payment as confirmed
        /// @dev Prevent further updates for the same payment transaction
        /// by setting `_paymentTxConfirmed[paymentTxId] = true`
        _currentStages[tradeId]++;
        _settledPayments[tradeId].isConfirmed = true;
        _paymentTxConfirmed[paymentTxId] = true;

        emit PaymentConfirmed(msg.sender, signer, tradeId, paymentTxId);
    }

    /**
        @notice Submits the settlement confirmation for a trade.
        @dev Caller must be the `Router` contract. Cannot modify the confirmation once submitted.
        @param requester The authorized `MPC Node`.
        @param tradeId The unique identifier of the trade.
        @param releaseTxId The transaction hash of the released settlement on the Bitcoin network.
        @param signature The signature provided by the MPC's threshold key.
    */
    function confirmSettlement(
        address requester,
        bytes32 tradeId,
        bytes calldata releaseTxId,
        bytes calldata signature
    )
        external
        override
        onlyMPCNode(requester)
        isSuspended(STAGE.CONFIRM_SETTLEMENT)
    {
        /// Ensure the trade is at the correct stage
        TradeData memory tradeData = _trades[tradeId];
        _validateStage(tradeId, STAGE.CONFIRM_SETTLEMENT);

        /// Validate the provided signature
        address signer = _signer().getSettlementConfirmationSigner(
            tradeId,
            keccak256(abi.encode(ZERO_VALUE, releaseTxId)),
            signature
        );
        _isValidMPCSignature(
            signer,
            tradeData.tradeInfo.fromChain[1],
            tradeData.scriptInfo.depositInfo[3]
        );

        /// Advance trade stage and record the settlement transaction hash
        _currentStages[tradeId]++;
        _settledPayments[tradeId].releaseTxId = releaseTxId;

        emit SettlementConfirmed(msg.sender, signer, tradeId, releaseTxId);
    }
}
