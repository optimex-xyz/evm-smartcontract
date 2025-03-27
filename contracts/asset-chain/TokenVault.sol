// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";

import "./utils/NonpayableVault.sol";

/*************************************************************************************************
    @title TokenVault contract                            
    @dev This contract is used as the Vault Contract across various asset chains.
    Handles the necessary logic for: 
        - Depositing and locking funds (ERC-20 Token Only)
        - Settling payments
        - Issuing refunds.
**************************************************************************************************/

contract TokenVault is NonpayableVault, ReentrancyGuardTransient {
    using SafeERC20 for IERC20;

    /// Address of the deposited and settle token
    address public immutable LOCKING_TOKEN;

    constructor(
        address pAddress,
        address tokenAddress
    ) NonpayableVault(pAddress, "Token Vault", "Version 1") {
        LOCKING_TOKEN = tokenAddress;
    }

    /**
        @notice Deposits the specified `amount` (ERC-20 tokens only) 
            to initialize the `tradeId` and lock the funds.
        @param ephemeralL2Address The address, derived from `ephemeralL2Key`, used for validation in the Protocol.
        @param input The `TradeInput` object containing trade-related information.
        @param data The `TradeDetail` object containing trade details for finalization on the asset chain.
    */
    function deposit(
        address ephemeralL2Address,
        TradeInput calldata input,
        TradeDetail calldata data
    ) external override(NonpayableVault) {
        /// Validate the following:
        /// - `fromUserAddress` and `msg.sender` to ensure the trade is deposited by the correct caller.
        /// - Ensure `fromTokenId` and `LOCKING_TOKEN` are matched.
        /// - Ensure the trade has not exceeded the `timeout`.
        /// - Ensure two following constraints:
        ///     - `amount` should not be 0
        ///     - `amount` (in the TradeDetail) and `amountIn` (in the TradeInput) is equal
        /// - Ensure `mpc`, `ephemeralAssetAddress`, and `refundAddress` are not 0x0.
        address fromUserAddress = address(
            bytes20(input.tradeInfo.fromChain[0])
        );
        address token = address(bytes20(input.tradeInfo.fromChain[2]));
        if (
            input.tradeInfo.fromChain[0].length != 20 ||
            input.tradeInfo.fromChain[2].length != 20
        ) revert InvalidAddressLength();
        if (fromUserAddress != msg.sender) revert Unauthorized();
        if (token != LOCKING_TOKEN) revert InvalidDepositToken();
        if (block.timestamp > data.timeout) revert InvalidTimeout();
        if (data.amount == 0 || data.amount != input.tradeInfo.amountIn)
            revert InvalidDepositAmount();
        if (
            data.mpc == address(0) ||
            data.ephemeralAssetAddress == address(0) ||
            data.refundAddress == address(0)
        ) revert AddressZero();

        /// transfer `amount` to the Vault contract
        IERC20(LOCKING_TOKEN).safeTransferFrom(
            fromUserAddress,
            address(this),
            data.amount
        );

        /// Calculate the `tradeId` based on the `input` and record a hash of trade detail object.
        /// Ensure deposit rejection for duplicate `tradeId`
        bytes32 tradeId = sha256(
            abi.encode(input.sessionId, input.solver, input.tradeInfo)
        );
        if (_tradeHashes[tradeId] != _EMPTY_HASH) revert DuplicatedDeposit();
        _tradeHashes[tradeId] = _getTradeHash(data);

        emit Deposited(
            tradeId,
            fromUserAddress,
            LOCKING_TOKEN,
            ephemeralL2Address,
            data
        );
    }

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
    ) external override(BaseVault, IBaseVault) nonReentrant {
        /// @dev:
        /// - Not checking `protocolFee` due to reasons:
        ///     - `protocolFee` is submitted by MPC
        ///     - MPC's also required to submit settlement confirmation in the Protocol
        /// - Ensure a hash of trade detail matches the one recorded when deposit
        /// - MPC allowed to transfer when `timestamp <= timeout`
        if (_tradeHashes[tradeId] != _getTradeHash(detail))
            revert TradeDetailNotMatched();
        if (block.timestamp > detail.timeout) revert Timeout();

        {
            /// validate `presign`
            address signer = _getPresignSigner(
                tradeId,
                keccak256(abi.encode(toAddress, detail.amount)),
                presign
            );
            if (signer != detail.ephemeralAssetAddress) revert InvalidPresign();

            /// validate `mpcSignature`
            signer = _getSettlementSigner(totalFee, presign, mpcSignature);
            if (signer != detail.mpc) revert InvalidMPCSign();
        }

        /// Delete storage before making a transfer
        delete _tradeHashes[tradeId];

        /// When `totalFee != 0`, transfer `totalFee`
        address pFeeAddr = protocol.pFeeAddr();
        if (totalFee != 0) _transfer(LOCKING_TOKEN, pFeeAddr, totalFee);

        /// transfer remaining balance to `toAddress`
        uint256 settleAmount = detail.amount - totalFee;
        _transfer(LOCKING_TOKEN, toAddress, settleAmount);

        emit Settled(
            tradeId,
            LOCKING_TOKEN,
            toAddress,
            msg.sender,
            settleAmount, //  amount after fee
            pFeeAddr,
            totalFee
        );
    }

    /**
        @notice Transfers the locked funds to the `refundAddress` for the specified trade.
        @dev Can only be claimed if `block.timestamp > timeout`
        @param tradeId The unique identifier assigned to the trade.
        @param detail The trade details, including relevant trade parameters.
    */
    function claim(
        bytes32 tradeId,
        TradeDetail calldata detail
    ) external override(BaseVault, IBaseVault) nonReentrant {
        if (_tradeHashes[tradeId] != _getTradeHash(detail))
            revert TradeDetailNotMatched();
        if (block.timestamp <= detail.timeout) revert ClaimNotAvailable();

        /// Delete storage before making a transfer
        delete _tradeHashes[tradeId];
        _transfer(LOCKING_TOKEN, detail.refundAddress, detail.amount);

        emit Claimed(
            tradeId,
            LOCKING_TOKEN,
            detail.refundAddress,
            msg.sender,
            detail.amount
        );
    }
}
