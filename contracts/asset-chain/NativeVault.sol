// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";

import "./utils/PayableVault.sol";

/*************************************************************************************************
                                  =========== PetaFi ===========
    @title NativeVault contract                            
    @dev This contract is used as the PetaFi Vault Contract across various asset chains.
    Handles the necessary logic for: 
        - Depositing and locking funds (Native Token only)
        - Settling payments
        - Issuing refunds.
**************************************************************************************************/

contract NativeVault is PayableVault, ReentrancyGuardTransient {
    address public immutable WRAPPED_TOKEN;

    /// @dev keccak256(toUtf8Bytes("native"))
    bytes32 private constant NATIVE =
        0xbefae8b7ff926e5ec4428d291aa6cb21f134a3e9f02ace30ff61c382a104c57f;

    constructor(
        address pAddress,
        address tokenAddress
    ) PayableVault(pAddress, "Native Vault", "Version 1") {
        WRAPPED_TOKEN = tokenAddress;
    }

    /**
        @notice Deposits the specified `amount` (Native Coin only) 
            to initialize the `tradeId` and lock the funds.
        @param ephemeralL2Address The address, derived from `ephemeralL2Key`, used for validation in the PetaFi Protocol.
        @param input The `TradeInput` object containing trade-related information.
        @param data The `TradeDetail` object containing trade details for finalization on the asset chain.
    */
    function deposit(
        address ephemeralL2Address,
        TradeInput calldata input,
        TradeDetail calldata data
    ) external payable override(PayableVault) {
        /// Validate the following:
        /// - `fromUserAddress` and `msg.sender` to ensure the trade is deposited by the correct caller.
        /// - Ensure `fromTokenId = toUtf8Bytes("native")`
        /// - Ensure the trade has not exceeded the `timeout`.
        /// - Ensure three following constraints:
        ///     - `amount` should not be 0
        ///     - `amount` (in the TradeDetail) and `amountIn` (in the TradeInput) is equal
        ///     - `msg.value` equals `amount`
        /// - `amount` should not be 0 and `msg.value` equals `amount`.
        /// - Ensure `mpc`, `ephemeralAssetAddress`, and `refundAddress` are not 0x0.
        address fromUserAddress = address(
            bytes20(input.tradeInfo.fromChain[0])
        );
        if (input.tradeInfo.fromChain[0].length != 20)
            revert InvalidAddressLength();
        if (fromUserAddress != msg.sender) revert Unauthorized();
        if (keccak256(input.tradeInfo.fromChain[2]) != NATIVE)
            revert InvalidDepositToken();
        if (block.timestamp > data.timeout) revert InvalidTimeout();
        if (
            data.amount == 0 ||
            msg.value != data.amount ||
            data.amount != input.tradeInfo.amountIn
        ) revert InvalidDepositAmount();
        if (
            data.mpc == address(0) ||
            data.ephemeralAssetAddress == address(0) ||
            data.refundAddress == address(0)
        ) revert AddressZero();

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
            address(0),
            ephemeralL2Address,
            data
        );
    }

    /**
        @notice Transfers the specified `amount` to `toAddress` to finalize the trade identified by `tradeId`.
        @dev Can only be executed if `block.timestamp <= timeout`.
        @param tradeId The unique identifier assigned to a trade.
        @param totalFee The total amount deducted as a fee.
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
        ///     - MPC's also required to submit settlement confirmation in the PetaFi Protocol
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
        if (totalFee != 0) _transfer(address(0), pFeeAddr, totalFee);

        /// transfer remaining balance to `toAddress`
        /// @dev: For native coin, converting into wrapped token then making a transfer
        uint256 settleAmount = detail.amount - totalFee;
        IWrappedToken(WRAPPED_TOKEN).deposit{value: settleAmount}();
        _transfer(WRAPPED_TOKEN, toAddress, settleAmount);

        emit Settled(
            tradeId,
            address(0), //  native coin (0x0)
            toAddress,
            msg.sender,
            settleAmount,
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
        _transfer(address(0), detail.refundAddress, detail.amount);

        emit Claimed(
            tradeId,
            address(0),
            detail.refundAddress,
            msg.sender,
            detail.amount
        );
    }
}
