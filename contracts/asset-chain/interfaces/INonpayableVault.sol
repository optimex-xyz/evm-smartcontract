// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./IBaseVault.sol";

interface INonpayableVault is IBaseVault {
    /**
        @notice Deposits the specified `amount` (ERC-20 tokens only) 
            to initialize the `tradeId` and lock the funds.
        @param ephemeralL2Address The address, derived from `ephemeralL2Key`, used for validation in the PetaFi Protocol.
        @param input The `TradeInput` object containing trade-related information.
        @param data The `TradeDetail` object containing trade details for finalization on the asset chain.
    */
    function deposit(
        address ephemeralL2Address,
        TradeInput calldata input,
        TradeDetail calldata data
    ) external;
}
