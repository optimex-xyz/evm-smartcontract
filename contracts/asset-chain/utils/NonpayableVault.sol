// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

import "./BaseVault.sol";
import "../interfaces/INonpayableVault.sol";

/*************************************************************************************************
                                  =========== PetaFi ===========
    @title NonpayableVault contract (Abstract)                      
    @dev This contract defines fundamental interfaces for TokenVault contracts.
    Handles the necessary logic for: 
        - Depositing and locking funds (ERC-20 Token only)
        - Settling payments
        - Issuing refunds.
**************************************************************************************************/

abstract contract NonpayableVault is BaseVault, INonpayableVault {
    constructor(
        address pAddress,
        string memory name,
        string memory version
    ) BaseVault(pAddress, name, version) {}

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
    ) external virtual;
}
