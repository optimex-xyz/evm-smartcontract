// SPDX-License-Identifier: None
pragma solidity ^0.8.20;

/**
    @title IWrappedToken Interface
    @dev Defines the interface for wrapping and unwrapping ETH.
*/
interface IWrappedToken {
    /**
        @notice Deposits ETH and wraps it into the wrapped token.
        @dev The caller must send ETH along with the transaction.
    */
    function deposit() external payable;

    /**
        @notice Unwraps the wrapped token and withdraws ETH.
        @dev Converts `wad` amount of wrapped tokens back into ETH and transfers it to the caller.
        @param wad The amount of wrapped tokens to unwrap and withdraw.
    */
    function withdraw(uint wad) external;
}
