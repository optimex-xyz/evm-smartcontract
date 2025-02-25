// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

interface IRouter {
    /**
        @notice Retrieves the current `Management` contract's address.
        @return The `Management` contract address.
    */
    function management() external view returns (address);

    /**
        @notice Retrieves the immutable `Signer` contract's address.
        @return The `Signer` contract address.
    */
    function SIGNER() external view returns (address);
}
