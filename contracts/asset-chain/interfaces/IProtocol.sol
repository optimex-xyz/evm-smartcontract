// SPDX-License-Identifier: None
pragma solidity ^0.8.20;

interface IProtocol {
    /**
        @notice Returns the address of the current owner.
        @return The address of the contract owner.
    */
    function owner() external view returns (address);

    /**
        @notice Returns the current address of the Protocol Fee Receiver.
        @return The protocol fee receiver's address.
    */
    function pFeeAddr() external view returns (address);
}
