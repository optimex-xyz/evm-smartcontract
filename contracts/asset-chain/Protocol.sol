// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";

import "./utils/AssetChainErrors.sol";

/******************************************************************************************
                              =========== PetaFi ===========
    @title Protocol contract                            
    @dev This contract is used as the PetaFi Protocol Contract across various asset chains.
    - Manages the Owner, who has special privileges to upgrade settings.
    - Manages the Protocol Fee Receiver.
*******************************************************************************************/

contract Protocol is Ownable {
    /// Address of Protocol Fee receiver
    address public pFeeAddr;

    /**
        @notice Emitted when the Protocol Fee Receiver address is updated.
        @param operator The address of the caller (Owner) who performed the update.
        @param newPFeeAddr The new Protocol Fee Receiver address.
        @dev Related function: `setPFeeAddress()`.
    */
    event PFeeAddressUpdated(address indexed operator, address newPFeeAddr);

    constructor(address initOwner, address pFeeAddress) Ownable(initOwner) {
        pFeeAddr = pFeeAddress;
    }

    /**
        @notice Sets a new Protocol Fee Receiver address.
        @dev Caller must be the current `Owner`.
        @param newPFeeAddr The new address to receive protocol fees.
    */
    function setPFeeAddress(address newPFeeAddr) external onlyOwner {
        if (newPFeeAddr == address(0)) revert AddressZero();

        pFeeAddr = newPFeeAddr;

        emit PFeeAddressUpdated(_msgSender(), newPFeeAddr);
    }
}
