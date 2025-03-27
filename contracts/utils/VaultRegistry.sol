// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "../interfaces/IManagement.sol";
import "./Errors.sol";

/***********************************************************************************************************
    @title VaultRegistry contract                               
    @dev This contract functions as the helper contract within the Protocol.
    - Supports to register the locking Vaults on EVM compatible asset-chains.
    - Validate whether `Vault` address, specified in the `tradeId`, is valid.
************************************************************************************************************/

contract VaultRegistry {
    /// Address of Management contract for permission control
    IManagement public management;

    /// mapping to store Vault contract addresses for each asset-chain
    /// keccak256(abi.encode(networkId, tokenId)) => vault
    mapping(bytes32 => address) private _vaults;

    /**
        @dev Event emitted when the Owner successfully updates a Vault's address for a specific `networkId` and `tokenId`.
        @param operator The address of the operator updating the Vault's address.
        @param previousVault The previous Vault's address.
        @param newVault The new Vault's address.
        @param networkId The unique identifier given to the asset-chain network.
        @param tokenId The unique identifier for the token.
        @dev Related function: setVault()
    */
    event AssetVaultUpdated(
        address indexed operator,
        address indexed previousVault,
        address indexed newVault,
        bytes networkId,
        bytes tokenId
    );

    modifier onlyManagementOwner() {
        if (msg.sender != management.owner()) revert Unauthorized();
        _;
    }

    modifier notAddressZero(address checkingAddress) {
        if (checkingAddress == address(0)) revert AddressZero();
        _;
    }

    constructor(IManagement management_) {
        management = management_;
    }

    /** 
        @notice Updates a new Management's contract address.
        @dev Caller must be the `Owner` of the current Management contract.
        @param newManagement The new Management contract's address.
    */
    function setManagement(
        address newManagement
    ) external onlyManagementOwner notAddressZero(newManagement) {
        management = IManagement(newManagement);
    }

    /** 
        @notice Retrieves the Vault's address associated with `tokenId` and `networkId`.
        @param networkId The unique identifier assigned to the network (asset-chain).
        @param tokenId The unique identifier assigned to the token.
        @return The Vault's address associated with the given `tokenId` and `networkId`, if found.
    */
    function getVault(
        bytes calldata networkId,
        bytes calldata tokenId
    ) external view returns (address) {
        bytes32 infoHash = keccak256(abi.encode(networkId, tokenId));
        return _vaults[infoHash];
    }

    /** 
        @notice Sets the Vault's address for a specific `tokenId` and `networkId`.
        @dev Caller must be the `Owner` of the current Management contract.
        @param vault The address of the deployed Vault contract on the `networkId`.
        @param networkId The unique identifier assigned to the network (asset-chain).
        @param tokenId The unique identifier assigned to the token.
    */
    function setVault(
        address vault,
        bytes calldata networkId,
        bytes calldata tokenId
    ) external onlyManagementOwner notAddressZero(vault) {
        /// validate whether `tokenId` is currently supported on the `networkId`
        if (!management.isValidToken(networkId, tokenId))
            revert TokenNotSupported();

        bytes32 infoHash = keccak256(abi.encode(networkId, tokenId));
        address previousVault = _vaults[infoHash];
        _vaults[infoHash] = vault;

        emit AssetVaultUpdated(
            msg.sender,
            previousVault,
            vault,
            networkId,
            tokenId
        );
    }

    /** 
        @notice Removes the Vault's address associated with `tokenId` and `networkId`.
        @dev Caller must be the `Owner` of the current Management contract.
        @param networkId The unique identifier assigned to the network (asset-chain).
        @param tokenId The unique identifier assigned to the token.
    */
    function removeVault(
        bytes calldata networkId,
        bytes calldata tokenId
    ) external onlyManagementOwner {
        bytes32 infoHash = keccak256(abi.encode(networkId, tokenId));
        address previousVault = _vaults[infoHash];
        if (previousVault == address(0)) revert VaultNotFound();

        delete _vaults[infoHash];

        emit AssetVaultUpdated(
            msg.sender,
            previousVault,
            address(0),
            networkId,
            tokenId
        );
    }
}
