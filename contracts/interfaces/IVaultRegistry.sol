// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

interface IVaultRegistry {
    /** 
        @notice Retrieves the Vault's address associated with `tokenId` and `networkId`.
        @param networkId The unique identifier assigned to the network (asset-chain).
        @param tokenId The unique identifier assigned to the token.
        @return The Vault's address associated with the given `tokenId` and `networkId`, if found.
    */
    function getVault(
        bytes calldata networkId,
        bytes calldata tokenId
    ) external view returns (address);
}
