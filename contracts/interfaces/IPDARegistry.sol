// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

interface IPDARegistry {
    /** 
        @notice Validates one `pubkey` matches the PDA's pubkey associated with `tokenId` and `networkId`.
        @param networkId The unique identifier given to the Solana network.
        @param tokenId The unique identifier for the token.
        @param pubkey The PDA Vault's pubkey to validate.
        @return True if the given `pubkey` matches, otherwise false.
    */
    function isValidVault(
        bytes calldata networkId,
        bytes calldata tokenId,
        bytes calldata pubkey
    ) external view returns (bool);
}
