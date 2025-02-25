// SPDX-License-Identifier: None
pragma solidity ^0.8.20;

import "./ITypes.sol";

/**
    @title IManagement contract
    @dev Provide interfaces that allow interaction to Management contract
*/
interface IManagement {
    /**
        @notice Returns the address of the current owner.
        @return The address of the contract owner.
    */
    function owner() external view returns (address);

    /**
        @notice Returns the current setting of the protocol's fee rate.
        @return The current protocol's fee rate as a uint256.
    */
    function pFeeRate() external view returns (uint256);

    /**
        @notice Returns the current status of the PetaFi Protocol.
        @return The current state of the protocol as a uint256.
    */
    function state() external view returns (uint256);

    /**
        @notice Checks if a given `account` is assigned as a Solver.
        @param account The address to validate as a Solver.
        @return True if the `account` is a Solver, false otherwise.
    */
    function solvers(address account) external view returns (bool);

    /**
        @notice Checks if a given `account` is assigned as an MPC Node's associated account.
        @param account The address to validate as an MPC Node's associated account.
        @return True if the `account` is an MPC Node's associated account, false otherwise.
    */
    function mpcNodes(address account) external view returns (bool);

    /** 
        @notice Returns the total number of supported tokens in the Protocol.
        @return The total number of supported tokens as a uint256.
    */
    function numOfSupportedTokens() external view returns (uint256);

    /** 
        @notice Retrieves a list of `TokenInfo` objects within the specified range [fromIdx, toIdx - 1].
        @param fromIdx The starting index of the range (inclusive).
        @param toIdx The ending index of the range (exclusive).
        @return list An array of `TokenInfo` objects within the specified range.
    */
    function getTokens(
        uint256 fromIdx,
        uint256 toIdx
    ) external view returns (ITypes.TokenInfo[] memory list);

    /** 
        @notice Checks if a given `networkId` is currently supported.
        @param networkId The unique identifier assigned to a network.
        @return True if the network is supported, otherwise false.
    */
    function isValidNetwork(
        bytes calldata networkId
    ) external view returns (bool);

    /** 
        @notice Checks if a given `tokenId` of a `networkId` is currently supported.
        @param networkId The unique identifier assigned to a network.
        @param tokenId The unique identifier assigned to a token within the network.
        @return True if the token is supported, otherwise false.
    */
    function isValidToken(
        bytes calldata networkId,
        bytes calldata tokenId
    ) external view returns (bool);

    /** 
        @notice Validates whether a given `pubkey` is registered and not expired.
        @param networkId The unique identifier assigned to a network.
        @param pubkey The `mpcAssetPubkey` or `mpcL2Pubkey` to validate.
        @return True if the pubkey is valid, otherwise false.
    */
    function isValidPubkey(
        bytes calldata networkId,
        bytes calldata pubkey
    ) external view returns (bool);

    /** 
        @notice Retrieves the most recent MPC pubkeys for a given `networkId`.
        @param networkId The unique identifier assigned to a network.
        @return The latest MPCInfo object for the specified network.
    */
    function getLatestMPCInfo(
        bytes calldata networkId
    ) external view returns (ITypes.MPCInfo memory);

    /**
        @notice Retrieves MPC information associated with a given `networkId` and `pubkey`.
        @param networkId The unique identifier for the network.
        @param pubkey The `mpcL2Pubkey` or `mpcAssetPubkey`.
        @return The MPCInfo struct containing details of MPC's pubkeys.
    */
    function getMPCInfo(
        bytes calldata networkId,
        bytes calldata pubkey
    ) external view returns (ITypes.MPCInfo memory);

    /** 
        @notice Checks if a given `networkId` is currently supported.
        @param pmmId The unique identifier assigned to one `PMM`.
        @return True if the network is supported, otherwise false.
    */
    function isValidPMM(bytes32 pmmId) external view returns (bool);

    /** 
        @notice Validates whether `account` is an associated account of `pmmId`.
        @param pmmId The unique identifier assigned to a `PMM`.
        @param account The PMM's associated account address.
        @return True if the account is associated with the PMM, otherwise false.
    */
    function isValidPMMAccount(
        bytes32 pmmId,
        address account
    ) external view returns (bool);

    /** 
        @notice Queries the total number of associated accounts for a given `pmmId`.
        @param pmmId The unique identifier assigned to a `PMM`.
        @return The number of associated accounts for the `pmmId`.
    */
    function numOfPMMAccounts(bytes32 pmmId) external view returns (uint256);

    /** 
        @notice Queries a list of associated accounts for a given `pmmId` within the specified range.
        @param pmmId The unique identifier assigned to a `PMM`.
        @param fromIdx The starting index.
        @param toIdx The ending index.
        @return A list of associated accounts within the specified range.
    */
    function getPMMAccounts(
        bytes32 pmmId,
        uint256 fromIdx,
        uint256 toIdx
    ) external view returns (address[] memory);

    /** 
        @notice Checks if the current `stage` is suspended.
        @param stage The current stage to check.
        @return True if the protocol is suspended, otherwise false.
    */
    function isSuspended(ITypes.STAGE stage) external view returns (bool);
}
