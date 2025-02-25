// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import "./interfaces/ITypes.sol";
import "./utils/Errors.sol";

/**************************************************************************************
                          =========== PetaFi ===========
    @title Management contract                               
    @dev This contract functions as the mini-governance of the PetaFi Protocol.
    - Manage the protocol's operational status.
    - Maintain the protocol's fee rate.
    - Maintain a list of authorized `Solver` addresses.
    - Maintain a list of authorized `MPC Nodes`.
    - Manages a list of supported Networks and Tokens on each network.
    - Manages a list of MPC public keys and their corresponding derived addresses.
    - Manages a list of supported PMMs and their associated accounts.
***************************************************************************************/
contract Management is Ownable, ITypes {
    using EnumerableSet for EnumerableSet.AddressSet;

    /// Protocol fee rate in basis points (bps). Example: 50 bps = 50 / 10,000 = 0.5%.
    uint256 public pFeeRate;

    /// Current operational state of the PetaFi Protocol
    Status public state;

    /// List of authorized `Solver` addresses
    mapping(address => bool) public solvers;

    /// List of authorized MPC nodes
    mapping(address => bool) public mpcNodes;

    /// Tracks the number of supported tokens per network (`networkId` => token count)
    mapping(bytes => uint256) private _numOfTokens;

    /// Mapping to store the index of an MPC's `mpcAssetPubkey` or `mpcL2Pubkey` in the `_mpcPubkeys`
    mapping(bytes32 => uint256) private _keyToIndex;

    /// Tracks the stored index of supported tokens, keyed by `keccak256(networkId, tokenId) => index`
    mapping(bytes32 => uint256) private _tokenToIndex;

    /// Mapping of `networkId` to authorized MPC's pubkeys, including expiration times.
    mapping(bytes => MPCInfo[]) private _mpcPubkeys;

    /// Mapping of `PMM` identifiers (`pmmId`) to their associated account addresses (as a set)
    mapping(bytes32 => EnumerableSet.AddressSet) private _pmmAccounts;

    /// List of all supported token information
    TokenInfo[] private _tokenInfoList;

    /**
        @dev Emitted when the Owner successfully adds or removes a `Solver`.
        @param solver The address of the `Solver` being added or removed.
        @param isSolver Indicates whether the `Solver` is being added (true) or removed (false).
        @dev Related function: setSolver()
    */
    event UpdatedSolver(address indexed solver, bool isSolver);

    /**
        @dev Emitted when the Owner successfully adds or removes an MPC Node.
        @param account The address of the MPC Node being added or removed.
        @param isMPC Indicates whether the node is being added (true) or removed (false).
        @dev Related function: setMPCNode()
    */
    event UpdatedMPCNode(address indexed account, bool isMPC);

    /**
        @dev Emitted when the Owner successfully adds or removes a supported token.
        @param networkId The unique identifier of the network.
        @param tokenId The unique identifier of the token within the network.
        @param isAdded Indicates whether the token is being added (true) or removed (false).
        @dev Related functions: setToken() and removeToken()
    */
    event UpdatedToken(bytes networkId, bytes tokenId, bool isAdded);

    /**
        @dev Event emitted when the Owner successfully adds or removes an authorized PMM.
        @param pmmId The unique identifier of the PMM being added or removed.
        @param isAdded Boolean indicating whether the PMM was added (`true`) or removed (`false`).
        @dev Related function: setPMM() and removePMM()
    */
    event UpdatedPMM(bytes32 indexed pmmId, bool isAdded);

    /**
        @dev Event emitted when the Owner successfully adds or removes a PMM's associated account.
        @param pmmId The unique identifier of the PMM.
        @param account The address of the associated account being added or removed.
        @param isAdded Boolean indicating whether the account was added (`true`) or removed (`false`).
        @dev Related functions: setPMMAccount()
    */
    event UpdatedPMMAccount(
        bytes32 indexed pmmId,
        address indexed account,
        bool isAdded
    );

    /**
        @dev Event emitted when the Owner successfully adds a new authorized MPC's public keys.
        @param mpcL2Address The address derived from `mpcL2Pubkey`.
        @param mpcL2Pubkey The MPC's pubkey for PetaFi L2 operations.
        @param mpcAssetPubkey The MPC's pubkey for asset-chain operations.
        @param networkId The identifier of the network where the MPC is being updated.
        @dev Related function: setMPCInfo()
    */
    event UpdatedMPCInfo(
        address indexed mpcL2Address,
        bytes mpcL2Pubkey,
        bytes mpcAssetPubkey,
        bytes networkId
    );

    /**
        @notice Emitted when an MPC's pubkey is revoked for a specific network.
        @param networkId The identifier of the network where the MPC's pubkey was revoked.
        @param pubkey The `mpcAssetPubkey` or `mpcL2Pubkey`
        @dev Related function: revokeMPCKey()
    */
    event RevokedMPCKey(bytes networkId, bytes pubkey);

    /**
        @dev Event emitted when the Owner successfully calls to suspend the protocol.
        @param owner The address of the Owner who triggered the suspension.
        @dev Related function: `suspend()`
    */
    event Suspended(address indexed owner);

    /**
        @dev Event emitted when the Owner successfully calls to shutdown the protocol.
        @param owner The address of the Owner who triggered the shutdown.
        @dev Related function: `shutdown()`
    */
    event Shutdown(address indexed owner);

    /**
        @dev Event emitted when the Owner successfully calls to resume the protocol.
        @param owner The address of the Owner who triggered the resume.
        @dev Related function: `resume()`
    */
    event Resume(address indexed owner);

    modifier notAddressZero(address checkingAddress) {
        if (checkingAddress == address(0)) revert AddressZero();
        _;
    }

    constructor(address initOwner, uint256 pFeeRate_) Ownable(initOwner) {
        pFeeRate = pFeeRate_;
    }

    /** 
        @notice Returns the total number of supported tokens in the Protocol.
        @return The total number of supported tokens as a uint256.
    */
    function numOfSupportedTokens() external view returns (uint256) {
        return _tokenInfoList.length;
    }

    /** 
        @notice Retrieves a list of `TokenInfo` objects within the specified range [fromIdx, toIdx - 1].
        @param fromIdx The starting index of the range (inclusive).
        @param toIdx The ending index of the range (exclusive).
        @return list An array of `TokenInfo` objects within the specified range.
    */
    function getTokens(
        uint256 fromIdx,
        uint256 toIdx
    ) external view returns (TokenInfo[] memory list) {
        if (toIdx > _tokenInfoList.length) revert OutOfRange();

        uint256 len = toIdx - fromIdx;
        list = new TokenInfo[](len);
        for (uint256 i; i < len; i++) list[i] = _tokenInfoList[fromIdx + i];
    }

    /** 
        @notice Checks if a given `networkId` is currently supported.
        @param networkId The unique identifier assigned to a network.
        @return True if the network is supported, otherwise false.
    */
    function isValidNetwork(
        bytes calldata networkId
    ) external view returns (bool) {
        return _isValidNetwork(networkId);
    }

    /** 
        @notice Checks if a given `tokenId` of a `networkId` is currently supported.
        @param networkId The unique identifier assigned to a network.
        @param tokenId The unique identifier assigned to a token within the network.
        @return True if the token is supported, otherwise false.
    */
    function isValidToken(
        bytes calldata networkId,
        bytes calldata tokenId
    ) external view returns (bool) {
        bytes32 idHash = _getHash(networkId, tokenId);
        return _tokenToIndex[idHash] != 0;
    }

    /** 
        @notice Validates whether a given `pubkey` is registered and not expired.
        @param networkId The unique identifier assigned to a network.
        @param pubkey The `mpcAssetPubkey` or `mpcL2Pubkey` to validate.
        @return True if the pubkey is valid, otherwise false.
    */
    function isValidPubkey(
        bytes calldata networkId,
        bytes calldata pubkey
    ) external view returns (bool) {
        uint256 index = _keyToIndex[_getHash(networkId, pubkey)];
        if (index == 0) return false;

        return block.timestamp <= _mpcPubkeys[networkId][index - 1].expireTime;
    }

    /** 
        @notice Retrieves the most recent MPC pubkeys for a given `networkId`.
        @param networkId The unique identifier assigned to a network.
        @return info The latest MPCInfo object for the specified network.
    */
    function getLatestMPCInfo(
        bytes calldata networkId
    ) external view returns (MPCInfo memory info) {
        uint256 len = _mpcPubkeys[networkId].length;
        if (len > 0) info = _mpcPubkeys[networkId][len - 1];
    }

    /**
        @notice Retrieves MPC information associated with a given `networkId` and `pubkey`.
        @param networkId The unique identifier for the network.
        @param pubkey The `mpcL2Pubkey` or `mpcAssetPubkey`.
        @return info The MPCInfo struct containing details of MPC's pubkeys.
    */
    function getMPCInfo(
        bytes calldata networkId,
        bytes calldata pubkey
    ) external view returns (MPCInfo memory info) {
        uint256 index = _keyToIndex[_getHash(networkId, pubkey)];
        if (index != 0) info = _mpcPubkeys[networkId][index - 1];
    }

    /** 
        @notice Checks if a given `networkId` is currently supported.
        @param pmmId The unique identifier assigned to one `PMM`.
        @return True if the network is supported, otherwise false.
    */
    function isValidPMM(bytes32 pmmId) external view returns (bool) {
        return _isValidPMM(pmmId);
    }

    /** 
        @notice Validates whether `account` is an associated account of `pmmId`.
        @param pmmId The unique identifier assigned to a `PMM`.
        @param account The PMM's associated account address.
        @return True if the account is associated with the PMM, otherwise false.
    */
    function isValidPMMAccount(
        bytes32 pmmId,
        address account
    ) external view returns (bool) {
        /// @dev: Returns false when either `pmmId` or `account` is unregistered
        return _pmmAccounts[pmmId].contains(account);
    }

    /** 
        @notice Queries the total number of associated accounts for a given `pmmId`.
        @param pmmId The unique identifier assigned to a `PMM`.
        @return The number of associated accounts for the `pmmId`.
    */
    function numOfPMMAccounts(bytes32 pmmId) external view returns (uint256) {
        return _numOfPMMAccounts(pmmId);
    }

    /** 
        @notice Queries a list of associated accounts for a given `pmmId` within the specified range.
        @param pmmId The unique identifier assigned to a `PMM`.
        @param fromIdx The starting index.
        @param toIdx The ending index.
        @return list A list of associated accounts within the specified range.
    */
    function getPMMAccounts(
        bytes32 pmmId,
        uint256 fromIdx,
        uint256 toIdx
    ) external view returns (address[] memory list) {
        uint256 maxSize = _numOfPMMAccounts(pmmId);
        if (maxSize == 0) return list;

        uint256 len = toIdx - fromIdx;
        list = new address[](len);
        for (uint256 i; i < len; i++) list[i] = _pmmAccounts[pmmId].at(i);
    }

    /** 
        @notice Checks if the current `stage` is suspended.
        @param stage The current stage to check.
        @return stop True if the protocol is suspended, otherwise false.
    */
    function isSuspended(STAGE stage) external view returns (bool stop) {
        Status currentStatus = state;
        if (
            currentStatus == Status.SHUTDOWN ||
            (currentStatus == Status.SUSPENDED && stage < STAGE.MAKE_PAYMENT)
        ) stop = true;
    }

    /** 
        @notice Sets the Protocol's status to `SUSPENDED` state.
        @dev Caller must be `Owner`
        @dev During the `SUSPENDED` state:
        - `submitTrade`, `confirmDeposit`, and `selectPMM` will be suspended.
        - `makePayment`, `confirmPayment`, and `confirmSettlement` won't be affected.
    */
    function suspend() external onlyOwner {
        state = Status.SUSPENDED;

        emit Suspended(_msgSender());
    }

    /** 
        @notice Sets the Protocol's status to `SHUTDOWN` state.
        @dev Caller must be `Owner`
        @dev During the `SHUTDOWN` state, both new and in-progress trades will be suspended.
    */
    function shutdown() external onlyOwner {
        state = Status.SHUTDOWN;

        emit Shutdown(_msgSender());
    }

    /** 
        @notice Resumes the Protocol and sets its status back to normal.
        @dev Caller must be `Owner`
    */
    function resume() external onlyOwner {
        delete state;

        emit Resume(_msgSender());
    }

    /** 
        @notice Sets a new value for the `pFeeRate`.
        @dev Caller must be `Owner`
        @param newFeeRate The new value for the protocol's fee rate.
    */
    function setFeeRate(uint256 newFeeRate) external onlyOwner {
        pFeeRate = newFeeRate;
    }

    /** 
        @notice Add/Remove an authorized `Solver`.
        @dev Caller must be `Owner`
        @param solver Address of an authorized `Solver` to be updated.
        @param isSolver New state of `Solver` (true = add; false = remove).
    */
    function setSolver(address solver, bool isSolver) external onlyOwner {
        bool isRegistered = solvers[solver];
        _validateStatus(isRegistered, isSolver);

        solvers[solver] = isSolver;

        emit UpdatedSolver(solver, isSolver);
    }

    /** 
        @notice Add/Remove an authorized `MPC Node`.
        @dev Caller must be `Owner`
        @param account The MPC Node's associated account.
        @param isMPC Option flag (true = add; false = remove).
    */
    function setMPCNode(address account, bool isMPC) external onlyOwner {
        bool isRegistered = mpcNodes[account];
        _validateStatus(isRegistered, isMPC);

        mpcNodes[account] = isMPC;

        emit UpdatedMPCNode(account, isMPC);
    }

    /** 
        @notice Adds an authorized MPC's public key information for a `networkId`.
        @dev Caller must be `Owner`
        @param networkId The unique identifier assigned to a network.
        @param info The `MPCInfo` struct containing:
        - `mpcL2Address` The address derived from `mpcL2Pubkey`.
        - `expireTime` The timestamp until which the MPC's public keys are valid.
        - `mpcAssetPubkey` The public key used by MPC on the specified `networkId`.
        - `mpcL2Pubkey` The public key used by MPC to authorize on the PetaFi Network.
        @param prevExpireTime The new expiration time for the previous MPC's public keys.
    */
    function setMPCInfo(
        bytes calldata networkId,
        MPCInfo calldata info,
        uint64 prevExpireTime
    ) external onlyOwner {
        /// Ensure the networkId is valid, and provided expireTime is in the future
        if (!_isValidNetwork((networkId))) revert NetworkNotFound();
        if (block.timestamp >= info.expireTime) revert AlreadyExpired();

        /// Store the new `info` in `_mpcPubkeys` for the specified `networkId`
        /// Update the `expireTime` for the previous key if this is an additional entry
        _mpcPubkeys[networkId].push(info);
        uint256 len = _mpcPubkeys[networkId].length;
        if (len > 1)
            _mpcPubkeys[networkId][len - 2].expireTime = prevExpireTime;

        /// Compute hashes for key mapping and map the keys to their respective index
        bytes32 assetKeyHash = _getHash(networkId, info.mpcAssetPubkey);
        bytes32 l2KeyHash = _getHash(networkId, info.mpcL2Pubkey);
        _keyToIndex[assetKeyHash] = len;
        _keyToIndex[l2KeyHash] = len;

        emit UpdatedMPCInfo(
            info.mpcL2Address,
            info.mpcL2Pubkey,
            info.mpcAssetPubkey,
            networkId
        );
    }

    /**
        @notice Revokes the specified MPC key for a given network.
        @dev Sets the expiration time of the specified MPC key to zero, effectively deactivating it.
        @dev Caller must be `Owner`
        @param networkId The identifier of the network where the MPC key is used.
        @param pubkey The public key of the MPC key to be revoked.
    */
    function revokeMPCKey(
        bytes calldata networkId,
        bytes calldata pubkey
    ) external onlyOwner {
        /// Check whether `pubkey` is registered and revoked
        uint256 index = _keyToIndex[_getHash(networkId, pubkey)];
        if (index == 0) revert InvalidPubkey();
        uint256 expireTime = _mpcPubkeys[networkId][index - 1].expireTime;
        if (expireTime == 0) revert MPCKeyAlreadyRevoked();

        _mpcPubkeys[networkId][index - 1].expireTime = 0;

        emit RevokedMPCKey(networkId, pubkey);
    }

    /** 
        @notice Set or update `tokenInfo` for a supported token.
        @dev Caller must be `Owner`
        @param tokenInfo The TokenInfo struct.
        - `tokenId` The unique identifier for the token in the `networkId`.
        - `networkId` The unique identifier for the network.
        - `symbol` The unique symbol for the token.
        - `externalURL` The URL for external data.
        - `description` A short description.
    */
    function setToken(TokenInfo calldata tokenInfo) external onlyOwner {
        /// @dev: This function can be used to update `tokenInfo` of one supported `tokenId`
        /// In that case, retrieve the index and update the `tokenInfo`
        bytes32 idHash = _getHash(tokenInfo.info[1], tokenInfo.info[0]);
        uint256 index = _tokenToIndex[idHash];
        if (index != 0) {
            /// stored index was increased by one
            _tokenInfoList[index - 1] = tokenInfo;
            return;
        }

        /// On registration:
        /// - Increase number of supported tokens for the `networkId` by 1 (`_numOfTokens`)
        /// - Push `tokenInfo` into `_tokenInfoList`
        /// - Get current length (after push) as an index, then store into mapping `_tokenToIndex`
        _numOfTokens[tokenInfo.info[1]]++;
        _tokenInfoList.push(tokenInfo);
        _tokenToIndex[idHash] = _tokenInfoList.length;

        emit UpdatedToken(tokenInfo.info[1], tokenInfo.info[0], true);
    }

    /** 
        @notice Removes one supported token.
        @dev Caller must be `Owner`
        @param networkId The unique identifier assigned to a network.
        @param tokenId The unique identifier assigned to a token in the `networkId`.
    */
    function removeToken(
        bytes calldata networkId,
        bytes calldata tokenId
    ) external onlyOwner {
        bytes32 idHash = _getHash(networkId, tokenId);
        uint256 index = _tokenToIndex[idHash];
        if (index == 0) revert UnregisteredAlready();

        /// On removing:
        /// - Decrease number of supported tokens for the `networkId` by 1 (`_numOfTokens`)
        /// - Delete index
        /// - If `_tokenInfoList` has only one left `tokenInfo`, pop the list
        /// - Otherwise, do as follows:
        ///   - Replace `index` by the last `tokenInfo`
        ///   - Update index of the replaced one
        ///   - Pop the list
        uint256 len = _tokenInfoList.length;
        TokenInfo memory lastInfo = _tokenInfoList[len - 1];
        if (len != 1) {
            _tokenInfoList[index - 1] = lastInfo;
            _tokenToIndex[_getHash(lastInfo.info[1], lastInfo.info[0])] = index;
        }

        _numOfTokens[networkId]--;
        delete _tokenToIndex[idHash];
        _tokenInfoList.pop();

        emit UpdatedToken(networkId, tokenId, false);
    }

    /** 
        @notice Add an authorized `PMM` and its first associated account.
        @dev Caller must be `Owner`
        @dev This function is used to register the `pmmId` and its first associated account.
        To register additional accounts, please use another function - setPMMAccount().
        @param pmmId The unique identifier assigned to one `PMM`.
        @param account The PMM's associated account address.
    */
    function setPMM(
        bytes32 pmmId,
        address account
    ) external onlyOwner notAddressZero(account) {
        /// `pmmId` already registered and `account = 0x0` will be rejected
        _validateStatus(_isValidPMM(pmmId), true);

        _pmmAccounts[pmmId].add(account);

        emit UpdatedPMM(pmmId, true);
        emit UpdatedPMMAccount(pmmId, account, true);
    }

    /** 
        @notice Remove an authorized `PMM` and also delete all associated accounts.
        @dev Caller must be `Owner`
        @dev Warning: This function removes all associated accounts from the `PMM` before deleting it.
        This operation can be costly if the set of associated accounts is large, as it involves iterating over the entire set
        @param pmmId The unique identifier assigned to one `PMM`.
    */
    function removePMM(bytes32 pmmId) external onlyOwner {
        /// `pmmId` must be registered
        _validateStatus(_isValidPMM(pmmId), false);

        uint256 len = _numOfPMMAccounts(pmmId);
        EnumerableSet.AddressSet storage set = _pmmAccounts[pmmId];

        /// @dev Warning: Iterating over the entire set can be costly for large sets
        /// Note: It is unnecessary to explicitly `delete _pmmAccounts[pmmId]`
        for (uint256 i = 0; i < len; i++) set.remove(set.at(i));

        emit UpdatedPMM(pmmId, false);
    }

    /** 
        @notice Add/Remove additional associated accounts for `pmmId`.
        @dev Caller must be `Owner`
        @param pmmId The unique identifier assigned to one `PMM`.
        @param account The PMM's associated account address.
        @param isAdded Option flag (true = add, false = remove).
    */
    function setPMMAccount(
        bytes32 pmmId,
        address account,
        bool isAdded
    ) external onlyOwner notAddressZero(account) {
        if (!_isValidPMM(pmmId)) revert PMMNotRegistered();

        /// Add or remove the account based on the `isAdded` flag
        /// Note: If removing the account results in an empty set,
        /// it is unnecessary to explicitly `delete _pmmAccounts[pmmId]`
        bool success = isAdded
            ? _pmmAccounts[pmmId].add(account)
            : _pmmAccounts[pmmId].remove(account);
        if (!success) {
            if (isAdded) revert RegisteredAlready();
            else revert UnregisteredAlready();
        }

        emit UpdatedPMMAccount(pmmId, account, isAdded);
    }

    function _getHash(
        bytes memory key1,
        bytes memory key2
    ) private pure returns (bytes32 keyHash) {
        keyHash = keccak256(abi.encode(key1, key2));
    }

    function _isValidNetwork(
        bytes calldata networkId
    ) private view returns (bool) {
        return _numOfTokens[networkId] != 0;
    }

    function _isValidPMM(bytes32 pmmId) private view returns (bool) {
        return _numOfPMMAccounts(pmmId) > 0;
    }

    function _numOfPMMAccounts(bytes32 pmmId) private view returns (uint256) {
        return _pmmAccounts[pmmId].length();
    }

    function _validateStatus(bool status, bool isAdded) private pure {
        if (status && isAdded) revert RegisteredAlready();
        if (!status && !isAdded) revert UnregisteredAlready();
    }

    function _isMatched(
        bytes memory pubkey1,
        bytes calldata pubkey2
    ) private pure returns (bool) {
        return keccak256(pubkey1) == keccak256(pubkey2);
    }
}
