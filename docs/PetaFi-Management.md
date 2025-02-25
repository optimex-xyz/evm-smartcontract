#### Overview

The `Management` contract is part of the `PetaFi Protocol`, designed to manage the protocol’s operational status, control access permissions, and handle authorized entities. This includes setting and updating the status of the protocol, managing authorized accounts (`Solvers`, `PMMs`, and `MPC Nodes`), and handling supported tokens and networks. The contract uses an owner-based access control (via `Ownable`) to ensure only authorized users can modify critical settings.

#### Key Components and Descriptions

1. Status Management:

   - Status Enum (`OPERATING`, `SUSPENDED`, `SHUTDOWN`) defines protocol states.
   - Functions: `suspend()`, `shutdown()`, `resume()` to control the state.

2. Access Control:

   - Authorized entities include `Solvers`, `MPC Nodes`, and `PMMs` each controlled by specific mappings and setters.

3. MPC Pubkey Management:

   - Tracks authorized MPC's public keys (`mpcAssetPubkey` and `mpcL2Pubkey`) along with expiration times for security.

4. Supported Networks and Tokens:

   - Stores and updates lists of supported `networks` and `tokens` for protocol operations.

5. Protocol Fee Rate:

   - `pFeeRate` defines the protocol fee rate in basis points, adjustable by the owner.

#### Functions Documentation

1. `function suspend()`

   - Purpose:
     - Sets the protocol status to `SUSPENDED`.
     - Temporarily halts certain operations like:
       - `submitTrade`, `confirmDeposit` and `selectPMM`.
   - Parameters: `None`
   - Requirements: Caller must be `Owner`.
   - Events: Emits `Suspend` event.

2. `function shutdown()`

   - Purpose:
     - Sets the protocol status to `SHUTDOWN`.
     - Halts all trading operations:
       - `submitTrade`, `confirmDeposit` and `selectPMM`.
       - `makePayment`, `confirmPayment` and `confirmSettlement`.
   - Parameters: `None`
   - Requirements: Caller must be `Owner`.
   - Events: Emits `Shutdown` event.

3. `function resume()`

   - Purpose:
     - Sets the protocol status to `OPERATING`.
     - Resumes protocol operations.
   - Parameters: `None`
   - Requirements: Caller must be `Owner`.
   - Events: Emits `Resume` event.

4. `function setFeeRate(uint256 newFeeRate)`

   - Purpose: Updates the protocol fee rate (bps).
   - Parameters:
     - `newFeeRate`:
       - Description: The new fee rate in basis points.
       - Type: `uint256`
   - Requirements: Caller must be `Owner`.
   - Events: `None`

5. `function setSolver(address solver, bool isSolver)`

   - Purpose: Adds or removes an authorized `Solver`.
   - Parameters:
     - `solver`:
       - Description: The Solver's address.
       - Type: `address`
     - `isSolver`:
       - Description: `true` to add, `false` to remove
       - Type: `bool`
   - Requirements: Caller must be `Owner`.
   - Events: Emits `UpdatedSolver` event.

6. `function setMPCNode(address account, bool isMPC)`

   - Purpose: Adds or removes an authorized `MPC Node`.
   - Parameters:
     - `account`:
       - Description: The account of the MPC Node
       - Type: `address`
     - `isMPC`:
       - Description: `true` to add, `false` to remove
       - Type: `bool`
   - Requirements: Caller must be `Owner`.
   - Events: Emits `UpdatedMPCNode` event.

7. `function setMPCInfo(bytes networkId, MPCInfo info, uint64 prevExpireTime)`

   - Purpose:
     - Adds an authorized MPC's public keys information for a `networkId`.
     - Set `expireTime` on the former MPC's public keys.
   - Parameters:
     - `networkId`:
       - Description: A unique identifierentifier assigned to a network.
       - Type: `bytes`.
     - `info`:
       - Description: A structured data object (`MPCInfo`) containing:
         - `mpcL2Address`: An address derived from `mpcL2Pubkey`, used to identify the `MPC` entity in operations on the PetaFi Protocol (L2).
         - `expireTime`: The timestamp after which the MPC public keys become inactive.
         - `mpcAssetPubkey`: The public key used to identify the `MPC` entity in operations on asset chains.
         - `mpcL2Pubkey`: The public key used to identify the `MPC` entity in operations on the PetaFi Protocol (L2).
       - Type: `MPCInfo` struct.
     - `prevExpireTime`:
       - Description: The expiration timestamp assigned to the former MPC public keys.
       - Type: `uint64`.
   - Requirements: Caller must be `Owner`.
   - Events: Emits `UpdatedMPCInfo` event.

8. `function revokeMPCKey(bytes networkId, bytes pubkey)`

   - Purpose: Revokes the specified MPC key for a given network.
   - Parameters:
     - `networkId`:
       - Description: A unique identifierentifier assigned to a network.
       - Type: `bytes`.
     - `pubkey`:
       - Description: The MPC's public key (`mpcAssetPubkey` or `mpcL2Pubkey`) to be revoked.
       - Type: `bytes`.
   - Requirements: Caller must be `Owner`.
   - Events: Emits `RevokedMPCKey` event.
   - Note: `mpcAssetPubkey` and `mpcL2Pubkey` always exist as a pair.

9. `function setToken(TokenInfo tokenInfo)`

   - Purpose: Adds or updates a supported token.
   - Parameters:
     - `tokenInfo`: ([example](Data-Types.md#Token-Info))
       - Description: A structured object (`TokenInfo`) contains:
         - `info`:
           - Description: An array of 5 `bytes` values specifying the token's key details:
             - `tokenId`:
               - The unique identifierentifier for the token.
               - Example: `native`, `0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2`, converted into bytes using ASCII encoding.
             - `networkId`:
               - The identifier of the blockchain network the token is on.
               - Example: `bitcoin-testnet`, `bitcoin`, `base-sepolia`, converted into bytes using ASCII encoding.
             - `symbol`:
               - The token's symbol.
               - Example: `ETH`, `WETH`, `BTC`, converted into bytes using ASCII encoding.
             - `externalURL`:
               - An external link with more information about the token.
               - Example: `https://sepolia.basescan.org/address/0x4200000000000000000000000000000000000006`, converted into bytes using ASCII encoding.
             - `description`: A brief description of the token (converted into bytes using ASCII encoding).
           - Type: `bytes[5]`
         - `decimals`:
           - Description: The number of decimal places used by the token.
           - Type: `uint256`
       - Type: `TokenInfo` object.
   - Requirements: Caller must be `Owner`.
   - Events: Emits `UpdatedToken` event.

10. `function removeToken(bytes networkId, bytes tokenId)`

    - Purpose: Removes a supported token.
    - Parameters:
      - `networkId`:
        - Description: The identifier of the blockchain network the token is on.
        - Type: `bytes`
        - Example: `bitcoin-testnet`, `base-sepolia`, `bitcoin`, `base`, converted into bytes using ASCII encoding.
      - `tokenId`:
        - Description: The unique identifierentifier for the token.
        - Type: `bytes`
        - Example: `bitcoin-testnet.btc`, `base-sepolia.eth`, `base-sepolia.weth`, converted into bytes using ASCII encoding.
    - Requirements: Caller must be `Owner`.
    - Events: Emits `UpdatedToken` event.

11. `function setPMM(bytes32 pmmId, address account)`

    - Purpose: Add an authorized `PMM` and its first associated account.
    - Parameters:
      - `pmmId`
        - Description: The unique identifier assigned to one PMM.
        - Type: `bytes32`
      - `account`
        - Description: The PMM's associated account.
        - Type: `address`
    - Requirements: Caller must be `Owner`.
    - Events: Emits `UpdatedPMM` and `UpdatedPMMAccount` events.
    - Note: This function is used to register the `pmmId` and its first associated account.
      To register additional accounts, please use another `setPMMAccount()`.

12. `function removePMM(bytes32 pmmId)`

    - Purpose: Remove an authorized `PMM` and also delete all associated accounts.
    - Parameters:
      - `pmmId`
        - Description: The unique identifier assigned to one PMM.
        - Type: `bytes32`
    - Requirements: Caller must be `Owner`.
    - Events: Emits `UpdatedPMM` event.
    - Warning: This function removes all associated accounts from the `PMM` before deleting it.
      This operation can be costly if the set of associated accounts is large, as it involves iterating over the entire set.

13. `function setPMMAccount(bytes32 pmmId, address account, bool isAdded)`

    - Purpose: Add/Remove additional associated accounts for a given `pmmId`.
    - Parameters:
      - `pmmId`
        - Description: The unique identifier assigned to one PMM.
        - Type: `bytes32`
      - `account`
        - Description: The PMM's associated account.
        - Type: `address`
      - `isAdded`
        - Description: Determines whether the account should be added (`true`) or removed (`false`).
        - Type: `bool`
    - Requirements: Caller must be `Owner`.
    - Events: Emits `UpdatedPMMAccount` events.

14. `function pFeeRate()`

    - Purpose: Returns the current protocol fee rate expressed in basis points (bps).
    - Parameters: `None`
    - Requirements: Caller can be `ANY`.
    - Events: `None`
    - Returns:
      - `feeRate`: The protocol fee rate in basis point.

15. `function state()`

    - Purpose: Returns the current operational status of the protocol
    - Parameters: `None`
    - Requirements: Caller can be `ANY`.
    - Events: `None`
    - Returns:
      - `currentState`: The current operational status of the protocol, represented by an integer.
        - `0`: `OPERATING` – Protocol is fully operational.
        - `1`: `SUSPENDED` – Protocol is temporarily and partially halted.
        - `2`: `SHUTDOWN` – Protocol is temporarily and fully closed.

16. `function solvers(address account)`

    - Purpose: Checks if a given `account` is an authorized Solver
    - Parameters:
      - `account`
        - Description: The account to verify as an authorized `Solver`.
        - Type: `address`
    - Requirements: Caller can be `ANY`.
    - Events: `None`
    - Returns: `true` or `false`

17. `function mpcNodes(address account)`

    - Purpose: Checks if a given `account` is an authorized `MPC Node`
    - Parameters:
      - `account`
        - Description: The account to verify as an authorized MPC Node.
        - Type: `address`
    - Requirements: Caller can be `ANY`.
    - Events: `None`
    - Returns `true` or `false`

18. `function numOfSupportedTokens()`

    - Purpose: Retrieves the total number of tokens currently supported by the protocol.
    - Parameters: `None`
    - Requirements: Caller can be `ANY`.
    - Events: `None`
    - Returns: A total number of supported tokens.

19. `function getTokens(uint256 fromIdx, uint256 toIdx)`

    - Purpose: Fetches a list of token information for a specified range of supported tokens.
    - Parameters:
      - `fromIdx`:
        - Description: The starting index of the token list (inclusive).
        - Type: `uint256`
      - `toIdx`:
        - Description: The ending index of the token list (exclusive).
        - Type: `uint256`
    - Requirements: Caller can be `ANY`.
    - Events: `None`
    - Returns: An array of `TokenInfo` objects representing the tokens within the specified range.

20. `function isValidNetwork(bytes networkId)`

    - Purpose: Checks if a given `networkId` is being supported
    - Parameters:
      - `networkId`
        - Description: The unique identifier assigned to one network
        - Type: `bytes`
    - Requirements: Caller can be `ANY`.
    - Events: `None`
    - Returns `true` or `false`

21. `function isValidToken(bytes networkId, bytes tokenId)`

    - Purpose: Checks if a given `tokenId` on the `networkId` is being supported
    - Parameters:
      - `networkId`
        - Description: The unique identifier assigned to one network
        - Type: `bytes`
      - `tokenId`
        - Description: The unique identifier assigned to one token
        - Type: `bytes`
    - Requirements: Caller can be `ANY`.
    - Events: `None`
    - Returns `true` or `false`

22. `function isValidPubkey(bytes pubkey)`

    - Purpose: Checking whether `pubkey` is valid (existed and active)
    - Parameters:
      - `pubkey`
        - Description: The public key
        - Type: `bytes`
    - Requirements: Caller can be `ANY`.
    - Events: `None`
    - Returns:
      - If the public key is valid (exists and is active), the address derived from the given MPC public key is returned.
      - If the public key is not valid, `0x0` is returned.

23. `function getLatestMPCInfo(bytes networkId)`

    - Purpose: Returns the most recent MPC public keys associated with a specific `networkId`.
    - Parameters:
      - `networkid`
        - Description: A unique identifierentifier assigned to a network.
        - Type: `bytes`
    - Requirements: Caller can be `ANY`.
    - Events: `None`
    - Returns: A structured data object (`MPCInfo`) containing:
      - `mpcL2Address`: An address derived from `mpcL2Pubkey`, used to identify the `MPC` entity in operations on the PetaFi Protocol (L2).
      - `expireTime`: The timestamp after which the MPC public keys become inactive.
      - `mpcAssetPubkey`: The public key used to identify the `MPC` entity in operations on asset chains.
      - `mpcL2Pubkey`: The public key used to identify the `MPC` entity in operations on the PetaFi Protocol (L2).
    - Note:
      - During a transition phase, the former MPC public key is assigned an `expireTime`.
      - This means that during this period, both the current active key and the previous key (if not yet expired) may be available.

24. `function getMPCInfo(bytes networkId, bytes pubkey)`

    - Purpose: Retrieves the MPC information associated with a given `networkId` and `pubkey`.
    - Parameters:
      - `networkid`
        - Description: A unique identifierentifier assigned to a network.
        - Type: `bytes`
      - `pubkey`
        - Description: Either `mpcAssetPubkey` or `mpcL2Pubkey`.
        - Type: `bytes`
    - Requirements: Caller can be `ANY`.
    - Events: `None`
    - Returns: A structured data object (`MPCInfo`) containing:
      - `mpcL2Address`: An address derived from `mpcL2Pubkey`, used to identify the `MPC` entity in operations on the PetaFi Protocol (L2).
      - `expireTime`: The timestamp after which the MPC public keys become inactive.
      - `mpcAssetPubkey`: The public key used to identify the `MPC` entity in operations on asset chains.
      - `mpcL2Pubkey`: The public key used to identify the `MPC` entity in operations on the PetaFi Protocol (L2).

25. `function isValidPMM(bytes32 pmmId)`

    - Purpose: Checks if a given `pmmId` is an authorized `PMM`
    - Parameters:
      - `pmmId`
        - Description: The unique identifier assigned to one PMM
        - Type: `bytes32`
    - Requirements: Caller can be `ANY`.
    - Events: `None`
    - Returns `true` or `false`

26. `function isValidPMMAccount(bytes32 pmmId, address account)`

    - Purpose: Checks if a given `account` is an associated account of `pmmId`.
    - Parameters:
      - `pmmId`
        - Description: The unique identifier assigned to one PMM
        - Type: `bytes32`
      - `account`
        - Description: The account to verify as a PMM's associated account
        - Type: `address`
    - Requirements: Caller can be `ANY`.
    - Events: `None`
    - Returns `true` or `false`

27. `function numOfPMMAccounts(bytes32 pmmId)`

    - Purpose: Retrieve the total number of associated accounts for a given `pmmId`.
    - Parameters:
      - `pmmId`
        - Description: The unique identifier assigned to one PMM
        - Type: `bytes32`
    - Requirements: Caller can be `ANY`.
    - Events: `None`
    - Returns The number of associated accounts for the `pmmId`.

28. `function getPMMAccounts(bytes32 pmmId, uint256 fromIdx, uint256 toIdx)`

    - Purpose: Fetches a list of associated accounts for a given `pmmId` within the specified range.
    - Parameters:
      - `pmmId`
        - Description: The unique identifier assigned to one PMM
        - Type: `bytes32`
      - `fromIdx`:
        - Description: The starting index of the token list (inclusive).
        - Type: `uint256`
      - `toIdx`:
        - Description: The ending index of the token list (exclusive).
        - Type: `uint256`
    - Requirements: Caller can be `ANY`.
    - Events: `None`
    - Returns: A list of associated accounts within the specified range.

29. `function isSuspended(uint256 stage)`

    - Purpose:
      - Used to enforce operation status checks.
      - Checks if the protocol is in a `suspended state` for a specific `stage`
      - Returns `true` or `false`.
    - Parameters:
      - `stage`
        - Description: The protocol stage to be checked.
        - Type: `uint256`
        - Range: `[0, 5]`
    - Requirements: Caller can be `ANY`.
    - Events: `None`
