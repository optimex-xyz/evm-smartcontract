#### Overview

The `Router` contract serves as the central trade management component within the `Optimex Protocol`, enabling cross-chain operations by coordinating between `Core Handler` contracts that handle specific trade routes. It provides dynamic routing capabilities and a framework for maintaining and updating `Core` contract versions, ensuring trades are directed through the correct pathway based on the source and destination blockchain networks (`fromChain` and `toChain`). The `Router` interacts with the `Management` contract for validation of supported networks and permission checks, and it stores and emits trade-related data and events to support a cohesive trade lifecycle management system.

#### Key Components and Descriptions

1.  Routes Handling:

    - Each `route` is represented by a unique hash key `keccak256(fromChain, toChain)`.
    - The `Owner` of the `Management` contract sets this routing hash to a specific `Core Handler` contract that handles trades for the designated route.
    - When a trade is submitted through the `Router`, it is routed to the appropriate handler by identifying the `fromChain` and `toChain` values within the trade data.
    - Upon recording a `tradeId` in the `Router`, a secondary mapping `tradeIdToCore` is established to manage subsequent actions for that `tradeId`. This setup ensures that if a new `Core Handler` is deployed, all new trades will route to the updated handler, while ongoing trades continue with their originally assigned handler.

2.  Updating Core Handlers without Impacting In-Progress Trades:

    - The `Router` allows the assignment of new `Core Handler` on existing routes without impacting in-progress trades. Using the `setRoute` function, a new Core contract can be assigned to a route.
    - Ongoing trades associated with a previous `Core Handler` retain their original mappings via `tradeIdToCore`, ensuring their seamless execution.
    - This design provides flexibility for updating routes and enhancing protocol functionality while maintaining continuity for existing trades.

3.  Version Control:

    - Each `Core Handler` contract assigned to a route is versioned through the `version` mapping that tracks the version history of each deployed `Core Handler`.
    - Upon updating a route with a new `Core Handler` contract, the version is incremented by 1, helping maintain a clear record of contract updates for each route.
    - This version control mechanism enables effective tracking and management of deployments, allowing developers to manage changes over time and ensure compatibility across upgrades.

4.  Protocol Data Hub:
    - The `Router` contract integrates functions to query and fetch protocol settings from the `Management` contract, enabling external contracts and users to retrieve network settings and permission-related information dynamically.
    - It also provides access to data associated with individual trades, such as their status, `Core Handler` mappings, and lifecycle events. This improves traceability and facilitates debugging or monitoring trade progress.
    - By centralizing data retrieval in the `Router`, developers can ensure consistent access patterns and minimize redundant data fetching across the protocol.

#### Functions Documentation

1. `function setManagement(address newManagement)`

   - Purpose: Updates the address of the `Management` contract.
   - Parameters:
     - `newManagement`:
       - Description: The new address of the Management contract.
       - Type: `address`
   - Requirements:
     - Caller must be the owner of the current `Management` contract.
     - `newManagement` must not be a zero address.
   - Events: `None`

2. `function setRoute(address core, bytes fromChain, bytes toChain)`

   - Purpose: Sets a routing `Core Handler` contract to handle trades between `fromChain` and `toChain`.
   - Parameters:
     - `core`:
       - Description: The address of the `Core Handler` contract.
       - Type: `address`
     - `fromChain`:
       - Description: The source `networkId`.
       - Type: `bytes`
       - Example: `"bitcoin-testnet"` -> ASCII encode -> `networkId = 0x626974636f696e2d746573746e6574`
     - `toChain`:
       - Description: The destination `networkId`.
       - Type: `bytes`
       - Example: `"base-sepolia"` -> ASCII encode -> `networkId = 0x626173652d7365706f6c6961`
   - Requirements:
     - Caller must be the owner of the current `Management` contract.
     - `core` must not be a zero address.
     - Both `fromChain` and `toChain` must be supported networks.
   - Events: Emits `UpdatedRoute` event.

3. `function submitTrade(bytes32 tradeId, TradeData data, Affiliate affiliateInfo, Presign[] presigns)`

   - Purpose: Submits `tradeId` info and presigns for the trade.
   - Parameters:
     - `tradeId`:
       - Description: The unique ID assigned to one trade.
       - Type: `bytes32`.
     - `data`:
       - Description: The trade information includes `TradeInfo` and `ScriptInfo` structs.
       - Type: `TradeData` object.
     - `affiliateInfo`:
       - Description: A struct containing affiliate details, including a total affiliate fee rate (bps) and other relevant information.
       - Type: `Affiliate` object.
     - `presigns`:
       - Description: The array of `Presign` struct.
       - Type: `Presign[]` object.
   - Requirements: Caller must have the `Solver` role, validated by the `Core Handler` contract.
   - Events: Emits `SubmitTradeInfo` event.

4. `function confirmDeposit(bytes32 tradeId, bytes signature, bytes[] depositFromList)`

   - Purpose: Submits a deposit confirmation for the trade.
   - Parameters:
     - `tradeId`:
       - Description: The unique ID assigned to one trade.
       - Type: `bytes32`.
     - `signature`:
       - Description: Signature from MPC’s threshold key.
       - Type: `bytes`.
     - `depositFromList`:
       - Description: Array of addresses making deposits.
       - Type: `bytes[]`.
   - Requirements: Caller must be an `MPC Node`’s associated account, validated by the `Core Handler` contract.
   - Events: Emits `ConfirmDeposit` event.

5. `function selectPMM(bytes32 tradeId, PMMSelection info)`

   - Purpose: Selects the PMM winner for the trade.
   - Parameters:
     - `tradeId`:
       - Description: The unique ID assigned to one trade.
       - Type: `bytes32`
     - `info`:
       - Description: Contains `SelectedPMM` proof and `RFQInfo`.
       - Type: `PMMSelection`
   - Requirements: Caller must have the `Solver` role, validated by the `Core Handler` contract.
   - Events: Emits `SelectPMM` event.

6. `function bundlePayment(BundlePayment bundle)`

   - Purpose: Announces the completion of payments for multiple trades.
   - Parameters:
     - `bundle`:
       - Description: A structured data package containing all necessary details for processing the payment of multiple trades.
       - Type: `BundlePayment` object.
   - Requirements: The caller must have the `Solver` role or be the `PMM` selected for the specified trades.
   - Events: Emits one or multiple `MakePayment` events.

7. `function confirmPayment(bytes32 tradeId, bytes signature)`

   - Purpose: Confirms the payment for the trade.
   - Parameters:
     - `tradeId`:
       - Description: The unique ID assigned to one trade.
       - Type: `bytes32`
     - `signature`:
       - Description: The signature provided by MPC's threshold keys.
       - Type: `bytes`
   - Requirements: Caller must be an MPC Node’s associated account, validated by the `Core Handler` contract.
   - Events: Emits `ConfirmPayment` event.

8. `function confirmSettlement(bytes32 tradeId, bytes releaseTxId, bytes signature)`

   - Purpose: Confirms settlement for the trade.
   - Parameters:
     - `tradeId`:
       - Description: The unique ID assigned to one trade.
       - Type: `bytes32`
     - `releaseTxId`:
       - Description: Transaction ID for the settlement.
       - Type: `bytes`
     - `signature`:
       - Description: The signature provided by MPC's threshold keys.
       - Type: `bytes`
   - Requirements: Caller must be an MPC Node’s associated account, validated by the `Core Handler` contract.
   - Events: Emits `ConfirmSettlement` event.

9. `function SIGNER()`

   - Purpose: Holds the address of the `Signer` (`immutable`) helper contract.
   - Parameters: `None`
   - Requirements: Caller can be `ANY`.
   - Events: `None`
   - Returns:
     - `signer`:
       - Description: The address of the `Signer` contract.

10. `function management()`

    - Purpose: Holds the address of the `Management` contract.
    - Parameters: `None`
    - Requirements: Caller can be `ANY`.
    - Events: `None`
    - Returns:
      - `management_`:
        - Description: The address of the `Management` contract.

11. `function getHandler(bytes fromChain, bytes toChain)`

    - Purpose: Retrieve the `Core Handler` contract that handles the trade between `fromChain` and `toChain`.
    - Parameters:
      - `fromChain`:
        - Description: The source `networkId`.
        - Type: `bytes`
      - `toChain`:
        - Description: The destination `networkId`.
        - Type: `bytes`
    - Requirements: Caller can be `ANY`.
    - Events: `None`
    - Returns:
      - `handler`:
        - Description:
          - The address of the `Core Handler` contract for the specified trade route.
          - If no handler exists, returns `0x0`.
      - `handlerType`:
        - Description:
          - The type of the `Core Handler` contract, which is either `BTCEVM`, `EVMBTC`, `BTCSOL`, or `SOLBTC`.
          - If no handler exists, returns an empty string `""`.

12. `function getHandlerOf(bytes32 tradeId)`

    - Purpose: Retrieve the `Core Handler` contract that handles the `tradeId`.
    - Parameters:
      - `tradeId`:
        - Description: The unique ID assigned to one trade.
        - Type: `bytes32`
    - Requirements: Caller can be `ANY`.
    - Events: `None`
    - Returns:
      - `handler`:
        - Description:
          - The address of the `Core Handler` contract for the specified tradeId.
          - If no handler exists, returns `0x0`.
      - `handlerType`:
        - Description:
          - The type of the `Core Handler` contract, which is either `BTCEVM`, `EVMBTC`, `BTCSOL`, or `SOLBTC`.
          - If no handler exists, returns an empty string `""`.

13. `function version(address core)`

    - Purpose: Tracks and retrieves the version of a specified `Core Handler` contract by its address.
    - Parameters:
      - `core`:
        - Description: The address of the `Core Handler` contract
        - Type: `address`
    - Requirements: Caller can be `ANY`.
    - Events: `None`
    - Returns:
      - `versionNo`:
        - Description: The version number of the specified `Core Handler` contract, starting from 1 and incrementing with each update (`1...n`).

14. `function getCurrentStage(bytes32 tradeId)`

    - Purpose: Retrieves the current stage number of a specific `tradeId`.
    - Parameters:
      - `tradeId`:
        - Description: The unique ID assigned to one trade.
        - Type: `bytes32`
    - Requirements: Caller can be `ANY`.
    - Events: `None`
    - Returns:
      - `stage`:
        - Description: The current stage of `tradeId`
          - `0`: Not yet submitted/recorded.
          - `1`: Trade submitted.
          - `2`: Deposit confirmed.
          - `3`: PMM selected.
          - `4`: Made payment (by the selected PMM).
          - `5`: Payment confirmed.
          - `6`: Settlement confirmed. (End of trade)

15. `function getTradeData(bytes32 tradeId)`

    - Purpose: Retrieves the `tradeData` information for a specific `tradeId`.
    - Parameters:
      - `tradeId`:
        - Description: The unique ID assigned to one trade.
        - Type: `bytes32`
    - Requirements: Caller can be `ANY`.
    - Events: `None`
    - Returns:
      - `data`:
        - Description: A structured data object (`TradeData`) containing:
          - `sessionId`: The unique session ID assigned to the trade, representing the interaction between the User and the DApp.
          - `tradeInfo`: A structured object that encapsulates the trade-specific details.
          - `scriptInfo`: A structured object that contains the deposited information relevant to the trade.

16. `function getPresigns(bytes32 tradeId)`

    - Purpose: Retrieves the `Presign` submissions for a specific `tradeId`.
    - Parameters:
      - `tradeId`:
        - Description: The unique ID assigned to one trade.
        - Type: `bytes32`
    - Requirements: Caller can be `ANY`.
    - Events: `None`
    - Returns:
      - `presignatures`:
        - Description: An array of structured object (`Presign[]`) containing multiple pre-signatures. Each object includes:
          - `pmmId`: The unique identifier assigned to a specific PMM.
          - `pmmRecvAddress`: The designated receiving address (on the source chain) provided by the PMM.
          - `presigns`: An array of pre-signatures, signed by the `userEphemeralKey` and utilized by MPC during settlement.
            - For Bitcoin: Includes multiple signatures to facilitate different levels of gas fee payments, enabling faster transaction execution when MPC settles the `bitcoinScript`.
            - For EVM: Contains only a single signature.

17. `function getAffiliateInfo(bytes32 tradeId)`

    - Purpose: Retrieves the affiliate information associated with a specified `tradeId`.
    - Parameters:
      - `tradeId`:
        - Description: The unique ID assigned to one trade.
        - Type: `bytes32`
    - Requirements: Caller can be `ANY`.
    - Events: `None`
    - Returns: A structured data object (`Affiliate`) containing:
      - `aggregatedValue`: The total affiliate fee rate.
      - `schema`: Defines the data structure and encoding method used to decode `data`.
      - `data`: Encoded affiliate-related information.

18. `function getPMMSelection(bytes32 tradeId)`

    - Purpose: Retrieves the `PMMSelection` proof for a specific `tradeId`.
    - Parameters:
      - `tradeId`:
        - Description: The unique ID assigned to one trade.
        - Type: `bytes32`
    - Requirements: Caller can be `ANY`.
    - Events: `None`
    - Returns:
      - `selection`:
        - Description: An array of structured object (`PMMSelection`) containing:
          - `rfqInfo`: A collection of details including `minAmountOut`, `tradeTimeout` and `rfqInfoSignature`.
          - `pmmInfo`: Contains details about the PMM selected to fulfill the trade.

19. `function getFeeDetails(bytes32 tradeId)`

    - Purpose: Retrieves the details of the fee charged for a specific `tradeId`.
    - Parameters:
      - `tradeId`:
        - Description: The unique ID assigned to one trade.
        - Type: `bytes32`
    - Requirements: Caller can be `ANY`.
    - Events: `None`
    - Returns: A structured data object (`FeeDetails`) containing:
      - `totalAmount`: The total fee amount.
      - `pFeeAmount`: The protocol fee amount, calculated based on the trade size.
      - `aFeeAmount`: The total affiliate fee amount, calculated based on the trade size.
      - `pFeeRate`: The protocol fee rate, expressed in basis points (bps).
      - `aFeeRate`: The total affiliate fee rate, expressed in basis points (bps).

20. `function getSettledPayment(bytes32 tradeId)`

    - Purpose: Retrieves the `settledPayment` information for a specific `tradeId`.
    - Parameters:
      - `tradeId`:
        - Description: The unique ID assigned to one trade.
        - Type: `bytes32`
    - Requirements: Caller can be `ANY`.
    - Events: `None`
    - Returns:
      - `settledPaymentData`:
        - Description: A structured data object (`SettledPayment`) containing:
          - `bundlerHash`: The hash representing a group of `tradeIds` paid by the corresponding `paymentTxId`.
          - `paymentTxId`: The transaction ID of the payment made on the destination chain (facilitated by a selected PMM).
          - `releaseTxId`: The transaction ID of the settlement processed on the source chain (executed by MPC).
          - `isConfirmed`: The confirmation status of the payment transaction.

21. `function getDepositAddressList(bytes32 tradeId)`

    - Purpose: Retrieves the list of confirmed deposit addresses for a specific `tradeId`.
    - Parameters:
      - `tradeId`:
        - Description: The unique ID assigned to one trade.
        - Type: `bytes32`
    - Requirements: Caller can be `ANY`.
    - Events: `None`
    - Returns:
      - `list`:
        - Description: An array of addresses (in `bytes`) used to fund the deposited transaction.
          - For Bitcoin: May include multiple `UTXO` entries.
          - For EVM: Contains only a single `address`.

22. `function getLastSignedPayment(bytes32 tradeId)`

    - Purpose: Query the recent timestamp `paymentTxId` was signed to update for the `tradeId`.
    - Parameters:
      - `tradeId`:
        - Description: The unique ID assigned to one trade.
        - Type: `bytes32`
    - Requirements: Caller can be `ANY`.
    - Events: `None`
    - Returns:
      - `signedAt`: The last timestamp `paymentTxId` was signed to update

23. `function getMaxAffiliateFeeRate(bytes fromChain, bytes toChain)`

    - Purpose: Retrieves a maximum affiliate fee rate for a given route `fromChain` and `toChain`.
    - Parameters:
      - `fromChain`:
        - Description: The source `networkId`.
        - Type: `bytes`
      - `toChain`:
        - Description: The destination `networkId`.
        - Type: `bytes`
    - Requirements: Caller can be `ANY`.
    - Events: `None`
    - Returns: The maximum allowable affiliate fee rate as a `uint256`, expressed in basis points (bps).

24. `function isValidNetwork(bytes networkId)`

    - Purpose: Checks if a given `networkId` is being supported
    - Parameters:
      - `networkId`
        - Description: The unique ID assigned to one network
        - Type: `bytes`
    - Requirements: Caller can be `ANY`.
    - Events: `None`
    - Returns: `true` or `false`

25. `function isValidToken(bytes networkId, bytes tokenId)`

    - Purpose: Checks if a given `tokenId` on the `networkId` is being supported
    - Parameters:
      - `networkId`
        - Description: The unique ID assigned to one network
        - Type: `bytes`
      - `tokenId`
        - Description: The unique ID assigned to one token
        - Type: `bytes`
    - Requirements: Caller can be `ANY`.
    - Events: `None`
    - Returns: `true` or `false`

26. `function isSolver(address account)`

    - Purpose: Checks if a given `account` is an authorized Solver
    - Parameters:
      - `account`
        - Description: The account to verify as an authorized `Solver`.
        - Type: `address`
    - Requirements: Caller can be `ANY`.
    - Events: `None`
    - Returns: `true` or `false`

27. `function isMPCNode(address account)`

    - Purpose: Checks if a given `account` is an authorized `MPC Node`
    - Parameters:
      - `account`
        - Description: The account to verify as an authorized MPC Node.
        - Type: `address`
    - Requirements: Caller can be `ANY`.
    - Events: `None`
    - Returns: `true` or `false`

28. `function isValidPMM(bytes32 pmmId)`

    - Purpose: Checks if a given `pmmId` is an authorized `PMM`
    - Parameters:
      - `pmmId`
        - Description: The unique ID assigned to one PMM
        - Type: `bytes32`
    - Requirements: Caller can be `ANY`.
    - Events: `None`
    - Returns: `true` or `false`

29. `function isValidPMMAccount(bytes32 pmmId, address account)`

    - Purpose:
      - Checks if a given `account` is an associated account of `pmmId`
      - Returns: `true` or `false`
    - Parameters:
      - `pmmId`
        - Description: The unique ID assigned to one PMM
        - Type: `bytes32`
      - `account`
        - Description: The account to verify as a PMM's associated account
        - Type: `address`
    - Requirements: Caller can be `ANY`.
    - Events: `None`

30. `function isValidPubkey(bytes pubkey)`

    - Purpose: Checking whether a `mpcAssetPubkey`/`mpcL2Pubkey` is valid (existed and active)
    - Parameters:
      - `pubkey`
        - Description: Either `mpcAssetPubkey` or `mpcL2Pubkey`.
        - Type: `bytes`
    - Requirements: Caller can be `ANY`.
    - Events: `None`
    - Returns: `true` or `false`.
    - Note: `mpcAssetPubkey` and `mpcL2Pubkey` always exist as a pair.

31. `function isSuspended(uint256 stage)`

    - Purpose:
      - Used to enforce operation status checks.
      - Checks if the protocol is in a `suspended state` for a specific `stage`
      - Returns: `true` or `false`.
    - Parameters:
      - `stage`
        - Description: The protocol stage to be checked.
        - Type: `uint256`
        - Range: `[0, 5]`
    - Requirements: Caller can be `ANY`.
    - Events: `None`

32. `function getManagementOwner()`

    - Purpose: Query current `Owner` of the Management contract
    - Parameters: `None`
    - Requirements: Caller can be `ANY`.
    - Events: `None`
    - Returns:
      - `owner`: The current `Owner` of `Mangement` contract

33. `function getProtocolState()`

    - Purpose: Returns the current operational status of the protocol.
    - Parameters: `None`
    - Requirements: Caller can be `ANY`.
    - Events: `None`
    - Returns:
      - `currentState`: The current operational status of the protocol, represented by an integer.
        - `0`: `OPERATING` – Protocol is fully operational.
        - `1`: `SUSPENDED` – Protocol is temporarily and partially halted.
        - `2`: `SHUTDOWN` – Protocol is temporarily and fully closed.

34. `function getPFeeRate()`

    - Purpose: Returns the current protocol fee rate expressed in basis points (bps).
    - Parameters: `None`
    - Requirements: Caller can be `ANY`.
    - Events: `None`
    - Returns:
      - `feeRate`: The protocol fee rate in basis point.

35. `function getLatestMPCInfo(bytes networkId)`

    - Purpose: Returns the most recent MPC public keys associated with a specific `networkId`.
    - Parameters:
      - `networkid`
        - Description: A unique identifier assigned to a network.
        - Type: `bytes`
    - Requirements: Caller can be `ANY`.
    - Events: `None`
    - Returns: A structured data object (`MPCInfo`) containing:
      - `mpcL2Address`: An address derived from `mpcL2Pubkey`, used to identify the `MPC` entity in operations on the Optimex Protocol (L2).
      - `expireTime`: The timestamp after which the MPC public keys become inactive.
      - `mpcAssetPubkey`: The public key used to identify the `MPC` entity in operations on asset chains.
      - `mpcL2Pubkey`: The public key used to identify the `MPC` entity in operations on the Optimex Protocol (L2).
    - Note:
      - During a transition phase, the former MPC public key is assigned an `expireTime`.
      - This means that during this period, both the current active key and the previous key (if not yet expired) may be available.

36. `function getMPCInfo(bytes networkId, bytes pubkey)`

    - Purpose: Retrieves the MPC information associated with a given `networkId` and `pubkey`.
    - Parameters:
      - `networkId`
        - Description: The unique identifier assigned to one network.
        - Type: `bytes`
      - `pubkey`
        - Description: Either `mpcAssetPubkey` or `mpcL2Pubkey`.
        - Type: `bytes`
    - Requirements: Caller can be `ANY`.
    - Events: `None`
    - Returns: A structured data object (`MPCInfo`) containing:
      - `mpcL2Address`: An address derived from `mpcL2Pubkey`, used to identify the `MPC` entity in operations on the Optimex Protocol (L2).
      - `expireTime`: The timestamp after which the MPC public keys become inactive.
      - `mpcAssetPubkey`: The public key used to identify the `MPC` entity in operations on asset chains.
      - `mpcL2Pubkey`: The public key used to identify the `MPC` entity in operations on the Optimex Protocol (L2).

37. `function numOfSupportedTokens()`

    - Purpose: Retrieves the total number of tokens currently supported by the protocol.
    - Parameters: `None`
    - Requirements: Caller can be `ANY`.
    - Events: `None`
    - Returns: A total number of supported tokens.

38. `function getTokens(uint256 fromIdx, uint256 toIdx)`

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

39. `function numOfPMMAccounts(bytes32 pmmId)`

    - Purpose: Retrieve the total number of associated accounts for a given `pmmId`.
    - Parameters:
      - `pmmId`
        - Description: The unique identifier assigned to one PMM
        - Type: `bytes32`
    - Requirements: Caller can be `ANY`.
    - Events: `None`
    - Returns The number of associated accounts for the `pmmId`.

40. `function getPMMAccounts(bytes32 pmmId, uint256 fromIdx, uint256 toIdx)`

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
