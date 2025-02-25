#### Overview

The `BTCEVM`, `EVMBTC`, `BTCSOL` and `SOLBTC` contracts, built on the core functionalities defined by the `Core` contract, facilitates cross-network trades between the `Bitcoin Network`, `EVM-compatible Networks` (Ethereum, Base, etc.), and `Solana Network`. This contract enables efficient and secure trade execution and confirmation, supporting multiple stages in the trade lifecycle, from initial trade submission to settlement. The contracts integrate with external protocols and systems, such as external helper (`Router`, `VaultRegistry`, `Signer`) contracts, and a `Management` contract, to handle routing, token and network verification, MPC (multi-party computation) signatures, and trade data validation.

#### Key Components and Descriptions

1.  Multi-Stage Trade Lifecycle: Each trade follows a predefined series of stages, which include trade information submission, deposit confirmation, `PMM` (Private Market Maker) selection, payment processing, and final settlement. The trade flow follows the below stages in sequence:

    - Submit Trade Info: Initiates the trade by validating and recording essential details, including deposit and token information.
    - Confirm Deposit: Confirms the initial deposit on the source network.
    - Select PMM: Determines the most suitable PMM for trade fulfillment.
    - Make Payment: Processes payment on the destination network, with signature validation.
    - Confirm Payment: Confirms payment completion to the user's receiving address.
    - Confirm Settlement: Finalizes trade by confirming the cross-network transaction.

2.  Role-Based Access Control: The contract defines specific roles (`Owner`, `Solver`, `MPC Node`) and associates access permissions based on roles using `onlyManagementOwner()`, `onlySolver()`, and `onlyMPCNode()` modifiers to restrict functionality based on role context.

3.  Suspension State Validation: All critical functions use the `isSuspended()` modifier to ensure that if the contract is in a suspended state, further operations are halted.

#### Functions Documentation

1.  `function setRouter(address newRouter)`

    - Purpose: Update the contract address of the `Router`.
    - Parameters:
      - `newRouter`:
        - Description: The new address of the Router contract.
        - Type: `address`
    - Requirements:
      - Caller must be the current `Owner` in the `Management` contract.
      - `newRouter` must not be a zero address.
    - Events: `None`

2.  `function setVaultRegistry(address newRegistry)`

    - Purpose: Update the contract address of the `VaultRegistry` contract. (`EVMBTC`)
    - Parameters:
      - `newRegistry`:
        - Description: The new address of the VaultRegistry contract.
        - Type: `address`
    - Requirements:
      - Caller must be the current `Owner` in the `Management` contract.
      - `newRegistry` must not be a zero address.
    - Events: `None`

3.  `function setMaxAffiliateFeeRate(uint256 newRate)`

    - Purpose: Updates the maximum allowable affiliate fee rate.
    - Parameters:
      - `newRate`:
        - Description: The new maximum affiliate fee rate, expressed in basis points (bps).
        - Type: `uint256`
    - Requirements:
      - Caller must be the current `Owner` in the `Management` contract.
    - Events: `None`

4.  `function submitTrade(address requester, bytes32 tradeId, TradeData data, Affiliate affiliateInfo, Presign[] presigns)`

    - Purpose: Submits `tradeId` info and presigns for the trade.
    - Parameters:
      - `requester`:
        - Description: The address of the initiating requester, managed by the `Router` contract.
        - Type: `address`
      - `tradeId`:
        - Description: The unique ID assigned to one trade.
        - Type: `bytes32`
      - `data`:
        - Description: The trade information includes `TradeInfo` and `ScriptInfo` structs.
        - Type: `TradeData`
      - `affiliateInfo`:
        - Description: A struct containing affiliate details, including a total affiliate fee rate (bps) and other relevant information.
        - Type: `Affiliate` object.
      - `presigns`:
        - Description: The array of `Presign` struct.
        - Type: `Presign[]`
    - Requirements:
      - Must be called by the `Router` contract.
      - The requester must have the `Solver` role.
      - Trade data cannot be re-submitted once initially submitted.
    - Events: Emits `TradeInfoSubmitted` event.
    - Note:
      - For `BTCEVM` and `BTCSOL`: `pFeeRate` is snapshot at this stage; `pFeeAmount` and `aFeeAmount` are calculated at the `selectPMM` stage.
      - For `EVMBTC` and `SOLBTC`: `pFeeRate` as well as `pFeeAmount` and `aFeeAmount` are calculated at this stage.

5.  `function confirmDeposit(address requester, bytes32 tradeId, bytes signature, bytes[] depositFromList)`

    - Purpose: Submits a deposit confirmation for the trade.
    - Parameters:
      - `requester`:
        - Description: The address of the initiating requester, managed by the `Router` contract.
        - Type: `address`
      - `tradeId`:
        - Description: The unique ID assigned to one trade.
        - Type: `bytes32`
      - `signature`:
        - Description: Signature from MPC’s threshold key.
        - Type: `bytes`
      - `depositFromList`:
        - Description: Array of addresses making deposits.
        - Type: `bytes[]`
    - Requirements:
      - Must be called by the `Router` contract.
      - The requester must be an authorized `MPC Node`.
      - Data cannot be re-submitted once initially submitted.
    - Events: Emits `DepositConfirmed` event.

6.  `function selectPMM(address requester, bytes32 tradeId, PMMSelection info)`

    - Purpose: Selects the PMM winner for the trade.
    - Parameters:
      - `requester`:
        - Description: The address of the initiating requester, managed by the `Router` contract.
        - Type: `address`
      - `tradeId`:
        - Description: The unique ID assigned to one trade.
        - Type: `bytes32`
      - `info`:
        - Description: Contains `SelectedPMM` proof and `RFQInfo`.
        - Type: `PMMSelection`
    - Requirements:
      - Must be called by the `Router` contract.
      - The requester must have the `Solver` role.
      - `tradeTimeout` must not have been exceeded.
      - Data cannot be re-submitted once initially submitted.
    - Events: Emits `SelectedPMM` event.
    - Note:
      - For `BTCEVM` and `BTCSOL`: `pFeeAmount` and `aFeeAmount` are calculated at this stage.
      - For `EVMBTC` and `SOLBTC`: already calculated and updated at the `submitTrade` stage.

7.  `function makePayment(address requester, uint256 indexOfTrade, BundlePayment bundle)`

    - Purpose: Announces the completion of payment for a specific trade.
    - Parameters:
      - `requester`:
        - Description: The address of the initiating requester, managed by the `Router` contract.
        - Type: `address`
      - `indexOfTrade`:
        - Description: The index corresponding to the `tradeId` within the bundle.
        - Type: `uint256`
      - `bundle`:
        - Description: A structured data package containing all necessary details for processing the payment of multiple trades.
        - Type: `BundlePayment`
    - Requirements:
      - Must be invoked by the `Router` contract.
      - The requester must have the `Solver` role or be the selected `PMM` for the specific trade.
      - `scriptTimeout` must not have been exceeded.
    - Events: Emits `MadePayment` event.
    - Note: Allows updating the `paymentTxId` for a trade if it has not yet been confirmed by the MPC, even when part of a bundle.

8.  `function confirmPayment(address requester, bytes32 tradeId, bytes signature)`

    - Purpose: Confirms receipt of payment by MPC node.
    - Parameters:
      - `requester`:
        - Description: The initiating requester's address.
          - By `Router`: handled by Router contract.
          - Direct request: requires `msg.sender = requester`.
        - Type: `address`
      - `tradeId`:
        - Description: The unique ID assigned to one trade.
        - Type: `bytes32`
      - `signature`:
        - Description: The signature provided by MPC's threshold keys.
        - Type: `bytes`
    - Requirements:
      - Must be called by `Router` or authorized `MPC Node`.
      - `scriptTimeout` must not have been exceeded.
    - Events: Emits `PaymentConfirmed` event.

9.  `function confirmSettlement(address requester, bytes32 tradeId, bytes releaseTxId, bytes signature)`

    - Purpose: Confirms settlement for the trade.
    - Parameters:
      - `requester`:
        - Description: The initiating requester's address.
          - By `Router`: handled by Router contract.
          - Direct request: requires `msg.sender = requester`.
        - Type: `address`
      - `tradeId`:
        - Description: The unique ID assigned to one trade.
        - Type: `bytes32`
      - `releaseTxId`:
        - Description: Transaction ID for the settlement.
        - Type: `bytes`
      - `signature`:
        - Description: The signature provided by MPC's threshold keys.
        - Type: `bytes`
    - Requirements: Must be called by `Router` or an authorized `MPC Node`.
    - Events: Emits `SettlementConfirmed` event.

10. `function maxAffiliateFeeRate()`

    - Purpose: Retrieves a maximum affiliate fee rate.
    - Parameters: `None`
    - Requirements: Caller can be `ANY`.
    - Events: `None`
    - Returns: The maximum allowable affiliate fee rate as a `uint256`, expressed in basis points (bps).

11. `function router()`

    - Purpose: Get the current `Router` contract.
    - Parameters: `None`
    - Requirements: Caller can be `ANY`.
    - Events: `None`
    - Returns: The address of the Router contract.

12. `function typeOfHandler()`

    - Purpose: Get the type of `Core Handler` contract.
    - Parameters: `None`
    - Requirements: Caller can be `ANY`.
    - Events: `None`
    - Returns:
      - `typeOfHandler`:
        - Description: The type of `Core Handler` contract (i.e. `EVMBTC` or `BTCEVM`).
        - Type: `string`

13. `function currentStage(bytes32 tradeId)`

    - Purpose: Retrieves the current stage (number) of a specific `tradeId`.
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

14. `function lastSignedPayment(bytes32 tradeId)`

    - Purpose: Query the recent timestamp `paymentTxId` was signed to update for the `tradeId`.
    - Parameters:
      - `tradeId`:
        - Description: The unique ID assigned to one trade.
        - Type: `bytes32`
    - Requirements: Caller can be `ANY`.
    - Events: `None`
    - Returns:
      - `signedAt`: The last timestamp `paymentTxId` was signed to update

15. `function feeDetails(bytes32 tradeId)`

    - Purpose: Retrieves a breakdown of the fee details associated with a specific `tradeId`.
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

16. `function affiliate(bytes32 tradeId)`

    - Purpose: Retrieves the affiliate information associated with the specified `tradeId`.
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

17. `function trade(bytes32 tradeId)`

    - Purpose: Retrieves the `tradeData` information for a specific `tradeId`.
    - Parameters:
      - `tradeId`:
        - Description: The unique ID assigned to one trade.
        - Type: `bytes32`
    - Requirements: Caller can be `ANY`.
    - Events: `None`
    - Returns:
      - `data`:
        - Description: A structured data object (`TradeData`) that includes:
          - `sessionId`: The unique session ID assigned to the trade, representing the interaction between the User and the DApp.
          - `tradeInfo`: A structured object that encapsulates the trade-specific details.
          - `scriptInfo`: A structured object that contains the deposited information relevant to the trade.

18. `function presign(bytes32 tradeId)`

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

19. `function depositAddressList(bytes32 tradeId)`

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

20. `function pmmSelection(bytes32 tradeId)`

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

21. `function settledPayment(bytes32 tradeId)`

    - Purpose: Retrieves the `settledPayment` details for a specific `tradeId`.
    - Parameters:
      - `tradeId`:
        - Description: The unique ID assigned to one trade.
        - Type: `bytes32`
    - Requirements: Caller can be `ANY`.
    - Events: `None`
    - Returns:
      - `settledPaymentData`:
        - Description: A structured data object (`SettledPayment`) that includes:
          - `bundlerHash`: The hash representing a group of `tradeIds` paid by the corresponding `paymentTxId`.
          - `paymentTxId`: The transaction ID of the payment made on the destination chain (facilitated by a selected PMM).
          - `releaseTxId`: The transaction ID of the settlement processed on the source chain (executed by MPC).
          - `isConfirmed`: The confirmation status of the payment transaction.
