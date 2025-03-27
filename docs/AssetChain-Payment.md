#### Overview

The `Payment` contract is a crucial component in the `Optimex Protocol` ecosystem, responsible for handling the PMM's payments across different smart-contract enabled asset-chains. It serves two purposes, namely facilitating secure payment made by PMM to the user, and collecting total charged fee incurred in the trade.
The contract references the `Protocol` contract to access protocol-level configurations, such as the protocol fee receiver address.
Additionally, it uses `SafeERC20` to handle token transfers safely, preventing transfer failures.

#### Key Components and Descriptions

1.  Protocol Reference:

    - The `protocol` variable references the `Protocol` contract, allowing the `Payment` contract to access settings, including the protocol fee receiver's address.

2.  Events:
    - `ProtocolUpdated`: Signals a change in the `Protocol` contract's address.
    - `PaymentTransferred`: Logs each payment transfer, including protocol fees and transaction details.

#### Functions Documentation

1. `function setProtocol(address newProtocol)`

   - Purpose: Updates the address of the `Protocol` contract.
   - Parameters:
     - `newProtocol`:
       - Description: The new address of the Protocol contract.
       - Type: `address`
   - Requirements:
     - Caller must be the `Owner` of the current `Protocol` contract.
     - `newProtocol` cannot be a zero address.
   - Events: Emits `ProtocolUpdated` event.

2. `function payment(bytes32 tradeId, address token, address toUser, uint256 amount, uint256 totalFee, uint256 deadline)`

   - Purpose: Distributes payment to the specified user and the protocol fee receiver.
   - Parameters:
     - `tradeId`:
       - Description: The unique identifier assigned to one trade.
       - Type: `bytes32`
     - `token`:
       - Description: The token used for the payment. A value of `0x0` indicates a native coin.
       - Type: `address`
     - `toUser`:
       - Description: The address of the recipient receiving the user's portion of the payment.
       - Type: `address`
     - `amount`:
       - Description: The total amount for the payment transaction, including the `protocolFee`.
       - Type: `uint256`
     - `totalFee`:
       - Description: The portion of the `amount` allocated as the total fee, to be transferred to `pFeeAddr`.
       - Type: `uint256`
     - `deadline`:
       - Description: The latest timestamp by which the payment must be processed.
       - Type: `uint256`
   - Requirements:
     - Caller can be any address.
     - For native coin payments, `msg.value` must equal the `amount`.
     - The `toUser` address must not be a zero address.
     - The `totalFee` must match the value specified by the Optimex Protocol for the trade. The `MPC` will verify the payment transaction before providing a payment confirmation on L2, which triggers the release of funds on the destination chain. **Dishonest behavior by the PMM will result in the loss of payment**.
   - Events: Emits `PaymentTransferred` event.

3. `function protocol()`

   - Purpose: Returns the address of the current `Protocol` contract.
   - Parameters: `None`
   - Requirements: Caller can be `ANY`.
   - Returns: The address of `Protocol` contract
   - Events: `None`
