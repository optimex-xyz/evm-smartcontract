#### Overview

The `Protocol` contract is a key component of the `PetaFi Protocol`, deployed across multiple asset-chains (e.g., Ethereum, Base, Optimism). This contract manages core functionalities specific to asset-chain operations, primarily overseeing the protocol fee receiver's address and providing owner-level privileges for updating critical settings. It utilizes OpenZeppelin’s Ownable module to restrict access to certain functions, ensuring only the owner can execute privileged actions.

#### Key Components and Descriptions

1.  Protocol Fee Receiver:

    - `pFeeAddr` stores the address designated to receive protocol fees.
    - The address can only be updated by the `owner` to ensure secure fee handling.

2.  Access Control:
    - Access is owner-restricted through inheritance from OpenZeppelin’s Ownable contract, limiting function execution for critical updates.

#### Functions Documentation

1.  `function setPFeeAddress(address newPFeeAddr)`

    - Purpose: Sets a new address for the protocol fee receiver.
    - Parameters:
      - `newPFeeAddr`:
        - Description: The address to be set as the protocol fee receiver.
        - Type: `address`
    - Requirements:
      - Caller must be the contract `Owner`.
      - `newPFeeAddr` cannot be a zero address.
    - Events: Emits `PFeeAddressUpdated` event.

2.  `function owner()`

    - Purpose: Returns the `owner`'s address of the `Protocol` contract.
    - Parameters: `None`
    - Requirements: Caller can be `ANY`.
    - Returns: The current `owner`.
    - Events: `None`
