#### Overview

The `VaultRegistry` contract is a utility component of the `PetaFi Protocol` designed to manage and validate `Vault` addresses across various asset chains. It enables users to retrieve locking `Vault` addresses using a combination of `networkId` and `tokenId`.

#### Key Components and Descriptions

1.  Dedicated Deployment:
    - A separate `Vault` contract is deployed for each supported token on each asset chain.
    - This approach ensures flexibility and isolation for each token and network combination.
2.  Multi-chain validation
    - Deployed addresses across various asset chains are registered and easy to verify.
    - Ensures consistency and integrity of Vault addresses within the protocol.

#### Functions Documentation

1.  `function setManagement(address newManagement)`
    - Purpose: Updates the address of the `Management` contract.
    - Parameters:
      - `newManagement`:
        - Description: The new Management contract's address.
        - Type: `address`
    - Requirements:
      - Caller must be the `owner` of the current `Management` contract.
      - New address must not be the zero address (0x0).
2.  `function setVault(address vault, bytes networkId, bytes tokenId)`
    - Purpose: Registers a locking `Vault` address for a specific `tokenId` on a given `networkId`.
    - Parameters:
      - `vault`:
        - Description: Address of the deployed `Vault`.
        - Type: `address`
      - `networkId`:
        - Description: The unique identifier assigned to one network.
        - Type: `bytes`
      - `tokenId`:
        - Description: The unique identifier assigned to one token.
        - Type: `bytes`
    - Requirements:
      - Caller must be the `owner` of the current `Management` contract.
      - Vault address should not be 0x0.
      - The `tokenId` for the specified `networkId` must be registered by the Admin.
    - Events: Emits `AssetVaultUpdated` event.
3.  `function removeVault(bytes networkId, bytes tokenId)`
    - Purpose: Deregisters the locking `Vault` address for a specific `tokenId` on a given `networkId`.
    - Parameters:
      - `networkId`:
        - Description: The unique identifier assigned to one network.
        - Type: `bytes`
      - `tokenId`:
        - Description: The unique identifier assigned to one token.
        - Type: `bytes`
    - Requirements:
      - Caller must be the `owner` of the current `Management` contract.
      - The locking Vault for the specified `tokenId` and `networkId` must already be registered.
    - Events: Emits `AssetVaultUpdated` event.
4.  `function getVault(bytes networkId, bytes tokenId)`
    - Purpose: Retrieves the deployed `Vault` address using the specified `networkId` and `tokenId`.
    - Parameters:
      - `networkId`:
        - Description: The unique identifier assigned to one network.
        - Type: `bytes`
      - `tokenId`:
        - Description: The unique identifier assigned to one token.
        - Type: `bytes`
    - Returns: Address of the deployed `Vault`.
5.  `function management()`
    - Purpose: Holds the address of the `Management` contract.
    - Parameters: `None`
    - Requirements: Caller can be `ANY`.
    - Events: `None`
