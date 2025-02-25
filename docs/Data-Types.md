### PetaFi Protocol Data Types (SMC)

This section covers essential data types within the `PetaFi Protocol` that enable efficient and secure handling of cross-chain trades. It defines the various token structures, encoding methods, and data structuring conventions used within the protocol. Each data type is carefully crafted to support seamless interoperability between `Bitcoin`, `Ethereum-based networks` and `Solana`, ensuring that token information, address encoding, and structured trade data maintain compatibility across chains.

#### Token Info Documentation

The `Token Info` defines token metadata for both native and non-native coins across Bitcoin, Ethereum-compatible networks, and Solana networks. This information ensures consistent representation of token identifiers, symbols, addresses, and other key properties in protocol transactions for both mainnet and testnet environments.

Schema Properties:

- `networkId`: Unique identifier assigned to one blockchain network.
- `tokenId`: Unique identifier assigned to one token within a network.
- `networkName`: Human-readable name of the network.
- `symbol`: Token symbol.
- `tokenAddress`: Contract address for the token (use "native" for native coins).
- `externalURL`: Link to the token's explorer page
- `description`: Brief description of the token and its network
- `logoURI`: URL for the token's logo image
- `decimals`: Number of decimal places for the token

###### Native Coins

```json
[
  {
    "info": {
      "networkId": "bitcoin",
      "tokenId": "BTC",
      "networkName": "Bitcoin",
      "symbol": "BTC",
      "tokenAddress": "native",
      "externalURL": "https://mempool.space/",
      "description": "Native BTC on Bitcoin mainnet",
      "logoURI": "https://storage.googleapis.com/bitfi-static-35291d79/images/tokens/btc.svg"
    },
    "decimals": 8
  },
  {
    "info": {
      "networkId": "ethereum",
      "tokenId": "ETH",
      "networkName": "Ethereum",
      "symbol": "ETH",
      "tokenAddress": "native",
      "externalURL": "https://etherscan.io/",
      "description": "Native ETH on Ethereum mainnet",
      "logoURI": "https://storage.googleapis.com/bitfi-static-35291d79/images/tokens/eth.svg"
    },
    "decimals": 18
  },
  {
    "info": {
      "networkId": "solana",
      "tokenId": "SOL",
      "networkName": "Solana",
      "symbol": "SOL",
      "tokenAddress": "native",
      "externalURL": "https://explorer.solana.com/",
      "description": "Native SOL on Solana mainnet",
      "logoURI": "https://cryptologos.cc/logos/solana-sol-logo.svg"
    },
    "decimals": 9
  },
  {
    "info": {
      "networkId": "bitcoin-testnet",
      "tokenId": "tBTC",
      "networkName": "Bitcoin Testnet",
      "symbol": "tBTC",
      "tokenAddress": "native",
      "externalURL": "https://mempool.space/testnet/",
      "description": "Native tBTC on Bitcoin testnet",
      "logoURI": "https://storage.googleapis.com/bitfi-static-35291d79/images/tokens/tbtc.svg"
    },
    "decimals": 8
  },
  {
    "info": {
      "networkId": "ethereum-sepolia",
      "tokenId": "ETH",
      "networkName": "Ethereum Sepolia",
      "symbol": "ETH",
      "tokenAddress": "native",
      "externalURL": "https://sepolia.etherscan.io/",
      "description": "Native ETH on Ethereum Sepolia testnet",
      "logoURI": "https://storage.googleapis.com/bitfi-static-35291d79/images/tokens/eth.svg"
    },
    "decimals": 18
  },
  {
    "info": {
      "networkId": "solana-devnet",
      "tokenId": "SOL",
      "networkName": "Solana Devnet",
      "symbol": "SOL",
      "tokenAddress": "native",
      "externalURL": "https://explorer.solana.com/?cluster=devnet",
      "description": "Native SOL on Solana devnet",
      "logoURI": "https://cryptologos.cc/logos/solana-sol-logo.svg"
    },
    "decimals": 9
  }
]
```

###### Non-native Tokens (ERC-20 or SPL Token)

```json
[
  {
    "info": {
      "networkId": "ethereum",
      "tokenId": "WETH",
      "networkName": "Ethereum",
      "symbol": "WETH",
      "tokenAddress": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
      "externalURL": "https://etherscan.io/token/0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
      "description": "Wrapped ETH on Ethereum mainnet",
      "logoURI": "https://storage.googleapis.com/bitfi-static-35291d79/images/tokens/eth.svg"
    },
    "decimals": 18
  },
  {
    "info": {
      "networkId": "ethereum",
      "tokenId": "ethereum_USDT",
      "networkName": "Ethereum",
      "symbol": "USDT",
      "tokenAddress": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
      "externalURL": "https://etherscan.io/token/0xdAC17F958D2ee523a2206206994597C13D831ec7",
      "description": "Tether USD on Ethereum mainnet",
      "logoURI": "https://storage.googleapis.com/bitfi-static-35291d79/images/tokens/usdt.svg"
    },
    "decimals": 6
  },
  {
    "info": {
      "networkId": "solana",
      "tokenId": "WSOL",
      "networkName": "Solana",
      "symbol": "WSOL",
      "tokenAddress": "So11111111111111111111111111111111111111112",
      "externalURL": "https://explorer.solana.com/address/So11111111111111111111111111111111111111112",
      "description": "Wrapped SOL on Solana mainnet",
      "logoURI": "https://cryptologos.cc/logos/solana-sol-logo.svg"
    },
    "decimals": 9
  },
  {
    "info": {
      "networkId": "solana",
      "tokenId": "USDT",
      "networkName": "Solana",
      "symbol": "USDT",
      "tokenAddress": "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB",
      "externalURL": "https://explorer.solana.com/address/Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB",
      "description": "Tether USD on Solana mainnet",
      "logoURI": "https://storage.googleapis.com/bitfi-static-35291d79/images/tokens/usdt.svg"
    },
    "decimals": 6
  },
  {
    "info": {
      "networkId": "ethereum-sepolia",
      "tokenId": "ethereum-sepolia-WETH",
      "networkName": "Ethereum Sepolia",
      "symbol": "WETH",
      "tokenAddress": "0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14",
      "externalURL": "https://sepolia.etherscan.io/token/0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14",
      "description": "Wrapped ETH on Ethereum Sepolia testnet",
      "logoURI": "https://storage.googleapis.com/bitfi-static-35291d79/images/tokens/eth.svg"
    },
    "decimals": 18
  },
  {
    "info": {
      "networkId": "ethereum-sepolia",
      "tokenId": "ethereum-sepolia-USDT",
      "networkName": "Ethereum Sepolia",
      "symbol": "USDT",
      "tokenAddress": "0x0fE00bF94bfB384F3EA16d1577827633Ee467C0d",
      "externalURL": "https://sepolia.etherscan.io/token/0x0fE00bF94bfB384F3EA16d1577827633Ee467C0d",
      "description": "Tether USD on Ethereum Sepolia testnet",
      "logoURI": "https://storage.googleapis.com/bitfi-static-35291d79/images/tokens/usdt.svg"
    },
    "decimals": 6
  },
  {
    "info": {
      "networkId": "solana-devnet",
      "tokenId": "devnet-WSOL",
      "networkName": "Solana Devnet",
      "symbol": "WSOL",
      "tokenAddress": "So11111111111111111111111111111111111111112",
      "externalURL": "https://explorer.solana.com/address/So11111111111111111111111111111111111111112?cluster=devnet",
      "description": "Wrapped SOL on Solana devnet",
      "logoURI": "https://cryptologos.cc/logos/solana-sol-logo.svg"
    },
    "decimals": 9
  },
  {
    "info": {
      "networkId": "solana-devnet",
      "tokenId": "devnet-USDT",
      "networkName": "Solana Devnet",
      "symbol": "USDT",
      "tokenAddress": "Gh9ZwEmdLJ8DscKNTkTqPbNwLNNBjuSzaG9Vp2KGtKJr",
      "externalURL": "https://explorer.solana.com/address/Gh9ZwEmdLJ8DscKNTkTqPbNwLNNBjuSzaG9Vp2KGtKJr?cluster=devnet",
      "description": "Tether USD on Solana devnet",
      "logoURI": "https://storage.googleapis.com/bitfi-static-35291d79/images/tokens/usdt.svg"
    },
    "decimals": 6
  }
]
```

#### `Bytes` Encoding

The `Bytes Encoding` explains encoding practices for representing different data types (e.g., addresses, public keys) across Bitcoin, EVM-compatible networks, and Solana. This standardizes the encoding of addresses, transactions, and signatures, differentiating between UTF-8 and hexadecimal representations to meet the specific requirements of each blockchain type.

- Data: `fromUserAddress`, `toUserAddress`, `pmmRecvAddress`, `utxoAddress`, `vaultAddress`, `vaultAta`
  - Encoding: `UTF-8` (Bitcoin and Solana) or `Hex-encoded` (EVM).
  - Example:
    - `fromUserAddress`/`toUserAddress`:
      - Bitcoin: `"tb1q85w8v43nj5gq2elmc57fj0jrk8q900sk3udj8h"`
        => `0x74623171383577387634336e6a35677132656c6d633537666a306a726b3871393030736b3375646a3868`
      - EVM: `"0x31003C2D5685c7D28D7174c3255307Eb9a0f3015"`
        => `0x31003C2D5685c7D28D7174c3255307Eb9a0f3015`
      - Solana: `"DK21qxJuG3VEdh2pSthxRAE9dMXuAf8ph4N3FWxwqi5M"`
        => `0x444b323171784a7547335645646832705374687852414539644d58754166387068344e33465778777169354d`
    - `utxoAddress`: `"bcrt1pf67lrceycfuhssrrpjn4q2sa8zapmmsp77jy8lsnqr95x632hmas6xr9q2"`
      => `0x6263727431706636376c726365796366756873737272706a6e3471327361387a61706d6d737037376a79386c736e7172393578363332686d6173367872397132`
    - `vaultAddress`: `"0x6ee8717c57c1A301Af1F94EC84b5A84E43104AaE"`
      => `0x6ee8717c57c1A301Af1F94EC84b5A84E43104AaE`
    - `vaultAta`: `"CkYWru9NFMia9U9dZHTUxWXNuLCmmspkBpN2jHxnH6Kd"`
      => `0x436b59577275394e464d6961395539645a4854557857584e754c436d6d73706b42704e326a48786e48364b64`
- Data: `depositFromList`
  - Array of addresses making deposits.
  - Encoding: `UTF-8` (Bitcoin and Solana) or `Hex-encoded` (EVM).
  - Example:
    - Bitcoin: `"tb1q85w8v43nj5gq2elmc57fj0jrk8q900sk3udj8h"`
      => `0x74623171383577387634336e6a35677132656c6d633537666a306a726b3871393030736b3375646a3868`
    - EVM: `"0x31003C2D5685c7D28D7174c3255307Eb9a0f3015"`
      => `0x31003C2D5685c7D28D7174c3255307Eb9a0f3015`
    - Solana: `"DK21qxJuG3VEdh2pSthxRAE9dMXuAf8ph4N3FWxwqi5M"`
      => `0x444b323171784a7547335645646832705374687852414539644d58754166387068344e33465778777169354d`
- Data: `refundPubkey` (Bitcoin and Solana) or `refundAddress` (EVM)
  - Encoding: `Hex-encode`
  - Example:
    - Bitcoin (pubkey): `"0x02adc1dc353a45e2a037ca62ffa3da00ea7c56cbbd7252f5a02e79999142699c58"`
      => `0x02adc1dc353a45e2a037ca62ffa3da00ea7c56cbbd7252f5a02e79999142699c58`
    - EVM (address): `"0x31003c2d5685c7d28d7174c3255307eb9a0f3015"`
      => `0x31003c2d5685c7d28d7174c3255307eb9a0f3015`
    - Solana (pubkey): `"0xb6e9d84743acdc450385e67d64ea57cf6f54d03af566fc368caab1222aa57240"`
      => `0xb6e9d84743acdc450385e67d64ea57cf6f54d03af566fc368caab1222aa57240`
- Data: `ephemeralAssetPubkey` and `mpcAssetPubkey`
  - Encoding: `Hex-encode`
  - Example:
    - `ephemeralAssetPubkey`: `"0x02adc1dc353a45e2a037ca62ffa3da00ea7c56cbbd7252f5a02e79999142699c58"`
      => `0x02adc1dc353a45e2a037ca62ffa3da00ea7c56cbbd7252f5a02e79999142699c58`
    - `mpcAssetPubkey`: `"0x03e06bd1b14ee9dffd3e2ae257f54b61c07912c43628a9924e1bd31c71838f6f28"`
      => `0x03e06bd1b14ee9dffd3e2ae257f54b61c07912c43628a9924e1bd31c71838f6f28`
- Data: `presign`, `rfqInfoSignature`, `pmmSignature`
  - Encoding: `Hex-encode`
  - Example:
    - `presign`: `"0xdbcb474887a703cff435ce4ded4505727bb1235f558c0ca984e09f80277989bc538e025dfe1f7d1985b0ac7422cc6a95e2b1cb9fce68d2f241eb61863c428ff41c"`
      => `0xdbcb474887a703cff435ce4ded4505727bb1235f558c0ca984e09f80277989bc538e025dfe1f7d1985b0ac7422cc6a95e2b1cb9fce68d2f241eb61863c428ff41c`
- Data: `depositTxId`, `paymentTxId` and `releaseTxId`
  - Encoding: `UTF-8` (Solana) or `Hex-encoded` (Bitcoin and EVM).
  - Example:
    - Bitcoin and EVM: `"0xe771a9a314227a2a39d5385b7ce3c5458f7d062783f84bb5d200dbae682afc99"`
      => `0xe771a9a314227a2a39d5385b7ce3c5458f7d062783f84bb5d200dbae682afc99"`
    - Solana: `"3ywvS2sw3DiFBDMBrqTQvhQGDgL2kUsKJfbEgy9zVL2DZmZmTYm211DQHQ2fEJDa7tAUKRA2hD8pe93SUdttAqKv"`
      => `33797776533273773344694642444d42727154517668514744674c326b55734b4a6662456779397a564c32445a6d5a6d54596d323131445148513266454a4461377441554b52413268443870653933535564747441714b76`
- Data: `fromNetworkId`, `toNetworkId`, `fromTokenId`, `toTokenId`
  - Encoding: `UTF-8`
  - Example:
    - `fromNetworkId`/`toNetworkId`:
      - `"bitcoin"` => `0x626974636f696e`
      - `"ethereum"` => `0x657468657265756d`
    - `fromTokenId`/`toTokenId`:
      - `"native"` => `0x6e6174697665`
      - `"0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"` => `0x307863303261616133396232323366653864306130653563346632376561643930383363373536636332`
      - `"So11111111111111111111111111111111111111112"` => `536f3131313131313131313131313131313131313131313131313131313131313131313131313131313132`

#### Data Structs

The `Data Structs` details core structures (TradeData, Presign, PMMSelection, and others) that represent transaction and protocol data. These structs organize essential trade and transaction details, such as session identifiers, trade amounts, deposit information, and protocol fees, to support streamlined data handling and retrieval within the protocol’s smart contracts.

1. Enum: `STAGE` and `STATUS`

```solidity
    enum STAGE {
        SUBMIT,
        CONFIRM_DEPOSIT,
        SELECT_PMM,
        MAKE_PAYMENT,
        CONFIRM_PAYMENT,
        CONFIRM_SETTLEMENT
    }
```

- Related functions:
  - `submitTrade()`, `confirmDeposit()`, `selectPMM()`
  - `makePayment()`, `confirmPayment()`, `confirmSettlement()`
  - `isSuspended()`
- Related contracts: `Core` (`BTCEVM`, `EVMBTC`, and `BTCSOL`, `SOLBTC`), and `Management` contracts.
- Descriptions: The `STAGE` enum defines a sequence of identifiers representing various stages in the lifecycle of a trade. It is used to track the `currentStage` of a trade associated with a unique `tradeId`. These stages ensure that each trade progresses through a predefined flow, maintaining the integrity and order of operations.

2. Enum: `Status`

```solidity
    enum Status {
        OPERATING,
        SUSPENDED,
        SHUTDOWN
    }
```

- Related functions:
  - `suspend()`, `shutdown()`, `resume()`
  - `isSuspended()`
- Related contracts: `Management` contract.
- Descriptions: The `Status` enum defines the operational states of the `PetaFi protocol`, providing a mechanism to control the availability and functionality of the system. Each state represents a specific operational mode that dictates the behavior of the protocol and its components.

3. Structs: `TradeData`, `TradeInfo`, and `ScriptInfo`

```solidity
    struct TradeData {
        uint256 sessionId;
        TradeInfo tradeInfo;
        ScriptInfo scriptInfo;
    }

    struct TradeInfo {
        uint256 amountIn;
        bytes[3] fromChain; // ["fromUserAddress", "fromNetworkId", "fromTokenId"]
        bytes[3] toChain; // ["toUserAddress", "toNetworkId", "toTokenId"]
    }

    /// @dev: `bytes[5] depositInfo`:
    /// - BTC -> EVM: ["utxoAddress", "depositTxId", "ephemeralAssetPubkey", "mpcAssetPubkey", "refundPubkey"]
    /// - BTC -> SOL: ["utxoAddress", "depositTxId", "ephemeralAssetPubkey", "mpcAssetPubkey", "refundPubkey"]
    /// - EVM -> BTC: ["vaultAddress", "depositTxId", "ephemeralAssetPubkey", "mpcAssetPubkey", "refundAddress"]
    /// - SOL -> BTC: ["vaultAta", "depositTxId", "ephemeralAssetPubkey", "mpcAssetPubkey", "refundPubkey"]
    struct ScriptInfo {
        bytes[5] depositInfo;
        address userEphemeralL2Address;
        uint64 scriptTimeout;
    }
```

- Related functions: `submitTrade()`.
- Related contracts: `Core` (`BTCEVM`, `EVMBTC`, and `BTCSOL`, `SOLBTC`), and `Router` contracts.
- Descriptions:
  - `sessionId`:
    - A unique identifier for each trade session.
    - Type: `uint256`
  - `amountIn`:
    - Amount of assets deposited for trade.
    - Type: `uint256`
  - `fromChain`: Array of `bytes` for source chain details:
    - [0] : `fromUserAddress`
    - [1] : `fromNetworkId`
    - [2] : `fromTokenId`
  - `toChain`: Array of `bytes` for destination chain details:
    - [0] : `toUserAddress`
    - [1] : `toNetworkId`
    - [2] : `toTokenId`
  - `depositInfo`: Array of `bytes` with deposit information based on trade direction.
    - [0] : `utxoAddress` (BTCEVM), `vaultAddress` (EVMBTC), or `vaultAta` (SOLBTC).
    - [1] : `depositTxId`
    - [2] : `ephemeralAssetPubkey`
    - [3] : `mpcAssetPubkey`
    - [4] : `refundPubkey` (BTCEVM, BTCSOL, SOLBTC) or `refundAddress` (EVMBTC)
  - `userEphemeralL2Address`:
    - Each trade involves two ephemeral keys: `ephemeralAssetKey` and `ephemeralL2Key`. And this is the address derived from the `ephemeralL2Key`.
    - Type: `address`
  - `scriptTimeout`:
    - Expiration timestamp for the trade script (BTCEVM: `btcScript`, EVMBTC: `Vault`, SOLBTC: `PDA`).
    - Type: `uint64`

4.  Struct: `Presign`

```solidity
    struct Presign {
        bytes32 pmmId;
        bytes pmmRecvAddress;
        bytes[] presigns; // presignatures
    }
```

- Related functions: `submitTrade()`.
- Related contracts: `Core` (`BTCEVM`, `EVMBTC`, and `BTCSOL`, `SOLBTC`), and `Router` contracts.
- Descriptions:
  - `pmmId`:
    - Unique identifier for a PMM.
    - Type: `bytes32`
    - Example1: `0x00000000000000000000000078bdc100555672a193359bd3e9cd68f23015a051`
    - Example2: `keccak256(toUtf8Bytes("PMM Identification 1"))`
      => `0xa5dd1493db6615997fced6844d021fd71accb5e2a864f622145776e4de754272`
  - `pmmRecvAddress`:
    - The PMM's receiving address (Bitcoin, EVM, or Solana)
    - Types: `bytes`
  - `presigns`:
    - Array of presignatures
    - Types: `bytes[]`

5.  Structs: `PMMSelection`, `SelectedPMMInfo`, and `RFQInfo`

```solidity
    struct PMMSelection {
        RFQInfo rfqInfo;
        SelectedPMMInfo pmmInfo;
    }

    struct RFQInfo {
        uint256 minAmountOut;
        uint64 tradeTimeout;
        bytes rfqInfoSignature;
    }

    struct SelectedPMMInfo {
        uint256 amountOut;
        bytes32 selectedPMMId;
        bytes[2] info; // ["pmmRecvAddress", "pmmSignature"]
        uint64 sigExpiry;
    }
```

- Related functions: `selectPMM()`.
- Related contracts: `Core` (`BTCEVM`, `EVMBTC`, and `BTCSOL`, `SOLBTC`), and `Router` contracts.
- Descriptions:
  - `minAmountOut`:
    - Minimum acceptable amount, provided by User, for the trade.
    - Type: `uint256`
  - `tradeTimeout`:
    - Timeout expectation for receiving payment.
    - Type: `uint64`
  - `rfqSignature`:
    - User’s signature, signed with `ephemeralAssetKey`, covering `minAmountOut`, `tradeTimeout`, and `affiliate`.
    - Type: `bytes`
  - `amountOut`:
    - Quoted amount provided by the selected PMM.
    - Type: `uint256`
  - `selectedPMMId`:
    - Identifier for the selected PMM, existing in the `Presign[]`.
    - Type: `bytes32`
  - `info`: Array of `bytes` containing:
    - [0] : `pmmRecvAddress`
    - [1] : `pmmSignature`
  - `sigExpiry`:
    - The expiration timestamp for `pmmSignature`
    - Type: `uint64`

6.  `SettledPayment` struct:

```solidity
    struct SettledPayment {
        bytes32 bundlerHash;
        bytes paymentTxId;
        bytes releaseTxId;
        bool isConfirmed;
    }
```

- Related functions: `makePayment()`, `confirmPayment()`, and `confirmSettlement()`.
- Related contracts: `Core` (`BTCEVM`, `EVMBTC`, and `BTCSOL`, `SOLBTC`), and `Router` contracts.
- Descriptions:
  - `bundlerHash`:
    - The hash representing a group of `tradeIds` paid by the corresponding `paymentTxId`.
    - Type: `bytes32`.
  - `paymentTxId`:
    - The transaction ID for the payment made by the selected PMM.
    - Type: `bytes`.
  - `releaseTxId`:
    - Transaction ID for the settlement, where the MPC executes the transfer of locked funds to the selected PMM.
    - Type: `bytes`.
  - `isConfirmed`:
    - Boolean flag indicating whether the payment has been confirmed.
    - Type: `bool`

7.  `BundlePayment` struct:

```solidity
    struct BundlePayment {
        bytes32[] tradeIds;
        uint64 signedAt;
        uint64 startIdx;
        bytes paymentTxId;
        bytes signature;
    }
```

- Related functions: `makePayment()` (Core) or `bundlePayment()` (Router).
- Related contracts: `Core` (`BTCEVM`, `EVMBTC`, and `BTCSOL`, `SOLBTC`), and `Router` contracts.
- Descriptions:
  - `tradeIds`:
    - A hash representing a group of trade IDs that are paid using the specified `paymentTxId`.
    - Type: `bytes32[]`.
  - `signedAt`:
    - A value representing the timestamp that payment is signed by a selected PMM.
    - Type: `uint64`
  - `startIdx`:
    - Identifies the starting transaction index for validation, where the MPC checks the corresponding data to ensure it matches the `amount` and `receiver` specified for each trade.
    - Type: `uint64`.
  - `paymentTxId`:
    - A payment transaction identifier for the payment executed by the selected PMM.
    - Type: `bytes`
  - `signature`:
    - A signature, for verification, signed by a selected PMM
    - Type: `bytes`

8.  `FeeDetails` struct

```solidity
    struct FeeDetails {
        uint256 totalAmount;
        uint256 pFeeAmount;
        uint256 aFeeAmount;
        uint128 pFeeRate;
        uint128 aFeeRate;
    }
```

- Related functions: `submitTrade()`, and `selectPMM()`.
- Related contracts: `Core` (`BTCEVM`, `EVMBTC`, and `BTCSOL`, `SOLBTC`), and `Router` contracts.
- Descriptions:
  - `totalAmount`:
    - The total fee amount charged for a trade.
    - Type: `uint256`
  - `pFeeAmount`:
    - The protocol fee amount charged for a trade.
    - Type: `uint256`
  - `aFeeAmount`:
    - The affiliate fee amount charged for a trade.
    - Type: `uint256`
  - `pFeeRate`:
    - The protocol fee rate applied to a trade, expressed in basis points.
    - Type: `uint128`
  - `aFeeRate`:
    - The total affiliate fee rate applied to a trade, expressed in basis points.
    - Type: `uint128`

9.  `Affiliate` struct

```solidity
    struct Affiliate {
        uint256 aggregatedValue;
        string schema;
        bytes data;
    }
```

- Related functions: `submitTrade()`.
- Related contracts: `Core` (`BTCEVM`, `EVMBTC`, and `BTCSOL`, `SOLBTC`), and `Router` contracts.
- Descriptions:
  - `aggregatedValue`:
    - The total affiliate fee rate applied to a trade, expressed in basis points.
    - Type: `uint256`
  - `schema`:
    - Defines the data structure and encoding method used to decode data.
    - Type: `string`
  - `data`:
    - Encoded affiliate-related information.
    - Type: `bytes`

10. `TokenInfo` struct

```solidity
    struct TokenInfo {
        bytes[5] info; // ["tokenId", "networkId", "symbol", "externalURL", "description"]
        uint256 decimals;
    }
```

- Related functions: `setToken()`, `getToken()`.
- Related contracts: `Management` contracts.
- Descriptions:
  - `info`:
    - An array of bytes storing essential metadata about the token: `tokenId`, `networkId`, `symbol`, `externalURL`, and `description`.
    - Type: `bytes[5]`
  - `decimals`:
    - The number of decimal places the token supports, defining its smallest divisible unit.
    - Type: `uint256`

11. `MPCInfo` struct

```solidity
    struct MPCInfo {
        address mpcL2Address;
        uint64 expireTime;
        bytes mpcL2Pubkey;
        bytes mpcAssetPubkey;
    }
```

- Related functions: `getLatestMPCInfo()`, `getMPCInfo`, and `isValidPubkey()`.
- Related contracts: `Management` contracts.
- Descriptions:
  - `mpcL2Address`:
    - The address derived from mpcL2Pubkey, serving as the identifier for the `MPC` entity in the PetaFi protocol (L2).
    - Type: `address`
  - `expireTime`:
    - The expiration timestamp for the `mpcL2Pubkey` and `mpcAssetPubkey`, associated with the `mpcL2Address` address.
    - Type: `uint64`
  - `mpcL2Pubkey`:
    - The public key of the `MPC` entity used for operations within the PetaFi protocol (L2).
    - Type: `bytes`
  - `mpcAssetPubkey`:
    - The public key of the `MPC` entity used for operations on the asset chain.
    - Type: `bytes`
