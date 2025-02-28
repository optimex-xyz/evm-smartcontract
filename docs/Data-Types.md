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
      "networkId": "bitcoin_testnet",
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
      "networkId": "ethereum_sepolia",
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
      "networkId": "solana_devnet",
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
      "networkId": "ethereum_sepolia",
      "tokenId": "ethereum_sepolia_WETH",
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
      "networkId": "ethereum_sepolia",
      "tokenId": "ethereum_sepolia_USDT",
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
      "networkId": "solana_devnet",
      "tokenId": "solana_devnet_WSOL",
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
      "networkId": "solana_devnet",
      "tokenId": "solana_devnet_USDT",
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

- Data: `fromNetworkId` and `toNetworkId`

  - Encoding: `UTF-8`
  - Example:
    - `"bitcoin"` => `0x626974636f696e`
    - `"ethereum"` => `0x657468657265756d`
    - `"solana"` => `0x736f6c616e61`

- Data: `depositTxId`, `paymentTxId`, and `releaseTxId`

  - Encoding: `UTF-8` (Solana) or `Hex-encoding` (EVM).
  - Example:
    - Bitcoin: `"275c3ce711bb385601db34787300ac05a7e6d25b1d6706a51c7b13c3b8161973"`
      => Encoded data: `0x32373563336365373131626233383536303164623334373837333030616330356137653664323562316436373036613531633762313363336238313631393733`
    - EVM: `"0xe771a9a314227a2a39d5385b7ce3c5458f7d062783f84bb5d200dbae682afc99"`
      => Encoded data: `0xe771a9a314227a2a39d5385b7ce3c5458f7d062783f84bb5d200dbae682afc99"`
    - Solana: `"3ywvS2sw3DiFBDMBrqTQvhQGDgL2kUsKJfbEgy9zVL2DZmZmTYm211DQHQ2fEJDa7tAUKRA2hD8pe93SUdttAqKv"`
      => Encoded data: `0x33797776533273773344694642444d42727154517668514744674c326b55734b4a6662456779397a564c32445a6d5a6d54596d323131445148513266454a4461377441554b52413268443870653933535564747441714b76`

- Data: `fromUserAddress`

  - Encoding: `UTF-8` (Bitcoin and Solana) or `Hex-encoding` (EVM).
  - Example:
    - Bitcoin (pubkey): `"021937db0faa696b04ab44ef089c6ed53da755662d8c8c8299746f3d3a827016cc"`
      => Encoded data: `0x303231393337646230666161363936623034616234346566303839633665643533646137353536363264386338633832393937343666336433613832373031366363`
    - EVM (address): `"0x31003C2D5685c7D28D7174c3255307Eb9a0f3015"`
      => Encoded data: `0x31003C2D5685c7D28D7174c3255307Eb9a0f3015`
    - Solana: `"DK21qxJuG3VEdh2pSthxRAE9dMXuAf8ph4N3FWxwqi5M"`
      => Encoded data: `0x444b323171784a7547335645646832705374687852414539644d58754166387068344e33465778777169354d`
  - Note: For Bitcoin, bitcoin script requires `creatorPubkey` included, thus user's pubkey will be using instead of an address.

- Data: `toUserAddress`

  - Encoding: `UTF-8` (Bitcoin and Solana) or `Hex-encoding` (EVM).
  - Example:
    - Bitcoin: `"tb1px9xpzszfa3c87dy8s986v37jdq5zf50c6086gj3af6cuvy4g0u8q93xqm6"`
      => Encoded data: `0x74623170783978707a737a666133633837647938733938367633376a6471357a6635306336303836676a3361663663757679346730753871393378716d36`
    - EVM: `"0x8147d4d4d039adb99b59cd82fb900dd40af87e40"`
      => Encoded data: `0x8147d4d4d039adb99b59cd82fb900dd40af87e40`
    - Solana: `"4u3fRS7rkHWE9SAPVFpyQgVYpDEjJkRQvR6DjRhBeuwN"`
      => Encoded data: `0x34753366525337726b4857453953415056467079516756597044456a4a6b5251765236446a5268426575774e`

- Data: `fromTokenId` and `toTokenId`

  - Encoding: `UTF-8` (Bitcoin, Solana, and native coin) or `Hex-encoding` (EVM)
  - Example:
    - Native coin: `"native"`
      => Encoded data: `0x6e6174697665`
    - EVM (ERC-20): `"0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"` (with checksum)
      => Encoded data: `0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2`
    - Solana (SPL): `"So11111111111111111111111111111111111111112"`
      => Encoded data: `0x536f3131313131313131313131313131313131313131313131313131313131313131313131313131313132`

- Data: `utxoAddress`

  - Description: UTXO address of deposited btc script
  - Encoding: `UTF-8`
  - Example: `"bcrt1pf67lrceycfuhssrrpjn4q2sa8zapmmsp77jy8lsnqr95x632hmas6xr9q2"`
    => Encoded data: `0x6263727431706636376c726365796366756873737272706a6e3471327361387a61706d6d737037376a79386c736e7172393578363332686d6173367872397132`

- Data: `vaultAddress`

  - Description: Address of deployed Vault contract on the asset-chain.
  - Encoding: `Hex-encoding`
  - Example: `"0x6ee8717c57c1A301Af1F94EC84b5A84E43104AaE"`
    => Encoded data: `0x6ee8717c57c1A301Af1F94EC84b5A84E43104AaE`

- Data: `vaultAta`

  - Description: Unique Vault's address per trade.
  - Encoding: `UTF-8`
  - Example: `"WjZM2S1t5v4MDK8xE9PmJnNME6H5Bezv9CAcdLJKVPx"`
    => Encoded data: `0x576a5a4d325331743576344d444b38784539506d4a6e4e4d4536483542657a7639434163644c4a4b565078`

- Data: `pmmRecvAddress`

  - Encoding: `UTF-8` (Bitcoin and Solana) or `Hex-encoding` (EVM).
  - Example:
    - Bitcoin: `"tb1pjat237hutlc4efv4vsd5usw92gm8xxzxxgujpadh90kqv3ac6kgshtjk5d"`
      => Encoded data: `0x746231706a61743233376875746c633465667634767364357573773932676d3878787a787867756a7061646839306b7176336163366b677368746a6b3564`
    - EVM: `"0x78bdc100555672a193359bd3e9cd68f23015a051"`
      => Encoded data: `0x78bdc100555672a193359bd3e9cd68f23015a051`
    - Solana: `"BuGWUha7mFXFQYpWtWenMnseL452vLUoYXXVWPZEuK3Q"`
      => Encoded data: `0x42754757556861376d465846515970577457656e4d6e73654c343532764c556f5958585657505a45754b3351`

- Data: `depositFromList`

  - Description: Array of addresses making deposits.
  - Encoding: `UTF-8` (Bitcoin and Solana) or `Hex-encoding` (EVM).
  - Example:
    - Bitcoin: `"tb1q85w8v43nj5gq2elmc57fj0jrk8q900sk3udj8h"`
      => Encoded data: `0x74623171383577387634336e6a35677132656c6d633537666a306a726b3871393030736b3375646a3868`
    - EVM: `"0x31003C2D5685c7D28D7174c3255307Eb9a0f3015"`
      => Encoded data: `0x31003C2D5685c7D28D7174c3255307Eb9a0f3015`
    - Solana: `"DK21qxJuG3VEdh2pSthxRAE9dMXuAf8ph4N3FWxwqi5M"`
      => Encoded data: `0x444b323171784a7547335645646832705374687852414539644d58754166387068344e33465778777169354d`

- Data: `ephemeralAssetPubkey`, `mpcAssetPubkey`

  - Encoding: `UTF-8` (Bitcoin and Solana) or `Hex-encoding` (EVM)
  - Example:
    - Bitcoin: `"02a867ba63dc813703a195028b210a400d91e84010e445bdbdbdf8ec8882d5f924"`
      => Encoded data: `0x303261383637626136336463383133373033613139353032386232313061343030643931653834303130653434356264626462646638656338383832643566393234`
    - EVM: `"0x02adc1dc353a45e2a037ca62ffa3da00ea7c56cbbd7252f5a02e79999142699c58"`
      => Encoded data: `0x02adc1dc353a45e2a037ca62ffa3da00ea7c56cbbd7252f5a02e79999142699c58`
    - Solana: `"49H6vRngVfGGxnuWPtFZybpXWeGmXNh6YxK6waA3V3MQ"`
      => Encoded data: `0x3439483676526e6756664747786e75575074465a796270585765476d584e683659784b367761413356334d51`

- Data: `mpcL2Pubkey`

  - Description: The key will be using in the L2 Protocol operations.
  - Encoding: `Hex-encoding` (EVM)
  - Example: `"0x038e579e9f340c4d0f8d5c96b9c01fdf3d84cf2658c9cc89e1ee8c03d727187b20"`
    => Encoded data: `0x038e579e9f340c4d0f8d5c96b9c01fdf3d84cf2658c9cc89e1ee8c03d727187b20`

- Data: `refundPubkey` (Bitcoin and Solana) or `refundAddress` (EVM)

  - Encoding: `UTF-8` (Bitcoin and Solana) or `Hex-encoding` (EVM)
  - Example:
    - Bitcoin: `"021937db0faa696b04ab44ef089c6ed53da755662d8c8c8299746f3d3a827016cc"`
      => Encoded data: `0x303231393337646230666161363936623034616234346566303839633665643533646137353536363264386338633832393937343666336433613832373031366363`
    - EVM (address): `"0x8147d4d4d039adb99b59cd82fb900dd40af87e40"`
      => Encoded data: `0x8147d4d4d039adb99b59cd82fb900dd40af87e40`
    - Solana: `"4u3fRS7rkHWE9SAPVFpyQgVYpDEjJkRQvR6DjRhBeuwN"`
      => Encoded data: `0x34753366525337726b4857453953415056467079516756597044456a4a6b5251765236446a5268426575774e`

- Data: `rfqInfoSignature`, `pmmSignature`, and `signature`

  - Encoding: `Hex-encoding`
  - Example: `"0xa09b2eedb44289b1374ac24d1ed601238266d10e4501f4fdab4c41d8fb6473a9228ea5e47673783b3131bdd4e3885c49b32c5b55bb2914b67c0a4a2a3c1a7da11b"`
    => Encoded data: `0xa09b2eedb44289b1374ac24d1ed601238266d10e4501f4fdab4c41d8fb6473a9228ea5e47673783b3131bdd4e3885c49b32c5b55bb2914b67c0a4a2a3c1a7da11b`

- Data: `presign`

  - Encoding: `Hex-encoding`
  - Example:
    - Bitcoin: `"0x70736274ff01005e0200000001731916b8c3137b1ca506671d5bd2e6a705ac00737834db015638bb11e73c5c270000000000ffffffff01f8160000000000002251209756a8fafc5ff15ca595641b4e41c55236731846323920f5b72bec0647b8d591000000000001012b204e000000000000225120794364c66f77e0ec7b62c5ff6b48dbe40db4b7d267f0a239deaacb7f933cc92e4114adf74d2c307868fde3d58263358d1d550c29bb6aa66c1a7ea17ef4051a6b6ccb449c5bbde6be8aa9934fef08cdbd3c15d437011834a17f70a5be55dc5989b984408fa7b3e8e90e46cfa86e27d1f5ce83c71a90b6a9ce35e5ed8c065c7f00fd911101cbaab4b17fbda6acb9a7ea014e8735af7bf38ac545ee05b778b040e93cb0244215c13718502fc5f6e9fb86ae0200a004a9eae3ac34dcc8da5224a0fbf6691b4481682d7a8fd485a729b2b54b95e9118b668d4e1b64cd27836f47a6745fb1d3376c644720b7591bcb318817bfe970463e4d0158ce80956c1f21011034a9b69214e33142fbac20adf74d2c307868fde3d58263358d1d550c29bb6aa66c1a7ea17ef4051a6b6ccbba529cc00000"`
      => Encoded data: `0x70736274ff01005e0200000001731916b8c3137b1ca506671d5bd2e6a705ac00737834db015638bb11e73c5c270000000000ffffffff01f8160000000000002251209756a8fafc5ff15ca595641b4e41c55236731846323920f5b72bec0647b8d591000000000001012b204e000000000000225120794364c66f77e0ec7b62c5ff6b48dbe40db4b7d267f0a239deaacb7f933cc92e4114adf74d2c307868fde3d58263358d1d550c29bb6aa66c1a7ea17ef4051a6b6ccb449c5bbde6be8aa9934fef08cdbd3c15d437011834a17f70a5be55dc5989b984408fa7b3e8e90e46cfa86e27d1f5ce83c71a90b6a9ce35e5ed8c065c7f00fd911101cbaab4b17fbda6acb9a7ea014e8735af7bf38ac545ee05b778b040e93cb0244215c13718502fc5f6e9fb86ae0200a004a9eae3ac34dcc8da5224a0fbf6691b4481682d7a8fd485a729b2b54b95e9118b668d4e1b64cd27836f47a6745fb1d3376c644720b7591bcb318817bfe970463e4d0158ce80956c1f21011034a9b69214e33142fbac20adf74d2c307868fde3d58263358d1d550c29bb6aa66c1a7ea17ef4051a6b6ccbba529cc00000`
    - EVM: `"0x2bca1c0d63c7ae01152d133e9c247d2299d262ef05d6f72f9e0abbd2ffcd967d749da03f42888a5d8b8674e5a09e29e1f0a9aec7e10d74f93ea21d0fb466490b1b"`
      => Encoded data: `0x2bca1c0d63c7ae01152d133e9c247d2299d262ef05d6f72f9e0abbd2ffcd967d749da03f42888a5d8b8674e5a09e29e1f0a9aec7e10d74f93ea21d0fb466490b1b`
    - Solana: `"0x020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000030da3a059ec6298e56de7b178b1668afe01246aab83a9e2b4059c71920fb37b0b5ce75f538ed191190a1aefce9a52a39f0174e3b7ce2dd71e7c0b72eecb70b050200030b2eb1e9f815be69a9d37568ea130d65bbc8344e14f64b11f8116b022ee324fa47714498aad4d85d3e9545ffef29d31639e0a853693fb73e730a9cbbf65fc6e95b251167ab30a5ad2de919fcf1d6c4b6558da1f52180047e886dfb139fc9911f5237446c2e340e6ef68331897a8141f2c9f473e2c00a0405a2bac3587d632e1d6b39e845f5711584fb28902144c0964f68b329f85adbea66089c4482a1ba8cd80982b7deeb9bc93f971e148fa90bc78aa9410f9b6eb1b26ad9d2c58272daafb260a1f89b46f792434f8bad1c057cdd3a3a4475717afc6dbec7084b479b5a3dcd03079df6ad4a9ac63982ffceee28e79efc676b93ae1ffe9cb05d6abe7fcf2ab4630000000000000000000000000000000000000000000000000000000000000000c19fa616ddf94c0da52fe00f41e4ed449f9ae438f65601bac3e72559a9ebaae806a7d517192c568ee08a845f73d29788cf035c3145b21ab344d8062ea9400000fe2efa0b4bbf0aa1f448a17c53ff00476f6581d3d8ba4327e9fb01da8e7c11f3020803010a000404000000090a00040102030704050608288015ae3c2f56826c5f16c406795ee97973a913a5f61084f279e53510545be82ff0a3b46839c4cc94"`
      => Encoded data: `0x020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000030da3a059ec6298e56de7b178b1668afe01246aab83a9e2b4059c71920fb37b0b5ce75f538ed191190a1aefce9a52a39f0174e3b7ce2dd71e7c0b72eecb70b050200030b2eb1e9f815be69a9d37568ea130d65bbc8344e14f64b11f8116b022ee324fa47714498aad4d85d3e9545ffef29d31639e0a853693fb73e730a9cbbf65fc6e95b251167ab30a5ad2de919fcf1d6c4b6558da1f52180047e886dfb139fc9911f5237446c2e340e6ef68331897a8141f2c9f473e2c00a0405a2bac3587d632e1d6b39e845f5711584fb28902144c0964f68b329f85adbea66089c4482a1ba8cd80982b7deeb9bc93f971e148fa90bc78aa9410f9b6eb1b26ad9d2c58272daafb260a1f89b46f792434f8bad1c057cdd3a3a4475717afc6dbec7084b479b5a3dcd03079df6ad4a9ac63982ffceee28e79efc676b93ae1ffe9cb05d6abe7fcf2ab4630000000000000000000000000000000000000000000000000000000000000000c19fa616ddf94c0da52fe00f41e4ed449f9ae438f65601bac3e72559a9ebaae806a7d517192c568ee08a845f73d29788cf035c3145b21ab344d8062ea9400000fe2efa0b4bbf0aa1f448a17c53ff00476f6581d3d8ba4327e9fb01da8e7c11f3020803010a000404000000090a00040102030704050608288015ae3c2f56826c5f16c406795ee97973a913a5f61084f279e53510545be82ff0a3b46839c4cc94`

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
