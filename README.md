### PetaFi Protocol Overview (SMC)

The `PetaFi Protocol` is a robust framework designed to facilitate cross-chain transactions and interactions in a decentralized finance (`DeFi`) environment. It utilizes a series of smart contracts deployed across different networks to ensure secure, efficient, and scalable operations. The protocol comprises several key components, deployed in both a private L2 network and across asset-chains (i.e. Ethereum, Base)

<p align="center">
  <img src="./docs/images/PetaFi.png" alt="PetaFi Smart Contracts" width="950px" height="300px"/>
</p>

All of the following contracts are designed to be replaceable (compose/decompose).

#### Protocol Features

1.  Cross-Chain Compatibility: The `PetaFi Protocol` is designed to operate seamlessly across multiple networks, including Ethereum and Base, enabling a diverse range of asset interactions.

2.  Scalability: Utilizing a private L2 network enhances the protocol's scalability, allowing for higher transaction throughput and lower fees.

3.  Security: The use of established cryptographic methods and smart contract patterns enhances the security of user transactions and protocol operations.

#### Deployed Contracts:

- `PetaFi Testnet`: [https://explorer-bitfi-p00c4t1rul.t.conduit.xyz/](https://explorer-bitfi-p00c4t1rul.t.conduit.xyz/)

  - `Management`: [0xd4DC8a029cdDdf57aBedBcD7D6dA47A6feC658c5](https://explorer-bitfi-p00c4t1rul.t.conduit.xyz/address/0xd4DC8a029cdDdf57aBedBcD7D6dA47A6feC658c5)
  - `VaultRegistry`: [0x4e42b9E52F3Ed95ca049840A228FA22E1c80F08C](https://explorer-bitfi-p00c4t1rul.t.conduit.xyz/address/0x4e42b9E52F3Ed95ca049840A228FA22E1c80F08C)
  - `Signer`: [0x0b6e5C2b5199BB918cEE2bcD380cC9D8C6B973DE](https://explorer-bitfi-p00c4t1rul.t.conduit.xyz/address/0x0b6e5C2b5199BB918cEE2bcD380cC9D8C6B973DE)
  - `Router`: [0x170e328522E748a1E941E002C1be61FF29176767](https://explorer-bitfi-p00c4t1rul.t.conduit.xyz/address/0x170e328522E748a1E941E002C1be61FF29176767)
  - `BTCEVM`: [0x49E8f79493d1B12B4b98C250544278572429c8A3](https://explorer-bitfi-p00c4t1rul.t.conduit.xyz/address/0x49E8f79493d1B12B4b98C250544278572429c8A3)
  - `EVMBTC`: [0x71d7b380EAB7A73238003B65C7Ad6dc67dEfd2B1](https://explorer-bitfi-p00c4t1rul.t.conduit.xyz/address/0x71d7b380EAB7A73238003B65C7Ad6dc67dEfd2B1)
  - `BTCSOL`: [0x0A298eB15CED471a70E3070bcDc698F9A8867A44](https://explorer-bitfi-p00c4t1rul.t.conduit.xyz/address/0x0A298eB15CED471a70E3070bcDc698F9A8867A44)
  - `SOLBTC`: [0x88ff96929ea0BC45823696d99EED3824A719F8cC](https://explorer-bitfi-p00c4t1rul.t.conduit.xyz/address/0x88ff96929ea0BC45823696d99EED3824A719F8cC)

- `Sepolia-Ethereum` (Asset-Chain):
  - `Protocol`: [0x69f6be7fd348Fe224166736700683f5845A33002](https://sepolia.etherscan.io/address/0x69f6be7fd348Fe224166736700683f5845A33002)
  - `Payment`: [0x1d8b58438D5Ccc8Fcb4b738C89078f7b4168C9c0](https://sepolia.etherscan.io/address/0x1d8b58438D5Ccc8Fcb4b738C89078f7b4168C9c0)
  - `ETHVault`: [0x4F22052BE5701f2Dac2F5AAA9A30037147FA77cB](https://sepolia.etherscan.io/address/0x4F22052BE5701f2Dac2F5AAA9A30037147FA77cB)
  - `WETHVault`: [0x7c83BA6646EBDe4999fe58886672Cde44CD1A6c3](https://sepolia.etherscan.io/address/0x7c83BA6646EBDe4999fe58886672Cde44CD1A6c3)
  - `USDTVault`: [0x927a077bC85fFF19A273E5FD8FFDE9A623238dc6](https://sepolia.etherscan.io/address/0x927a077bC85fFF19A273E5FD8FFDE9A623238dc6)
  - `WBTCVault`: [0x4e6359F869B21916daFD88938e30EE8B5220E882](https://sepolia.etherscan.io/address/0x4e6359F869B21916daFD88938e30EE8B5220E882)
  - `WETH`: [0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14](https://sepolia.etherscan.io/token/0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14)
  - `USDT`: [0x0fE00bF94bfB384F3EA16d1577827633Ee467C0d](https://sepolia.etherscan.io/token/0x0fE00bF94bfB384F3EA16d1577827633Ee467C0d)
  - `WBTC`: [0x49b88c12b37Edf62E71eF88dB0D6Dc11197207eA](https://sepolia.etherscan.io/token/0x49b88c12b37Edf62E71eF88dB0D6Dc11197207eA)

#### Local Testing (via Hardhat):

###### Prerequisites:

- `Node` version: `v20.14.0` or newer
- `Yarn` version: `v1.22.22` or newer
- Environment file:
  - Create `.env` file via using a provided template (`.env.example`)

###### Install Dependencies:

- Run a following command:

```bash
yarn
```

- Finally, run local tests:

```bash
//  run full tests
yarn test

//  run a single test
yarn test test/<path_to_file>/<filename>.ts
```
