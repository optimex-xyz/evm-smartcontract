import { HardhatUserConfig } from "hardhat/config";
import "hardhat-contract-sizer";
import "@nomicfoundation/hardhat-toolbox";
import "@typechain/hardhat";
import "hardhat-gas-reporter";
import "solidity-coverage";
import * as dotenv from "dotenv";

dotenv.config();

const config: HardhatUserConfig = {
  networks: {
    eth_main: {
      url: process.env.ETH_MAINNET_RPC || "",
      accounts:
        process.env.MAINNET_DEPLOYER !== undefined
          ? [process.env.MAINNET_DEPLOYER]
          : [],
      timeout: 900000,
      chainId: 1,
      gasPrice: 12_000_000_000, // 12 GWei
    },
    eth_test: {
      url: process.env.ETH_TESTNET_RPC || "",
      accounts:
        process.env.TESTNET_DEPLOYER !== undefined
          ? [process.env.TESTNET_DEPLOYER]
          : [],
      timeout: 900000,
      chainId: 11155111,
    },
    testnet: {
      url: process.env.TESTNET || "",
      accounts:
        process.env.TESTNET_DEPLOYER !== undefined
          ? [process.env.TESTNET_DEPLOYER]
          : [],
      timeout: 900000,
      chainId: 258386,
    },
  },

  solidity: {
    version: "0.8.28",
    settings: {
      viaIR: true,
      optimizer: {
        enabled: true,
        runs: 200,
      },
      evmVersion: "cancun",
    },
  },

  contractSizer: {
    alphaSort: true,
    disambiguatePaths: false,
    runOnCompile: false,
    strict: true,
    only: [],
  },

  gasReporter: {
    enabled: true,
  },

  paths: {
    sources: "./contracts",
    tests: "./test",
    cache: "./build/cache",
    artifacts: "./build/artifacts",
  },

  etherscan: {
    apiKey: "empty",
    customChains: [
      {
        network: "testnet",
        chainId: 258386,
        urls: {
          apiURL: "https://explorer-bitfi-p00c4t1rul.t.conduit.xyz/api",
          browserURL: "https://explorer-bitfi-p00c4t1rul.t.conduit.xyz:443",
        },
      },
    ],
  },
};

export default config;
