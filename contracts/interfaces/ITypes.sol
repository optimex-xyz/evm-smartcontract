// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

interface ITypes {
    /***********************************************************************
                              Core Types
    - Struct types being used in the following contracts:
        - Core
        - BTCEVM
        - EVMBTC
        - BTCSOL
        - SOLBTC
    ***********************************************************************/

    enum STAGE {
        SUBMIT,
        CONFIRM_DEPOSIT,
        SELECT_PMM,
        MAKE_PAYMENT,
        CONFIRM_PAYMENT,
        CONFIRM_SETTLEMENT
    }

    struct FeeDetails {
        uint256 totalAmount; //  Total fee amount
        uint256 pFeeAmount; //  Protocol fee amount
        uint256 aFeeAmount; //  Aggregated affiliate fee amount
        uint128 pFeeRate; //  Protocol fee rate (in basis points, e.g., 10000 = 100%)
        uint128 aFeeRate; //  Aggregated affiliate fee rate (in basis points)
    }

    struct SettledPayment {
        bytes32 bundlerHash;
        bytes paymentTxId;
        bytes releaseTxId;
        bool isConfirmed;
    }

    struct BundlePayment {
        bytes32[] tradeIds;
        uint64 signedAt;
        uint64 startIdx;
        bytes paymentTxId;
        bytes signature;
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

    struct TradeData {
        uint256 sessionId;
        TradeInfo tradeInfo;
        ScriptInfo scriptInfo;
    }

    struct Affiliate {
        uint256 aggregatedValue;
        string schema;
        bytes data;
    }

    struct Presign {
        bytes32 pmmId;
        bytes pmmRecvAddress;
        bytes[] presigns;
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

    struct PMMSelection {
        RFQInfo rfqInfo;
        SelectedPMMInfo pmmInfo;
    }

    /***********************************************************************
                              Management Types
    - Struct types being used in the following contract:
        - Management
    ***********************************************************************/

    enum Status {
        OPERATING,
        SUSPENDED,
        SHUTDOWN
    }

    struct TokenInfo {
        bytes[5] info; // ["tokenId", "networkId", "symbol", "externalURL", "description"]
        uint256 decimals;
    }

    struct MPCInfo {
        address mpcL2Address;
        uint64 expireTime;
        bytes mpcL2Pubkey;
        bytes mpcAssetPubkey;
    }
}
