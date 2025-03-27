// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/Address.sol";

import "../interfaces/IBaseVault.sol";
import "../interfaces/IProtocol.sol";
import "../utils/AssetChainErrors.sol";

/*************************************************************************************************
    @title BaseVault contract (Abstract)                       
    @dev This contract defines fundamental interfaces for Vault contracts.
    Provides the base necessary logic for: 
        - Settling payments
        - Issuing refunds.
**************************************************************************************************/

abstract contract BaseVault is IBaseVault, EIP712 {
    using ECDSA for bytes32;
    using SafeERC20 for IERC20;

    bytes32 internal constant _EMPTY_HASH = bytes32(0);

    /************************************************************************************************

    _PRESIGN = keccak256("Presign(bytes32 tradeId,bytes32 infoHash)")

        - infoHash = keccak256(abi.encode(pmmRecvAddress, amount))

    *************************************************************************************************/
    bytes32 internal constant _PRESIGN =
        0x4688b1433855d3bee57e03543daa667dd7303cb521188301fe987ba34d12f83e;

    /************************************************************************************************

    _SETTLEMENT = keccak256("Settlement(uint256 totalFee,bytes presign)")

    *************************************************************************************************/
    bytes32 internal constant _SETTLEMENT =
        0x216c04309d7d13eca933fc37c2c3908738b23eb5b2650f7ca9cb7ac26ca6d9d8;

    /// address of the Protocol contract
    IProtocol public protocol;

    /// Mapping of trade details for each `tradeId`
    mapping(bytes32 => bytes32) internal _tradeHashes;

    /**
        @notice Emitted when the Protocol Owner successfully updates the Protocol contract.
        @param operator The address of the caller who performed the update.
        @param newProtocol The new address of the Protocol contract.
        @dev Related function: `setProtocol()`.
    */
    event ProtocolUpdated(address indexed operator, address newProtocol);

    constructor(
        address pAddress,
        string memory name,
        string memory version
    ) EIP712(name, version) {
        protocol = IProtocol(pAddress);
    }

    /** 
        @notice Updates the Protocol contract to a new address.
        @dev Caller must be the current `Owner` of Protocol contract.
        @param newProtocol The new address of the Protocol contract.
    */
    function setProtocol(address newProtocol) external virtual {
        if (msg.sender != protocol.owner()) revert Unauthorized();
        if (newProtocol == address(0)) revert AddressZero();

        protocol = IProtocol(newProtocol);

        emit ProtocolUpdated(msg.sender, newProtocol);
    }

    /**
        @notice Retrieves the hash of the trade details for a given `tradeId`.
        @param tradeId The unique identifier assigned to a trade.
        @return tradeHash The hash of the `TradeDetail` object associated with the given `tradeId`.
    */
    function getTradeHash(
        bytes32 tradeId
    ) external view returns (bytes32 tradeHash) {
        return _tradeHashes[tradeId];
    }

    /**
        @notice Transfers the specified `amount` to `toAddress` to finalize the trade identified by `tradeId`.
        @dev Can only be executed if `block.timestamp <= timeout`.
        @param tradeId The unique identifier assigned to a trade.
        @param totalFee The total fee amount deducted from the settlement.
        @param toAddress The address of the selected PMM (`pmmRecvAddress`).
        @param detail The trade details, including relevant trade parameters.
        @param presign The pre-signature signed by `ephemeralAssetAddress`.
        @param mpcSignature The MPC's signature authorizing the settlement.
    */
    function settlement(
        bytes32 tradeId,
        uint256 totalFee,
        address toAddress,
        TradeDetail calldata detail,
        bytes calldata presign,
        bytes calldata mpcSignature
    ) external virtual;

    /**
        @notice Transfers the locked funds to the `refundAddress` for the specified trade.
        @dev Can only be claimed if `block.timestamp > timeout`
        @param tradeId The unique identifier assigned to the trade.
        @param detail The trade details, including relevant trade parameters.
    */
    function claim(
        bytes32 tradeId,
        TradeDetail calldata detail
    ) external virtual;

    function _transfer(address token, address to, uint256 amount) internal {
        if (token == address(0)) Address.sendValue(payable(to), amount);
        else IERC20(token).safeTransfer(to, amount);
    }

    function _getTradeHash(
        TradeDetail calldata data
    ) internal pure returns (bytes32 tradeHash) {
        return keccak256(abi.encode(data));
    }

    function _getPresignSigner(
        bytes32 tradeId,
        bytes32 infoHash,
        bytes calldata signature
    ) internal view returns (address signer) {
        signer = _hashTypedDataV4(
            keccak256(abi.encode(_PRESIGN, tradeId, infoHash))
        ).recover(signature);
    }

    function _getSettlementSigner(
        uint256 protocolFee,
        bytes calldata presign,
        bytes calldata signature
    ) internal view returns (address signer) {
        signer = _hashTypedDataV4(
            keccak256(abi.encode(_SETTLEMENT, protocolFee, keccak256(presign)))
        ).recover(signature);
    }
}
