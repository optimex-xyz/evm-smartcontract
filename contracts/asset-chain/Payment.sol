// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import "@openzeppelin/contracts/utils/Address.sol";

import "./interfaces/IProtocol.sol";
import "./utils/AssetChainErrors.sol";

/******************************************************************************************
                                =========== PetaFi ===========
    @title Payment contract                            
    @dev This contract is used as the PetaFi Payment Contract across various asset chains.
    - Supports PMM in settling payments to users.
    - Splits the payment into two destinations:
        - To the user.
        - To the Protocol Fee Receiver.
*******************************************************************************************/

contract Payment is ReentrancyGuardTransient {
    using SafeERC20 for IERC20;

    /// Address of Protocol contract
    IProtocol public protocol;

    /**
        @notice Emitted when the Protocol Owner successfully updates the Protocol contract.
        @param owner The address of the caller who performed the update.
        @param newProtocol The new address of the Protocol contract.
        @dev Related function: `setProtocol()`.
    */
    event ProtocolUpdated(address indexed owner, address indexed newProtocol);

    /**
        @notice Emitted when a PMM successfully settles a payment.
        @param tradeId The unique identifier of the trade.
        @param from The address initiating the payment.
        @param to The recipient address receiving the payment.
        @param pFeeAddr The address receiving the protocol fee.
        @param token The address of the payment token (native coin = `0x0`).
        @param payToUser The net amount transferred to the recipient after deducting a total fee.
        @param totalFee The total fee amount deducted from the payment.
        @dev Related function: `payment()`.
    */
    event PaymentTransferred(
        bytes32 indexed tradeId,
        address indexed from,
        address indexed to,
        address pFeeAddr,
        address token,
        uint256 payToUser,
        uint256 totalFee
    );

    constructor(address pAddress) {
        protocol = IProtocol(pAddress);
    }

    /** 
        @notice Updates the Protocol contract to a new address.
        @dev Caller must be the current `Owner` of Protocol contract.
        @param newProtocol The new address of the Protocol contract.
    */
    function setProtocol(address newProtocol) external {
        if (msg.sender != protocol.owner()) revert Unauthorized();
        if (newProtocol == address(0)) revert AddressZero();

        protocol = IProtocol(newProtocol);

        emit ProtocolUpdated(msg.sender, newProtocol);
    }

    /** 
        @notice Transfers payment to the recipient (`toUser`) and the total fee to the designated address.
        @param tradeId The unique identifier assigned to the trade.
        @param token The address of the payment token (use `0x0` for native coins).
        @param toUser The recipient address receiving the payment.
        @param amount The payment amount, inclusive of the `totalFee`.
        @param totalFee The total fee amount deducted from `amount`.
        @param deadline The latest timestamp by which the payment must be executed.
    */
    function payment(
        bytes32 tradeId,
        address token,
        address toUser,
        uint256 amount,
        uint256 totalFee,
        uint256 deadline
    ) external payable nonReentrant {
        /// @dev: It's not necessary to validate the totalFee.
        /// Dishonest behavior by the PMM will result in the loss of payment.
        /// The MPC will verify the payment transaction before providing a payment confirmation on L2,
        /// which triggers the release of funds on the destination chain.

        /// Validate parameters as follows:
        /// - Payment transaction should be rejected when `deadline` is passed.
        /// - Ensure `amount` should not be 0 and `amount` should be greater than `totalFee`.
        /// - If using the native coin, ensure msg.value == amount.
        /// - The `toUser` address should not be 0x0.
        if (block.timestamp > deadline) revert DeadlineExceeded();
        if (amount == 0 || amount <= totalFee) revert InvalidPaymentAmount();
        if (token == address(0) && msg.value != amount)
            revert NativeCoinNotMatched();
        if (toUser == address(0)) revert AddressZero();

        address payer = msg.sender;
        address protocolFeeAddress = protocol.pFeeAddr();

        /// When `totalFee != 0`, transfer `totalFee`
        if (totalFee != 0)
            _transfer(token, payer, protocolFeeAddress, totalFee);

        /// transfer remaining to `toUser`
        _transfer(token, payer, toUser, amount - totalFee);

        emit PaymentTransferred(
            tradeId,
            payer,
            toUser,
            protocolFeeAddress,
            token,
            amount - totalFee,
            totalFee
        );
    }

    function _transfer(
        address token,
        address from,
        address to,
        uint256 amount
    ) private {
        if (token == address(0)) Address.sendValue(payable(to), amount);
        else IERC20(token).safeTransferFrom(from, to, amount);
    }
}
