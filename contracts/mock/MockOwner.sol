// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";

import "../Management.sol";
import "../Router.sol";
import "../utils/VaultRegistry.sol";
import "../utils/Core.sol";
import "../interfaces/ITypes.sol";

error OnlyWhitelisted();

contract MockOwner is Ownable {
    /// whitelisted accounts that can access
    mapping(address => bool) public accounts;

    modifier onlyWhitelist() {
        if (!accounts[msg.sender]) revert OnlyWhitelisted();
        _;
    }

    constructor(address initOwner) Ownable(initOwner) {
        accounts[initOwner] = true;
    }

    function whitelist(address account, bool isAdded) external onlyOwner {
        accounts[account] = isAdded;
    }

    /***********************************************
                      Core Handler
    ************************************************/

    function setMaxAffiliateFeeRate(
        address core,
        uint256 newRate
    ) external onlyWhitelist {
        Core(core).setMaxAffiliateFeeRate(newRate);
    }

    /***********************************************
                      Management
    ************************************************/

    function transferOwnership(
        address management,
        address to
    ) external onlyWhitelist {
        Management(management).transferOwnership(to);
    }

    function suspend(address management) external onlyWhitelist {
        Management(management).suspend();
    }

    function shutdown(address management) external onlyWhitelist {
        Management(management).shutdown();
    }

    function resume(address management) external onlyWhitelist {
        Management(management).resume();
    }

    function setFeeRate(
        address management,
        uint256 newFeeRate
    ) external onlyWhitelist {
        Management(management).setFeeRate(newFeeRate);
    }

    function setSolver(
        address management,
        address solver,
        bool isSolver
    ) external onlyWhitelist {
        Management(management).setSolver(solver, isSolver);
    }

    function setMPCNode(
        address management,
        address account,
        bool isMPC
    ) external onlyWhitelist {
        Management(management).setMPCNode(account, isMPC);
    }

    function setMPCInfo(
        address management,
        bytes calldata networkId,
        ITypes.MPCInfo calldata info,
        uint64 prevExpireTime
    ) external onlyWhitelist {
        Management(management).setMPCInfo(networkId, info, prevExpireTime);
    }

    function setToken(
        address management,
        ITypes.TokenInfo calldata tokenInfo
    ) external onlyWhitelist {
        Management(management).setToken(tokenInfo);
    }

    function removeToken(
        address management,
        bytes calldata networkId,
        bytes calldata tokenId
    ) external onlyWhitelist {
        Management(management).removeToken(networkId, tokenId);
    }

    function setPMM(
        address management,
        bytes32 pmmId,
        address account
    ) external onlyWhitelist {
        Management(management).setPMM(pmmId, account);
    }

    function removePMM(
        address management,
        bytes32 pmmId
    ) external onlyWhitelist {
        Management(management).removePMM(pmmId);
    }

    function setPMMAccount(
        address management,
        bytes32 pmmId,
        address account,
        bool isAdded
    ) external onlyWhitelist {
        Management(management).setPMMAccount(pmmId, account, isAdded);
    }

    /***********************************************
                      VaultRegistry
    ************************************************/
    function setVault(
        address registry,
        address vault,
        bytes calldata networkId,
        bytes calldata tokenId
    ) external onlyWhitelist {
        VaultRegistry(registry).setVault(vault, networkId, tokenId);
    }

    /***********************************************
                      Router
    ************************************************/
    function setRoute(
        address router,
        address core,
        bytes calldata fromChain,
        bytes calldata toChain
    ) external onlyWhitelist {
        Router(router).setRoute(core, fromChain, toChain);
    }
}
