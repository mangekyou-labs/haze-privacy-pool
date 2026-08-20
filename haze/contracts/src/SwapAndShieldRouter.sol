// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {HazeAccess} from "./HazeAccess.sol";
import {HazePool} from "./HazePool.sol";

interface IERC20Router {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
}

/// @title SwapAndShieldRouter
/// @notice Allowlisted public swap then atomic USDC deposit into HazePool.
/// @dev No owner, proxy, upgrade, or emergency-exit path. No vendor-named adapters.
contract SwapAndShieldRouter {
    bool public constant NOT_FOR_PRODUCTION = true;

    struct SwapRoute {
        address adapter;
        bytes data;
        bytes32 expectedRouteHash;
    }

    HazeAccess public immutable access;
    HazePool public immutable pool;
    address public immutable usdc;

    mapping(address => bool) public tokenAllowed;
    mapping(address => bool) public adapterAllowed;

    address public pendingToken;
    bool public pendingTokenAllowed;
    uint48 public pendingTokenEta;
    bool public tokenScheduled;

    address public pendingAdapter;
    bool public pendingAdapterAllowed;
    uint48 public pendingAdapterEta;
    bool public adapterScheduled;

    bool private locked;

    event TokenScheduled(address indexed token, bool allowed, uint48 activateAt);
    event TokenUpdated(address indexed token, bool allowed);
    event AdapterScheduled(address indexed adapter, bool allowed, uint48 activateAt);
    event AdapterUpdated(address indexed adapter, bool allowed);

    constructor(
        HazeAccess access_,
        HazePool pool_,
        address usdc_,
        address[] memory tokens,
        address[] memory adapters
    ) {
        require(
            address(access_) != address(0) && address(pool_) != address(0) && usdc_ != address(0),
            "ENCODING_INVALID"
        );
        require(address(pool_.usdc()) == usdc_, "ENCODING_INVALID");
        require(pool_.approvedRouter() == address(this), "ENCODING_INVALID");
        access = access_;
        pool = pool_;
        usdc = usdc_;
        for (uint256 i = 0; i < tokens.length; ++i) {
            _setToken(tokens[i], true);
        }
        for (uint256 i = 0; i < adapters.length; ++i) {
            _setAdapter(adapters[i], true);
        }
    }

    function swapAndShield(HazePool.TransactArgs calldata args, SwapRoute calldata route) external {
        require(!locked, "REENTRANCY");
        locked = true;
        require(!access.paused(), "PAUSED");
        require(args.intent.action == 4, "ENCODING_INVALID");
        require(msg.sender == args.intent.user, "UNAUTHORIZED");
        require(args.intent.deadline == 0 || args.intent.deadline >= block.timestamp, "AUTH_WINDOW");

        bytes32 routeHash = keccak256(abi.encode(route.adapter, route.data));
        require(routeHash == route.expectedRouteHash && routeHash == args.intent.routeHash, "ENCODING_INVALID");
        require(tokenAllowed[args.intent.tokenIn] && args.intent.tokenIn != usdc, "TOKEN_NOT_ALLOWED");
        require(adapterAllowed[route.adapter], "TOKEN_NOT_ALLOWED");
        require(args.intent.amountIn != 0 && args.intent.publicAmount != 0, "ENCODING_INVALID");

        IERC20Router token = IERC20Router(args.intent.tokenIn);
        uint256 sourceBefore = token.balanceOf(address(this));
        require(token.transferFrom(msg.sender, address(this), args.intent.amountIn), "ENCODING_INVALID");
        require(token.balanceOf(address(this)) - sourceBefore == args.intent.amountIn, "ENCODING_INVALID");

        _approveExact(token, route.adapter, args.intent.amountIn);
        uint256 usdcBefore = IERC20Router(usdc).balanceOf(address(this));
        (bool ok, bytes memory ret) = route.adapter.call(route.data);
        _approveExact(token, route.adapter, 0);
        if (!ok) {
            _bubble(ret);
        }
        require(token.balanceOf(address(this)) == 0, "ENCODING_INVALID");

        uint256 usdcAfter = IERC20Router(usdc).balanceOf(address(this));
        require(usdcAfter >= usdcBefore, "SLIPPAGE");
        uint256 usdcOut = usdcAfter - usdcBefore;
        require(usdcOut >= args.intent.minUsdcOut, "SLIPPAGE");
        require(usdcOut == args.intent.publicAmount, "ENCODING_INVALID");

        _approveExact(IERC20Router(usdc), address(pool), usdcOut);
        pool.depositFromRouter(msg.sender, args);
        _approveExact(IERC20Router(usdc), address(pool), 0);

        require(token.balanceOf(address(this)) == 0 && IERC20Router(usdc).balanceOf(address(this)) == 0, "ENCODING_INVALID");
        require(token.allowance(address(this), route.adapter) == 0, "ENCODING_INVALID");
        require(IERC20Router(usdc).allowance(address(this), address(pool)) == 0, "ENCODING_INVALID");
        locked = false;
    }

    function scheduleToken(address token, bool allowed) external {
        require(!access.paused(), "PAUSED");
        require(msg.sender == access.governance(), "UNAUTHORIZED");
        _assertToken(token);
        pendingToken = token;
        pendingTokenAllowed = allowed;
        pendingTokenEta = uint48(block.timestamp) + access.minDelay();
        tokenScheduled = true;
        emit TokenScheduled(token, allowed, pendingTokenEta);
    }

    function activateToken() external {
        require(!access.paused(), "PAUSED");
        require(tokenScheduled && block.timestamp >= pendingTokenEta, "TIMELOCK");
        _setToken(pendingToken, pendingTokenAllowed);
        emit TokenUpdated(pendingToken, pendingTokenAllowed);
        tokenScheduled = false;
        pendingToken = address(0);
        pendingTokenEta = 0;
    }

    function scheduleAdapter(address adapter, bool allowed) external {
        require(!access.paused(), "PAUSED");
        require(msg.sender == access.governance(), "UNAUTHORIZED");
        _assertAdapter(adapter);
        pendingAdapter = adapter;
        pendingAdapterAllowed = allowed;
        pendingAdapterEta = uint48(block.timestamp) + access.minDelay();
        adapterScheduled = true;
        emit AdapterScheduled(adapter, allowed, pendingAdapterEta);
    }

    function activateAdapter() external {
        require(!access.paused(), "PAUSED");
        require(adapterScheduled && block.timestamp >= pendingAdapterEta, "TIMELOCK");
        _setAdapter(pendingAdapter, pendingAdapterAllowed);
        emit AdapterUpdated(pendingAdapter, pendingAdapterAllowed);
        adapterScheduled = false;
        pendingAdapter = address(0);
        pendingAdapterEta = 0;
    }

    function _setToken(address token, bool allowed) internal {
        _assertToken(token);
        tokenAllowed[token] = allowed;
    }

    function _setAdapter(address adapter, bool allowed) internal {
        _assertAdapter(adapter);
        adapterAllowed[adapter] = allowed;
    }

    function _assertToken(address token) internal view {
        require(token != address(0) && token != usdc, "ENCODING_INVALID");
    }

    function _assertAdapter(address adapter) internal view {
        require(
            adapter != address(0) && adapter != usdc && adapter != address(this) && adapter != address(pool),
            "ENCODING_INVALID"
        );
    }

    function _approveExact(IERC20Router token, address spender, uint256 amount) internal {
        require(token.approve(spender, 0), "ENCODING_INVALID");
        if (amount != 0) {
            require(token.approve(spender, amount), "ENCODING_INVALID");
        }
    }

    function _bubble(bytes memory ret) internal pure {
        if (ret.length > 0) {
            assembly ("memory-safe") {
                revert(add(ret, 32), mload(ret))
            }
        }
        revert("ENCODING_INVALID");
    }
}
