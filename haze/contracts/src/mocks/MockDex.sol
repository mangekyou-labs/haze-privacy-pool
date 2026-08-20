// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IERC20Lite {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @notice Deterministic 1:1 mock DEX used only in local and CI environments.
contract MockDex {
    address public immutable usdc;

    constructor(address usdc_) {
        usdc = usdc_;
    }

    function swapExactIn(address tokenIn, uint256 amountIn, uint256 minUsdcOut, address recipient)
        external
        returns (uint256 usdcOut)
    {
        require(IERC20Lite(tokenIn).transferFrom(msg.sender, address(this), amountIn), "in");
        usdcOut = amountIn;
        require(usdcOut >= minUsdcOut, "slippage");
        require(IERC20Lite(usdc).transfer(recipient, usdcOut), "out");
    }
}
