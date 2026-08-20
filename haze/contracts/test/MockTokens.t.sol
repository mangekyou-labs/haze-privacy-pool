// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {MockUsdc} from "../src/mocks/MockUsdc.sol";
import {MockSourceToken} from "../src/mocks/MockSourceToken.sol";
import {MockDex} from "../src/mocks/MockDex.sol";

contract MockTokensTest is Test {
    function testUsdcHasSixDecimals() public {
        MockUsdc usdc = new MockUsdc();
        assertEq(usdc.decimals(), 6);
    }

    function testDexSwapsSourceForUsdc() public {
        MockUsdc usdc = new MockUsdc();
        MockSourceToken source = new MockSourceToken();
        MockDex dex = new MockDex(address(usdc));
        source.mint(address(this), 1_000_000);
        usdc.mint(address(dex), 1_000_000);
        source.approve(address(dex), 1_000_000);
        uint256 out = dex.swapExactIn(address(source), 1_000_000, 1_000_000, address(this));
        assertEq(out, 1_000_000);
        assertEq(usdc.balanceOf(address(this)), 1_000_000);
    }
}
