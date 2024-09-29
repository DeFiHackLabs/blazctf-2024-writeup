# Doju

Author: cbd1913 ([X/Twitter](https://x.com/cbd1913))

In this challenge, we are presented with two Solidity contracts: **Doju** and **Challenge**. The Doju contract implements a bonding curve token, and the Challenge contract interacts with it. Our goal is to exploit a vulnerability in the Doju contract to increase the balance of the `0xc0ffee` address beyond half of the maximum `uint256` value.

The Doju contract is a simplified ERC20 token with a bonding curve mechanism for buying and selling tokens:

- **Buying Tokens**: Users can buy tokens by sending ETH to the contract. The amount of tokens minted is determined by a bonding curve formula in the `_ethToTokens` function.
- **Selling Tokens**: Users can sell tokens back to the contract in exchange for ETH, using the bonding curve formula in the `_tokensToEth` function.

Key functions in the contract:

- `buyTokens(address to)`: Mints new tokens based on the amount of ETH sent.
- `sellTokens(uint256 tokenAmount, address to, uint256 minOut)`: Burns tokens and sends ETH back to the user.
- `transfer(address to, uint256 value)`: Transfers tokens to another address or triggers a sell if the to address is the burn address (address(0)).

The bonding curve ensures that the token price increases as the total supply increases and decreases as the supply decreases. And the Challenge contract has a function isSolved() that checks if the balance of 0xc0ffee is greater than half of the maximum uint256 value:

```solidity
function isSolved() public view returns (bool) {
    return doju.balanceOf(address(0xc0ffee)) > type(uint256).max / 2;
}
```

## Observation

One might consider force-sending ETH to the Doju contract (e.g., via selfdestruct) to manipulate the bonding curve calculations. However, this approach doesn’t provide a practical way to drain or mint a large number of Doju tokens due to the bonding curve’s mathematical constraints.

However, the critical vulnerability lies within the sellTokens function:

```solidity
function sellTokens(uint256 tokenAmount, address to, uint256 minOut) public {
    uint256 ethValue = _tokensToEth(tokenAmount);
    _transfer(msg.sender, address(this), tokenAmount);
    totalSupply -= tokenAmount;
    (bool success,) = payable(to).call{value: ethValue}(abi.encodePacked(minOut, to, tokenAmount, msg.sender, ethValue));
    require(minOut > ethValue, "minOut not met");
    require(success, "Transfer failed");
    emit Burn(msg.sender, tokenAmount);
    emit Transfer(msg.sender, address(0), tokenAmount);
}
```

1. Arbitrary External Call: The contract performs a low-level call to the to address with controlled data and forwards ETH (ethValue).
1. Ineffective minOut Check: The require(minOut > ethValue, "minOut not met"); condition is illogical because minOut should be less than or equal to ethValue to ensure the user receives at least minOut. This condition can be bypassed by setting minOut to a high value.

## Exploit

Our plan is to exploit the arbitrary external call to make the Doju contract call its own transfer function with controlled parameters, transferring a massive amount of tokens to the 0xc0ffee address. We need to carefully construct the data passed to the call so that when the Doju contract executes it, it interprets it as a call to `transfer(address to, uint256 value)`. The call uses abi.encodePacked:

```solidity
abi.encodePacked(minOut, to, tokenAmount, msg.sender, ethValue)
```

We can control minOut and tokenAmount, and `to` should be set as the contract's address. Our goal is to set up the data so that:

- The first 4 bytes correspond to the function selector of `transfer(address,uint256)`.
- The next 32 bytes is an address that we have control over.
- The following 32 bytes represent the value, which we’ll set to a large number.

So we can set the first 4 bytes of `minOut` are to be `0xa9059cbb` which is the function selector of `transfer(address,uint256)`. And the last 16 bytes plus the first 4 bytes of `to` should be an address that we have control over. We can use tools like [Profanity2](https://github.com/1inch/profanity2) to generate the address with given suffix. And the last 16 bytes of `to` will be interpreted as the amount to transfer, so can set `tokenAmount` = 0 to let the contract transfer a large amount of Doju token out.
