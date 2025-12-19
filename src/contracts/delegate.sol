// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract Delegate {
    event Hello();
    event World();
    event Address(address indexed sender_address, address indexed origin_address, address indexed this_address);

    function emitHello() public {
        emit Hello();
    }

    function emitWorld() public {
        emit World();
    }

    function emitHelloWorld() public {
        emitHello();
        emitWorld();
    }
    function emitAddress() public {
        emit Address(msg.sender, tx.origin, address(this));
    }
}
