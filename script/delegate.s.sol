// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script} from "forge-std/Script.sol";
import {Delegate} from "../src/delegate.sol";

contract DelegateScript is Script {
    Delegate public delegate;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        delegate = new Delegate();

        vm.stopBroadcast();
    }
}
