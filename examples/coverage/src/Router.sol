// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Ledger} from "./Ledger.sol";

contract Router {
    Ledger public immutable ledger;

    constructor() { ledger = new Ledger(address(this)); }

    function deposit() external payable {
        ledger.credit{value: msg.value}(msg.sender);
    }
}
