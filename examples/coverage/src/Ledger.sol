// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

contract Ledger {
    mapping(address => uint256) public balances;
    address public immutable router;

    constructor(address router_) { router = router_; }

    function credit(address depositor) external payable {
        require(msg.sender == router, "router only");
        balances[depositor] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "empty");
        balances[msg.sender] = 0;
        (bool sent,) = msg.sender.call{value: amount}("");
        require(sent, "transfer failed");
    }
}
