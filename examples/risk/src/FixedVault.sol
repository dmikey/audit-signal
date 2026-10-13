// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

// Educational remediation fixture; not a production-audited implementation.
contract FixedVault {
    mapping(address => uint256) public balances;
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "nothing to withdraw");
        balances[msg.sender] = 0;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }
}
