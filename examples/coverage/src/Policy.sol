// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

contract Policy {
    address public immutable owner;
    mapping(address => bool) public approved;

    constructor() { owner = msg.sender; }

    function setApproved(address account, bool allowed) external {
        require(msg.sender == owner, "owner only");
        approved[account] = allowed;
    }
}
