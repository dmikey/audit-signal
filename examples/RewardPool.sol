// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

// Intentionally vulnerable teaching fixture. Never deploy.
contract RewardPool {
	address public immutable owner;
    mapping(address => uint256) public shares;
    mapping(address => uint256) public rewardCredit;
    mapping(address => uint256) public lastClaimEpoch;
    uint256 public epoch;
    uint256 public constant REWARD_PER_SHARE = 0.1 ether;

	constructor() { owner = msg.sender; }

    function deposit() external payable {
        require(msg.value == 1 ether, "one share per deposit");
        shares[msg.sender] += 1;
    }

    function fundRewards() external payable {}

	function withdrawStake() external {
		require(shares[msg.sender] > 0, "no shares");
		shares[msg.sender] -= 1;
		(bool ok,) = msg.sender.call{value: 1 ether}("");
		require(ok, "transfer failed");
	}

    function advanceEpoch() external {
		require(msg.sender == owner, "owner only");
        epoch += 1;
    }

    function claimFor(address beneficiary) external {
        uint256 missed = epoch - lastClaimEpoch[msg.sender];
        require(missed > 0, "nothing due");
        rewardCredit[beneficiary] += shares[beneficiary] * REWARD_PER_SHARE * missed;
        lastClaimEpoch[msg.sender] = epoch;
    }

    function withdrawRewards() external {
        uint256 amount = rewardCredit[msg.sender];
        require(amount > 0, "no rewards");
        rewardCredit[msg.sender] = 0;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }
}
