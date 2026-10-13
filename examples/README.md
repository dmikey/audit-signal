# Example audit: VulnerableVault

This example runs real Slither against [VulnerableVault.sol](VulnerableVault.sol), an intentionally vulnerable ETH vault. The committed [Markdown report](reports/vulnerable-vault/report.md) and [JSON report](reports/vulnerable-vault/report.json) show the output from Slither 0.11.6 and Solidity 0.8.28.

**Execution status:** static analysis completed; Copilot review, exploit execution and GitHub issue publication have not run. The walkthrough below explains the source code; it is not output from the Copilot review stage. Never deploy this fixture.

## Findings

| Detector | Severity | Confidence | Evidence |
| --- | --- | --- | --- |
| `reentrancy-eth` | High | Medium | `withdraw()` transfers ETH on line 14 before clearing the caller's balance on line 16. |
| `low-level-calls` | Informational | High | `withdraw()` uses an external low-level call on line 14. |

### Reentrancy candidate

An attacker contract can deposit ETH, call `withdraw()`, and use its receiving callback to call `withdraw()` again. The nested invocation reads the same balance because the first invocation has not cleared it yet. If the vault holds additional ETH, repeated withdrawals could consume funds credited to other depositors. This describes a possible attack sequence; no attacker contract or dynamic exploit test was executed for this report.

A proposed fix moves the balance update before the external call:

```solidity
function withdraw() external {
    uint256 amount = balances[msg.sender];
    require(amount > 0, "nothing to withdraw");
    balances[msg.sender] = 0;
    (bool ok,) = msg.sender.call{value: amount}("");
    require(ok, "transfer failed");
}
```

The reverting `require` restores the balance if the transfer fails. Consider a reentrancy guard for a larger contract with multiple entry points, and check interactions across those functions. This snippet is a remediation proposal, not an audited replacement contract.

To validate it, fund the vault from a normal depositor and an attacker contract, attempt recursive withdrawal, and assert that the attacker receives at most its own credited balance. Also check that the normal depositor's funds remain available and that a failed transfer restores the withdrawing account's balance. Those tests remain to be implemented and run.

### Low-level call observation

The call invokes recipient code and is relevant to the reentrancy finding. Its Boolean return value is already checked. The informational observation by itself does not establish a separate exploit, and a low-level call may still be appropriate after applying safe state-update ordering.

## Reproduce the static audit

From the repository root:

```sh
go build -trimpath -o bin/slither-agent ./cmd/slither-agent
./bin/slither-agent setup --solc-version 0.8.28
./bin/slither-agent audit \
  --target examples/VulnerableVault.sol \
  --scope example/vault \
  --solc-version 0.8.28 \
  --ai none \
  --out reports/example-vault
```

Open `reports/example-vault/report.md`. The report should contain the two detector findings above. The timestamp, revision and dirty-checkout status reflect your run and may differ from the committed snapshot. JSON also includes the exact contract source and its SHA-256 digest.

## Add Copilot review

With Copilot authentication configured as described in the [main README](../README.md):

```sh
npm install -g @github/copilot@1.0.97
./bin/slither-agent review \
  --report reports/example-vault/report.json \
  --out reports/example-vault-reviewed \
  --model auto
```

This adds a verdict, reasoning, exploit scenario, remediation and validation steps for every detector finding. The committed static snapshot does not contain those fields. Keep example findings separate from real production issues; neither command above publishes issues.
