# Example audits

## Independent discovery example: RewardPool

[RewardPool.sol](RewardPool.sol) is another intentionally vulnerable fixture. Its `claimFor` function calculates rewards for a beneficiary but reads and updates `lastClaimEpoch` for the caller. The live Copilot discovery pass identified this mismatch as a separate High-severity candidate. Eleven fresh callers can claim for the same beneficiary in one epoch. The [Foundry test](risk/test/RewardPoolRisk.t.sol) passes after paying 1.1 ETH from a pool with only 1 ETH of reward funding, leaving 0.9 ETH to back a 1 ETH stake; full stake withdrawal then fails. This is a local fixture proof, not a deployed-contract exploit.

The [risk plan](risk/reward-plan.json) maps the discovery to that exact test. The [reviewed Markdown report](reports/reward-pool-ai/report.md), [JSON report](reports/reward-pool-ai/report.json), and [raw Foundry results](reports/reward-pool-ai/forge-results.json) show the full pipeline on a real Slither scan (`imported: false`, `reviewed: true`, model `gpt-5.6-sol`). Slither reported two informational low-level calls, while Copilot independently identified the claim checkpoint mismatch and rated it likely valid after the local exploit test. The other two AI candidates remain dynamically untested. Run `audit --ai none`, `discover`, `risk`, then `review` on this fixture to reproduce it. Never deploy this fixture.

This example runs real Slither against [VulnerableVault.sol](VulnerableVault.sol), an intentionally vulnerable ETH vault. The committed [Markdown report](reports/vulnerable-vault/report.md) and [JSON report](reports/vulnerable-vault/report.json) show the output from Slither 0.11.6 and Solidity 0.8.28.

**Execution status:** static analysis, local EVM exploit/risk tests and live GPT-5.4 Copilot review completed; the reentrancy example is [GitHub issue #1](https://github.com/dmikey/slither-agent/issues/1). The walkthrough below explains the source code; it is not output from the Copilot review stage. Never deploy this fixture.

## Findings

| Detector | Severity | Confidence | Evidence |
| --- | --- | --- | --- |
| `reentrancy-eth` | High | Medium | `withdraw()` transfers ETH on line 14 before clearing the caller's balance on line 16. |
| `low-level-calls` | Informational | High | `withdraw()` uses an external low-level call on line 14. |

### Reentrancy candidate

An attacker contract can deposit ETH, call `withdraw()`, and use its receiving callback to call `withdraw()` again. The nested invocation reads the same balance because the first invocation has not cleared it yet. If the vault holds additional ETH, repeated withdrawals could consume funds credited to other depositors. The [attack test](risk/test/VaultRisk.t.sol) executed this sequence locally: a 1 ETH deposit produced 6 ETH in withdrawals and drained the victim's 5 ETH. The original static-only snapshot predates that test run; see the [risk report](reports/vulnerable-vault-risk/report.md) for executed evidence.

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

To validate it, fund the vault from a normal depositor and an attacker contract, attempt recursive withdrawal, and assert that the attacker receives at most its own credited balance. Also check that the normal depositor's funds remain available and that a failed transfer restores the withdrawing account's balance. The local test suite now exercises those checks, including 256 fuzz cases for deposit amounts and callback counts. Passing these tests establishes the recorded fixture behavior; it does not certify production safety.

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

## Execute penetration and risk tests

Install [Foundry v1.8.5](https://github.com/foundry-rs/foundry/releases/tag/v1.8.5), then run:

```sh
./bin/slither-agent risk \
  --report reports/example-vault/report.json \
  --project examples/risk --source-root . \
  --plan examples/risk/plan.json \
  --solc .slither-venv/.solc-select/artifacts/solc-0.8.28/solc-0.8.28 \
  --out reports/example-vault-risk
```

The [plan](risk/plan.json) links the reentrancy detector to four exact tests: reproducing the attack, checking the remediation against that attack, restoring credit after a rejected transfer, and fuzzing victim-fund preservation. All four passed, with 256 fuzz executions. The informational low-level-call finding remains dynamically untested. Read the committed [risk Markdown report](reports/vulnerable-vault-risk/report.md), [JSON report](reports/vulnerable-vault-risk/report.json) and [raw Foundry results](reports/vulnerable-vault-risk/forge-results.json).

## Add Copilot review

The [live AI-reviewed Markdown report](reports/vulnerable-vault-ai/report.md) and [JSON report](reports/vulnerable-vault-ai/report.json) record `model: gpt-5.4`, `reviewed: true`, and `imported: false`. The last value means Slither actually ran, rather than importing an external Slither result. GPT-5.4 assessed the reentrancy candidate as likely valid and the informational low-level-call observation as unlikely to be a separate vulnerability. Both findings remain in the report.

With an authenticated `gh` login or Copilot token as described in the [main README](../README.md):

```sh
npm install -g @github/copilot@1.0.97
./bin/slither-agent review \
  --report reports/example-vault-risk/report.json \
  --out reports/example-vault-reviewed \
  --model gpt-5.4
```

This adds a verdict, reasoning, exploit scenario, remediation and validation steps for every detector finding. The committed static snapshot does not contain those fields. Keep example findings separate from real production issues; neither command above publishes issues.
