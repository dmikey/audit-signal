# Smart contract audit

Scope: `example/vault`

Revision: `56129417d7f69eceaff249a294afa793f3f23354` (dirty: false)

Slither: `0.11.6`; AI model: `gpt-5.4`; AI reviewed: true; imported: false

Automated findings require human validation. Executed risk tests establish only recorded local harness outcomes, not production safety or a complete security audit. AI source coverage: 1 files; dependency/vendor directories are excluded.

2 findings


### Executed risk tests

Environment: **local-evm** · Stage: **passed** · Passed: 4 · Failed: 0 · Skipped: 0

- `test/VaultRisk.t.sol:VaultRiskTest:test_ReentrancyDrainsVictimFunds()` — **Success**, plan claim: **exploit-reproduced**. Attacker deposits 1 ETH and withdraws 6 ETH, consuming the victim's 5 ETH in the local EVM.
  Execution: `{
          "Unit": {
            "gas": 934786
          }
        }`
- `test/VaultRisk.t.sol:VaultRiskTest:test_FixedVaultBlocksSameAttack()` — **Success**, plan claim: **mitigation-holds**. The same callback attack receives only its own deposit in the checks-effects-interactions remediation fixture.
  Execution: `{
          "Unit": {
            "gas": 577885
          }
        }`
- `test/VaultRisk.t.sol:VaultRiskTest:test_FailedTransferRestoresCredit()` — **Success**, plan claim: **risk-property**. A rejecting recipient causes withdrawal to revert and retains its credit in the remediation fixture.
  Execution: `{
          "Unit": {
            "gas": 417128
          }
        }`
- `test/VaultRisk.t.sol:VaultRiskTest:testFuzz_FixedVaultPreservesVictimFunds(uint96,uint8)` — **Success**, plan claim: **risk-property**. Fuzz deposit amounts and callback counts; remediation fixture must preserve victim funds and credit.
  Execution: `{
          "Fuzz": {
            "first_case": {
              "gas": 600226,
              "stipend": 21476
            },
            "runs": 256,
            "mean_gas": 578712,
            "median_gas": 578702,
            "failed_corpus_replays": 0
          }
        }`

Evidence applies to assertions in the recorded local test harness. A passing remediation fixture does not change the audited source or establish production safety.
<!-- slither-agent:7e0a159ec248c9c7b9ae24a6ed3e13f2e63d7f4c87ff23c89697740da5aef1a8 -->
## reentrancy-eth

**Severity:** High · **Confidence:** Medium · **Origin:** slither

**Scope:** `example/vault` · **Revision:** `56129417d7f69eceaff249a294afa793f3f23354` · **Dirty:** false · **Imported:** false

**Status:** automated candidate; requires human validation.

### Detector evidence

Reentrancy in VulnerableVault.withdraw() (examples/VulnerableVault.sol#12-17):
	External calls:
	- (ok,None) = msg.sender.call{value: amount}() (examples/VulnerableVault.sol#14)
	State variables written after the call(s):
	- balances[msg.sender] = 0 (examples/VulnerableVault.sol#16)
	VulnerableVault.balances (examples/VulnerableVault.sol#6) can be used in cross function reentrancies:
	- VulnerableVault.balances (examples/VulnerableVault.sol#6)
	- VulnerableVault.deposit() (examples/VulnerableVault.sol#8-10)
	- VulnerableVault.withdraw() (examples/VulnerableVault.sol#12-17)


- `examples/VulnerableVault.sol` lines [12 13 14 15 16 17]
- `examples/VulnerableVault.sol` lines [14]
- `examples/VulnerableVault.sol` lines [16]

### AI review

Model: `gpt-5.4` · Verdict: **likely-valid**

In examples/VulnerableVault.sol lines 12-16, withdraw() loads balances[msg.sender] into amount, performs an external ETH transfer to msg.sender via call at line 14, and only then clears balances[msg.sender] at line 16. There is no access control, reentrancy guard, or pre-call state update. That ordering leaves the credited balance unchanged during the external call, so a contract recipient can reenter withdraw() and receive the same amount multiple times before its balance is zeroed. The supplied risk evidence includes an executed exploit-reproduced test, test/VaultRisk.t.sol:VaultRiskTest::test_ReentrancyDrainsVictimFunds(), which passed and claims the attacker withdrew 6 ETH after depositing 1 ETH by consuming another user’s 5 ETH. The mitigation-holds and risk-property tests are useful for a separate fixed fixture only and do not remediate the audited VulnerableVault source.

### Exploit scenario

Preconditions: the vault holds ETH from other users and the attacker’s address is a contract with a payable fallback/receive function. Attack sequence: the attacker deposits a small amount, calls withdraw(), receives the first call{value: amount}, reenters withdraw() from the fallback before line 16 executes, and repeats until the vault’s pooled ETH is drained or gas runs out. Because balances[msg.sender] is not cleared until after the external call returns, each nested withdrawal observes the same credited amount.

### Remediation

Apply checks-effects-interactions: set balances[msg.sender] = 0 before the external call, then send ETH; if the transfer fails, revert so the whole transaction rolls back. Optionally add a reentrancy guard (for example, nonReentrant) as defense in depth. Keep the failure path explicit so user credit is not silently lost.

### Validation to perform

Confirm on the vulnerable source by executing a reentrancy test that deposits victim funds and demonstrates repeated nested withdrawals. After the fix, run a separate negative test showing the same attacker can recover only its own credited amount, plus a failure-path test proving a rejected transfer reverts without burning credit.

### Executed risk tests

Environment: **local-evm** · Stage: **passed** · Passed: 4 · Failed: 0 · Skipped: 0

- `test/VaultRisk.t.sol:VaultRiskTest:test_ReentrancyDrainsVictimFunds()` — **Success**, plan claim: **exploit-reproduced**. Attacker deposits 1 ETH and withdraws 6 ETH, consuming the victim's 5 ETH in the local EVM.
  Execution: `{
          "Unit": {
            "gas": 934786
          }
        }`
- `test/VaultRisk.t.sol:VaultRiskTest:test_FixedVaultBlocksSameAttack()` — **Success**, plan claim: **mitigation-holds**. The same callback attack receives only its own deposit in the checks-effects-interactions remediation fixture.
  Execution: `{
          "Unit": {
            "gas": 577885
          }
        }`
- `test/VaultRisk.t.sol:VaultRiskTest:test_FailedTransferRestoresCredit()` — **Success**, plan claim: **risk-property**. A rejecting recipient causes withdrawal to revert and retains its credit in the remediation fixture.
  Execution: `{
          "Unit": {
            "gas": 417128
          }
        }`
- `test/VaultRisk.t.sol:VaultRiskTest:testFuzz_FixedVaultPreservesVictimFunds(uint96,uint8)` — **Success**, plan claim: **risk-property**. Fuzz deposit amounts and callback counts; remediation fixture must preserve victim funds and credit.
  Execution: `{
          "Fuzz": {
            "first_case": {
              "gas": 600226,
              "stipend": 21476
            },
            "runs": 256,
            "mean_gas": 578712,
            "median_gas": 578702,
            "failed_corpus_replays": 0
          }
        }`

Evidence applies to assertions in the recorded local test harness. A passing remediation fixture does not change the audited source or establish production safety.

[Slither detector documentation](https://github.com/crytic/slither/wiki/Detector-Documentation#reentrancy-eth)

---

<!-- slither-agent:837afa4c26de785758112cebadfdb5ee411b54085c94bbcbb7030d9438668faa -->
## low-level-calls

**Severity:** Informational · **Confidence:** High · **Origin:** slither

**Scope:** `example/vault` · **Revision:** `56129417d7f69eceaff249a294afa793f3f23354` · **Dirty:** false · **Imported:** false

**Status:** automated candidate; requires human validation.

### Detector evidence

Low level call in VulnerableVault.withdraw() (examples/VulnerableVault.sol#12-17):
	- (ok,None) = msg.sender.call{value: amount}() (examples/VulnerableVault.sol#14)


- `examples/VulnerableVault.sol` lines [12 13 14 15 16 17]
- `examples/VulnerableVault.sol` lines [14]

### AI review

Model: `gpt-5.4` · Verdict: **likely-false-positive**

The source at examples/VulnerableVault.sol line 14 does use a low-level call to send ETH, so Slither accurately detected that pattern, but as a standalone security issue this is weakly supported. The call result is checked immediately with require(ok, "transfer failed") at line 15, so this is not an unchecked-call-return bug. In modern Solidity, using call for ETH transfers is common when the contract intentionally avoids the fixed stipend limitations of transfer/send. The meaningful security consequence here is the reentrancy surface created by calling out before state is updated, which is already captured by the separate reentrancy finding. The supplied risk section explicitly lists this finding ID as dynamically untested, so there is no exploit evidence for an independent low-level-call vulnerability.

### Exploit scenario

No distinct exploit is demonstrated solely from using call here. An attacker benefits only because the contract calls out before clearing state, enabling the reentrancy described in the other finding. If withdraw() updated state first or used a reentrancy guard, the same low-level call pattern would not by itself let an attacker drain funds.

### Remediation

Do not treat low-level call usage alone as the bug. Fix the surrounding interaction pattern: clear state before the external transfer and/or add a reentrancy guard. If desired for clarity, keep call but wrap it in a helper or comment the intentional use; no separate replacement is required merely because it is a low-level call.

### Validation to perform

Manually review whether any additional unchecked return, arbitrary target, or malformed calldata risk exists beyond the already-confirmed reentrancy path. A focused test can confirm that, after reentrancy remediation, the contract still transfers ETH correctly to recipients that need more than 2300 gas while preserving safety.

### Executed risk tests

Environment: **local-evm** · Stage: **passed** · Passed: 4 · Failed: 0 · Skipped: 0

No mapped dynamic test executed for this finding.

Evidence applies to assertions in the recorded local test harness. A passing remediation fixture does not change the audited source or establish production safety.

[Slither detector documentation](https://github.com/crytic/slither/wiki/Detector-Documentation#low-level-calls)

---

