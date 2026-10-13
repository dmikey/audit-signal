# Smart contract audit

Scope: `example/vault`

Revision: `56129417d7f69eceaff249a294afa793f3f23354` (dirty: false)

Slither: `0.11.6`; AI model: ``; AI reviewed: false; imported: false

Automated findings require human validation. Executed risk tests establish only recorded local harness outcomes, not production safety or a complete security audit. AI source coverage: 1 files; dependency/vendor directories are excluded.

2 findings


### Executed risk tests

Environment: **local-evm** · Stage: **passed** · Passed: 4 · Failed: 0 · Skipped: 0

- `test/VaultRisk.t.sol:VaultRiskTest:test_ReentrancyDrainsVictimFunds()` — **Success**, plan claim: **exploit-reproduced**. Attacker deposits 1 ETH and withdraws 6 ETH, consuming the victim's 5 ETH in the local EVM.
  Execution: `{"Unit":{"gas":934786}}`
- `test/VaultRisk.t.sol:VaultRiskTest:test_FixedVaultBlocksSameAttack()` — **Success**, plan claim: **mitigation-holds**. The same callback attack receives only its own deposit in the checks-effects-interactions remediation fixture.
  Execution: `{"Unit":{"gas":577885}}`
- `test/VaultRisk.t.sol:VaultRiskTest:test_FailedTransferRestoresCredit()` — **Success**, plan claim: **risk-property**. A rejecting recipient causes withdrawal to revert and retains its credit in the remediation fixture.
  Execution: `{"Unit":{"gas":417128}}`
- `test/VaultRisk.t.sol:VaultRiskTest:testFuzz_FixedVaultPreservesVictimFunds(uint96,uint8)` — **Success**, plan claim: **risk-property**. Fuzz deposit amounts and callback counts; remediation fixture must preserve victim funds and credit.
  Execution: `{"Fuzz":{"first_case":{"gas":600226,"stipend":21476},"runs":256,"mean_gas":578712,"median_gas":578702,"failed_corpus_replays":0}}`

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

### Executed risk tests

Environment: **local-evm** · Stage: **passed** · Passed: 4 · Failed: 0 · Skipped: 0

- `test/VaultRisk.t.sol:VaultRiskTest:test_ReentrancyDrainsVictimFunds()` — **Success**, plan claim: **exploit-reproduced**. Attacker deposits 1 ETH and withdraws 6 ETH, consuming the victim's 5 ETH in the local EVM.
  Execution: `{"Unit":{"gas":934786}}`
- `test/VaultRisk.t.sol:VaultRiskTest:test_FixedVaultBlocksSameAttack()` — **Success**, plan claim: **mitigation-holds**. The same callback attack receives only its own deposit in the checks-effects-interactions remediation fixture.
  Execution: `{"Unit":{"gas":577885}}`
- `test/VaultRisk.t.sol:VaultRiskTest:test_FailedTransferRestoresCredit()` — **Success**, plan claim: **risk-property**. A rejecting recipient causes withdrawal to revert and retains its credit in the remediation fixture.
  Execution: `{"Unit":{"gas":417128}}`
- `test/VaultRisk.t.sol:VaultRiskTest:testFuzz_FixedVaultPreservesVictimFunds(uint96,uint8)` — **Success**, plan claim: **risk-property**. Fuzz deposit amounts and callback counts; remediation fixture must preserve victim funds and credit.
  Execution: `{"Fuzz":{"first_case":{"gas":600226,"stipend":21476},"runs":256,"mean_gas":578712,"median_gas":578702,"failed_corpus_replays":0}}`

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

### Executed risk tests

Environment: **local-evm** · Stage: **passed** · Passed: 4 · Failed: 0 · Skipped: 0

No mapped dynamic test executed for this finding.

Evidence applies to assertions in the recorded local test harness. A passing remediation fixture does not change the audited source or establish production safety.

[Slither detector documentation](https://github.com/crytic/slither/wiki/Detector-Documentation#low-level-calls)

---

