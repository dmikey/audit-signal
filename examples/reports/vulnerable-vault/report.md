# Smart contract audit

Scope: `example/vault`

Revision: `23ca3cbce01ecd02c888bc686009aa94daa1b52e` (dirty: false)

Slither: `0.11.6`; AI model: ``; AI reviewed: false; AI discovery: false; discovery model: ``; imported: false

Automated findings require human validation. Executed risk tests establish only recorded local harness outcomes, not production safety or a complete security audit. AI source coverage: 1 files; dependency/vendor directories are excluded.

2 findings

<!-- slither-agent:7e0a159ec248c9c7b9ae24a6ed3e13f2e63d7f4c87ff23c89697740da5aef1a8 -->
## reentrancy-eth

**Severity:** High · **Confidence:** Medium · **Origin:** slither

**Scope:** `example/vault` · **Revision:** `23ca3cbce01ecd02c888bc686009aa94daa1b52e` · **Dirty:** false · **Imported:** false

**Status:** automated candidate; requires human validation.

### Evidence layers

- **Detection:** `slither` `0.11.6` reported `reentrancy-eth` (detected).
- **Dynamic testing:** not-run.

A detector hit, AI assessment, and passing local test are distinct evidence. A test result supports only its recorded assertion and plan claim.

### Source evidence

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

[Slither detector documentation](https://github.com/crytic/slither/wiki/Detector-Documentation#reentrancy-eth)

---

<!-- slither-agent:837afa4c26de785758112cebadfdb5ee411b54085c94bbcbb7030d9438668faa -->
## low-level-calls

**Severity:** Informational · **Confidence:** High · **Origin:** slither

**Scope:** `example/vault` · **Revision:** `23ca3cbce01ecd02c888bc686009aa94daa1b52e` · **Dirty:** false · **Imported:** false

**Status:** automated candidate; requires human validation.

### Evidence layers

- **Detection:** `slither` `0.11.6` reported `low-level-calls` (detected).
- **Dynamic testing:** not-run.

A detector hit, AI assessment, and passing local test are distinct evidence. A test result supports only its recorded assertion and plan claim.

### Source evidence

Low level call in VulnerableVault.withdraw() (examples/VulnerableVault.sol#12-17):
	- (ok,None) = msg.sender.call{value: amount}() (examples/VulnerableVault.sol#14)


- `examples/VulnerableVault.sol` lines [12 13 14 15 16 17]
- `examples/VulnerableVault.sol` lines [14]

[Slither detector documentation](https://github.com/crytic/slither/wiki/Detector-Documentation#low-level-calls)

---

