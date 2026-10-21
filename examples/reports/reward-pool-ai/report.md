# Smart contract audit

Scope: `example/reward-pool`

Revision: `61e5b8f370758105ec3649088664dbce6516d085` (dirty: false)

Slither: `0.11.6`; AI model: `gpt-5.6-sol`; AI reviewed: true; AI discovery: true; discovery model: `gpt-5.6-sol`; imported: false

Automated findings require human validation. Executed risk tests establish only recorded local harness outcomes, not production safety or a complete security audit. AI source coverage: 1 files; dependency/vendor directories are excluded.

5 findings


### Executed risk tests

Environment: **local-evm** · Stage: **passed** · Passed: 5 · Failed: 0 · Skipped: 0

- `test/RewardPoolRisk.t.sol:RewardPoolRiskTest:test_FreshCallersExhaustReservesAndLockStake()` — **Success**, plan claim: **exploit-reproduced**. Eleven fresh callers credit the same beneficiary in one epoch; withdrawing rewards consumes stake and blocks full stake withdrawal in the local EVM.
  Execution: `{
          "Unit": {
            "gas": 1650030
          }
        }`

Evidence applies to assertions in the recorded local test harness. A passing remediation fixture does not change the audited source or establish production safety.
<!-- slither-agent:52f589267a38845bee5cc3d4d02931681244befc82c7309135c316e160fb0073 -->
## ai-caller-beneficiary-claim-state-mismatch

**Severity:** High · **Confidence:** AI hypothesis · **Origin:** ai-discovery

**Scope:** `example/reward-pool` · **Revision:** `61e5b8f370758105ec3649088664dbce6516d085` · **Dirty:** false · **Imported:** false

**Status:** automated candidate; requires human validation.

### Evidence layers

- **Discovery:** `copilot` model `gpt-5.6-sol` proposed `ai-caller-beneficiary-claim-state-mismatch` as a candidate.
- **Review:** `copilot` model `gpt-5.6-sol` assessed this as **likely-valid**.
- **Dynamic testing:** `foundry` `forge Version: 1.8.5` ran `test/RewardPoolRisk.t.sol:RewardPoolRiskTest:test_FreshCallersExhaustReservesAndLockStake()` — **Success**; plan claim: **exploit-reproduced**.

A detector hit, AI assessment, and passing local test are distinct evidence. A test result supports only its recorded assertion and plan claim.

### Source evidence

Sybil callers can multiply one beneficiary's rewards: Reward accrual uses the beneficiary's shares but calculates and records claimed epochs under msg.sender. A beneficiary can therefore have arbitrarily many fresh addresses call claimFor for the same beneficiary, crediting the same epochs repeatedly and draining the pool.

- `examples/RewardPool.sol` lines [35]

Source line: `uint256 missed = epoch - lastClaimEpoch[msg.sender];`

**Discovery model:** `gpt-5.6-sol`

**Hypothesized attack:** At least one epoch has advanced and a beneficiary owns shares. Multiple addresses whose lastClaimEpoch is behind the current epoch each call claimFor(beneficiary), repeatedly adding rewards for the beneficiary's same shares and epochs; the beneficiary then withdraws the accumulated credit.

**Proposed fix:** Key both the accrual calculation and checkpoint update by beneficiary, and restrict who may initiate a claim if third-party claiming is unnecessary: use lastClaimEpoch[beneficiary] consistently.

**Validation needed:** Give one beneficiary one share, advance one epoch, call claimFor for that beneficiary from two previously unused addresses, and verify that the second call cannot increase rewardCredit beyond one epoch's reward.

### AI review

Model: `gpt-5.6-sol` · Verdict: **likely-valid**

In examples/RewardPool.sol lines 34-38, missed epochs and the checkpoint update are keyed by msg.sender, while credited rewards and shares are keyed by beneficiary. Consequently, every fresh caller has lastClaimEpoch equal to zero and can credit the same beneficiary for the same epochs. Access is unrestricted, and withdrawRewards at lines 41-47 lets the beneficiary extract the duplicated credit. The executed local-EVM test test_FreshCallersExhaustReservesAndLockStake() is exploit-reproduced evidence: it passed while asserting that eleven fresh callers credit one beneficiary, whose withdrawal consumes reserves and prevents full stake withdrawal.

### Exploit scenario

After the owner advances at least one epoch, a beneficiary holding shares coordinates multiple fresh addresses. Each address calls claimFor(beneficiary), independently computes missed from its own zero checkpoint, and adds rewards based on the beneficiary's unchanged shares. The beneficiary then calls withdrawRewards and can drain reward funding and deposited principal. No privileged caller or reentrancy is required.

### Remediation

Use lastClaimEpoch[beneficiary] for both the missed-epoch calculation and checkpoint update. If permissionless claiming is unnecessary, additionally require msg.sender == beneficiary or explicit beneficiary authorization. Apply checks-effects-interactions and ensure reward liabilities are reserve-backed.

### Validation to perform

Repeat the supplied exploit with one beneficiary and multiple fresh callers, asserting that only the first claim increases rewardCredit and later calls cannot credit the same epochs. Also test claims before and after share-balance changes and confirm stake principal remains withdrawable.

### Executed risk tests

Environment: **local-evm** · Stage: **passed** · Passed: 5 · Failed: 0 · Skipped: 0

- `test/RewardPoolRisk.t.sol:RewardPoolRiskTest:test_FreshCallersExhaustReservesAndLockStake()` — **Success**, plan claim: **exploit-reproduced**. Eleven fresh callers credit the same beneficiary in one epoch; withdrawing rewards consumes stake and blocks full stake withdrawal in the local EVM.
  Execution: `{
          "Unit": {
            "gas": 1650030
          }
        }`

Evidence applies to assertions in the recorded local test harness. A passing remediation fixture does not change the audited source or establish production safety.

---

<!-- slither-agent:9dc60d29f1884222aa364fd581d68d59feb6481c5e0cf55866a8f22edcf5a72a -->
## ai-retroactive-reward-accrual

**Severity:** High · **Confidence:** AI hypothesis · **Origin:** ai-discovery

**Scope:** `example/reward-pool` · **Revision:** `61e5b8f370758105ec3649088664dbce6516d085` · **Dirty:** false · **Imported:** false

**Status:** automated candidate; requires human validation.

### Evidence layers

- **Discovery:** `copilot` model `gpt-5.6-sol` proposed `ai-retroactive-reward-accrual` as a candidate.
- **Review:** `copilot` model `gpt-5.6-sol` assessed this as **likely-valid**.
- **Dynamic testing:** unmapped.

A detector hit, AI assessment, and passing local test are distinct evidence. A test result supports only its recorded assertion and plan claim.

### Source evidence

New shares receive rewards for past epochs: The credit calculation multiplies the beneficiary's current share balance by every epoch missed since the caller's checkpoint, without tracking when those shares were acquired. A user can deposit after epochs have elapsed and immediately claim rewards for periods in which no stake was held.

- `examples/RewardPool.sol` lines [37]

Source line: `rewardCredit[beneficiary] += shares[beneficiary] * REWARD_PER_SHARE * missed;`

**Discovery model:** `gpt-5.6-sol`

**Hypothesized attack:** One or more epochs advance before an address acquires shares. The address then deposits and calls claimFor for itself using an unchanged old checkpoint, receiving credit for all preceding epochs despite holding no shares during them.

**Proposed fix:** Accrue rewards when share balances change using a cumulative reward-per-share index, or initialize/update the account's claim checkpoint on deposit so newly acquired shares cannot earn prior epochs.

**Validation needed:** Advance several epochs before a new address deposits, then claim for that address and verify that no rewards are credited for epochs preceding its deposit.

### AI review

Model: `gpt-5.6-sol` · Verdict: **likely-valid**

In examples/RewardPool.sol lines 16-19, deposit increases shares without establishing or settling a reward checkpoint. Lines 34-38 later multiply the beneficiary's current shares by every epoch missed since the caller's checkpoint. For a new depositor claiming for itself, lastClaimEpoch is initially zero, so shares acquired after epoch advancement receive rewards for earlier epochs. No historical balance accounting prevents this. The finding is listed as dynamically untested, so no executed test confirms this exploit in the supplied harness.

### Exploit scenario

The owner advances one or more epochs before an attacker deposits. The attacker deposits 1 ether, receives one share, and immediately calls claimFor(attacker). Because its checkpoint remains zero, the contract credits REWARD_PER_SHARE multiplied by all elapsed epochs, including periods before the attacker held a share. Profit requires sufficient contract liquidity and rewards exceeding relevant costs.

### Remediation

Use a cumulative reward-per-share index and settle each account's accrued rewards before every deposit or withdrawal, then update its reward debt for the new balance. At minimum, initialize a first-time depositor's checkpoint to the current epoch, though checkpoint-only accounting must also correctly handle later deposits and partial withdrawals.

### Validation to perform

Advance several epochs with no attacker stake, then deposit and claim from a fresh address; assert that no pre-deposit rewards are credited. Also test additional deposits and partial withdrawals after accrual to ensure only shares held during each interval earn rewards.

### Executed risk tests

Environment: **local-evm** · Stage: **passed** · Passed: 5 · Failed: 0 · Skipped: 0

No mapped dynamic test executed for this finding.

Evidence applies to assertions in the recorded local test harness. A passing remediation fixture does not change the audited source or establish production safety.

---

<!-- slither-agent:e872d62ca1771d91a7b69046d17f76ffb89862b6eb4de83829c7996e14b9135c -->
## ai-principal-reward-accounting-mingling

**Severity:** High · **Confidence:** AI hypothesis · **Origin:** ai-discovery

**Scope:** `example/reward-pool` · **Revision:** `61e5b8f370758105ec3649088664dbce6516d085` · **Dirty:** false · **Imported:** false

**Status:** automated candidate; requires human validation.

### Evidence layers

- **Discovery:** `copilot` model `gpt-5.6-sol` proposed `ai-principal-reward-accounting-mingling` as a candidate.
- **Review:** `copilot` model `gpt-5.6-sol` assessed this as **likely-valid**.
- **Dynamic testing:** unmapped.

A detector hit, AI assessment, and passing local test are distinct evidence. A test result supports only its recorded assertion and plan claim.

### Source evidence

Reward withdrawals can consume staked principal: The contract pays reward credits directly from its undifferentiated ether balance and does not track or reserve deposited principal separately from funded rewards. Valid reward claims can therefore spend ether required to honor outstanding shares, leaving later stake withdrawals insolvent.

- `examples/RewardPool.sol` lines [45]

Source line: `(bool ok,) = msg.sender.call{value: amount}("");`

**Discovery model:** `gpt-5.6-sol`

**Hypothesized attack:** The contract has outstanding shares whose deposits form part of its balance, while separately funded reward liquidity is less than valid reward credits. A credited account withdraws rewards, consuming principal-backed ether; an outstanding shareholder subsequently calls withdrawStake and the transfer fails because the contract lacks the owed principal.

**Proposed fix:** Track reward funding separately from total contract balance, require credited rewards to be fully covered by available reward reserves, decrement that reserve on reward withdrawal, and never allow reward payments to reduce ether reserved for outstanding shares.

**Validation needed:** Create multiple outstanding shares, provide less reward funding than accrued credit, withdraw a reward, and verify that the implementation either rejects an underfunded reward withdrawal or still retains exactly 1 ether for every remaining share.

### AI review

Model: `gpt-5.6-sol` · Verdict: **likely-valid**

Deposits at examples/RewardPool.sol lines 16-19 and reward funding at line 21 enter the same ether balance. withdrawRewards at lines 41-47 pays the full recorded credit without tracking reward reserves or preserving 1 ether per outstanding share, while withdrawStake at lines 22-27 assumes that principal remains available. Thus a reward payment can reduce the balance below aggregate principal liabilities. Exploitability requires reward credit exceeding separately funded reward liquidity, which the contract permits. This finding is unmapped and therefore dynamically untested, notwithstanding the separate mapped test describing principal consumption through duplicated claims.

### Exploit scenario

Users deposit stake, creating principal liabilities. Reward credits accrue while dedicated reward funding is absent or insufficient. A credited account withdraws rewards from the undifferentiated contract balance, consuming ether backing outstanding shares. A later shareholder's withdrawStake call then fails for insufficient balance, rolling back that withdrawal and locking the affected principal until the pool is replenished.

### Remediation

Track total principal liabilities and a separate available reward reserve. Increase the reward reserve only through explicit reward funding, require every reward payment to be covered by that reserve, and decrement it on payment. Alternatively, isolate principal and rewards in separate accounting contracts or vaults. Ensure accrued reward liabilities cannot exceed funded reserves.

### Validation to perform

Create multiple shares, accrue a valid reward credit larger than explicitly funded rewards, and attempt reward withdrawal. Assert that it reverts before touching principal or that the post-withdrawal balance remains at least 1 ether times total outstanding shares. Then verify every shareholder can withdraw principal.

### Executed risk tests

Environment: **local-evm** · Stage: **passed** · Passed: 5 · Failed: 0 · Skipped: 0

No mapped dynamic test executed for this finding.

Evidence applies to assertions in the recorded local test harness. A passing remediation fixture does not change the audited source or establish production safety.

---

<!-- slither-agent:018dc0e61b579383df90e27f45aad6250c3fcb563754e4e640ea8621d907b223 -->
## low-level-calls

**Severity:** Informational · **Confidence:** High · **Origin:** slither

**Scope:** `example/reward-pool` · **Revision:** `61e5b8f370758105ec3649088664dbce6516d085` · **Dirty:** false · **Imported:** false

**Status:** automated candidate; requires human validation.

### Evidence layers

- **Detection:** `slither` `0.11.6` reported `low-level-calls` (detected).
- **Review:** `copilot` model `gpt-5.6-sol` assessed this as **likely-false-positive**.
- **Dynamic testing:** unmapped.

A detector hit, AI assessment, and passing local test are distinct evidence. A test result supports only its recorded assertion and plan claim.

### Source evidence

Low level call in RewardPool.withdrawRewards() (examples/RewardPool.sol#41-47):
	- (ok,None) = msg.sender.call{value: amount}() (examples/RewardPool.sol#45)


- `examples/RewardPool.sol` lines [41 42 43 44 45 46 47]
- `examples/RewardPool.sol` lines [45]

### AI review

Model: `gpt-5.6-sol` · Verdict: **likely-false-positive**

The low-level call in examples/RewardPool.sol line 45 forwards ether to msg.sender, but lines 42-44 first read and zero that caller's rewardCredit, and line 46 requires call success. A reentrant withdrawRewards therefore encounters zero credit, and a failed transfer reverts the zeroing as part of the transaction. The low-level call itself does not demonstrate an exploit; the material risks arise from incorrect reward and reserve accounting. This finding is dynamically untested.

### Exploit scenario

A malicious recipient can execute arbitrary fallback logic during the call, but reentering withdrawRewards cannot recover the same credit because it has already been zeroed. Other public functions do not provide an evident reentrant path to restore that credit. Reentrancy could matter if future code introduces cross-function state dependencies, but no current exploit is demonstrated from this call alone.

### Remediation

No vulnerability-specific change is required for the call as currently ordered. For defense in depth, retain checks-effects-interactions, consider a reentrancy guard around withdrawal entry points, and optionally use a reviewed address-send helper while still checking failure. Fix the independent reward-accounting and reserve issues separately.

### Validation to perform

Use a receiver contract whose fallback reenters withdrawRewards and other withdrawal functions, asserting that it cannot withdraw more than its legitimate balances. Also test a receiver that reverts, confirming the entire transaction rolls back and rewardCredit remains available for a later successful withdrawal.

### Executed risk tests

Environment: **local-evm** · Stage: **passed** · Passed: 5 · Failed: 0 · Skipped: 0

No mapped dynamic test executed for this finding.

Evidence applies to assertions in the recorded local test harness. A passing remediation fixture does not change the audited source or establish production safety.

[Slither detector documentation](https://github.com/crytic/slither/wiki/Detector-Documentation#low-level-calls)

---

<!-- slither-agent:1d877563d62479f37c4a2267954f7265d32f9f22a177f727907da1457314bfea -->
## low-level-calls

**Severity:** Informational · **Confidence:** High · **Origin:** slither

**Scope:** `example/reward-pool` · **Revision:** `61e5b8f370758105ec3649088664dbce6516d085` · **Dirty:** false · **Imported:** false

**Status:** automated candidate; requires human validation.

### Evidence layers

- **Detection:** `slither` `0.11.6` reported `low-level-calls` (detected).
- **Review:** `copilot` model `gpt-5.6-sol` assessed this as **likely-false-positive**.
- **Dynamic testing:** unmapped.

A detector hit, AI assessment, and passing local test are distinct evidence. A test result supports only its recorded assertion and plan claim.

### Source evidence

Low level call in RewardPool.withdrawStake() (examples/RewardPool.sol#22-27):
	- (ok,None) = msg.sender.call{value: 1000000000000000000}() (examples/RewardPool.sol#25)


- `examples/RewardPool.sol` lines [22 23 24 25 26 27]
- `examples/RewardPool.sol` lines [25]

### AI review

Model: `gpt-5.6-sol` · Verdict: **likely-false-positive**

The low-level call in examples/RewardPool.sol line 25 occurs after line 24 decrements msg.sender's shares, and line 26 requires success. A reentrant caller with one share cannot withdraw it twice because the nested call sees zero shares. A caller with multiple shares can reenter and withdraw additional shares, but each nested payment is paired with another decrement and is equivalent to making multiple authorized withdrawals. Transfer failure reverts the decrement. No exploit follows solely from using call, and this finding is dynamically untested.

### Exploit scenario

A malicious shareholder's fallback can reenter withdrawStake. Each successful nested invocation requires and consumes another share, so the caller cannot receive more than 1 ether per recorded share. Insolvency may make the call fail, but that results from principal/reward commingling rather than the low-level call primitive.

### Remediation

No security fix is necessary solely for this call under the current state ordering. For defense in depth and resilience to future cross-function changes, add a reentrancy guard to withdrawal functions while preserving the pre-call share decrement and checked call result. Address reserve segregation independently.

### Validation to perform

Test malicious receivers holding one and multiple shares that recursively call withdrawStake and withdrawRewards. Assert that total stake payments never exceed 1 ether per consumed share, state is correct after nested calls, and a reverting receiver causes full rollback.

### Executed risk tests

Environment: **local-evm** · Stage: **passed** · Passed: 5 · Failed: 0 · Skipped: 0

No mapped dynamic test executed for this finding.

Evidence applies to assertions in the recorded local test harness. A passing remediation fixture does not change the audited source or establish production safety.

[Slither detector documentation](https://github.com/crytic/slither/wiki/Detector-Documentation#low-level-calls)

---

