# Scanner focus and benchmark plan

The goal is an evidence-driven security scanner for private smart contract repositories. A useful finding must identify source, state the assumption it relies on, survive a separate review, and where possible include an executed local test. An AI verdict alone is a candidate, never proof.

## Landscape

| Tool | Established strength | Our relationship to it |
| --- | --- | --- |
| [Slither](https://github.com/crytic/slither) | Fast Solidity/Vyper static detectors, source locations, CI integration, custom analyses | Required baseline and compiler-aware source of deterministic findings |
| [Aderyn](https://github.com/Cyfrin/aderyn) | Solidity static analysis with editor integration | Alternative deterministic analyzer worth evaluating as an optional second signal |
| [Mythril](https://github.com/ConsenSysDiligence/mythril) | Symbolic execution over EVM bytecode and transaction sequences | Optional deeper path exploration for selected high-risk candidates |
| [Echidna](https://github.com/crytic/echidna) and [Medusa](https://github.com/crytic/medusa) | Property testing and stateful, coverage-guided fuzzing | Complement the current Foundry tests when protocol invariants are available |
| [Foundry](https://getfoundry.sh/forge/invariant-testing) | Local executable tests, fuzzing and invariants | Current reproducible exploit and regression-test harness |

## What to improve next

1. **Measure detection quality.** Maintain vulnerable and repaired pairs, including multi-contract business-logic cases. Track true positives, duplicate findings, false positives, missed known flaws, and time/cost per scan. Run the same cases at a pinned model and compiler version so changes are comparable.
2. **Broaden source context.** The compilation coverage receipt now lists compiler units, target files, dependencies, exclusions, and unresolved sources from the same Slither run. The bounded AI source bundle still fails above its configured size. Add contract-level chunking that preserves caller/callee and inheritance context without exposing vendor sources unnecessarily. A compilation-complete scan should never imply detector path coverage.
3. **Increase dynamic confirmation.** Map AI candidates to targeted Foundry invariants, then support optional Echidna/Medusa and symbolic checks where appropriate. Report the exact assertion, harness hash, tool version and whether an exploit was reproduced. Never infer production exploitability from a passing fixture alone.
4. **Make triage useful in pull requests.** Keep GitHub Issues for durable, deduplicated findings; add SARIF/code-scanning output and a clear reviewed/proven/untested state for each candidate. Default publication to reviewed likely-valid findings, with explicit overrides for uncertainty.
5. **Test privacy and adversarial inputs.** Keep private source in the caller repository, use narrowly scoped credentials, and evaluate prompt-injection attempts in source/comments and malformed model output. Preserve exact provenance for imported static results and model-generated findings.

The protocol assurance map now links reviewed assets, roles, assumptions, and invariants to exact audited sources and Foundry tests. Its vulnerable/repaired vault pair demonstrates counterexample, checked-local, and unmapped states; source and harness hashes make these claims reviewable. CI now scores the pair as two labeled detector cases, a narrow regression check rather than a score for real-world detection quality. The RewardPool fixture proves one business-logic issue in a local EVM and remains a separate regression case.
