# Audit Signal

A portable Go binary that runs [Slither](https://github.com/crytic/slither), searches source for additional issues with **Copilot, OpenAI, or Anthropic**, reviews all findings, and creates deduplicated GitHub security issues. Intended for private smart contract repositories, including Foundry, Hardhat and standalone Solidity/Vyper targets.

The [scanner strategy and benchmark plan](docs/SCANNER_STRATEGY.md) compares the main alternatives and defines how we will measure detection quality, proof, coverage and false positives.

Copilot remains the default, with no provider API key required when Copilot access is available. OpenAI and Anthropic are optional bring-your-own-key choices. The Go binary has no third-party Go dependencies. Python/Slither and the Copilot CLI remain external runtime dependencies; the CLI is only needed for Copilot.

Audit Signal is the new name for the existing `slither-agent` repository. Older reports retain their original names as historical evidence. The publisher recognizes both old and new issue markers, so upgrading does not create duplicate findings in a target repository. GitHub does not redirect Action or reusable-workflow `uses:` references after a repository rename: update callers to `dmikey/audit-signal` when adopting this release. Workflows still using `dmikey/slither-agent` must change their `uses:` references.

## Example audit

See the [VulnerableVault audit walkthrough](examples/README.md), with committed [Markdown](examples/reports/vulnerable-vault/report.md) and [JSON](examples/reports/vulnerable-vault/report.json) reports from a real Slither scan. It explains the High-severity reentrancy finding, a proposed fix and the validation still needed. See also the [executed penetration/risk report](examples/reports/vulnerable-vault-risk/report.md): four passing local EVM tests, including a reproduced drain and 256 fuzz cases. A [live GPT-5.4 review](examples/reports/vulnerable-vault-ai/report.md) also completed successfully.

## Build and run

Requires Go 1.20+, [uv](https://docs.astral.sh/uv/getting-started/installation/), and a patched Node.js release for Copilot CLI. Local development and the reusable workflow use **Node.js 26.12.1**, which includes the [October 21, 2026 TLS security fixes](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases). Callers can override `node-version` with another patched release. CI produces binaries for Linux, macOS and Windows. Slither setup and live scanning are tested on Linux and macOS; Windows compiler availability depends on your toolchain.

```sh
go build -trimpath -o bin/audit-signal ./cmd/audit-signal
./bin/audit-signal setup --solc-version 0.8.28
npm install -g @github/copilot@1.0.97
```

Setup installs `slither-analyzer==0.11.6` and `solc-select==1.2.0` into `.slither-venv`, and downloads the requested compiler into `.slither-venv/.solc-select`. It does not change your global compiler selection. Python dependencies of those pinned packages are resolved by uv at install time. Choose the compiler your contracts require.

For local use, run `gh auth login` with a GitHub account that has Copilot access. When no token environment variable is set, the agent captures the existing `gh` login in memory and supplies it to its isolated Copilot process. Alternatively, supply a supported `COPILOT_GITHUB_TOKEN`, `GH_TOKEN`, or `GITHUB_TOKEN`. A fine-grained PAT needs the **Copilot Requests** permission and Copilot access. The reviewer does not reuse local Copilot login/config files. Keep tokens in your environment or GitHub secrets; never commit them.

```sh
./bin/audit-signal audit \
  --target /path/to/private-contracts \
  --scope playmos/contracts \
  --solc-version 0.8.28 --model auto

# Review reports/report.md, record human decisions, then publish privately:
./bin/audit-signal triage init --report reports/report.json --file triage.json
# Fill each pending decision with hold/publish, owner, and reason.
./bin/audit-signal triage check --report reports/report.json --file triage.json
./bin/audit-signal publish \
  --report reports/report.json --repo owner/private-contracts --triage-file triage.json
```

Use the project root as `--target` when compilation depends on Foundry/Hardhat configuration. Install project dependencies first; use `slither.config.json` for Slither/framework settings. Use `--venv` or `--slither` for external tool installations. Scope is required and should remain stable across machines and revisions.

`audit` defaults to AI review. Use `--ai none` for a Slither-only run. `review --report ...` adds AI review to an existing report. `audit --input slither.json --target ... --scope ...` imports Slither output and marks the report as imported. Imported output must correspond to the supplied source; the tool cannot independently establish its provenance.

AI discovery can vary across runs. Once a maintainer validates a source-level candidate, retain its ID, check, severity, description, source file, line, exact `source_excerpt`, exploit scenario, remediation, and validation in a version 1 `curated-findings.json` manifest with the report's `scope` and `source_set_sha256`. Run `curate --report reports/report.json --file curated-findings.json --out reports` immediately after a fresh Slither scan, or pass `curated-findings-file` to the Action/reusable workflow. The command verifies the source hash, line, excerpt, and deterministic ID, then marks the entry as a retained candidate. It does not carry forward an old AI verdict: the current run must review it again. A changed audited source set requires refreshing the manifest. New AI discoveries on the same line are deduplicated against retained candidates.

AI review validates exact coverage of every finding ID. If a model omits or malformedly returns part of a batch, the scanner retries that segment in smaller batches; it still fails if a single finding cannot be reviewed, and it never saves a partial review as complete.

To use a preferred provider and model locally, set its API key in the environment and select both flags. The key is read by the review process and is never written to reports. `auto` is supported only with Copilot; use a model ID your chosen provider accepts. The scanner sends the bounded source bundle and findings to that provider's API, so check its data handling terms before auditing private code.

```sh
export OPENAI_API_KEY='your-key-from-a-secret-manager'
./bin/audit-signal audit --target contracts --scope owner/contracts \
  --provider openai --model YOUR_OPENAI_MODEL
# Or: ANTHROPIC_API_KEY with --provider anthropic --model YOUR_ANTHROPIC_MODEL
```

To search for flaws beyond Slither's detectors, run `discover` after the static audit, then `review` before publication. Discovery requires exact source file, line and excerpt evidence for each candidate. Candidates on the same source line as an existing Medium-or-higher Slither finding are discarded as overlaps while distinct candidates continue to triage. A new discovery clears any prior review, and the reviewer evaluates all findings together. The model may miss flaws or propose false positives; a line match establishes provenance, not exploitability. To make a discovery concrete, add a project-specific Foundry test and map its source file and line in the risk plan; this survives model-generated check-name changes.

```sh
./bin/audit-signal audit --target contracts --scope owner/contracts --ai none
./bin/audit-signal discover --report reports/report.json --model auto
./bin/audit-signal risk --report reports/report.json --project . --source-root . --plan risk-plan.json
./bin/audit-signal review --report reports/report.json --model auto
./bin/audit-signal triage init --report reports/report.json --file triage.json
# Fill and check the human decisions before publication.
./bin/audit-signal publish --report reports/report.json --repo owner/private-contracts --triage-file triage.json
```

AI review consumes a bounded source bundle (48 KB by default). It excludes vendor/build directories (`node_modules`, `lib`, `out`, `cache`, `artifacts`) and ignores symlinks. An oversized bundle fails explicitly; narrow the target or raise `--max-source-bytes`. Reviews run in batches of up to eight findings, with the full bounded source bundle sent to the selected provider for each batch. Each serialized batch is capped at 256 KB; larger source bundles still need a narrower target. Every finding must receive exactly one valid review before the report is marked reviewed. Invalid, incomplete or failed AI output leaves the original Slither report available and prevents normal publication. Multiple batches consume more provider requests and may repeat private source in those requests.

## Use in GitHub CI/CD

### One-step installable action

After checkout, add `uses: dmikey/audit-signal@v0.12.4` to an Ubuntu or macOS job. The action builds the Go binary, installs pinned Slither and the requested compiler in runner temporary storage, scans the target, and exposes both report paths. It attempts Copilot review by default when the caller grants `copilot-requests: write`; if Copilot is unavailable, the job fails visibly:

```yaml
name: Smart contract audit
on: [workflow_dispatch]
permissions:
  contents: read
  copilot-requests: write
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with:
          persist-credentials: false
      - id: scan
        uses: dmikey/audit-signal@v0.12.4
        with:
          target: '.'
          solc-version: '0.8.28'
      - uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: |
            ${{ steps.scan.outputs.report-json }}
            ${{ steps.scan.outputs.report-markdown }}
          retention-days: 1
```

Set `ai: none` for a static audit with no model access. For the default Copilot review, you may also set `discover: 'true'` to look beyond Slither findings and `copilot-token: ${{ secrets.COPILOT_TOKEN }}` when using a PAT. To use another provider, set `provider` and `model` and supply the matching secret through `with`, for example `openai-api-key: ${{ secrets.OPENAI_API_KEY }}` or `anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}`. Secrets are supplied only to the selected AI steps, after the static scan. Do not place provider keys in job-level `env`, where dependency setup would inherit them. Install any trusted Foundry/Hardhat dependencies in a step before the action.

To record an existing local test suite in the same report, set `suite-project`
to `contracts` and `suite-command-json` to a JSON argument array such as
`["./node_modules/.bin/hardhat","test","--network","hardhat"]`. The action
exposes `suite-log` and `report-directory` even when the suite fails, so an
`always()` artifact step can retain diagnostics briefly. It runs before Copilot's
Node version is installed, so the caller's project toolchain is retained for
compilation and tests. Add `suite-result-format: mocha-spec` for a Hardhat/Mocha
spec suite to require a positive reported test count; the default `exit-only`
records successful command completion without claiming that tests ran. Suite
results are project-level evidence only.

This action writes reports to the runner's temporary directory and does not publish issues. Use the reusable workflow below when you need isolated jobs for risk tests, AI review, and issue publication. Its jobs keep model credentials away from project setup and give issue-write permission only to the publisher. GitHub [distinguishes composite actions from reusable workflows](https://docs.github.com/en/actions/tutorials/create-actions/create-a-composite-action#composite-actions-and-reusable-workflows).

### Full reusable workflow

**GitHub Models retired July 30, 2026.** Use [Copilot CLI in Actions](https://docs.github.com/en/copilot/how-tos/copilot-cli/use-copilot-cli-in-actions) instead of the old `models: read` inference API.

For organization repositories, enable **Allow use of Copilot CLI billed to the organization** and grant `copilot-requests: write`. The workflow can then use `GITHUB_TOKEN`; no separate model key or PAT is required. AI credits are billed to the organization. For personal repositories or organizations without that policy, create a fine-grained PAT with **Copilot Requests** and store it as `COPILOT_TOKEN`. This uses the user's Copilot access and billing. See [GitHub's authentication options](https://docs.github.com/en/copilot/how-tos/copilot-cli/automate-copilot-cli/automate-with-actions).

Add the following workflow **inside the private contract repository**. Pin the tool workflow and `agent-ref` to the same reviewed commit for production; the version tag below is a convenient starting point.

```yaml
name: Smart contract security audit
on:
  workflow_dispatch:
permissions:
  contents: read
  copilot-requests: write
  issues: write
jobs:
  audit:
    uses: dmikey/audit-signal/.github/workflows/audit.yml@v0.12.4
    with:
      target: '.'
      solc-version: '0.8.28'
      node-version: '26.12.1'
      model: auto
      # discover: true (default; searches source for additional candidates)
      publish: true
      triage-file: .audit-signal/triage.json
      # Optional Foundry exploit / fuzz / invariant test stage:
      # risk-project: .
      # risk-plan: risk-plan.json
      # fuzz-runs: 256
      # Hardhat example; use your trusted project setup as needed:
      # setup-command: npm ci
      # max-source-bytes: 96000
    # Only needed for personal repos / PAT authentication:
    # secrets:
    #   COPILOT_TOKEN: ${{ secrets.COPILOT_TOKEN }}
```

For a provider key, add `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` under the **private caller repository's** Settings → Secrets and variables → Actions. Then select the provider and model in the same workflow:

```yaml
jobs:
  audit:
    uses: dmikey/audit-signal/.github/workflows/audit.yml@v0.12.4
    with:
      provider: openai # or anthropic
      model: YOUR_PROVIDER_MODEL_ID
      agent-ref: v0.12.4
      target: '.'
      publish: false
    secrets:
      OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
      # For Anthropic instead: ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

Use one provider secret at a time. GitHub passes it only to the review job and only when that provider is selected. OpenAI requests disable response storage and model tools; Anthropic requests include no tools. The tool never logs provider responses on API failure and refuses redirects. Offline tests cover both adapters; live use depends on your own key, model access and provider billing.

The reusable workflow runs optional local risk tests after scanning/building, then discovers source-level candidates and reviews all findings in a separate job before issue publication. The contract checkout has no persisted credentials. Only the review job receives the selected AI credential; only the publisher receives issue-write permission. The Copilot reviewer runs from an empty temporary directory, disables repository instructions and built-in MCPs, and exposes no model tools. Source and detector text are treated as untrusted evidence. Project setup still executes code, so run this on trusted revisions, not `pull_request_target` with fork code. For Foundry, install `forge` in your trusted `setup-command` before `forge install`; choose versions appropriate for your project.

Reports include source code and may include security-sensitive evidence. Artifacts expire after one day and inherit the caller repository's visibility. Keep this workflow in the private contract repository; do not dispatch private Playmos audits in this public tool repository. A repository-scoped `GITHUB_TOKEN` cannot read or publish to an unrelated private repo; run in that repo or supply separately scoped credentials for a custom integration.

## Penetration and risk tests

For a repository's existing Hardhat or other project test suite, record a bounded
execution separately from finding-specific risk tests:

```bash
audit-signal suite --report reports/report.json --source-root . --project contracts \
  --out reports --command-json '["./node_modules/.bin/hardhat","test","--network","hardhat"]'
```

`suite` verifies every audited source hash before execution, runs the supplied
argument array without a shell or inherited credentials, saves a private capped
log and its SHA-256, and records the exit status in `project_tests`. By default,
an exit code of zero is labeled `completed` because the scanner cannot tell if
any tests actually ran. For Hardhat/Mocha's spec reporter, add
`--result-format mocha-spec` (or Action input `suite-result-format: mocha-spec`).
The scanner then requires one unambiguous `N passing` summary with N greater
than zero, records passing/pending/failing counts, and rejects missing summaries,
reported failures, or truncated logs. This verifies the runner's reported count,
not the quality or completeness of its assertions. It runs
trusted repository code, so use a restricted runner and avoid commands that
contact a live network unless intended. A passing regression suite is reported
at project level only; it never marks a scanner finding as reproduced or fixed.
Use the mapped `risk` stage below for that stronger claim. Do not put secrets in
command arguments, since the command is saved in the report.

The `risk` command adds an executed Foundry test stage before AI review. It runs your trusted project's exploit, fuzz and invariant tests in a local EVM, with an explicit [detector-to-test plan](examples/risk/plan.json). Tests are supplied by the project; the tool does not automatically generate attack contracts for arbitrary findings. [The example suite](examples/risk/test/VaultRisk.t.sol) reproduces a reentrancy drain, checks the remediation fixture, tests failed-transfer credit restoration, and runs 256 fuzz cases.

For an existing Hardhat/Mocha project, `risk-mocha` executes each exact test title in a reviewed plan separately on the local Hardhat network. It requires exactly one passing test for each claim, hashes the test file and private output log, checks audited source hashes before and after execution, and records the runner separately from Foundry. Map by an exact `finding_id` to avoid attributing one property test to every occurrence of a detector. A case can instead map to `invariant_ids` and `subject_source` when a high-value attack path has no detector hit. This verifies that the trusted harness ran and passed; reviewers still need to inspect the assertions and threat model.

```sh
audit-signal risk-mocha --report reports/report.json --source-root . \
  --project contracts --plan contracts/audit-signal-risk-plan.json --out reports
audit-signal assure --report reports/report.json \
  --intent contracts/audit-signal-intent.json --out reports
```

In the installable Action, set `suite-project: contracts` and `risk-mocha-plan: contracts/audit-signal-risk-plan.json`; `intent-file` then adds the invariant assurance map. Run this only on trusted project code. The Hardhat network is local, but a test harness can still attempt outbound requests; the runner strips credentials, not network access.

```sh
./bin/audit-signal audit --target . --scope owner/contracts --ai none
./bin/audit-signal risk --report reports/report.json --project . \
  --source-root . --plan risk-plan.json --solc /path/to/installed/solc
./bin/audit-signal review --report reports/report.json
./bin/audit-signal triage check --report reports/report.json --file triage.json
./bin/audit-signal publish --report reports/report.json --repo owner/private-contracts --triage-file triage.json
```

Use Foundry v1.8.5 or a version supporting `forge test --json-file`. Compilation is offline, so install the correct solc beforehand or pass `--solc`. Source hashes must match the Slither snapshot; changed source requires a new audit. The plan specifies an exact suite/test signature, either a detector `check` or source `file` and `line`, a descriptive claim (`exploit-reproduced`, `mitigation-holds`, or `risk-property`) and description. Detector mappings associate evidence with every finding of that type; source-location mappings target one fault site. Claims describe the intended assertions, and a successful test means those assertions passed. It does not automatically establish the security of every mapped finding.

Reports retain the exact test status, fuzz/invariant execution metadata, harness/config hashes, plan hash, Foundry version and finding IDs without dynamic coverage. Raw `forge-results.json` and `risk.log` are saved beside the reports. Missing/skipped mapped tests, failed tests, malformed output and execution errors fail the stage and block normal review/publication; existing AI review is invalidated before execution. Tests that prove an exploit works should assert the observed loss and pass when it is reproduced. A remediation fixture passing does not repair the original audited contract.

The workflow enables this stage when `risk-project` is set; otherwise dynamic testing is skipped. Its risk stage runs before AI discovery, so tests for newly discovered candidates need a subsequent manual `risk` run or a project-specific workflow adjustment. Run only trusted local suites: FFI and filesystem cheatcode permissions are disabled and credentials are removed from the test process, but Forge is not a complete network sandbox. This tool does not provide RPC endpoints, private keys, deploy contracts or broadcast transactions. A suite with explicit fork/RPC calls would need separate authorization and isolation. No live-chain penetration testing is included.

## Compilation coverage receipt

Every direct scan now emits `coverage.json` and `coverage.md`. Slither exports the compiler units from the **same run** as its detector findings; Audit Signal compares their source files with the target source inventory. The receipt records compiler versions, contract names, source hashes, dependencies, source-bundle exclusions, and any target file missing from compilation. `complete` means every inventoried target source appeared in the exported compilation units and no source or unit was unresolved. It does not mean every execution path was explored. Imported Slither JSON receives `unavailable` coverage because Audit Signal did not witness its compilation.

For a project with imports, point `--target` at its Foundry or Hardhat project directory rather than one Solidity file. [Slither recommends project-level analysis](https://github.com/crytic/slither/blob/master/README.md) when dependencies are involved. The AI source bundle still has a bounded size and omits vendor/generated directories; compiled dependencies are listed separately by hash, without copying their contents into the AI prompt. A source-bundle exclusion is visible even when Slither compiled that dependency.

Set `require_complete_scan: true` in the caller's [policy](examples/coverage/policy.json) to fail the merge gate if coverage is absent, imported, incomplete, or has an unapproved source-bundle exclusion. Review and list intentional paths exactly in `allowed_coverage_exclusions`, for example `"allowed_coverage_exclusions": ["lib"]`; do not use wildcards. Legacy reports without a coverage receipt fail this rule and must be rescanned. The [three-contract fixture](examples/coverage) exercises project compilation in CI, including a contract that is not imported by the other two. A separate unit test removes one compiled source and verifies the gate blocks the partial result.

The coverage receipt is a compiler-input account, not a measurement of detector path coverage, fuzz coverage, or production safety. A green result still requires human review of the protocol's invariant list and the test assertions. The current source-bundle limit remains fail-closed; larger repositories must raise `max-source-bytes` while we add scalable AI chunking.

## Protocol assurance map

Check a reviewed intent manifest into the contract repository to describe the assets, roles, assumptions, and security invariants that matter to the protocol. [The vulnerable vault manifest](examples/intent/vault-vulnerable.json) shows the version 1 JSON schema. Each invariant has an ID, severity, statement, and exact audited source paths. The manifest's `scope` must equal the report scope. The scanner rejects unknown references, duplicate IDs, path traversal, and test mappings to a different audited source.

Add `invariant_ids` and `subject_source` to cases in the [Foundry risk plan](examples/risk/plan.json). The plan's subject binding is a reviewed claim about what a test exercises; the scanner verifies that source is in the audited bundle and records its hash alongside the harness hash, plan hash, Forge version, and a targeted replay command. The replay may require the recorded compiler and fuzz settings. It cannot infer that arbitrary test code actually asserts the invariant, so security reviewers must inspect the harness. A test on a repaired fixture is never credited to the vulnerable source.

```sh
audit-signal assure --report reports/report.json \
  --intent .audit-signal/intent.json --out reports
audit-signal gate --report reports/report.json \
  --policy .audit-signal/policy.json --intent .audit-signal/intent.json \
  --expected-revision "$(git rev-parse HEAD)" --out reports
```

`assurance.json` and `assurance.md` distinguish `checked-local` (mapped assertions passed), `counterexample-local` (a mapped exploit-reproduction test passed), `unmapped`, `untested`, `out-of-scope`, and failed or skipped test stages. Unmapped and untested invariants receive a suggested Foundry test outline for human review; it is not an executable or AI-generated test. Passing local checks is not formal verification or a claim about deployed contracts.

Set `require_assurance: true` and `minimum_invariant_severity` in the policy to block gaps or counterexamples at that severity or higher. [The example assurance policy](examples/intent/policy.json) blocks High invariants without `checked-local` evidence. Accepted-finding baselines do not waive invariants. Both the installable Action and reusable workflow accept `intent-file`; without a policy they still emit an assurance map, and with a policy they include invariant decisions in `gate.json`. The installable Action only scans, so its map starts as `untested` unless a caller runs `risk` before a separate `assure`/`gate` invocation. The reusable workflow can run Foundry first when `risk-project` is set.

CI exercises the [vulnerable](examples/intent/vault-vulnerable.json) and [repaired](examples/intent/vault-fixed.json) vaults with real Slither and Foundry. The vulnerable vault's High fund-isolation invariant is a local counterexample and blocks the gate. The repaired vault's corresponding local tests pass; a lower-priority deposit-accounting invariant remains visibly unmapped. These are fixture outcomes, not production certification.

## Merge policy gate

The optional `gate` command turns a completed report into a deterministic CI decision. Check a policy JSON file into the **contract repository**; [the example policy](examples/policy.json) blocks new High-severity, directly detected Slither findings. Set `evidence` to `ai-reviewed` to require a completed AI review and a `likely-valid` verdict, or to `local-exploit-test` to require a successful local Foundry test with the explicit `exploit-reproduced` claim. These are distinct evidence rules: a model verdict is not a reproduced exploit, and a passing risk-property test is not an exploit test. Imported reports and dirty checkouts fail unless the policy explicitly permits them. An incomplete required AI or risk stage fails the gate rather than producing a clean result.

```sh
audit-signal gate --report reports/report.json --policy .audit-signal/policy.json \
  --baseline .audit-signal/baseline.json
```

Both GitHub install paths pass the caller commit as `--expected-revision`, so a stale report cannot satisfy the gate.

The baseline is optional. Without it, every finding matching the policy is new and blocks. To accept a known finding, add its exact 64-character ID from `report.json` to a versioned baseline with the same report `scope`, an accountable `owner`, a `reason`, and an ISO `expires` date. [The empty baseline example](examples/baseline.example.json) shows the shape; an entry in `accepted` looks like `{"finding_id":"<exact ID>","owner":"security-team","reason":"tracked remediation","expires":"2026-12-31"}`. Acceptance expires **after** that UTC date. A changed finding ID is new and must be reviewed again. Accepted findings remain visible in `gate.json` and `gate.md`; expired acceptances block. The gate never writes GitHub issues or modifies the baseline.

For the installable Action, pass `policy-file: .audit-signal/policy.json` and optionally `baseline-file: .audit-signal/baseline.json`. It exposes `gate-json` and `gate-markdown` outputs, and fails the job when the policy blocks. The reusable workflow accepts the same paths as inputs, reads them from the caller checkout after AI review, uploads the decision with the report, and skips publication on a failed gate. Run the workflow on `pull_request` with `publish: false`; configure its successful job as a [required status check](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets) in the caller's branch ruleset. If that repository uses a merge queue, also trigger the caller workflow on `merge_group`. Protect the caller's policy, baseline and workflow files with security-team CODEOWNERS review; otherwise a pull request can relax its own gate.

## Report contents and publication

The tool writes `report.json`, `report.md`, and `slither.log`. JSON contains source hashes/content, Git revision, dirty-checkout status, detector severity/confidence, source locations and AI review. Each finding also has derived `evidence_layers`: detection or discovery tool and version/model, separate AI review verdict, and each mapped Foundry test with its status and plan claim. `not-run` means no dynamic stage ran; `unmapped` means a successful dynamic stage had no test mapped to that finding; `no-executed-evidence` means the dynamic stage failed before that finding gained test evidence. Imported Slither output is marked `imported`, not reported as a direct scan. AI discovery adds separate candidates with source-line evidence; AI review adds a verdict, reasoning, exploit scenario, remediation, and validation steps. The tool does **not** silently remove Slither findings or promote model opinion or a passing test into a proven production exploit. The layer records are derived from the report's original evidence and checked when loading; future engines can use the same stage/tool distinction.

Use `audit-signal render --report path/to/report.json` to add the layer view to an existing report without running Slither, Copilot or Foundry again. It rewrites `report.json` and `report.md` beside the input unless `--out` selects another directory.

`triage init` creates a versioned decision file for every finding at or above its minimum severity. A human fills each `pending` record with `hold` or `publish`, an owner, and a reason. `triage check` requires a decision for every current finding at the minimum severity, rejects duplicates, stale scope or source hashes, and publication decisions without a `likely-valid` AI review. It preserves an owned `hold` for a source-bound AI candidate that is absent from a later nondeterministic discovery run, but never accepts an absent `publish` decision. A new source set requires fresh decisions. The [Playmos pilot](https://github.com/playmos-labs/playmos-sdk/pull/955) exercises this gate against a private contract repository.

`publish` requires `--triage-file` by default and only selects findings marked `publish`. `--allow-untriaged` is an explicit compatibility override; the reusable workflow does not use it. Publication otherwise defaults to Medium and High findings with a `likely-valid` AI verdict, at most 20 selected findings. `--min-severity Low` includes Low findings; `--verdict needs-review` or `--verdict all` changes review filtering; `--finding-id` selects one exact candidate; `--max-issues` changes the cap. Exceeding the cap fails before issue writes. Normal publication requires a complete AI review; `--allow-unreviewed` explicitly permits static-only candidates. Public destinations are blocked unless `--allow-public-destination` is supplied.

`benchmark` scores labeled fixture scans and fails CI on a regression. The first [manifest](examples/benchmark/manifest.json) checks that fresh Slither runs detect `reentrancy-eth` in the vulnerable vault and omit it in the repaired vault. CI produces a machine-readable score from those two cases; this is a narrow regression signal, not a general recall or false-positive rate. Add new vulnerable/repaired pairs and reviewed labels to grow the benchmark.

Issues receive `security`, `audit-signal`, and `severity:*` labels. Each includes detector evidence, source locations, revision metadata and AI assessment. A deterministic fingerprint prevents duplicates for the same scope, detector, locations and evidence; source/line changes may create a new candidate. Open issues are updated when evidence changes; closed issues are left closed. Human labels are preserved. `publication.json` records created/updated/unchanged issue URLs. Run publishers serially per scope; the reusable workflow supplies concurrency control. Publication uses ordinary GitHub Issues, not Security Advisories or code-scanning alerts.

## Validation

```sh
make test    # race-enabled unit/integration tests + go vet
make smoke   # installs real Slither/solc and audits an intentionally vulnerable fixture
make risk-smoke # requires forge; adds local exploit, remediation and fuzz tests
```

Tests cover failed analysis, checkout-independent IDs, source disclosure boundaries, malformed AI review, public-destination protection, issue caps, issue deduplication, updates and closed-issue handling. CI verifies real `reentrancy-eth` detection and builds portable binaries. Live Copilot review has been verified locally with GPT-5.4 and the existing GitHub CLI login; the public smoke workflow exercises only static and dynamic tests. CI review still requires the caller's Copilot policy/credentials. The example vault is intentionally vulnerable and must never be deployed.
