# slither-agent

A portable Go binary that runs [Slither](https://github.com/crytic/slither), searches source for additional issues with **Copilot, OpenAI, or Anthropic**, reviews all findings, and creates deduplicated GitHub security issues. Intended for private smart contract repositories, including Foundry, Hardhat and standalone Solidity/Vyper targets.

The [scanner strategy and benchmark plan](docs/SCANNER_STRATEGY.md) compares the main alternatives and defines how we will measure detection quality, proof, coverage and false positives.

Copilot remains the default, with no provider API key required when Copilot access is available. OpenAI and Anthropic are optional bring-your-own-key choices. The Go binary has no third-party Go dependencies. Python/Slither and the Copilot CLI remain external runtime dependencies; the CLI is only needed for Copilot.

## Example audit

See the [VulnerableVault audit walkthrough](examples/README.md), with committed [Markdown](examples/reports/vulnerable-vault/report.md) and [JSON](examples/reports/vulnerable-vault/report.json) reports from a real Slither scan. It explains the High-severity reentrancy finding, a proposed fix and the validation still needed. See also the [executed penetration/risk report](examples/reports/vulnerable-vault-risk/report.md): four passing local EVM tests, including a reproduced drain and 256 fuzz cases. A [live GPT-5.4 review](examples/reports/vulnerable-vault-ai/report.md) also completed successfully.

## Build and run

Requires Go 1.20+, [uv](https://docs.astral.sh/uv/getting-started/installation/), and a patched Node.js release for Copilot CLI. Local development and the reusable workflow use **Node.js 26.12.1**, which includes the [October 21, 2026 TLS security fixes](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases). Callers can override `node-version` with another patched release. CI produces binaries for Linux, macOS and Windows. Slither setup and live scanning are tested on Linux and macOS; Windows compiler availability depends on your toolchain.

```sh
go build -trimpath -o bin/slither-agent ./cmd/slither-agent
./bin/slither-agent setup --solc-version 0.8.28
npm install -g @github/copilot@1.0.97
```

Setup installs `slither-analyzer==0.11.6` and `solc-select==1.2.0` into `.slither-venv`, and downloads the requested compiler into `.slither-venv/.solc-select`. It does not change your global compiler selection. Python dependencies of those pinned packages are resolved by uv at install time. Choose the compiler your contracts require.

For local use, run `gh auth login` with a GitHub account that has Copilot access. When no token environment variable is set, the agent captures the existing `gh` login in memory and supplies it to its isolated Copilot process. Alternatively, supply a supported `COPILOT_GITHUB_TOKEN`, `GH_TOKEN`, or `GITHUB_TOKEN`. A fine-grained PAT needs the **Copilot Requests** permission and Copilot access. The reviewer does not reuse local Copilot login/config files. Keep tokens in your environment or GitHub secrets; never commit them.

```sh
./bin/slither-agent audit \
  --target /path/to/private-contracts \
  --scope playmos/contracts \
  --solc-version 0.8.28 --model auto

# Review reports/report.md, then publish in the private contract repository:
./bin/slither-agent publish \
  --report reports/report.json --repo owner/private-contracts
```

Use the project root as `--target` when compilation depends on Foundry/Hardhat configuration. Install project dependencies first; use `slither.config.json` for Slither/framework settings. Use `--venv` or `--slither` for external tool installations. Scope is required and should remain stable across machines and revisions.

`audit` defaults to AI review. Use `--ai none` for a Slither-only run. `review --report ...` adds AI review to an existing report. `audit --input slither.json --target ... --scope ...` imports Slither output and marks the report as imported. Imported output must correspond to the supplied source; the tool cannot independently establish its provenance.

To use a preferred provider and model locally, set its API key in the environment and select both flags. The key is read by the review process and is never written to reports. `auto` is supported only with Copilot; use a model ID your chosen provider accepts. The scanner sends the bounded source bundle and findings to that provider's API, so check its data handling terms before auditing private code.

```sh
export OPENAI_API_KEY='your-key-from-a-secret-manager'
./bin/slither-agent audit --target contracts --scope owner/contracts \
  --provider openai --model YOUR_OPENAI_MODEL
# Or: ANTHROPIC_API_KEY with --provider anthropic --model YOUR_ANTHROPIC_MODEL
```

To search for flaws beyond Slither's detectors, run `discover` after the static audit, then `review` before publication. Discovery requires exact source file, line and excerpt evidence for each candidate. A new discovery clears any prior review, and the reviewer evaluates all findings together. The model may miss flaws or propose false positives; a line match establishes provenance, not exploitability. To make a discovery concrete, add a project-specific Foundry test and map its source file and line in the risk plan; this survives model-generated check-name changes.

```sh
./bin/slither-agent audit --target contracts --scope owner/contracts --ai none
./bin/slither-agent discover --report reports/report.json --model auto
./bin/slither-agent risk --report reports/report.json --project . --source-root . --plan risk-plan.json
./bin/slither-agent review --report reports/report.json --model auto
./bin/slither-agent publish --report reports/report.json --repo owner/private-contracts
```

AI review consumes a bounded source bundle (48 KB by default). It excludes vendor/build directories (`node_modules`, `lib`, `out`, `cache`, `artifacts`) and ignores symlinks. An oversized bundle fails explicitly; narrow the target or raise `--max-source-bytes`. The serialized review payload is capped at 256 KB. Each Slither finding must receive exactly one valid review. Invalid, incomplete or failed AI output leaves the original Slither report available and prevents normal publication.

## Use in GitHub CI/CD

### One-step installable action

After checkout, add `uses: dmikey/slither-agent@v0.6.0` to an Ubuntu or macOS job. The action builds the Go binary, installs pinned Slither and the requested compiler in runner temporary storage, scans the target, and exposes both report paths. It attempts Copilot review by default when the caller grants `copilot-requests: write`; if Copilot is unavailable, the job fails visibly:

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
        uses: dmikey/slither-agent@v0.6.0
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
    uses: dmikey/slither-agent/.github/workflows/audit.yml@v0.6.0
    with:
      target: '.'
      solc-version: '0.8.28'
      node-version: '26.12.1'
      model: auto
      # discover: true (default; searches source for additional candidates)
      publish: true
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
    uses: dmikey/slither-agent/.github/workflows/audit.yml@v0.6.0
    with:
      provider: openai # or anthropic
      model: YOUR_PROVIDER_MODEL_ID
      agent-ref: v0.6.0
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

The `risk` command adds an executed Foundry test stage before AI review. It runs your trusted project's exploit, fuzz and invariant tests in a local EVM, with an explicit [detector-to-test plan](examples/risk/plan.json). Tests are supplied by the project; the tool does not automatically generate attack contracts for arbitrary findings. [The example suite](examples/risk/test/VaultRisk.t.sol) reproduces a reentrancy drain, checks the remediation fixture, tests failed-transfer credit restoration, and runs 256 fuzz cases.

```sh
./bin/slither-agent audit --target . --scope owner/contracts --ai none
./bin/slither-agent risk --report reports/report.json --project . \
  --source-root . --plan risk-plan.json --solc /path/to/installed/solc
./bin/slither-agent review --report reports/report.json
./bin/slither-agent publish --report reports/report.json --repo owner/private-contracts
```

Use Foundry v1.8.5 or a version supporting `forge test --json-file`. Compilation is offline, so install the correct solc beforehand or pass `--solc`. Source hashes must match the Slither snapshot; changed source requires a new audit. The plan specifies an exact suite/test signature, either a detector `check` or source `file` and `line`, a descriptive claim (`exploit-reproduced`, `mitigation-holds`, or `risk-property`) and description. Detector mappings associate evidence with every finding of that type; source-location mappings target one fault site. Claims describe the intended assertions, and a successful test means those assertions passed. It does not automatically establish the security of every mapped finding.

Reports retain the exact test status, fuzz/invariant execution metadata, harness/config hashes, plan hash, Foundry version and finding IDs without dynamic coverage. Raw `forge-results.json` and `risk.log` are saved beside the reports. Missing/skipped mapped tests, failed tests, malformed output and execution errors fail the stage and block normal review/publication; existing AI review is invalidated before execution. Tests that prove an exploit works should assert the observed loss and pass when it is reproduced. A remediation fixture passing does not repair the original audited contract.

The workflow enables this stage when `risk-project` is set; otherwise dynamic testing is skipped. Its risk stage runs before AI discovery, so tests for newly discovered candidates need a subsequent manual `risk` run or a project-specific workflow adjustment. Run only trusted local suites: FFI and filesystem cheatcode permissions are disabled and credentials are removed from the test process, but Forge is not a complete network sandbox. This tool does not provide RPC endpoints, private keys, deploy contracts or broadcast transactions. A suite with explicit fork/RPC calls would need separate authorization and isolation. No live-chain penetration testing is included.

## Report contents and publication

The tool writes `report.json`, `report.md`, and `slither.log`. JSON contains source hashes/content, Git revision, dirty-checkout status, detector severity/confidence, source locations and AI review. Each finding also has derived `evidence_layers`: detection or discovery tool and version/model, separate AI review verdict, and each mapped Foundry test with its status and plan claim. `not-run` means no dynamic stage ran; `unmapped` means a successful dynamic stage had no test mapped to that finding; `no-executed-evidence` means the dynamic stage failed before that finding gained test evidence. Imported Slither output is marked `imported`, not reported as a direct scan. AI discovery adds separate candidates with source-line evidence; AI review adds a verdict, reasoning, exploit scenario, remediation, and validation steps. The tool does **not** silently remove Slither findings or promote model opinion or a passing test into a proven production exploit. The layer records are derived from the report's original evidence and checked when loading; future engines can use the same stage/tool distinction.

Use `slither-agent render --report path/to/report.json` to add the layer view to an existing report without running Slither, Copilot or Foundry again. It rewrites `report.json` and `report.md` beside the input unless `--out` selects another directory.

`publish` defaults to Medium and High findings with a `likely-valid` AI verdict, at most 20 selected findings. `--min-severity Low` includes Low findings; `--verdict needs-review` or `--verdict all` changes review filtering; `--finding-id` selects one exact candidate; `--max-issues` changes the cap. Exceeding the cap fails before issue writes. Normal publication requires a complete AI review; `--allow-unreviewed` explicitly permits static-only candidates. Public destinations are blocked unless `--allow-public-destination` is supplied.

Issues receive `security`, `slither-agent`, and `severity:*` labels. Each includes detector evidence, source locations, revision metadata and AI assessment. A deterministic fingerprint prevents duplicates for the same scope, detector, locations and evidence; source/line changes may create a new candidate. Open issues are updated when evidence changes; closed issues are left closed. Human labels are preserved. `publication.json` records created/updated/unchanged issue URLs. Run publishers serially per scope; the reusable workflow supplies concurrency control. Publication uses ordinary GitHub Issues, not Security Advisories or code-scanning alerts.

## Validation

```sh
make test    # race-enabled unit/integration tests + go vet
make smoke   # installs real Slither/solc and audits an intentionally vulnerable fixture
make risk-smoke # requires forge; adds local exploit, remediation and fuzz tests
```

Tests cover failed analysis, checkout-independent IDs, source disclosure boundaries, malformed AI review, public-destination protection, issue caps, issue deduplication, updates and closed-issue handling. CI verifies real `reentrancy-eth` detection and builds portable binaries. Live Copilot review has been verified locally with GPT-5.4 and the existing GitHub CLI login; the public smoke workflow exercises only static and dynamic tests. CI review still requires the caller's Copilot policy/credentials. The example vault is intentionally vulnerable and must never be deployed.
