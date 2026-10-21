package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type RiskCase struct {
	Check         string   `json:"check"`
	File          string   `json:"file,omitempty"`
	Line          int      `json:"line,omitempty"`
	InvariantIDs  []string `json:"invariant_ids,omitempty"`
	SubjectSource string   `json:"subject_source,omitempty"`
	Suite         string   `json:"suite"`
	Test          string   `json:"test"`
	Claim         string   `json:"claim"`
	Description   string   `json:"description"`
}
type RiskEvidence struct {
	RiskCase
	FindingIDs []string        `json:"finding_ids"`
	Status     string          `json:"status"`
	Reason     string          `json:"reason,omitempty"`
	Kind       json.RawMessage `json:"kind"`
}
type RiskRun struct {
	Status             string            `json:"status"`
	Environment        string            `json:"environment"`
	Project            string            `json:"project,omitempty"`
	ForgeVersion       string            `json:"forge_version"`
	StartedAt          string            `json:"started_at"`
	PlanSHA256         string            `json:"plan_sha256"`
	HarnessHashes      map[string]string `json:"harness_hashes"`
	Evidence           []RiskEvidence    `json:"evidence"`
	UntestedFindingIDs []string          `json:"untested_finding_ids"`
	Passed             int               `json:"passed"`
	Failed             int               `json:"failed"`
	Skipped            int               `json:"skipped"`
}
type forgeTest struct {
	Status string          `json:"status"`
	Reason string          `json:"reason"`
	Kind   json.RawMessage `json:"kind"`
}
type forgeSuite struct {
	Tests map[string]forgeTest `json:"test_results"`
}

func riskCommand(ctx context.Context, args []string, w io.Writer) error {
	f := flags("risk", w)
	path := f.String("report", "reports/report.json", "Input Slither report")
	project := f.String("project", ".", "Trusted Foundry test project")
	sourceRoot := f.String("source-root", ".", "Root for report source paths; source hashes must match")
	planPath := f.String("plan", "risk-plan.json", "Explicit detector-to-test mapping")
	out := f.String("out", "reports", "Output report and test-evidence directory")
	forge := f.String("forge", "forge", "Foundry forge executable")
	solc := f.String("solc", "", "Optional compiler executable (offline compilation)")
	fuzzRuns := f.Int("fuzz-runs", 256, "Fuzz executions per fuzz test")
	timeout := f.Duration("timeout", 10*time.Minute, "Risk test timeout")
	if err := parse(f, args); err != nil {
		return err
	}
	if *fuzzRuns < 1 || *timeout <= 0 {
		return fmt.Errorf("fuzz-runs and timeout must be positive")
	}
	r, err := loadReport(*path)
	if err != nil {
		return err
	}
	if len(r.Sources) == 0 {
		return fmt.Errorf("risk tests require source evidence")
	}
	for name, src := range r.Sources {
		clean := filepath.Clean(filepath.FromSlash(name))
		if filepath.IsAbs(clean) || clean == ".." || len(clean) >= 3 && clean[:3] == ".."+string(os.PathSeparator) {
			return fmt.Errorf("invalid report source path")
		}
		b, e := os.ReadFile(filepath.Join(*sourceRoot, clean))
		if e != nil || digest(string(b)) != src.SHA256 {
			return fmt.Errorf("audited source changed or unavailable: %s; rerun audit", name)
		}
	}
	planData, err := os.ReadFile(*planPath)
	if err != nil {
		return err
	}
	cases, err := parseRiskPlan(planData, r)
	if err != nil {
		return err
	}
	proj, err := filepath.Abs(*project)
	if err != nil {
		return err
	}
	rootAbs, err := filepath.Abs(*sourceRoot)
	if err != nil {
		return err
	}
	projectRel, err := filepath.Rel(rootAbs, proj)
	if err != nil || projectRel == ".." || strings.HasPrefix(projectRel, ".."+string(os.PathSeparator)) {
		for _, c := range cases {
			if len(c.InvariantIDs) > 0 {
				return fmt.Errorf("invariant test project must be inside source root for replay")
			}
		}
		projectRel = ""
	}
	harness, err := collectSources(proj, proj, 2*1024*1024)
	if err != nil {
		return err
	}
	hashes := map[string]string{}
	for name, src := range harness {
		hashes[name] = src.SHA256
	}
	config, err := os.ReadFile(filepath.Join(proj, "foundry.toml"))
	if err != nil {
		return fmt.Errorf("project requires foundry.toml: %w", err)
	}
	hashes["foundry.toml"] = digest(string(config))
	if len(harness) == 0 {
		return fmt.Errorf("project has no test source")
	}
	if err = os.MkdirAll(*out, 0700); err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "slither-risk-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	executable := *forge
	if filepath.IsAbs(executable) || filepath.Dir(executable) != "." {
		executable = absolute(executable)
	}
	env := []string{"PATH=" + os.Getenv("PATH"), "FOUNDRY_FFI=false", "FOUNDRY_FS_PERMISSIONS=[]", "FOUNDRY_FUZZ_RUNS=" + fmt.Sprint(*fuzzRuns)}
	for _, k := range []string{"TMPDIR", "SYSTEMROOT", "USERPROFILE"} {
		if v := os.Getenv(k); v != "" {
			env = append(env, k+"="+v)
		}
	}
	version := exec.CommandContext(ctx, executable, "--version")
	version.Env = env
	ver, err := version.Output()
	if err != nil {
		return fmt.Errorf("forge unavailable; install Foundry or pass --forge")
	}
	resultPath := filepath.Join(dir, "results.json")
	cmdArgs := []string{"test", "--offline", "--json-file", resultPath, "--fuzz-runs", fmt.Sprint(*fuzzRuns)}
	if *solc != "" {
		cmdArgs = append(cmdArgs, "--use", absolute(*solc))
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	log, err := os.OpenFile(filepath.Join(*out, "risk.log"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, executable, cmdArgs...)
	cmd.Dir = proj
	cmd.Env = env
	cmd.Stdout = log
	cmd.Stderr = log
	risk := RiskRun{Status: "error", Environment: "local-evm", Project: filepath.ToSlash(projectRel), ForgeVersion: string(bytes.TrimSpace(ver)), StartedAt: time.Now().UTC().Format(time.RFC3339), PlanSHA256: digest(string(planData)), HarnessHashes: hashes, Evidence: []RiskEvidence{}, UntestedFindingIDs: []string{}}
	// New evidence invalidates an earlier AI review, including when tests fail.
	r.Risk = &risk
	r.Reviewed = false
	r.Model = ""
	r.Provider = ""
	for i := range r.Findings {
		r.Findings[i].Review = nil
	}
	if err := saveReport(*out, r); err != nil {
		log.Close()
		return err
	}
	runErr := cmd.Run()
	log.Close()
	data, readErr := os.ReadFile(resultPath)
	if readErr != nil {
		saveErr := saveReport(*out, r)
		if saveErr != nil {
			return saveErr
		}
		return fmt.Errorf("risk runner produced no results; inspect risk.log (%v)", runErr)
	}
	if len(data) > 16*1024*1024 {
		return fmt.Errorf("Foundry results exceed 16 MB")
	}
	if err = os.WriteFile(filepath.Join(*out, "forge-results.json"), data, 0600); err != nil {
		return err
	}
	risk, err = evaluateRisk(data, cases, r, risk)
	r.Risk = &risk
	if runErr != nil {
		r.Risk.Status = "error"
	}
	if saveErr := saveReport(*out, r); saveErr != nil {
		return saveErr
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "Risk tests: %d passed, %d failed, %d skipped; %d unmapped findings. Evidence saved to %s\n", risk.Passed, risk.Failed, risk.Skipped, len(risk.UntestedFindingIDs), *out)
	if runErr != nil || risk.Status != "passed" {
		return fmt.Errorf("risk stage did not pass; inspect report and risk.log (%v)", runErr)
	}
	return nil
}

func parseRiskPlan(data []byte, r Report) ([]RiskCase, error) {
	var plan struct {
		Version int        `json:"version"`
		Cases   []RiskCase `json:"cases"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&plan); err != nil {
		return nil, err
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return nil, fmt.Errorf("trailing risk plan data")
	}
	if plan.Version != 1 || len(plan.Cases) == 0 {
		return nil, fmt.Errorf("risk plan requires version 1 and at least one case")
	}
	seen := map[string]bool{}
	for _, c := range plan.Cases {
		matches := false
		for _, finding := range r.Findings {
			if riskCaseMatches(c, finding) {
				matches = true
				break
			}
		}
		selectorCount := 0
		if c.Check != "" {
			selectorCount++
		}
		if c.File != "" {
			selectorCount++
		}
		if selectorCount > 1 || (selectorCount == 0 && len(c.InvariantIDs) == 0) || (selectorCount == 1 && !matches) || (c.Check != "" && c.Line != 0) || (c.File != "" && (c.Line < 1 || !safeSourcePath(c.File))) || c.Suite == "" || c.Test == "" || c.Description == "" || (c.Claim != "exploit-reproduced" && c.Claim != "mitigation-holds" && c.Claim != "risk-property") {
			return nil, fmt.Errorf("invalid risk case or finding selector not present in report: %s", c.Test)
		}
		if len(c.InvariantIDs) > 0 {
			if !safeSourcePath(c.SubjectSource) {
				return nil, fmt.Errorf("invariant test %s requires a safe subject_source", c.Test)
			}
			if _, ok := r.Sources[c.SubjectSource]; !ok {
				return nil, fmt.Errorf("invariant test %s subject_source is absent from audited sources", c.Test)
			}
			ids := map[string]bool{}
			for _, id := range c.InvariantIDs {
				if !validIntentID(id) || ids[id] {
					return nil, fmt.Errorf("invalid or duplicate invariant ID in test %s", c.Test)
				}
				ids[id] = true
			}
		} else if c.SubjectSource != "" {
			return nil, fmt.Errorf("subject_source requires invariant_ids in test %s", c.Test)
		}
		key := c.Suite + "\x00" + c.Test
		if seen[key] {
			return nil, fmt.Errorf("duplicate risk case: %s", c.Test)
		}
		seen[key] = true
	}
	return plan.Cases, nil
}

func riskCaseMatches(c RiskCase, f Finding) bool {
	if c.Check != "" {
		return c.Check == f.Check
	}
	for _, loc := range f.Locations {
		if loc.File == c.File {
			for _, line := range loc.Lines {
				if line == c.Line {
					return true
				}
			}
		}
	}
	return false
}

func evaluateRisk(data []byte, cases []RiskCase, r Report, risk RiskRun) (RiskRun, error) {
	var suites map[string]forgeSuite
	if err := json.Unmarshal(data, &suites); err != nil {
		return risk, fmt.Errorf("invalid Foundry JSON: %w", err)
	}
	total := 0
	for _, suite := range suites {
		for _, result := range suite.Tests {
			total++
			switch result.Status {
			case "Success":
				risk.Passed++
			case "Failure":
				risk.Failed++
			case "Skipped":
				risk.Skipped++
			default:
				return risk, fmt.Errorf("unknown Foundry status")
			}
		}
	}
	if total == 0 {
		return risk, fmt.Errorf("Foundry executed no tests")
	}
	covered := map[string]bool{}
	risk.Status = "passed"
	for _, c := range cases {
		result, ok := suites[c.Suite].Tests[c.Test]
		if !ok {
			risk.Status = "error"
			return risk, fmt.Errorf("mapped test did not execute: %s:%s", c.Suite, c.Test)
		}
		e := RiskEvidence{RiskCase: c, FindingIDs: []string{}, Status: result.Status, Reason: result.Reason, Kind: result.Kind}
		for _, f := range r.Findings {
			if riskCaseMatches(c, f) {
				e.FindingIDs = append(e.FindingIDs, f.ID)
				covered[f.ID] = true
			}
		}
		risk.Evidence = append(risk.Evidence, e)
		if result.Status != "Success" {
			risk.Status = "failed"
		}
	}
	if risk.Failed > 0 {
		risk.Status = "failed"
	}
	for _, f := range r.Findings {
		if !covered[f.ID] {
			risk.UntestedFindingIDs = append(risk.UntestedFindingIDs, f.ID)
		}
	}
	return risk, nil
}

func riskMarkdown(r Report, id string) string {
	if r.Risk == nil {
		return ""
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "\n### Executed risk tests\n\nEnvironment: **%s** · Stage: **%s** · Passed: %d · Failed: %d · Skipped: %d\n\n", r.Risk.Environment, r.Risk.Status, r.Risk.Passed, r.Risk.Failed, r.Risk.Skipped)
	matched := false
	for _, e := range r.Risk.Evidence {
		for _, fid := range e.FindingIDs {
			if id != "" && fid != id {
				continue
			}
			matched = true
			fmt.Fprintf(&b, "- `%s:%s` — **%s**, plan claim: **%s**. %s\n", e.Suite, e.Test, e.Status, e.Claim, e.Description)
			if len(e.Kind) > 0 {
				fmt.Fprintf(&b, "  Execution: `%s`\n", string(e.Kind))
			}
			break
		}
	}
	if !matched {
		b.WriteString("No mapped dynamic test executed for this finding.\n")
	}
	b.WriteString("\nEvidence applies to assertions in the recorded local test harness. A passing remediation fixture does not change the audited source or establish production safety.\n")
	return b.String()
}
