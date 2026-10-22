package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// risk-mocha runs one exact, reviewer-selected Mocha test per mapped claim.
// The harness and runner remain trusted project code; the scanner verifies
// execution and provenance, not the semantic quality of an assertion.
func riskMochaCommand(ctx context.Context, args []string, w io.Writer) error {
	f := flags("risk-mocha", w)
	reportPath := f.String("report", "reports/report.json", "Input audit report")
	sourceRoot := f.String("source-root", ".", "Audited source root")
	project := f.String("project", ".", "Trusted Hardhat project inside the source root")
	planPath := f.String("plan", "risk-plan.json", "Explicit finding-to-test plan")
	out := f.String("out", "reports", "Output report and private test logs")
	hardhat := f.String("hardhat", "./node_modules/.bin/hardhat", "Hardhat executable in the project")
	timeout := f.Duration("timeout", 10*time.Minute, "Total attack-test timeout")
	if err := parse(f, args); err != nil {
		return err
	}
	if *timeout <= 0 {
		return fmt.Errorf("risk-mocha timeout must be positive")
	}
	r, err := loadReport(*reportPath)
	if err != nil {
		return err
	}
	if len(r.Sources) == 0 {
		return fmt.Errorf("risk-mocha requires audited source evidence")
	}
	rootAbs, err := filepath.Abs(*sourceRoot)
	if err != nil {
		return err
	}
	rootAbs, err = filepath.EvalSymlinks(rootAbs)
	if err != nil {
		return err
	}
	projectAbs, err := filepath.Abs(*project)
	if err != nil {
		return err
	}
	projectAbs, err = filepath.EvalSymlinks(projectAbs)
	if err != nil {
		return err
	}
	projectRel, err := filepath.Rel(rootAbs, projectAbs)
	if err != nil || projectRel == ".." || strings.HasPrefix(projectRel, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("Hardhat project must be inside audited source root")
	}
	if err := verifySuiteSources(rootAbs, r.Sources); err != nil {
		return err
	}
	planData, err := os.ReadFile(*planPath)
	if err != nil {
		return err
	}
	cases, err := parseRiskPlan(planData, r)
	if err != nil {
		return err
	}
	hashes := map[string]string{}
	for _, c := range cases {
		if !safeSourcePath(c.Suite) || !(strings.HasSuffix(c.Suite, ".ts") || strings.HasSuffix(c.Suite, ".js")) || !strings.HasPrefix(c.Suite, "test/") {
			return fmt.Errorf("risk-mocha suite must be a relative test/*.ts or test/*.js file")
		}
		if strings.ContainsAny(c.Test, "\r\n") || len(c.Test) > 512 {
			return fmt.Errorf("invalid Mocha test title")
		}
		path := filepath.Join(projectAbs, filepath.FromSlash(c.Suite))
		info, statErr := os.Lstat(path)
		if statErr != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("mapped Hardhat test file missing or unsafe: %s", c.Suite)
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		hashes[c.Suite] = digest(string(data))
	}
	for _, name := range []string{"hardhat.config.ts", "hardhat.config.js", "package-lock.json"} {
		path := filepath.Join(projectAbs, name)
		if info, statErr := os.Lstat(path); statErr == nil && info.Mode().IsRegular() {
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			hashes[name] = digest(string(data))
		}
	}
	outAbs, err := filepath.Abs(*out)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(outAbs, 0700); err != nil {
		return err
	}
	if len(r.ProjectTests) > 0 {
		for _, prior := range r.ProjectTests {
			if filepath.Base(prior.LogFile) != prior.LogFile {
				return fmt.Errorf("invalid prior project test log path")
			}
			data, readErr := os.ReadFile(filepath.Join(outAbs, prior.LogFile))
			if readErr != nil || digest(string(data)) != prior.LogSHA256 {
				return fmt.Errorf("prior project test log missing or changed: %s", prior.LogFile)
			}
		}
	}
	executable := *hardhat
	if !filepath.IsAbs(executable) {
		executable = filepath.Join(projectAbs, executable)
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return fmt.Errorf("Hardhat executable missing: %w", err)
	}
	exeRel, err := filepath.Rel(projectAbs, executable)
	if err != nil || exeRel == ".." || strings.HasPrefix(exeRel, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("Hardhat executable must be inside the trusted project")
	}
	info, err := os.Lstat(executable)
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("Hardhat executable missing or unsafe")
	}
	env := []string{"PATH=" + os.Getenv("PATH"), "CI=true", "HARDHAT_DISABLE_TELEMETRY_PROMPT=true", "FOUNDRY_FFI=false", "FOUNDRY_FS_PERMISSIONS=[]"}
	if tmp := os.Getenv("TMPDIR"); tmp != "" {
		env = append(env, "TMPDIR="+tmp)
	}
	deadline, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	versionCmd := exec.CommandContext(deadline, executable, "--version")
	versionCmd.Dir, versionCmd.Env = projectAbs, env
	version, err := versionCmd.Output()
	if err != nil {
		return fmt.Errorf("Hardhat unavailable: %w", err)
	}
	risk := RiskRun{Status: "error", Environment: "local-evm", Runner: "hardhat", RunnerVersion: strings.TrimSpace(string(version)), Project: filepath.ToSlash(projectRel), StartedAt: time.Now().UTC().Format(time.RFC3339), PlanSHA256: digest(string(planData)), HarnessHashes: hashes, Evidence: []RiskEvidence{}, UntestedFindingIDs: []string{}}
	r.Risk = &risk
	r.Reviewed, r.Model, r.Provider = false, "", ""
	for i := range r.Findings {
		r.Findings[i].Review = nil
	}
	if err := saveReport(outAbs, r); err != nil {
		return err
	}
	covered := map[string]bool{}
	for _, c := range cases {
		if err := verifySuiteSources(rootAbs, r.Sources); err != nil {
			return err
		}
		if err := verifyMochaHarness(projectAbs, hashes); err != nil {
			return err
		}
		log, err := os.CreateTemp(outAbs, "attack-test-*.log")
		if err != nil {
			return err
		}
		logName := filepath.Base(log.Name())
		bounded := &boundedLog{w: log, remaining: 2 * 1024 * 1024}
		pattern := "^" + regexp.QuoteMeta(c.Test) + "$"
		cmd := exec.CommandContext(deadline, executable, "test", "--network", "hardhat", "--grep", pattern, c.Suite)
		cmd.Dir, cmd.Env, cmd.Stdout, cmd.Stderr = projectAbs, env, bounded, bounded
		runErr := cmd.Run()
		if err := log.Close(); err != nil {
			return err
		}
		data, err := os.ReadFile(log.Name())
		if err != nil {
			return err
		}
		passed, pending, failed := 0, 0, 0
		var resultErr error
		if bounded.truncated {
			resultErr = fmt.Errorf("attack-test log truncated")
		} else {
			passed, pending, failed, resultErr = mochaSpecResults(data)
		}
		status, reason := "Error", "test identity or result not verified"
		if runErr == nil && resultErr == nil && passed == 1 && pending == 0 && failed == 0 {
			status, reason = "Success", ""
			risk.Passed++
		} else if failed > 0 {
			status, reason = "Failure", "mapped test reported a failed assertion"
			risk.Failed++
		} else if runErr != nil {
			reason = "Hardhat command failed without a verified failing assertion"
		} else if resultErr != nil {
			reason = resultErr.Error()
		} else {
			reason = "expected exactly one passing test and no pending tests"
		}
		kind, _ := json.Marshal(map[string]any{"Hardhat": map[string]int{"passing": passed, "pending": pending, "failing": failed}})
		e := RiskEvidence{RiskCase: c, FindingIDs: []string{}, Status: status, Reason: reason, Kind: kind, LogFile: logName, LogSHA256: digest(string(data))}
		for _, f := range r.Findings {
			if riskCaseMatches(c, f) {
				e.FindingIDs = append(e.FindingIDs, f.ID)
				covered[f.ID] = true
			}
		}
		risk.Evidence = append(risk.Evidence, e)
		if status == "Failure" {
			risk.Status = "failed"
		}
		r.Risk = &risk
		if err := saveReport(outAbs, r); err != nil {
			return err
		}
		if status != "Success" {
			return fmt.Errorf("mapped Hardhat attack test %s: %s; inspect %s", c.Test, reason, log.Name())
		}
	}
	if err := verifySuiteSources(rootAbs, r.Sources); err != nil {
		return err
	}
	if err := verifyMochaHarness(projectAbs, hashes); err != nil {
		return err
	}
	for _, f := range r.Findings {
		if !covered[f.ID] {
			risk.UntestedFindingIDs = append(risk.UntestedFindingIDs, f.ID)
		}
	}
	risk.Status = "passed"
	r.Risk = &risk
	if err := saveReport(outAbs, r); err != nil {
		return err
	}
	fmt.Fprintf(w, "Mapped Hardhat attack tests: %d passed, %d unmapped findings; evidence saved to %s\n", risk.Passed, len(risk.UntestedFindingIDs), outAbs)
	return nil
}

func verifyMochaHarness(project string, hashes map[string]string) error {
	for name, hash := range hashes {
		data, err := os.ReadFile(filepath.Join(project, filepath.FromSlash(name)))
		if err != nil || digest(string(data)) != hash {
			return fmt.Errorf("Hardhat harness changed or unavailable: %s", name)
		}
	}
	return nil
}
