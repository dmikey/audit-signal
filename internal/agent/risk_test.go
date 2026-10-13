package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRiskResultsRequireExecutedMappedAssertions(t *testing.T) {
	fs, _ := parseSlither(fixture("/one"), "scope", "/one")
	other := fs[0]
	other.ID = digest("unmapped")
	other.Check = "low-level-calls"
	r := Report{Findings: append(fs, other)}
	cases := []RiskCase{{Check: "reentrancy-eth", Suite: "test/Attack.t.sol:Attack", Test: "testAttack()", Claim: "exploit-reproduced", Description: "loss assertion"}}
	for _, tc := range []struct{ name, status, want string }{{"pass", "Success", "passed"}, {"failed", "Failure", "failed"}, {"skipped", "Skipped", "failed"}} {
		t.Run(tc.name, func(t *testing.T) {
			data, _ := json.Marshal(map[string]forgeSuite{cases[0].Suite: {Tests: map[string]forgeTest{cases[0].Test: {Status: tc.status, Kind: json.RawMessage(`{"Fuzz":{"runs":256}}`)}}}})
			risk, err := evaluateRisk(data, cases, r, RiskRun{Status: "error"})
			if err != nil {
				t.Fatal(err)
			}
			if risk.Status != tc.want || len(risk.Evidence) != 1 || len(risk.UntestedFindingIDs) != 1 || risk.UntestedFindingIDs[0] != other.ID {
				t.Fatalf("incorrect coverage/status: %+v", risk)
			}
		})
	}
	for _, data := range []string{`{}`, `garbage`, `{"test/Attack.t.sol:Attack":{"test_results":{"differentTest()":{"status":"Success"}}}}`} {
		risk, err := evaluateRisk([]byte(data), cases, r, RiskRun{Status: "error"})
		if err == nil || risk.Status == "passed" {
			t.Fatal("accepted missing test evidence")
		}
	}
}

func TestRiskCommandPreservesFailureAndStripsCredentials(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mock runner")
	}
	root := t.TempDir()
	project := filepath.Join(root, "project")
	os.Mkdir(project, 0700)
	content := "contract Vault {}"
	os.WriteFile(filepath.Join(root, "Vault.sol"), []byte(content), 0600)
	os.WriteFile(filepath.Join(project, "Attack.t.sol"), []byte("contract Attack {}"), 0600)
	os.WriteFile(filepath.Join(project, "foundry.toml"), []byte("[profile.default]\nffi = true\n"), 0600)
	fs, _ := parseSlither(fixture("/one"), "scope", "/one")
	fs[0].Review = &Review{ID: fs[0].ID, Verdict: "needs-review", Reasoning: "before test", ExploitScenario: "before test", Remediation: "before test", Validation: "before test"}
	r := Report{Version: 1, Scope: "scope", Findings: fs, Reviewed: true, Sources: map[string]Source{"Vault.sol": {Content: content, SHA256: digest(content)}}}
	in := filepath.Join(root, "input")
	saveReport(in, r)
	plan := filepath.Join(root, "plan.json")
	os.WriteFile(plan, []byte(`{"version":1,"cases":[{"check":"reentrancy-eth","suite":"Attack.t.sol:Attack","test":"testAttack()","claim":"risk-property","description":"balance conservation"}]}`), 0600)
	runner := filepath.Join(root, "forge-mock")
	code := `#!/usr/bin/env python3
import os,sys,json
if '--version' in sys.argv:
 print('forge mock'); sys.exit(0)
assert 'GITHUB_TOKEN' not in os.environ
assert 'PRIVATE_BUILD_SECRET' not in os.environ
assert os.environ['FOUNDRY_FFI']=='false'
assert os.environ['FOUNDRY_FS_PERMISSIONS']=='[]'
assert '--offline' in sys.argv
p=sys.argv[sys.argv.index('--json-file')+1]
with open(p,'w') as f: json.dump({'Attack.t.sol:Attack':{'test_results':{'testAttack()':{'status':'Failure','reason':'loss','kind':{'Unit':{'gas':42}}}}}},f)
sys.exit(1)
`
	os.WriteFile(runner, []byte(code), 0700)
	t.Setenv("GITHUB_TOKEN", "must-not-disclose")
	t.Setenv("PRIVATE_BUILD_SECRET", "must-not-disclose")
	out := filepath.Join(root, "out")
	args := []string{"risk", "--report", filepath.Join(in, "report.json"), "--project", project, "--source-root", root, "--plan", plan, "--forge", runner, "--out", out}
	err := Run(context.Background(), args, &strings.Builder{})
	if err == nil {
		t.Fatal("failed risk tests must fail the command")
	}
	saved, err := loadReport(filepath.Join(out, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	if saved.Reviewed || saved.Findings[0].Review != nil || saved.Risk.Status == "passed" || saved.Risk.Failed != 1 {
		t.Fatal("stale review or failed evidence was lost")
	}
	os.WriteFile(filepath.Join(root, "Vault.sol"), []byte("changed"), 0600)
	err = Run(context.Background(), args, &strings.Builder{})
	if err == nil || !strings.Contains(err.Error(), "source changed") {
		t.Fatal("changed source accepted")
	}
}
