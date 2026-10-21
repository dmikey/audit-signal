package agent

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGateSeparatesEvidenceAndAcceptedRisk(t *testing.T) {
	id := digest("finding")
	today := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	finding := Finding{ID: id, Check: "reentrancy-eth", Severity: "High", Confidence: "High", Description: "external call before update", Origin: "slither", Review: &Review{ID: id, Verdict: "likely-valid", Reasoning: "source", ExploitScenario: "drain", Remediation: "update first", Validation: "test"}}
	r := Report{Version: 1, Scope: "org/contracts:.", Reviewed: true, Model: "auto", Provider: "copilot", Findings: []Finding{finding}, Sources: map[string]Source{}}
	p := GatePolicy{Version: 1, MinimumSeverity: "Medium", Evidence: "ai-reviewed"}
	b := GateBaseline{Version: 1, Scope: r.Scope, Accepted: []GateAcceptance{}}
	got, err := evaluateGate(r, p, b, today)
	if err != nil || got.Passed || got.Blocked != 1 || got.Decisions[0].Status != "new-finding" {
		t.Fatalf("new reviewed finding did not block: %+v %v", got, err)
	}
	b.Accepted = []GateAcceptance{{FindingID: id, Owner: "security-team", Reason: "tracked for next release", Expires: "2026-10-21"}}
	got, err = evaluateGate(r, p, b, today)
	if err != nil || !got.Passed || got.Accepted != 1 {
		t.Fatalf("unexpired reviewed acceptance did not pass: %+v %v", got, err)
	}
	got, err = evaluateGate(r, p, b, today.AddDate(0, 0, 1))
	if err != nil || got.Passed || got.Decisions[0].Status != "expired-acceptance" {
		t.Fatalf("expired acceptance did not block: %+v %v", got, err)
	}
	r.Findings[0].Review.Verdict = "likely-false-positive"
	got, err = evaluateGate(r, p, GateBaseline{Version: 1, Scope: r.Scope}, today)
	if err != nil || !got.Passed || got.NotActionable != 1 {
		t.Fatalf("false positive was treated as actionable: %+v %v", got, err)
	}
	r.Reviewed = false
	if _, err = evaluateGate(r, p, b, today); err == nil {
		t.Fatal("unreviewed scan bypassed reviewed policy")
	}
	r.Reviewed = true
	r.Findings[0].Review.Verdict = "likely-valid"
	p.Evidence = "local-exploit-test"
	if _, err = evaluateGate(r, p, b, today); err == nil {
		t.Fatal("missing risk stage bypassed local test policy")
	}
	r.Risk = &RiskRun{Status: "passed", Environment: "local-evm", Evidence: []RiskEvidence{{RiskCase: RiskCase{Claim: "risk-property"}, FindingIDs: []string{id}, Status: "Success"}}}
	got, err = evaluateGate(r, p, GateBaseline{Version: 1, Scope: r.Scope}, today)
	if err != nil || !got.Passed {
		t.Fatalf("risk property was mistaken for exploit reproduction: %+v %v", got, err)
	}
	r.Risk.Evidence[0].Claim = "exploit-reproduced"
	got, err = evaluateGate(r, p, GateBaseline{Version: 1, Scope: r.Scope}, today)
	if err != nil || got.Passed || got.Blocked != 1 {
		t.Fatalf("executed exploit was not actionable: %+v %v", got, err)
	}
	p.Evidence = "slither-detected"
	r.Imported = true
	if _, err = evaluateGate(r, p, b, today); err == nil {
		t.Fatal("imported report bypassed provenance policy")
	}
}

func TestGateCommandWritesFailureReceiptAndRejectsBadBaseline(t *testing.T) {
	dir := t.TempDir()
	id := digest("candidate")
	r := Report{Version: 1, Scope: "example/vault", Findings: []Finding{{ID: id, Check: "reentrancy-eth", Severity: "High", Confidence: "High", Description: "external call", Origin: "slither"}}, Sources: map[string]Source{}}
	if err := saveReport(dir, r); err != nil {
		t.Fatal(err)
	}
	policy := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(policy, []byte(`{"version":1,"minimum_severity":"Medium","evidence":"slither-detected"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := gateCommand([]string{"--report", filepath.Join(dir, "report.json"), "--policy", policy, "--expected-revision", "another-commit"}, &bytes.Buffer{}); err == nil {
		t.Fatal("stale report revision satisfied policy gate")
	}
	err := gateCommand([]string{"--report", filepath.Join(dir, "report.json"), "--policy", policy}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "blocked 1") {
		t.Fatalf("expected blocking result, got %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "gate.json"))
	if err != nil {
		t.Fatal(err)
	}
	var result GateResult
	if err := json.Unmarshal(b, &result); err != nil || result.Passed || result.Blocked != 1 {
		t.Fatalf("failure receipt missing: %+v %v", result, err)
	}
	baseline := filepath.Join(dir, "baseline.json")
	bad := `{"version":1,"scope":"other/repo","accepted":[{"finding_id":"` + id + `","owner":"team","reason":"approved","expires":"2027-01-01"}]}`
	if err := os.WriteFile(baseline, []byte(bad), 0600); err != nil {
		t.Fatal(err)
	}
	if err := gateCommand([]string{"--report", filepath.Join(dir, "report.json"), "--policy", policy, "--baseline", baseline}, &bytes.Buffer{}); err == nil {
		t.Fatal("mismatched baseline scope was accepted")
	}
}
