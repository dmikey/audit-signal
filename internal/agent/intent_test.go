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

func intentFixture() IntentManifest {
	return IntentManifest{Version: 1, Scope: "example/vault", Assets: []IntentAsset{{ID: "deposited-eth", Description: "user funds"}}, Roles: []IntentRole{{ID: "depositor", Description: "fund owner"}}, Assumptions: []IntentAssumption{{ID: "recipient-can-reenter", Statement: "recipient can call back"}}, Invariants: []IntentInvariant{{ID: "funds-isolated", Title: "Depositor funds remain isolated", Statement: "A caller cannot withdraw another depositor's funds", Severity: "High", Assets: []string{"deposited-eth"}, Roles: []string{"depositor"}, Assumptions: []string{"recipient-can-reenter"}, Sources: []string{"Vault.sol"}}}}
}

func TestIntentEvidenceCannotCrossSourceOrConfuseClaims(t *testing.T) {
	m := intentFixture()
	if err := validateIntent(m, m.Scope); err != nil {
		t.Fatal(err)
	}
	r := Report{Version: 1, Scope: m.Scope, Sources: map[string]Source{"Vault.sol": {Content: "contract Vault {}", SHA256: digest("contract Vault {}")}}, Findings: []Finding{}}
	assurance, err := assessIntent(r, m, digest("report"), digest("intent"))
	if err != nil || assurance.Invariants[0].Status != "untested" || assurance.Invariants[0].Proposal == nil {
		t.Fatalf("missing evidence was not exposed: %+v %v", assurance, err)
	}
	caseOne := RiskCase{InvariantIDs: []string{"funds-isolated"}, SubjectSource: "Vault.sol", Suite: "test/Vault.t.sol:VaultTest", Test: "testDrain()", Claim: "exploit-reproduced", Description: "drain"}
	plan, _ := json.Marshal(struct {
		Version int        `json:"version"`
		Cases   []RiskCase `json:"cases"`
	}{1, []RiskCase{caseOne}})
	if _, err := parseRiskPlan(plan, r); err != nil {
		t.Fatalf("invariant-only test mapping rejected: %v", err)
	}
	forge, _ := json.Marshal(map[string]forgeSuite{caseOne.Suite: {Tests: map[string]forgeTest{caseOne.Test: {Status: "Success"}}}})
	risk, err := evaluateRisk(forge, []RiskCase{caseOne}, r, RiskRun{Status: "error", Environment: "local-evm", Project: "examples/risk", PlanSHA256: digest("plan"), HarnessHashes: map[string]string{"test/Vault.t.sol": digest("harness")}})
	if err != nil {
		t.Fatal(err)
	}
	r.Risk = &risk
	assurance, err = assessIntent(r, m, digest("report"), digest("intent"))
	if err != nil || assurance.Invariants[0].Status != "counterexample-local" || !strings.Contains(assurance.Invariants[0].Tests[0].Replay, "--match-test") {
		t.Fatalf("local counterexample not replayable: %+v %v", assurance, err)
	}
	p := GatePolicy{Version: 1, MinimumSeverity: "High", Evidence: "slither-detected", RequireAssurance: true, MinimumInvariantSeverity: "High"}
	gate, err := evaluateGate(r, p, GateBaseline{Version: 1, Scope: r.Scope}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	applyAssuranceGate(&gate, assurance)
	if gate.Passed || gate.Blocked != 1 || gate.InvariantDecisions[0].Status != "counterexample-local" {
		t.Fatalf("counterexample escaped merge gate: %+v", gate)
	}
	r.Risk.Evidence[0].Claim = "risk-property"
	assurance, err = assessIntent(r, m, digest("report"), digest("intent"))
	if err != nil || assurance.Invariants[0].Status != "checked-local" {
		t.Fatalf("passing property mislabeled: %+v %v", assurance, err)
	}
	r.Risk.Evidence[0].SubjectSource = "Other.sol"
	r.Sources["Other.sol"] = Source{Content: "contract Other {}", SHA256: digest("contract Other {}")}
	if _, err := assessIntent(r, m, digest("report"), digest("intent")); err == nil {
		t.Fatal("test on another source was attributed to audited invariant")
	}
	m.Invariants[0].Sources = []string{"Missing.sol"}
	r.Risk = nil
	assurance, err = assessIntent(r, m, digest("report"), digest("intent"))
	if err != nil || assurance.Invariants[0].Status != "out-of-scope" {
		t.Fatalf("missing source was hidden: %+v %v", assurance, err)
	}
}

func TestIntentStrictValidationAndStandaloneAssurance(t *testing.T) {
	m := intentFixture()
	m.Invariants[0].Roles = []string{"administrator"}
	if err := validateIntent(m, m.Scope); err == nil {
		t.Fatal("unknown role reference accepted")
	}
	m = intentFixture()
	m.Invariants[0].Sources = []string{"../private.sol"}
	if err := validateIntent(m, m.Scope); err == nil {
		t.Fatal("traversal source path accepted")
	}
	m = intentFixture()
	dir := t.TempDir()
	r := Report{Version: 1, Scope: m.Scope, Sources: map[string]Source{"Vault.sol": {Content: "contract Vault {}", SHA256: digest("contract Vault {}")}}, Findings: []Finding{}}
	if err := saveReport(dir, r); err != nil {
		t.Fatal(err)
	}
	intentPath := filepath.Join(dir, "intent.json")
	b, _ := json.Marshal(m)
	if err := os.WriteFile(intentPath, b, 0600); err != nil {
		t.Fatal(err)
	}
	if err := assureCommand([]string{"--report", filepath.Join(dir, "report.json"), "--intent", intentPath}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var got AssuranceResult
	out, err := os.ReadFile(filepath.Join(dir, "assurance.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(out, &got); err != nil || got.Invariants[0].Status != "untested" || got.ReportSHA256 == "" {
		t.Fatalf("standalone assurance missing evidence: %+v %v", got, err)
	}
}
