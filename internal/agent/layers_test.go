package agent

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEvidenceLayersSeparateDetectionReviewAndExecutedTest(t *testing.T) {
	source := "uint256 missed = epoch - lastClaimEpoch[msg.sender];\n"
	static := Finding{ID: digest("static"), Check: "low-level-calls", Severity: "Informational", Confidence: "High", Description: "external call", Origin: "slither"}
	proposal := Finding{ID: digest("discovery"), Check: "ai-claim-checkpoint", Severity: "High", Confidence: "AI hypothesis", Description: "repeated claim", Origin: "ai-discovery", Locations: []Location{{File: "Pool.sol", Lines: []int{1}}}, Discovery: &DiscoveryEvidence{SourceExcerpt: strings.TrimSpace(source), ExploitScenario: "fresh callers", Remediation: "key by beneficiary", Validation: "repeat claim"}}
	for _, f := range []*Finding{&static, &proposal} {
		f.Review = &Review{ID: f.ID, Verdict: "likely-valid", Reasoning: "source evidence", ExploitScenario: "repeat claim", Remediation: "fix", Validation: "test"}
	}
	r := Report{Version: 1, Scope: "example/pool", SlitherVersion: "0.11.6", Discovered: true, DiscoveryModel: "gpt-5.6-sol", Reviewed: true, Model: "gpt-5.6-sol", Findings: []Finding{static, proposal}, Sources: map[string]Source{"Pool.sol": {Content: source, SHA256: digest(source)}}, Risk: &RiskRun{Status: "passed", Environment: "local-evm", ForgeVersion: "forge Version: 1.8.5\ncommit details", Evidence: []RiskEvidence{{RiskCase: RiskCase{File: "Pool.sol", Line: 1, Suite: "test/Pool.t.sol:PoolTest", Test: "testRepeatClaim()", Claim: "exploit-reproduced"}, FindingIDs: []string{proposal.ID}, Status: "Success"}}}}
	dir := t.TempDir()
	// An older report without the derived field can be rendered without running
	// Slither, Copilot, or Foundry again.
	old, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "report.json")
	if err := os.WriteFile(path, old, 0600); err != nil {
		t.Fatal(err)
	}
	if err := renderCommand([]string{"--report", path}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	got, err := loadReport(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Findings[0].EvidenceLayers) != 3 || got.Findings[0].EvidenceLayers[0].Tool != "slither" || got.Findings[0].EvidenceLayers[2].Status != "unmapped" {
		t.Fatalf("static finding provenance mixed with test outcome: %+v", got.Findings[0].EvidenceLayers)
	}
	layers := got.Findings[1].EvidenceLayers
	if len(layers) != 3 || layers[0].Stage != "discovery" || layers[0].Status != "candidate" || layers[1].Stage != "review" || layers[1].Status != "likely-valid" || layers[2].Stage != "dynamic-test" || layers[2].Status != "Success" || layers[2].Claim != "exploit-reproduced" || layers[2].Test != "testRepeatClaim()" {
		t.Fatalf("AI candidate, review, and test were conflated: %+v", layers)
	}
	md, err := os.ReadFile(filepath.Join(dir, "report.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"### Evidence layers", "**Detection:** `slither`", "**Discovery:** `copilot`", "**Review:** `copilot`", "**Dynamic testing:** `foundry`", "**Dynamic testing:** unmapped"} {
		if !strings.Contains(string(md), marker) {
			t.Fatalf("report missing %q", marker)
		}
	}
	got.Findings[1].EvidenceLayers[2].Status = "proven"
	tampered, _ := json.Marshal(got)
	if err := os.WriteFile(path, tampered, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadReport(path); err == nil {
		t.Fatal("accepted a forged layer status that contradicts executed evidence")
	}
	r.Imported = true
	if layer := findingEvidenceLayers(r, static)[0]; layer.Status != "imported" {
		t.Fatalf("imported detector output reported as a direct scan: %+v", layer)
	}
	r.Risk.Status = "error"
	r.Risk.Evidence = nil
	if layer := findingEvidenceLayers(r, proposal)[2]; layer.Status != "no-executed-evidence" {
		t.Fatalf("failed risk stage reported as an unmapped finding: %+v", layer)
	}
	r.Risk = nil
	if layer := findingEvidenceLayers(r, proposal)[2]; layer.Status != "not-run" {
		t.Fatalf("absent risk stage reported as executed: %+v", layer)
	}
}
