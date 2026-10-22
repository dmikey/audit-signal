package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadReportRejectsTamperedRetainedCandidate(t *testing.T) {
	content := "contract Vault {\n    uint balance;\n    function withdraw() external {}\n}\n"
	excerpt := "function withdraw() external {}"
	scope, file, check := "owner/repo:contracts", "Vault.sol", "ai-withdraw-check"
	f := Finding{
		ID:    digest(scope + "\x00" + check + "\x00" + file + "\x003\x00" + excerpt),
		Check: check, Severity: "Medium", Confidence: "AI hypothesis", Description: "candidate",
		Origin: "curated-discovery", Locations: []Location{{File: file, Lines: []int{3}}},
		Discovery: &DiscoveryEvidence{SourceExcerpt: excerpt, ExploitScenario: "withdraw", Remediation: "guard", Validation: "test"},
	}
	r := Report{Version: 1, Scope: scope, Findings: []Finding{f}, Sources: map[string]Source{file: {Content: content, SHA256: digest(content)}}}
	dir := t.TempDir()
	write := func(report Report) string {
		t.Helper()
		path := filepath.Join(dir, "report.json")
		data, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	path := write(r)
	if _, err := loadReport(path); err != nil {
		t.Fatalf("valid retained candidate rejected: %v", err)
	}

	wrongLine := r
	wrongLine.Findings = []Finding{f}
	wrongLine.Findings[0].Locations = []Location{{File: file, Lines: []int{2}}}
	if _, err := loadReport(write(wrongLine)); err == nil {
		t.Fatal("accepted forged source line")
	}
	wrongID := r
	wrongID.Findings = []Finding{f}
	wrongID.Findings[0].ID = digest("forged")
	if _, err := loadReport(write(wrongID)); err == nil {
		t.Fatal("accepted forged finding ID")
	}
	wrongExcerpt := r
	wrongExcerpt.Findings = []Finding{f}
	wrongExcerpt.Findings[0].Discovery = &DiscoveryEvidence{SourceExcerpt: "balance", ExploitScenario: "withdraw", Remediation: "guard", Validation: "test"}
	if _, err := loadReport(write(wrongExcerpt)); err == nil {
		t.Fatal("accepted forged source excerpt")
	}
}

func TestRetainedCandidateIssueBodySeparatesProvenanceAndLocalTest(t *testing.T) {
	id := digest("candidate")
	f := Finding{ID: id, Check: "ai-candidate", Severity: "Medium", Confidence: "AI hypothesis", Description: "candidate", Origin: "curated-discovery", Discovery: &DiscoveryEvidence{SourceExcerpt: "revert Exists(id);", ExploitScenario: "reserve id", Remediation: "scope id", Validation: "test"}}
	r := Report{Scope: "owner/repo:contracts", DiscoveryModel: "auto", Model: "gpt-5.6-sol", Findings: []Finding{f}, Risk: &RiskRun{Status: "passed", Evidence: []RiskEvidence{{RiskCase: RiskCase{Claim: "exploit-reproduced"}, FindingIDs: []string{id}, Status: "Success"}}}}
	body := issueBody(r, f)
	for _, want := range []string{"Retained from a source-bound manifest", "local exploit behavior reproduced; deployment impact requires validation"} {
		if !strings.Contains(body, want) {
			t.Fatalf("issue body missing %q", want)
		}
	}
	if strings.Contains(body, "**Discovery model:** `auto`") {
		t.Fatal("retained candidate falsely attributed to current discovery model")
	}
	r.Risk.Status = "failed"
	if strings.Contains(issueBody(r, f), "local exploit behavior reproduced") {
		t.Fatal("failed risk run promoted to reproduced exploit")
	}
	r.Risk.Status = "passed"
	r.Risk.Evidence[0].FindingIDs = []string{digest("unrelated")}
	if strings.Contains(issueBody(r, f), "local exploit behavior reproduced") {
		t.Fatal("unrelated test promoted to this finding")
	}
}
