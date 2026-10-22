package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTriageBindsEveryFindingToAuditedSources(t *testing.T) {
	valid := Finding{ID: digest("valid"), Severity: "High", Review: &Review{Verdict: "likely-valid"}}
	uncertain := Finding{ID: digest("uncertain"), Severity: "Medium", Review: &Review{Verdict: "needs-review"}}
	r := Report{Scope: "owner/repo:contracts", Reviewed: true, Sources: map[string]Source{"Vault.sol": {SHA256: digest("source")}}, Findings: []Finding{valid, uncertain}}
	tg := Triage{Version: 1, Scope: r.Scope, SourceSetSHA256: sourceSetDigest(r), MinSeverity: "Medium", Decisions: []TriageDecision{
		{FindingID: valid.ID, Disposition: "publish", Owner: "security-team", Reason: "Reproduced locally and reviewed"},
		{FindingID: uncertain.ID, Disposition: "hold", Owner: "security-team", Reason: "Needs dependency source"},
	}}
	if err := validateTriage(r, tg); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*Report, *Triage)
	}{
		{"changed source", func(r *Report, _ *Triage) { r.Sources["Vault.sol"] = Source{SHA256: digest("changed")} }},
		{"missing finding", func(_ *Report, tg *Triage) { tg.Decisions = tg.Decisions[:1] }},
		{"duplicate finding", func(_ *Report, tg *Triage) { tg.Decisions[1].FindingID = tg.Decisions[0].FindingID }},
		{"uncertain publication", func(_ *Report, tg *Triage) { tg.Decisions[1].Disposition = "publish" }},
		{"missing owner", func(_ *Report, tg *Triage) { tg.Decisions[0].Owner = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copyReport, copyTriage := r, tg
			copyReport.Sources = map[string]Source{"Vault.sol": r.Sources["Vault.sol"]}
			copyTriage.Decisions = append([]TriageDecision(nil), tg.Decisions...)
			tc.change(&copyReport, &copyTriage)
			if err := validateTriage(copyReport, copyTriage); err == nil {
				t.Fatal("accepted invalid triage")
			}
		})
	}
}

func TestTriagePreservesAbsentHoldsButRequiresCurrentDecisions(t *testing.T) {
	current := Finding{ID: digest("current"), Severity: "High", Review: &Review{Verdict: "likely-valid"}}
	r := Report{Scope: "owner/repo:contracts", Reviewed: true, Sources: map[string]Source{"Vault.sol": {SHA256: digest("source")}}, Findings: []Finding{current}}
	absentID := digest("nondeterministic-discovery")
	tg := Triage{Version: 1, Scope: r.Scope, SourceSetSHA256: sourceSetDigest(r), MinSeverity: "Medium", Decisions: []TriageDecision{
		{FindingID: current.ID, Disposition: "publish", Owner: "security-team", Reason: "Reviewed and reproduced"},
		{FindingID: absentID, Disposition: "hold", Owner: "security-team", Reason: "Gas-limit test needed"},
	}}
	if err := validateTriage(r, tg); err != nil {
		t.Fatalf("an absent hold must survive model nondeterminism: %v", err)
	}
	copyTriage := tg
	copyTriage.Decisions = append([]TriageDecision(nil), tg.Decisions...)
	copyTriage.Decisions[1].Disposition = "publish"
	if err := validateTriage(r, copyTriage); err == nil {
		t.Fatal("approved absent finding")
	}
	copyTriage.Decisions[1].Disposition = "hold"
	copyTriage.Decisions[1].FindingID = "not-a-finding-id"
	if err := validateTriage(r, copyTriage); err == nil {
		t.Fatal("accepted malformed absent finding ID")
	}
	tg.Decisions = tg.Decisions[1:]
	if err := validateTriage(r, tg); err == nil {
		t.Fatal("accepted current finding without a decision")
	}
}

func TestTriageInitDoesNotOverwriteAndCheckRequiresDecisions(t *testing.T) {
	dir := t.TempDir()
	r := Report{Version: 1, Scope: "owner/repo:contracts", Sources: map[string]Source{"A.sol": {SHA256: digest("A"), Content: "A"}}, Findings: []Finding{{ID: digest("f"), Check: "reentrancy-eth", Severity: "High", Description: "test finding"}}}
	if err := saveReport(dir, r); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "triage.json")
	args := []string{"triage", "init", "--report", filepath.Join(dir, "report.json"), "--file", file}
	if err := Run(context.Background(), args, &strings.Builder{}); err != nil {
		t.Fatal(err)
	}
	if err := Run(context.Background(), args, &strings.Builder{}); err == nil {
		t.Fatal("overwrote existing human decisions")
	}
	if err := Run(context.Background(), []string{"triage", "check", "--report", filepath.Join(dir, "report.json"), "--file", file}, &strings.Builder{}); err == nil {
		t.Fatal("pending decision passed")
	}
	info, err := os.Stat(file)
	if err != nil || info.Mode().Perm()&0077 != 0 {
		t.Fatalf("triage file permissions: %v %v", info, err)
	}
}
