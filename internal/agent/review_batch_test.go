package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestReviewRetriesIncompleteBatchWithoutAcceptingPartialResults(t *testing.T) {
	source := "contract Vault {}\n"
	r := Report{Version: 1, Scope: "owner/repo:contracts", Sources: map[string]Source{"Vault.sol": {Content: source, SHA256: digest(source)}}, Findings: []Finding{}}
	for i := 0; i < 8; i++ {
		r.Findings = append(r.Findings, Finding{ID: digest(fmt.Sprint(i)), Check: "example", Severity: "Medium", Description: "candidate"})
	}
	calls := 0
	runner := func(_ context.Context, _, _, _, prompt string) ([]byte, error) {
		calls++
		prefix := "UNTRUSTED AUDIT PAYLOAD:\n"
		idx := strings.LastIndex(prompt, prefix)
		if idx < 0 {
			t.Fatal("missing review payload")
		}
		var payload struct {
			Findings []Finding `json:"findings"`
		}
		if err := json.Unmarshal([]byte(prompt[idx+len(prefix):]), &payload); err != nil {
			t.Fatal(err)
		}
		count := len(payload.Findings)
		if count > 2 {
			count-- // Simulate the model omitting an item from a large batch.
		}
		out := struct {
			Reviews []Review `json:"reviews"`
		}{Reviews: []Review{}}
		for _, f := range payload.Findings[:count] {
			out.Reviews = append(out.Reviews, Review{ID: f.ID, Verdict: "needs-review", Reasoning: "context needed", ExploitScenario: "unknown", Remediation: "inspect", Validation: "test"})
		}
		return json.Marshal(out)
	}
	if err := reviewReportWithRunner(context.Background(), &r, "copilot", "copilot", "auto", runner); err != nil {
		t.Fatal(err)
	}
	if !r.Reviewed || calls < 5 {
		t.Fatalf("review was not retried in smaller batches: reviewed=%t calls=%d", r.Reviewed, calls)
	}
	for _, f := range r.Findings {
		if f.Review == nil || f.Review.ID != f.ID {
			t.Fatalf("finding lacks an exact review: %s", f.ID)
		}
	}
}
