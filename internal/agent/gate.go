package agent

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// GatePolicy is deliberately small: a reviewer can see the entire merge rule
// in the caller repository. The evidence modes are alternatives, not an
// implication that an AI verdict or a detector hit proves an exploit.
type GatePolicy struct {
	Version                  int    `json:"version"`
	MinimumSeverity          string `json:"minimum_severity"`
	Evidence                 string `json:"evidence"`
	AllowImported            bool   `json:"allow_imported"`
	AllowDirty               bool   `json:"allow_dirty"`
	RequireAssurance         bool   `json:"require_assurance,omitempty"`
	MinimumInvariantSeverity string `json:"minimum_invariant_severity,omitempty"`
}

type GateAcceptance struct {
	FindingID string `json:"finding_id"`
	Owner     string `json:"owner"`
	Reason    string `json:"reason"`
	Expires   string `json:"expires"`
}

type GateBaseline struct {
	Version  int              `json:"version"`
	Scope    string           `json:"scope"`
	Accepted []GateAcceptance `json:"accepted"`
}

type GateDecision struct {
	FindingID string `json:"finding_id"`
	Check     string `json:"check"`
	Severity  string `json:"severity"`
	Status    string `json:"status"`
	Reason    string `json:"reason,omitempty"`
	Owner     string `json:"owner,omitempty"`
	Expires   string `json:"expires,omitempty"`
}

type GateResult struct {
	Version            int                     `json:"version"`
	Scope              string                  `json:"scope"`
	Revision           string                  `json:"revision,omitempty"`
	Policy             GatePolicy              `json:"policy"`
	Passed             bool                    `json:"passed"`
	Blocked            int                     `json:"blocked"`
	Accepted           int                     `json:"accepted"`
	NotActionable      int                     `json:"not_actionable"`
	Decisions          []GateDecision          `json:"decisions"`
	InvariantDecisions []GateInvariantDecision `json:"invariant_decisions,omitempty"`
	Assurance          *AssuranceResult        `json:"assurance,omitempty"`
}

type GateInvariantDecision struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Status   string `json:"status"`
	Blocked  bool   `json:"blocked"`
}

func readStrictJSON(path string, value any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(b) > 1024*1024 {
		return fmt.Errorf("%s exceeds 1 MiB", path)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(value); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("%s: unexpected trailing data", path)
	}
	return nil
}

func validateGatePolicy(p GatePolicy) error {
	if p.Version != 1 || !validSeverity(p.MinimumSeverity) {
		return fmt.Errorf("policy requires version 1 and a valid minimum_severity")
	}
	if p.RequireAssurance && !validSeverity(p.MinimumInvariantSeverity) {
		return fmt.Errorf("require_assurance needs a valid minimum_invariant_severity")
	}
	if !p.RequireAssurance && p.MinimumInvariantSeverity != "" {
		return fmt.Errorf("minimum_invariant_severity requires require_assurance")
	}
	switch p.Evidence {
	case "slither-detected", "ai-reviewed", "local-exploit-test":
		return nil
	default:
		return fmt.Errorf("policy evidence must be slither-detected, ai-reviewed, or local-exploit-test")
	}
}

func validateGateBaseline(b GateBaseline, scope string) error {
	if b.Version != 1 || b.Scope != scope {
		return fmt.Errorf("baseline version or scope does not match report")
	}
	seen := map[string]bool{}
	for _, a := range b.Accepted {
		if len(a.FindingID) != 64 || strings.ToLower(a.FindingID) != a.FindingID || strings.TrimSpace(a.Owner) == "" || strings.TrimSpace(a.Reason) == "" || seen[a.FindingID] {
			return fmt.Errorf("baseline has an invalid or duplicate acceptance")
		}
		if _, err := hex.DecodeString(a.FindingID); err != nil {
			return fmt.Errorf("baseline has an invalid finding ID")
		}
		if _, err := time.Parse("2006-01-02", a.Expires); err != nil {
			return fmt.Errorf("baseline acceptance %s needs an ISO expiry date", a.FindingID)
		}
		seen[a.FindingID] = true
	}
	return nil
}

func actionableEvidence(r Report, f Finding, mode string) bool {
	switch mode {
	case "slither-detected":
		return f.Origin == "slither" && !r.Imported
	case "ai-reviewed":
		return r.Reviewed && f.Review != nil && f.Review.Verdict == "likely-valid"
	case "local-exploit-test":
		if r.Risk == nil || r.Risk.Status != "passed" {
			return false
		}
		for _, layer := range findingEvidenceLayers(r, f) {
			if layer.Stage == "dynamic-test" && layer.Tool == "foundry" && layer.Status == "Success" && layer.Claim == "exploit-reproduced" {
				return true
			}
		}
	}
	return false
}

func evaluateGate(r Report, p GatePolicy, baseline GateBaseline, today time.Time) (GateResult, error) {
	result := GateResult{Version: 1, Scope: r.Scope, Revision: r.Revision, Policy: p, Passed: true, Decisions: []GateDecision{}}
	if err := validateGatePolicy(p); err != nil {
		return result, err
	}
	if err := validateGateBaseline(baseline, r.Scope); err != nil {
		return result, err
	}
	if r.Imported && !p.AllowImported {
		return result, fmt.Errorf("policy disallows imported analysis")
	}
	if r.Dirty && !p.AllowDirty {
		return result, fmt.Errorf("policy disallows a dirty source checkout")
	}
	if p.Evidence == "ai-reviewed" && !r.Reviewed {
		return result, fmt.Errorf("policy requires completed AI review")
	}
	if p.Evidence == "local-exploit-test" && (r.Risk == nil || r.Risk.Status != "passed") {
		return result, fmt.Errorf("policy requires a successful local risk stage")
	}
	accepted := map[string]GateAcceptance{}
	for _, a := range baseline.Accepted {
		accepted[a.FindingID] = a
	}
	for _, f := range r.Findings {
		d := GateDecision{FindingID: f.ID, Check: f.Check, Severity: f.Severity}
		if rank(f.Severity) < rank(p.MinimumSeverity) {
			d.Status = "not-actionable"
			d.Reason = "below severity threshold"
			result.NotActionable++
		} else if !actionableEvidence(r, f, p.Evidence) {
			d.Status = "not-actionable"
			d.Reason = "required evidence absent"
			result.NotActionable++
		} else if a, ok := accepted[f.ID]; ok {
			d.Owner, d.Reason, d.Expires = a.Owner, a.Reason, a.Expires
			expiry, _ := time.Parse("2006-01-02", a.Expires)
			if expiry.Before(today.UTC().Truncate(24 * time.Hour)) {
				d.Status = "expired-acceptance"
				result.Blocked++
			} else {
				d.Status = "accepted"
				result.Accepted++
			}
		} else {
			d.Status = "new-finding"
			result.Blocked++
		}
		result.Decisions = append(result.Decisions, d)
	}
	sort.Slice(result.Decisions, func(i, j int) bool { return result.Decisions[i].FindingID < result.Decisions[j].FindingID })
	result.Passed = result.Blocked == 0
	return result, nil
}

func applyAssuranceGate(result *GateResult, assurance AssuranceResult) {
	result.Assurance = &assurance
	for _, invariant := range assurance.Invariants {
		decision := GateInvariantDecision{ID: invariant.ID, Severity: invariant.Severity, Status: invariant.Status}
		if result.Policy.RequireAssurance && rank(invariant.Severity) >= rank(result.Policy.MinimumInvariantSeverity) && invariant.Status != "checked-local" {
			decision.Blocked = true
			result.Blocked++
		}
		result.InvariantDecisions = append(result.InvariantDecisions, decision)
	}
	result.Passed = result.Blocked == 0
}

func saveGateResult(dir string, result GateResult) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "gate.json"), append(b, '\n'), 0600); err != nil {
		return err
	}
	var md strings.Builder
	fmt.Fprintf(&md, "# Audit Signal policy gate\n\nScope: `%s` · Revision: `%s`\n\nResult: **%s** · Blocked: %d · Accepted: %d · Not actionable under policy: %d\n\nPolicy: severity **%s** or higher; evidence **%s**.\n\n", result.Scope, result.Revision, map[bool]string{true: "pass", false: "fail"}[result.Passed], result.Blocked, result.Accepted, result.NotActionable, result.Policy.MinimumSeverity, result.Policy.Evidence)
	for _, d := range result.Decisions {
		fmt.Fprintf(&md, "- `%s` %s (%s): **%s**", d.FindingID, d.Check, d.Severity, d.Status)
		if d.Owner != "" {
			fmt.Fprintf(&md, "; owner: %s; expires: %s; reason: %s", d.Owner, d.Expires, d.Reason)
		}
		md.WriteByte('\n')
	}
	if len(result.InvariantDecisions) > 0 {
		md.WriteString("\n## Protocol invariants\n\n")
		for _, d := range result.InvariantDecisions {
			fmt.Fprintf(&md, "- `%s` (%s): **%s**; blocked: %t\n", d.ID, d.Severity, d.Status, d.Blocked)
		}
	}
	return os.WriteFile(filepath.Join(dir, "gate.md"), []byte(md.String()), 0600)
}

func gateCommand(args []string, w io.Writer) error {
	f := flags("gate", w)
	reportPath := f.String("report", "reports/report.json", "Audit report JSON")
	policyPath := f.String("policy", "", "Versioned policy JSON in the caller repository (required)")
	baselinePath := f.String("baseline", "", "Optional accepted-finding baseline JSON")
	intentPath := f.String("intent", "", "Reviewed protocol intent JSON for assurance evaluation")
	expectedRevision := f.String("expected-revision", "", "Expected audited Git revision; fail on stale reports")
	out := f.String("out", "", "Output directory; defaults to report directory")
	if err := parse(f, args); err != nil {
		return err
	}
	if *policyPath == "" {
		return fmt.Errorf("gate requires --policy")
	}
	r, err := loadReport(*reportPath)
	if err != nil {
		return err
	}
	if *expectedRevision != "" && r.Revision != *expectedRevision {
		return fmt.Errorf("report revision %q does not match expected revision %q", r.Revision, *expectedRevision)
	}
	var policy GatePolicy
	if err := readStrictJSON(*policyPath, &policy); err != nil {
		return err
	}
	baseline := GateBaseline{Version: 1, Scope: r.Scope, Accepted: []GateAcceptance{}}
	if *baselinePath != "" {
		if err := readStrictJSON(*baselinePath, &baseline); err != nil {
			return err
		}
	}
	result, err := evaluateGate(r, policy, baseline, time.Now().UTC())
	if err != nil {
		return err
	}
	if policy.RequireAssurance && *intentPath == "" {
		return fmt.Errorf("policy requires --intent for protocol assurance")
	}
	dir := *out
	if dir == "" {
		dir = filepath.Dir(*reportPath)
	}
	if *intentPath != "" {
		reportData, err := os.ReadFile(*reportPath)
		if err != nil {
			return err
		}
		manifest, intentHash, err := readIntent(*intentPath, r.Scope)
		if err != nil {
			return err
		}
		assurance, err := assessIntent(r, manifest, digest(string(reportData)), intentHash)
		if err != nil {
			return err
		}
		if err := saveAssurance(dir, assurance); err != nil {
			return err
		}
		applyAssuranceGate(&result, assurance)
	}
	if err := saveGateResult(dir, result); err != nil {
		return err
	}
	fmt.Fprintf(w, "Policy gate: %d blocked, %d accepted, %d not actionable. Results: %s\n", result.Blocked, result.Accepted, result.NotActionable, filepath.Join(dir, "gate.json"))
	if !result.Passed {
		return fmt.Errorf("policy gate blocked %d finding(s) or invariant(s)", result.Blocked)
	}
	return nil
}
