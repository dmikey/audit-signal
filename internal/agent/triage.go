package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// Triage is a human-owned publication decision bound to the audited source set.
// AI verdicts and local test outcomes remain separate evidence in the report.
type Triage struct {
	Version         int              `json:"version"`
	Scope           string           `json:"scope"`
	SourceSetSHA256 string           `json:"source_set_sha256"`
	MinSeverity     string           `json:"min_severity"`
	Decisions       []TriageDecision `json:"decisions"`
}

type TriageDecision struct {
	FindingID   string `json:"finding_id"`
	Disposition string `json:"disposition"`
	Owner       string `json:"owner"`
	Reason      string `json:"reason"`
}

func sourceSetDigest(r Report) string {
	names := make([]string, 0, len(r.Sources))
	for name := range r.Sources {
		names = append(names, name)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, name := range names {
		fmt.Fprintf(&b, "%s\x00%s\n", name, r.Sources[name].SHA256)
	}
	return digest(b.String())
}

func triageCommand(args []string, w io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("triage requires init or check")
	}
	f := flags("triage "+args[0], w)
	reportPath := f.String("report", "reports/report.json", "Reviewed audit report")
	file := f.String("file", "triage.json", "Triage decision file")
	min := f.String("min-severity", "Medium", "Minimum severity requiring a decision (init only)")
	if err := parse(f, args[1:]); err != nil {
		return err
	}
	r, err := loadReport(*reportPath)
	if err != nil {
		return err
	}
	switch args[0] {
	case "init":
		if !validSeverity(*min) {
			return fmt.Errorf("invalid triage minimum severity")
		}
		t := Triage{Version: 1, Scope: r.Scope, SourceSetSHA256: sourceSetDigest(r), MinSeverity: *min, Decisions: []TriageDecision{}}
		for _, finding := range r.Findings {
			if rank(finding.Severity) >= rank(*min) {
				t.Decisions = append(t.Decisions, TriageDecision{FindingID: finding.ID, Disposition: "pending"})
			}
		}
		b, err := json.MarshalIndent(t, "", "  ")
		if err != nil {
			return err
		}
		out, err := os.OpenFile(*file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		_, writeErr := out.Write(append(b, '\n'))
		closeErr := out.Close()
		if writeErr != nil {
			return writeErr
		}
		if closeErr != nil {
			return closeErr
		}
		fmt.Fprintf(w, "Created %s with %d pending decisions.\n", *file, len(t.Decisions))
		return nil
	case "check":
		t, err := loadTriage(*file)
		if err != nil {
			return err
		}
		if err := validateTriage(r, t); err != nil {
			return err
		}
		publish := 0
		for _, d := range t.Decisions {
			if d.Disposition == "publish" {
				publish++
			}
		}
		fmt.Fprintf(w, "Triage complete: %d decisions, %d approved for publication; source set %s.\n", len(t.Decisions), publish, t.SourceSetSHA256)
		return nil
	default:
		return fmt.Errorf("unknown triage operation %q", args[0])
	}
}

func loadTriage(path string) (Triage, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Triage{}, err
	}
	var t Triage
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&t); err != nil {
		return Triage{}, err
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return Triage{}, fmt.Errorf("trailing triage data")
	}
	return t, nil
}

func validateTriage(r Report, t Triage) error {
	if t.Version != 1 || t.Scope != r.Scope || !validSeverity(t.MinSeverity) || t.SourceSetSHA256 != sourceSetDigest(r) {
		return fmt.Errorf("triage version, scope, severity, or audited source set differs from report; rerun triage")
	}
	findings := map[string]Finding{}
	for _, f := range r.Findings {
		findings[f.ID] = f
	}
	seen := map[string]bool{}
	for _, d := range t.Decisions {
		f, ok := findings[d.FindingID]
		if !ok || seen[d.FindingID] || rank(f.Severity) < rank(t.MinSeverity) {
			return fmt.Errorf("unknown, duplicate, or out-of-scope triage finding %s", d.FindingID)
		}
		seen[d.FindingID] = true
		if (d.Disposition != "hold" && d.Disposition != "publish") || strings.TrimSpace(d.Owner) == "" || strings.TrimSpace(d.Reason) == "" {
			return fmt.Errorf("finding %s requires hold/publish, owner, and reason", d.FindingID)
		}
		if d.Disposition == "publish" && (!r.Reviewed || f.Review == nil || f.Review.Verdict != "likely-valid") {
			return fmt.Errorf("finding %s cannot be published without a likely-valid AI review", d.FindingID)
		}
	}
	for _, f := range r.Findings {
		if rank(f.Severity) >= rank(t.MinSeverity) && !seen[f.ID] {
			return fmt.Errorf("finding %s has no triage decision", f.ID)
		}
	}
	return nil
}
