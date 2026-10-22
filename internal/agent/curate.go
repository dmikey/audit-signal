package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Curated findings are previously reviewed source-level hypotheses that a
// maintainer explicitly retains. They are re-checked against the current source
// and re-reviewed on every run; the manifest never carries an AI verdict.
type curatedManifest struct {
	Version         int              `json:"version"`
	Scope           string           `json:"scope"`
	SourceSetSHA256 string           `json:"source_set_sha256"`
	Findings        []curatedFinding `json:"findings"`
}

type curatedFinding struct {
	ID              string `json:"id"`
	Check           string `json:"check"`
	Severity        string `json:"severity"`
	Description     string `json:"description"`
	File            string `json:"file"`
	Line            int    `json:"line"`
	SourceExcerpt   string `json:"source_excerpt"`
	ExploitScenario string `json:"exploit_scenario"`
	Remediation     string `json:"remediation"`
	Validation      string `json:"validation"`
}

func curateCommand(args []string, w io.Writer) error {
	f := flags("curate", w)
	reportPath := f.String("report", "reports/report.json", "Fresh Slither report")
	manifestPath := f.String("file", "curated-findings.json", "Source-bound findings manifest")
	out := f.String("out", "reports", "Output directory")
	if err := parse(f, args); err != nil {
		return err
	}
	r, err := loadReport(*reportPath)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(*manifestPath)
	if err != nil {
		return err
	}
	if err := applyCuratedFindings(&r, data); err != nil {
		return err
	}
	if err := saveReport(*out, r); err != nil {
		return err
	}
	fmt.Fprintf(w, "Retained %d source-verified findings; saved to %s\n", len(r.Findings), *out)
	return nil
}

func applyCuratedFindings(r *Report, data []byte) error {
	if len(data) > 1024*1024 {
		return fmt.Errorf("curated findings manifest exceeds 1 MB")
	}
	if r.Reviewed || r.Risk != nil || r.Discovered {
		return fmt.Errorf("curate requires a fresh pre-test, pre-review report")
	}
	var manifest curatedManifest
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&manifest); err != nil {
		return fmt.Errorf("invalid curated findings manifest: %w", err)
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return fmt.Errorf("trailing curated findings data")
	}
	if manifest.Version != 1 || manifest.Scope != r.Scope || manifest.SourceSetSHA256 != sourceSetDigest(*r) || len(manifest.Findings) == 0 {
		return fmt.Errorf("curated findings version, scope, source set, or entries differ from report")
	}
	existing := make(map[string]bool, len(r.Findings))
	for _, f := range r.Findings {
		existing[f.ID] = true
	}
	for _, c := range manifest.Findings {
		if !strings.HasPrefix(c.Check, "ai-") || !discoveryCheck.MatchString(strings.TrimPrefix(c.Check, "ai-")) || !validSeverity(c.Severity) || c.Severity == "Optimization" || strings.TrimSpace(c.Description) == "" || strings.TrimSpace(c.ExploitScenario) == "" || strings.TrimSpace(c.Remediation) == "" || strings.TrimSpace(c.Validation) == "" {
			return fmt.Errorf("invalid curated finding %s", c.ID)
		}
		if len(c.Description)+len(c.ExploitScenario)+len(c.Remediation)+len(c.Validation) > 16000 || filepath.IsAbs(c.File) || c.File != filepath.ToSlash(filepath.Clean(c.File)) || c.File == ".." || strings.HasPrefix(c.File, "../") {
			return fmt.Errorf("unsafe curated finding %s", c.ID)
		}
		src, ok := r.Sources[c.File]
		if !ok || digest(src.Content) != src.SHA256 {
			return fmt.Errorf("curated source missing or changed: %s", c.File)
		}
		lines := strings.Split(src.Content, "\n")
		excerpt := strings.TrimSpace(c.SourceExcerpt)
		if c.Line < 1 || c.Line > len(lines) || excerpt == "" || strings.TrimSpace(lines[c.Line-1]) != excerpt {
			return fmt.Errorf("curated source excerpt differs: %s:%d", c.File, c.Line)
		}
		id := digest(r.Scope + "\x00" + c.Check + "\x00" + c.File + "\x00" + fmt.Sprint(c.Line) + "\x00" + excerpt)
		if c.ID != id || existing[id] {
			return fmt.Errorf("curated finding ID differs or is duplicated: %s", c.ID)
		}
		existing[id] = true
		r.Findings = append(r.Findings, Finding{
			ID: id, Check: c.Check, Severity: c.Severity, Confidence: "curated hypothesis",
			Description: c.Description, Locations: []Location{{File: c.File, Lines: []int{c.Line}}},
			Origin: "curated-discovery", Discovery: &DiscoveryEvidence{
				SourceExcerpt: excerpt, ExploitScenario: c.ExploitScenario,
				Remediation: c.Remediation, Validation: c.Validation,
			},
		})
	}
	sort.Slice(r.Findings, func(i, j int) bool {
		if rank(r.Findings[i].Severity) != rank(r.Findings[j].Severity) {
			return rank(r.Findings[i].Severity) > rank(r.Findings[j].Severity)
		}
		return r.Findings[i].ID < r.Findings[j].ID
	})
	return nil
}
