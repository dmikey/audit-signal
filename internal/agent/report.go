package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type Location struct {
	File  string `json:"file"`
	Lines []int  `json:"lines"`
}
type Finding struct {
	ID          string     `json:"id"`
	Check       string     `json:"check"`
	Severity    string     `json:"severity"`
	Confidence  string     `json:"confidence"`
	Description string     `json:"description"`
	Locations   []Location `json:"locations"`
	Origin      string     `json:"origin"`
	Review      *Review    `json:"review,omitempty"`
}
type Review struct {
	ID              string `json:"id"`
	Verdict         string `json:"verdict"`
	Reasoning       string `json:"reasoning"`
	ExploitScenario string `json:"exploit_scenario"`
	Remediation     string `json:"remediation"`
	Validation      string `json:"validation"`
}
type Source struct {
	SHA256  string `json:"sha256"`
	Content string `json:"content"`
}
type Report struct {
	Version        int               `json:"version"`
	Scope          string            `json:"scope"`
	Target         string            `json:"target"`
	Revision       string            `json:"revision,omitempty"`
	Dirty          bool              `json:"dirty"`
	Imported       bool              `json:"imported"`
	CreatedAt      string            `json:"created_at"`
	SlitherVersion string            `json:"slither_version"`
	Model          string            `json:"model,omitempty"`
	Reviewed       bool              `json:"reviewed"`
	Findings       []Finding         `json:"findings"`
	Sources        map[string]Source `json:"sources"`
	Risk           *RiskRun          `json:"risk,omitempty"`
}
type slitherOutput struct {
	Success *bool           `json:"success"`
	Error   json.RawMessage `json:"error"`
	Results struct {
		Detectors []struct {
			Check       string `json:"check"`
			Impact      string `json:"impact"`
			Confidence  string `json:"confidence"`
			Description string `json:"description"`
			Elements    []struct {
				SourceMapping struct {
					Relative string `json:"filename_relative"`
					Absolute string `json:"filename_absolute"`
					Lines    []int  `json:"lines"`
				} `json:"source_mapping"`
			} `json:"elements"`
		} `json:"detectors"`
	} `json:"results"`
}

func digest(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func parseSlither(data []byte, scope, root string) ([]Finding, error) {
	var shape map[string]json.RawMessage
	if err := json.Unmarshal(data, &shape); err != nil {
		return nil, fmt.Errorf("invalid Slither JSON: %w", err)
	}
	var resultShape map[string]json.RawMessage
	if err := json.Unmarshal(shape["results"], &resultShape); err != nil || resultShape["detectors"] == nil || string(resultShape["detectors"]) == "null" {
		return nil, fmt.Errorf("Slither JSON is missing detector results")
	}
	var out slitherOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("invalid Slither JSON: %w", err)
	}
	if out.Success == nil || !*out.Success {
		return nil, fmt.Errorf("Slither did not complete successfully; inspect slither.log")
	}
	findings := []Finding{}
	seen := map[string]bool{}
	for _, d := range out.Results.Detectors {
		if d.Check == "" || !validSeverity(d.Impact) || d.Confidence == "" || d.Description == "" {
			return nil, fmt.Errorf("malformed Slither detector")
		}
		f := Finding{Check: d.Check, Severity: d.Impact, Confidence: d.Confidence, Description: strings.ReplaceAll(d.Description, root+string(os.PathSeparator), ""), Origin: "slither", Locations: []Location{}}
		locSeen := map[string]bool{}
		for _, e := range d.Elements {
			name := e.SourceMapping.Relative
			if name == "" && e.SourceMapping.Absolute != "" {
				name, _ = filepath.Rel(root, e.SourceMapping.Absolute)
			}
			name = filepath.ToSlash(filepath.Clean(name))
			if name == "." || filepath.IsAbs(name) || name == ".." || strings.HasPrefix(name, "../") {
				continue
			}
			lines := append([]int(nil), e.SourceMapping.Lines...)
			sort.Ints(lines)
			for _, line := range lines {
				if line < 1 {
					return nil, fmt.Errorf("invalid source line")
				}
			}
			key := fmt.Sprintf("%s:%v", name, lines)
			if !locSeen[key] {
				f.Locations = append(f.Locations, Location{File: name, Lines: lines})
				locSeen[key] = true
			}
		}
		sort.Slice(f.Locations, func(i, j int) bool { return fmt.Sprint(f.Locations[i]) < fmt.Sprint(f.Locations[j]) })
		b, _ := json.Marshal(f.Locations)
		f.ID = digest(scope + "\x00" + f.Check + "\x00" + string(b) + "\x00" + f.Description)
		if !seen[f.ID] {
			findings = append(findings, f)
			seen[f.ID] = true
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		if rank(findings[i].Severity) != rank(findings[j].Severity) {
			return rank(findings[i].Severity) > rank(findings[j].Severity)
		}
		return findings[i].ID < findings[j].ID
	})
	return findings, nil
}

func rank(s string) int {
	return map[string]int{"High": 4, "Medium": 3, "Low": 2, "Informational": 1, "Optimization": 0}[s]
}
func validSeverity(s string) bool {
	_, ok := map[string]int{"High": 4, "Medium": 3, "Low": 2, "Informational": 1, "Optimization": 0}[s]
	return ok
}

// Only Solidity/Vyper source is sent to the reviewer. Symlinks are never followed.
func collectSources(root, target string, limit int) (map[string]Source, error) {
	sources := map[string]Source{}
	size := 0
	err := filepath.WalkDir(target, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if d.IsDir() {
			if path != target {
				switch d.Name() {
				case ".git", "node_modules", "lib", "out", "cache", "artifacts", ".slither-venv", ".solc-select", "reports":
					return filepath.SkipDir
				}
			}
			return nil
		}
		if filepath.Ext(path) != ".sol" && filepath.Ext(path) != ".vy" {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Size() > int64(limit-size) {
			return fmt.Errorf("source bundle exceeds %d bytes; narrow --target or raise --max-source-bytes", limit)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		size += len(b)
		name, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		sources[filepath.ToSlash(name)] = Source{SHA256: digest(string(b)), Content: string(b)}
		return nil
	})
	return sources, err
}

func saveReport(dir string, r Report) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(dir, "report.json"), append(b, '\n'), 0600); err != nil {
		return err
	}
	var md strings.Builder
	fmt.Fprintf(&md, "# Smart contract audit\n\nScope: `%s`\n\nRevision: `%s` (dirty: %t)\n\nSlither: `%s`; AI model: `%s`; AI reviewed: %t; imported: %t\n\nAutomated findings require human validation. Executed risk tests establish only recorded local harness outcomes, not production safety or a complete security audit. AI source coverage: %d files; dependency/vendor directories are excluded.\n\n%d findings\n\n", r.Scope, r.Revision, r.Dirty, r.SlitherVersion, r.Model, r.Reviewed, r.Imported, len(r.Sources), len(r.Findings))
	if r.Risk != nil {
		md.WriteString(riskMarkdown(r, ""))
	}
	for _, f := range r.Findings {
		md.WriteString(issueBody(r, f))
		md.WriteString("\n---\n\n")
	}
	return os.WriteFile(filepath.Join(dir, "report.md"), []byte(md.String()), 0600)
}

func loadReport(path string) (Report, error) {
	var r Report
	b, err := os.ReadFile(path)
	if err != nil {
		return r, err
	}
	if err = json.Unmarshal(b, &r); err != nil {
		return r, err
	}
	if r.Version != 1 || r.Scope == "" || r.Findings == nil {
		return r, fmt.Errorf("unsupported or incomplete report")
	}
	seen := map[string]bool{}
	for _, f := range r.Findings {
		if len(f.ID) != 64 || !validSeverity(f.Severity) || f.Check == "" || f.Description == "" || seen[f.ID] {
			return r, fmt.Errorf("invalid finding in report")
		}
		if _, err = hex.DecodeString(f.ID); err != nil {
			return r, fmt.Errorf("invalid finding ID")
		}
		seen[f.ID] = true
	}
	for name, src := range r.Sources {
		if digest(src.Content) != src.SHA256 {
			return r, fmt.Errorf("source digest mismatch: %s", name)
		}
	}
	if r.Reviewed {
		for _, f := range r.Findings {
			if f.Review == nil || f.Review.ID != f.ID || !validVerdict(f.Review.Verdict) || strings.TrimSpace(f.Review.Reasoning) == "" || strings.TrimSpace(f.Review.ExploitScenario) == "" || strings.TrimSpace(f.Review.Remediation) == "" || strings.TrimSpace(f.Review.Validation) == "" {
				return r, fmt.Errorf("incomplete AI review")
			}
		}
	}
	if r.Risk != nil {
		if r.Risk.Environment != "local-evm" || (r.Risk.Status != "passed" && r.Risk.Status != "failed" && r.Risk.Status != "error") {
			return r, fmt.Errorf("invalid risk evidence")
		}
		for _, e := range r.Risk.Evidence {
			for _, id := range e.FindingIDs {
				if !seen[id] {
					return r, fmt.Errorf("risk evidence refers to unknown finding")
				}
			}
		}
	}
	return r, nil
}

func issueBody(r Report, f Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "<!-- slither-agent:%s -->\n## %s\n\n**Severity:** %s · **Confidence:** %s · **Origin:** %s\n\n**Scope:** `%s` · **Revision:** `%s` · **Dirty:** %t · **Imported:** %t\n\n**Status:** automated candidate; requires human validation.\n\n### Detector evidence\n\n%s\n\n", f.ID, f.Check, f.Severity, f.Confidence, f.Origin, r.Scope, r.Revision, r.Dirty, r.Imported, f.Description)
	for _, l := range f.Locations {
		fmt.Fprintf(&b, "- `%s` lines %v\n", l.File, l.Lines)
	}
	if f.Review != nil {
		fmt.Fprintf(&b, "\n### AI review\n\nModel: `%s` · Verdict: **%s**\n\n%s\n\n### Exploit scenario\n\n%s\n\n### Remediation\n\n%s\n\n### Validation to perform\n\n%s\n", r.Model, f.Review.Verdict, f.Review.Reasoning, f.Review.ExploitScenario, f.Review.Remediation, f.Review.Validation)
	}
	b.WriteString(riskMarkdown(r, f.ID))
	fmt.Fprintf(&b, "\n[Slither detector documentation](https://github.com/crytic/slither/wiki/Detector-Documentation#%s)\n", f.Check)
	return b.String()
}
