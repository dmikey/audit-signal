package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type BenchmarkCase struct {
	Name      string `json:"name"`
	Report    string `json:"report"`
	Scope     string `json:"scope"`
	Target    string `json:"target"`
	Check     string `json:"check"`
	Expected  string `json:"expected"`
	RiskClaim string `json:"risk_claim,omitempty"`
}

type BenchmarkResult struct {
	Name      string `json:"name"`
	Expected  string `json:"expected"`
	Observed  bool   `json:"observed"`
	Passed    bool   `json:"passed"`
	RiskClaim string `json:"risk_claim,omitempty"`
}

type BenchmarkScore struct {
	Version int               `json:"version"`
	Passed  int               `json:"passed"`
	Total   int               `json:"total"`
	Results []BenchmarkResult `json:"results"`
}

func benchmarkCommand(args []string, w io.Writer) error {
	f := flags("benchmark", w)
	manifestPath := f.String("manifest", "examples/benchmark/manifest.json", "Labeled benchmark cases")
	out := f.String("out", "reports/benchmark-score.json", "Machine-readable score")
	expectedRevision := f.String("expected-revision", "", "Require every scan to match this Git commit")
	if err := parse(f, args); err != nil {
		return err
	}
	b, err := os.ReadFile(*manifestPath)
	if err != nil {
		return err
	}
	var manifest struct {
		Version int             `json:"version"`
		Cases   []BenchmarkCase `json:"cases"`
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&manifest); err != nil {
		return err
	}
	var extra any
	if dec.Decode(&extra) != io.EOF || manifest.Version != 1 || len(manifest.Cases) == 0 {
		return fmt.Errorf("benchmark requires version 1 and nonempty cases")
	}
	score := BenchmarkScore{Version: 1, Total: len(manifest.Cases), Results: []BenchmarkResult{}}
	seen := map[string]bool{}
	for _, c := range manifest.Cases {
		if c.Name == "" || seen[c.Name] || c.Scope == "" || c.Target == "" || c.Check == "" || (c.Expected != "present" && c.Expected != "absent") || c.Report == "" || filepath.IsAbs(c.Report) || !safeSourcePath(c.Report) {
			return fmt.Errorf("invalid benchmark case %q", c.Name)
		}
		seen[c.Name] = true
		path := filepath.Join(filepath.Dir(*manifestPath), filepath.FromSlash(c.Report))
		r, err := loadReport(path)
		if err != nil {
			return fmt.Errorf("benchmark case %s: %w", c.Name, err)
		}
		if r.Scope != c.Scope || filepath.Base(r.Target) != c.Target || (*expectedRevision != "" && r.Revision != *expectedRevision) {
			return fmt.Errorf("benchmark case %s has stale or wrong scope, target, or revision", c.Name)
		}
		if r.Imported || len(r.Sources) == 0 || r.Coverage == nil || r.Coverage.Status != "complete" {
			return fmt.Errorf("benchmark case %s requires a fresh complete Slither scan", c.Name)
		}
		observed := false
		for _, finding := range r.Findings {
			if finding.Check == c.Check {
				observed = true
				break
			}
		}
		if c.RiskClaim != "" {
			if c.RiskClaim != "risk-property" && c.RiskClaim != "exploit-reproduced" && c.RiskClaim != "mitigation-holds" {
				return fmt.Errorf("invalid benchmark risk claim")
			}
			matched := false
			if r.Risk != nil && r.Risk.Status == "passed" {
				for _, e := range r.Risk.Evidence {
					if e.Claim == c.RiskClaim && e.Status == "Success" {
						matched = true
						break
					}
				}
			}
			observed = observed && matched
		}
		passed := observed == (c.Expected == "present")
		if passed {
			score.Passed++
		}
		score.Results = append(score.Results, BenchmarkResult{Name: c.Name, Expected: c.Expected, Observed: observed, Passed: passed, RiskClaim: c.RiskClaim})
	}
	data, err := json.MarshalIndent(score, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0700); err != nil {
		return err
	}
	if err := os.WriteFile(*out, append(data, '\n'), 0600); err != nil {
		return err
	}
	fmt.Fprintf(w, "Benchmark: %d/%d labeled cases passed; score saved to %s\n", score.Passed, score.Total, *out)
	if score.Passed != score.Total {
		return fmt.Errorf("benchmark regression: %d/%d cases passed", score.Passed, score.Total)
	}
	return nil
}
