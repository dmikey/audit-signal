package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func coverageFixture(t *testing.T) (string, map[string]Source, []byte) {
	t.Helper()
	root := t.TempDir()
	for _, name := range []string{"A.sol", "B.sol"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("contract "+strings.TrimSuffix(name, ".sol")+" {}"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	sources, err := collectSources(root, root, 1000)
	if err != nil {
		t.Fatal(err)
	}
	units := map[string]any{}
	for _, name := range []string{"A.sol", "B.sol"} {
		units[name] = map[string]any{"ast": map[string]any{"nodeType": "SourceUnit"}, "contracts": map[string]any{strings.TrimSuffix(name, ".sol"): map[string]any{}}}
	}
	data, err := json.Marshal(map[string]any{"success": true, "results": map[string]any{"detectors": []any{}, "compilations": []any{map[string]any{"compilation_units": map[string]any{"unit-one": map[string]any{"compiler": map[string]any{"compiler": "solc", "version": "0.8.28"}, "filenames": []any{map[string]any{"relative": "A.sol", "absolute": filepath.Join(root, "A.sol")}, map[string]any{"relative": "B.sol", "absolute": filepath.Join(root, "B.sol")}}, "source_units": units}}}}}})
	if err != nil {
		t.Fatal(err)
	}
	return root, sources, data
}

func TestCoverageReceiptAndFailClosedGate(t *testing.T) {
	root, sources, data := coverageFixture(t)
	coverage, err := buildCoverage(data, root, root, sources, false)
	if err != nil || coverage.Status != "complete" || len(coverage.CompiledSources) != 2 || len(coverage.CompilationUnits) != 1 {
		t.Fatalf("complete compilation not recorded: %+v %v", coverage, err)
	}
	r := Report{Version: 1, Scope: "example/coverage", Sources: sources, Findings: []Finding{}, Coverage: coverage}
	if err := saveReport(root, r); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadReport(filepath.Join(root, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	loaded.Coverage.CompilationUnits[0].Sources = nil
	if err := saveReport(root, loaded); err != nil {
		t.Fatal(err)
	}
	if _, err := loadReport(filepath.Join(root, "report.json")); err == nil {
		t.Fatal("inconsistent complete-coverage receipt was accepted")
	}
	loaded.Coverage = coverage
	if err := saveReport(root, loaded); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "coverage.md")); err != nil {
		t.Fatal(err)
	}
	policy := GatePolicy{Version: 1, MinimumSeverity: "High", Evidence: "slither-detected", RequireCompleteScan: true}
	baseline := GateBaseline{Version: 1, Scope: r.Scope}
	gate, err := evaluateGate(loaded, policy, baseline, time.Now())
	if err != nil || !gate.Passed || gate.CoverageDecision == nil {
		t.Fatalf("complete scan blocked: %+v %v", gate, err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	results := raw["results"].(map[string]any)
	compilation := results["compilations"].([]any)[0].(map[string]any)
	unit := compilation["compilation_units"].(map[string]any)["unit-one"].(map[string]any)
	delete(unit["source_units"].(map[string]any), "B.sol")
	partial, _ := json.Marshal(raw)
	coverage, err = buildCoverage(partial, root, root, sources, false)
	if err != nil || coverage.Status != "incomplete" || !strings.Contains(strings.Join(coverage.Unresolved, " "), "B.sol") {
		t.Fatalf("missing compiled source not exposed: %+v %v", coverage, err)
	}
	r.Coverage = coverage
	gate, err = evaluateGate(r, policy, baseline, time.Now())
	if err != nil || gate.Passed || gate.CoverageDecision == nil || !gate.CoverageDecision.Blocked {
		t.Fatalf("partial scan passed gate: %+v %v", gate, err)
	}
	coverage, err = buildCoverage(data, root, root, sources, true)
	if err != nil || coverage.Status != "unavailable" {
		t.Fatalf("imported coverage mislabeled: %+v %v", coverage, err)
	}
	r.Coverage = coverage
	gate, err = evaluateGate(r, policy, baseline, time.Now())
	if err != nil || gate.Passed {
		t.Fatalf("imported scan passed complete-coverage gate: %+v %v", gate, err)
	}
}

func TestCoverageExclusionsRequireExplicitPolicy(t *testing.T) {
	root, sources, data := coverageFixture(t)
	if err := os.Mkdir(filepath.Join(root, "lib"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "lib", "Vendor.sol"), []byte("contract Vendor {}"), 0600); err != nil {
		t.Fatal(err)
	}
	coverage, err := buildCoverage(data, root, root, sources, false)
	if err != nil || len(coverage.Exclusions) != 1 || coverage.Exclusions[0].Path != "lib" {
		t.Fatalf("vendor exclusion missing: %+v %v", coverage, err)
	}
	r := Report{Version: 1, Scope: "example/coverage", Sources: sources, Findings: []Finding{}, Coverage: coverage}
	baseline := GateBaseline{Version: 1, Scope: r.Scope}
	policy := GatePolicy{Version: 1, MinimumSeverity: "High", Evidence: "slither-detected", RequireCompleteScan: true}
	gate, err := evaluateGate(r, policy, baseline, time.Now())
	if err != nil || gate.Passed || !strings.Contains(strings.Join(gate.CoverageDecision.Reasons, " "), "lib") {
		t.Fatalf("unapproved exclusion passed: %+v %v", gate, err)
	}
	policy.AllowedCoverageExclusions = []string{"lib"}
	gate, err = evaluateGate(r, policy, baseline, time.Now())
	if err != nil || !gate.Passed {
		t.Fatalf("reviewed exclusion did not pass: %+v %v", gate, err)
	}
}
