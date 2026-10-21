package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestProjectSuiteRecordsUnmappedEvidenceAndFailsClosed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test helper uses /bin/sh")
	}
	root := t.TempDir()
	out := t.TempDir()
	source := "contract Vault {}\n"
	if err := os.WriteFile(filepath.Join(root, "Vault.sol"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	findings, err := parseSlither(fixture(root), "scope", root)
	if err != nil {
		t.Fatal(err)
	}
	r := Report{Version: 1, Scope: "scope", Findings: findings, Sources: map[string]Source{"Vault.sol": {SHA256: digest(source), Content: source}}}
	if err := saveReport(out, r); err != nil {
		t.Fatal(err)
	}
	command := func(script string) string {
		b, _ := json.Marshal([]string{"/bin/sh", "-c", script})
		return string(b)
	}
	run := func(cmd string) error {
		return Run(context.Background(), []string{"suite", "--report", filepath.Join(out, "report.json"), "--source-root", root, "--project", root, "--out", out, "--command-json", command(cmd)}, &strings.Builder{})
	}
	t.Setenv("SUITE_SHOULD_NOT_LEAK", "secret")
	if err := run(`test -z "$SUITE_SHOULD_NOT_LEAK" && echo suite-pass`); err != nil {
		t.Fatal(err)
	}
	after, err := loadReport(filepath.Join(out, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(after.ProjectTests) != 1 || after.ProjectTests[0].Status != "completed" || after.ProjectTests[0].ExitCode != 0 {
		t.Fatalf("missing project suite evidence: %+v", after.ProjectTests)
	}
	if after.Risk != nil || len(after.Findings) != 1 || after.Findings[0].EvidenceLayers[1].Stage != "dynamic-test" || after.Findings[0].EvidenceLayers[1].Status != "not-run" {
		t.Fatalf("project suite was promoted to finding-level risk: %+v", after.Findings)
	}
	log, err := os.ReadFile(filepath.Join(out, after.ProjectTests[0].LogFile))
	if err != nil || string(log) != "suite-pass\n" || after.ProjectTests[0].LogSHA256 != digest(string(log)) {
		t.Fatalf("incorrect log evidence: %q, %v", log, err)
	}
	if err := run("echo suite-fail; exit 7"); err == nil {
		t.Fatal("failed suite was accepted")
	}
	after, err = loadReport(filepath.Join(out, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(after.ProjectTests) != 2 || after.ProjectTests[1].Status != "failed" || after.ProjectTests[1].ExitCode != 7 {
		t.Fatalf("failed suite evidence lost: %+v", after.ProjectTests)
	}
	if err := run("echo changed > Vault.sol"); err == nil || !strings.Contains(err.Error(), "audited source changed") {
		t.Fatalf("post-run source drift not rejected: %v", err)
	}
	after, err = loadReport(filepath.Join(out, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(after.ProjectTests) != 3 || after.ProjectTests[2].Status != "error" {
		t.Fatalf("post-run source drift not recorded: %+v", after.ProjectTests)
	}
	if err := run("echo should-not-run"); err == nil || !strings.Contains(err.Error(), "audited source changed") {
		t.Fatalf("source drift not rejected: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "Vault.sol"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, after.ProjectTests[0].LogFile), []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := run("echo should-not-run"); err == nil || !strings.Contains(err.Error(), "prior project test log missing or changed") {
		t.Fatalf("prior log tampering not rejected: %v", err)
	}
}

func TestMochaSuiteRequiresPositiveUnambiguousResults(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test helper uses /bin/sh")
	}
	tests := []struct {
		name, output, status, resultError string
		passed, pending, failed           int
	}{
		{"passing", "  3 passing (2s)\n  1 pending\n", "passed", "", 3, 1, 0},
		{"ansi", "\033[32m  2 passing (40ms)\033[0m\n", "passed", "", 2, 0, 0},
		{"zero", "  0 passing (1ms)\n", "error", "Mocha ran zero passing tests", 0, 0, 0},
		{"missing", "all done\n", "error", "Mocha passing summary missing", 0, 0, 0},
		{"ambiguous", "  1 passing\n  2 passing\n", "error", "ambiguous Mocha passing summaries", 0, 0, 0},
		{"failing", "  2 passing\n  1 failing\n", "error", "Mocha reported failing tests", 2, 0, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root, out := t.TempDir(), t.TempDir()
			source := "contract Vault {}\n"
			if err := os.WriteFile(filepath.Join(root, "Vault.sol"), []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			findings, err := parseSlither(fixture(root), "scope", root)
			if err != nil {
				t.Fatal(err)
			}
			r := Report{Version: 1, Scope: "scope", Findings: findings, Sources: map[string]Source{"Vault.sol": {SHA256: digest(source), Content: source}}}
			if err := saveReport(out, r); err != nil {
				t.Fatal(err)
			}
			command, _ := json.Marshal([]string{"/bin/sh", "-c", "printf '%s' '" + tt.output + "'"})
			err = Run(context.Background(), []string{"suite", "--report", filepath.Join(out, "report.json"), "--source-root", root, "--project", root, "--out", out, "--result-format", "mocha-spec", "--command-json", string(command)}, &strings.Builder{})
			if (err == nil) != (tt.status == "passed") {
				t.Fatalf("unexpected command result: %v", err)
			}
			after, err := loadReport(filepath.Join(out, "report.json"))
			if err != nil {
				t.Fatal(err)
			}
			run := after.ProjectTests[0]
			if run.Status != tt.status || run.ResultError != tt.resultError || run.PassedTests != tt.passed || run.PendingTests != tt.pending || run.FailedTests != tt.failed {
				t.Fatalf("incorrect result evidence: %+v", run)
			}
		})
	}
}
