package agent

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestMappedHardhatAttackTestEvidence(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mock Hardhat runner")
	}
	for _, tc := range []struct {
		name, summary, wantStatus string
		exit                      int
	}{
		{"passed", "  1 passing (3ms)\n", "Success", 0},
		{"zero", "  0 passing (1ms)\n", "Error", 0},
		{"ambiguous-match", "  2 passing (1ms)\n", "Error", 0},
		{"failed", "  0 passing (1ms)\n  1 failing\n", "Failure", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, out := t.TempDir(), t.TempDir()
			project := filepath.Join(root, "contracts")
			if err := os.MkdirAll(filepath.Join(project, "test"), 0700); err != nil {
				t.Fatal(err)
			}
			source := "contract Vault {}\n"
			if err := os.WriteFile(filepath.Join(root, "Vault.sol"), []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(project, "test", "Attack.test.ts"), []byte("assert attack outcome"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(project, "hardhat.config.ts"), []byte("mocha: spec"), 0600); err != nil {
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
			plan := filepath.Join(root, "plan.json")
			if err := os.WriteFile(plan, []byte(`{"version":1,"cases":[{"check":"reentrancy-eth","suite":"test/Attack.test.ts","test":"Attack denies theft","claim":"risk-property","description":"Attack cannot take victim funds"}]}`), 0600); err != nil {
				t.Fatal(err)
			}
			runner := filepath.Join(project, "hardhat-mock")
			code := "#!/usr/bin/env python3\nimport sys\nif '--version' in sys.argv:\n print('Hardhat 2.28.6'); sys.exit(0)\nassert sys.argv[1:] == ['test','--network','hardhat','--grep','^Attack denies theft$','test/Attack.test.ts']\nprint(" + pythonQuote(tc.summary) + ", end='')\nsys.exit(" + string(rune('0'+tc.exit)) + ")\n"
			if err := os.WriteFile(runner, []byte(code), 0700); err != nil {
				t.Fatal(err)
			}
			err = Run(context.Background(), []string{"risk-mocha", "--report", filepath.Join(out, "report.json"), "--source-root", root, "--project", project, "--plan", plan, "--hardhat", runner, "--out", out}, &strings.Builder{})
			if (err == nil) != (tc.wantStatus == "Success") {
				t.Fatalf("unexpected outcome: %v", err)
			}
			after, err := loadReport(filepath.Join(out, "report.json"))
			if err != nil {
				t.Fatal(err)
			}
			if after.Risk == nil || after.Risk.Runner != "hardhat" || len(after.Risk.Evidence) != 1 || after.Risk.Evidence[0].Status != tc.wantStatus {
				t.Fatalf("wrong attack evidence: %+v", after.Risk)
			}
			e := after.Risk.Evidence[0]
			log, err := os.ReadFile(filepath.Join(out, e.LogFile))
			if err != nil || e.LogSHA256 != digest(string(log)) {
				t.Fatalf("missing or unhashed log: %v", err)
			}
			if after.Findings[0].EvidenceLayers[1].Tool != "hardhat" || after.Findings[0].EvidenceLayers[1].Status != tc.wantStatus {
				t.Fatalf("incorrect finding evidence: %+v", after.Findings[0].EvidenceLayers)
			}
		})
	}
}

func pythonQuote(s string) string {
	return "'" + strings.ReplaceAll(strings.ReplaceAll(s, "\\", "\\\\"), "\n", "\\n") + "'"
}
