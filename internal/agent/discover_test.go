package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDiscoveryGroundsSourceAndInvalidatesReview(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mock process")
	}
	code := "contract Pool {\n    mapping(address => uint) public last;\n    function claim(address beneficiary) public { uint delta = last[msg.sender]; }\n}\n"
	r := Report{Version: 1, Scope: "example/pool", Reviewed: true, Model: "previous", Sources: map[string]Source{"Pool.sol": {Content: code, SHA256: digest(code)}}, Findings: []Finding{}}
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-copilot")
	mock := `#!/usr/bin/env python3
import sys, os, json
assert '--available-tools=' in sys.argv
assert 'PRIVATE_BUILD_SECRET' not in os.environ
payload=json.loads(sys.stdin.read().split('UNTRUSTED AUDIT PAYLOAD:\n',1)[1])
assert 'Pool.sol' in payload['sources']
print(json.dumps({'findings':[{'check':'reward-claim-key-mismatch','title':'Wrong claim key','severity':'High','description':'A fresh caller can repeat the claim','file':'Pool.sol','line':3,'source_excerpt':'function claim(address beneficiary) public { uint delta = last[msg.sender]; }','exploit_scenario':'use fresh callers','remediation':'key claim state by beneficiary','validation':'test repeat claim'}]}))
`
	if err := os.WriteFile(script, []byte(mock), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GH_TOKEN", "fake-review-token")
	t.Setenv("PRIVATE_BUILD_SECRET", "do-not-pass")
	if err := discoverReport(context.Background(), &r, script, "auto"); err != nil {
		t.Fatal(err)
	}
	if !r.Discovered || r.Reviewed || r.Model != "" || len(r.Findings) != 1 || r.Findings[0].Origin != "ai-discovery" {
		t.Fatalf("incorrect discovery state: %+v", r)
	}
	if err := saveReport(dir, r); err != nil {
		t.Fatal(err)
	}
	if _, err := loadReport(filepath.Join(dir, "report.json")); err != nil {
		t.Fatal(err)
	}
	bad := []byte(`{"findings":[{"check":"reward-claim-key-mismatch","title":"Wrong claim key","severity":"High","description":"repeat claim","file":"Pool.sol","line":3,"source_excerpt":"invented line","exploit_scenario":"fresh callers","remediation":"fix key","validation":"test"}]}`)
	if _, err := parseDiscoveries(r.Scope, r.Sources, nil, bad); err == nil {
		t.Fatal("accepted invented source line")
	}
	misnumbered := []byte(`{"findings":[{"check":"reward-claim-key-mismatch","title":"Wrong claim key","severity":"High","description":"repeat claim","file":"Pool.sol","line":2,"source_excerpt":"function claim(address beneficiary) public { uint delta = last[msg.sender]; }","exploit_scenario":"fresh callers","remediation":"fix key","validation":"test"}]}`)
	grounded, err := parseDiscoveries(r.Scope, r.Sources, nil, misnumbered)
	if err != nil || len(grounded) != 1 || grounded[0].Locations[0].Lines[0] != 3 {
		t.Fatalf("unique source excerpt was not normalized: %v", err)
	}
}

func TestDiscoverySkipsDetectorOverlapAndKeepsDistinctCandidate(t *testing.T) {
	code := "contract Pool {\n    mapping(address => uint) public last;\n    function claim(address beneficiary) public { uint delta = last[msg.sender]; }\n}\n"
	sources := map[string]Source{"Pool.sol": {Content: code, SHA256: digest(code)}}
	existing := []Finding{{Origin: "slither", Severity: "Medium", Locations: []Location{{File: "Pool.sol", Lines: []int{3}}}}}
	base := candidate{Check: "claim-key-mismatch", Title: "Claim key mismatch", Severity: "Medium", Description: "A claim may use the wrong key", File: "Pool.sol", Line: 3, SourceExcerpt: "function claim(address beneficiary) public { uint delta = last[msg.sender]; }", ExploitScenario: "A caller changes addresses", Remediation: "Use the intended key", Validation: "Test two callers"}
	distinct := base
	distinct.Check = "public-state-exposure"
	distinct.Line = 2
	distinct.SourceExcerpt = "mapping(address => uint) public last;"
	data, err := json.Marshal(struct {
		Findings []candidate `json:"findings"`
	}{[]candidate{base, distinct}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseDiscoveries("example/pool", sources, existing, data)
	if err != nil || len(got) != 1 || got[0].Check != "ai-public-state-exposure" {
		t.Fatalf("overlap should be skipped without dropping distinct candidate: %+v, %v", got, err)
	}
}
