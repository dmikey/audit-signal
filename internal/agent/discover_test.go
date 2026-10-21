package agent

import (
	"context"
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
}
