package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func fixture(root string) []byte {
	return []byte(fmt.Sprintf(`{"success":true,"error":null,"results":{"detectors":[{"check":"reentrancy-eth","impact":"High","confidence":"Medium","description":"withdraw (%s/Vault.sol#5) calls before updating balances","elements":[{"source_mapping":{"filename_relative":"Vault.sol","lines":[5,6]}}]}]}}`, root))
}

func TestSlitherValidationAndIdentity(t *testing.T) {
	a, err := parseSlither(fixture("/one"), "org/contracts", "/one")
	if err != nil {
		t.Fatal(err)
	}
	b, err := parseSlither(fixture("/two"), "org/contracts", "/two")
	if err != nil {
		t.Fatal(err)
	}
	if a[0].ID != b[0].ID {
		t.Fatal("identity should survive checkout relocation")
	}
	c, _ := parseSlither(fixture("/one"), "org/other", "/one")
	if c[0].ID == a[0].ID {
		t.Fatal("scope collision")
	}
	for _, bad := range []string{`{}`, `{"success":false,"error":"compile error"}`, `not json`, `{"success":true,"results":{"detectors":[{"check":"x","impact":"Critical"}]}}`} {
		if _, e := parseSlither([]byte(bad), "scope", "/tmp"); e == nil {
			t.Fatalf("accepted invalid analysis: %s", bad)
		}
	}
}

func TestSourceBundleBoundaries(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "Vault.sol"), []byte("contract Vault {}"), 0600)
	os.WriteFile(filepath.Join(root, ".env"), []byte("secret"), 0600)
	os.Mkdir(filepath.Join(root, "node_modules"), 0700)
	os.WriteFile(filepath.Join(root, "node_modules", "Ignored.sol"), []byte("ignore"), 0600)
	if err := os.Symlink(filepath.Join(root, ".env"), filepath.Join(root, "Secret.sol")); err != nil {
		t.Log("symlink test unavailable on this platform")
	}
	src, err := collectSources(root, root, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(src) != 1 || src["Vault.sol"].Content != "contract Vault {}" {
		t.Fatalf("unexpected source disclosure: %v", src)
	}
	if _, e := collectSources(root, root, 1); e == nil {
		t.Fatal("source cap did not fail")
	}
}

func TestAIReviewFailsClosed(t *testing.T) {
	fs, _ := parseSlither(fixture("/one"), "scope", "/one")
	r := Report{Findings: fs}
	v := Review{ID: fs[0].ID, Verdict: "needs-review", Reasoning: "source evidence", ExploitScenario: "requires attacker callback", Remediation: "update balance before call", Validation: "write reentrancy test"}
	b, _ := json.Marshal(map[string]any{"reviews": []Review{v}})
	if err := applyReviews(&r, b); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{[]byte(`{"reviews":[]}`), append(append([]byte(nil), b...), []byte(`{}`)...), []byte(`{"reviews":[],"extra":"x"}`)} {
		if e := applyReviews(&r, bad); e == nil {
			t.Fatal("accepted invalid response")
		}
	}
	v.ID = "invented"
	b, _ = json.Marshal(map[string]any{"reviews": []Review{v}})
	if e := applyReviews(&r, b); e == nil {
		t.Fatal("accepted hallucinated ID")
	}
}

func TestGitHubPublishDeduplicatesAndPreservesClosed(t *testing.T) {
	fs, _ := parseSlither(fixture("/one"), "org/contracts", "/one")
	r := Report{Scope: "org/contracts", Findings: fs}
	var stored *githubIssue
	creates, patches := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		if q.Header.Get("Authorization") != "Bearer test-token" {
			t.Error("missing auth")
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case q.URL.Path == "/repos/org/contracts":
			fmt.Fprint(w, `{"private":true}`)
		case q.URL.Path == "/repos/org/contracts/labels" && q.Method == "GET":
			fmt.Fprint(w, `[{"name":"security"},{"name":"slither-agent"},{"name":"severity:high"}]`)
		case q.URL.Path == "/repos/org/contracts/issues" && q.Method == "GET":
			if stored == nil {
				fmt.Fprint(w, `[]`)
			} else {
				json.NewEncoder(w).Encode([]githubIssue{*stored})
			}
		case q.URL.Path == "/repos/org/contracts/issues" && q.Method == "POST":
			creates++
			stored = &githubIssue{Number: 1, URL: "https://github.com/org/contracts/issues/1", State: "open"}
			json.NewDecoder(q.Body).Decode(stored)
			json.NewEncoder(w).Encode(stored)
		case q.URL.Path == "/repos/org/contracts/issues/1" && q.Method == "PATCH":
			patches++
			json.NewDecoder(q.Body).Decode(stored)
			json.NewEncoder(w).Encode(stored)
		case q.URL.Path == "/repos/org/contracts/issues/1/labels":
			fmt.Fprint(w, `[]`)
		default:
			t.Errorf("unexpected call: %s %s", q.Method, q.URL)
			http.Error(w, "unexpected", 500)
		}
	}))
	defer server.Close()
	c := githubClient{server.URL, "test-token", server.Client()}
	for i := 0; i < 2; i++ {
		if _, err := c.publish(context.Background(), "org/contracts", r, fs, false); err != nil {
			t.Fatal(err)
		}
	}
	if creates != 1 || patches != 0 {
		t.Fatalf("duplicate writes: create=%d patch=%d", creates, patches)
	}
	r.Revision = "changed"
	if _, e := c.publish(context.Background(), "org/contracts", r, fs, false); e != nil {
		t.Fatal(e)
	}
	if patches != 1 {
		t.Fatal("existing open issue was not updated")
	}
	stored.State = "closed"
	r.Revision = "changed-again"
	receipt, e := c.publish(context.Background(), "org/contracts", r, fs, false)
	if e != nil {
		t.Fatal(e)
	}
	if patches != 1 || receipt[0].Action != "closed-existing" {
		t.Fatal("closed issue changed")
	}
}

func TestPublicDestinationFailsBeforeWrites(t *testing.T) {
	writes := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		if q.Method != "GET" {
			writes++
		}
		fmt.Fprint(w, `{"private":false}`)
	}))
	defer server.Close()
	c := githubClient{server.URL, "test-token", server.Client()}
	_, err := c.publish(context.Background(), "org/public", Report{}, []Finding{}, false)
	if err == nil || !strings.Contains(err.Error(), "public") || writes != 0 {
		t.Fatal("public disclosure guard failed")
	}
}

func TestPublishLimitBeforeCredentials(t *testing.T) {
	fs, _ := parseSlither(fixture("/one"), "scope", "/one")
	other := fs[0]
	other.ID = digest("other")
	fs = append(fs, other)
	dir := t.TempDir()
	r := Report{Version: 1, Scope: "scope", Findings: fs}
	if err := saveReport(dir, r); err != nil {
		t.Fatal(err)
	}
	err := Run(context.Background(), []string{"publish", "--report", filepath.Join(dir, "report.json"), "--repo", "org/contracts", "--max-issues", "1", "--allow-unreviewed"}, &strings.Builder{})
	if err == nil || !strings.Contains(err.Error(), "exceed") {
		t.Fatalf("limit failed: %v", err)
	}
}

func TestPublishSelectionRequiresLikelyValidByDefault(t *testing.T) {
	base := Finding{ID: digest("valid"), Check: "ai-accounting", Severity: "High", Review: &Review{Verdict: "likely-valid"}}
	falsePositive := Finding{ID: digest("false"), Check: "ai-noise", Severity: "High", Review: &Review{Verdict: "likely-false-positive"}}
	uncertain := Finding{ID: digest("uncertain"), Check: "ai-uncertain", Severity: "High", Review: &Review{Verdict: "needs-review"}}
	r := Report{Reviewed: true, Findings: []Finding{base, falsePositive, uncertain}}
	selected, err := selectFindings(r, "Medium", "", "likely-valid")
	if err != nil || len(selected) != 1 || selected[0].ID != base.ID {
		t.Fatalf("default publish selected unvalidated candidates: %+v, %v", selected, err)
	}
	if _, err := selectFindings(r, "Medium", falsePositive.ID, "likely-valid"); err == nil {
		t.Fatal("explicit ID bypassed verdict filter")
	}
	selected, err = selectFindings(r, "Medium", uncertain.ID, "needs-review")
	if err != nil || len(selected) != 1 || selected[0].ID != uncertain.ID {
		t.Fatal("explicit needs-review selection failed")
	}
}

func TestToolEnvironmentUsesLocalCompilerCache(t *testing.T) {
	env := toolEnv(".slither-venv", "0.8.28")
	if !strings.Contains(strings.Join(env, "\n"), "VIRTUAL_ENV="+absolute(".slither-venv")) {
		t.Fatal("solc-select cache is not isolated")
	}
	if !strings.Contains(strings.Join(env, "\n"), "SOLC_VERSION=0.8.28") {
		t.Fatal("compiler not selected per invocation")
	}
}

func TestReviewerProcessUsesOnlyEvidenceAndRestrictedEnvironment(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mock process")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-copilot")
	code := `#!/usr/bin/env python3
import sys,os,json
assert '--available-tools=' in sys.argv
assert '--no-custom-instructions' in sys.argv
assert '--disable-builtin-mcps' in sys.argv
assert '--deny-tool=shell,write,read,url,memory' in sys.argv
assert 'PRIVATE_BUILD_SECRET' not in os.environ
assert os.environ['COPILOT_ALLOW_ALL']=='false'
assert os.environ['GH_TOKEN']=='fake-review-token'
assert os.getcwd()!=os.environ.get('ORIGINAL_DIR','')
payload=json.loads(sys.stdin.read().split('UNTRUSTED AUDIT PAYLOAD:\n',1)[1])
print('******'+json.dumps({'reviews':[{'id':f['id'],'verdict':'needs-review','reasoning':'Vault.sol line 5','exploit_scenario':'callback before write','remediation':'checks effects interactions','validation':'write attacker test'} for f in payload['findings']]}))
`
	if err := os.WriteFile(script, []byte(code), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PRIVATE_BUILD_SECRET", "must-not-disclose")
	t.Setenv("GH_TOKEN", "fake-review-token")
	fs, _ := parseSlither(fixture("/one"), "scope", "/one")
	r := Report{Scope: "scope", Findings: fs, Sources: map[string]Source{"Vault.sol": {Content: "contract Vault {}", SHA256: digest("contract Vault {}")}}}
	if err := reviewReport(context.Background(), &r, script, "auto"); err != nil {
		t.Fatal(err)
	}
	if !r.Reviewed || r.Findings[0].Review == nil {
		t.Fatal("review not retained")
	}
	t.Setenv("GH_TOKEN", "")
	t.Setenv("COPILOT_GITHUB_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "")
	gh := filepath.Join(dir, "gh")
	if err := os.WriteFile(gh, []byte("#!/bin/sh\nprintf 'fake-review-token\\n'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	if err := reviewReport(context.Background(), &r, script, "auto"); err != nil {
		t.Fatalf("existing gh login fallback failed: %v", err)
	}
}
