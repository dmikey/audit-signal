package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var intentIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,63}$`)
var solidityNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func validIntentID(id string) bool { return intentIDPattern.MatchString(id) }

func safeSourcePath(name string) bool {
	return name != "" && name != "." && !strings.ContainsAny(name, "\\:\x00") &&
		!strings.HasPrefix(name, "/") && filepath.ToSlash(filepath.Clean(name)) == name &&
		name != ".." && !strings.HasPrefix(name, "../")
}

type IntentAsset struct {
	ID          string `json:"id"`
	Description string `json:"description"`
}

type IntentRole struct {
	ID          string `json:"id"`
	Description string `json:"description"`
}

type IntentAssumption struct {
	ID        string `json:"id"`
	Statement string `json:"statement"`
}

type IntentInvariant struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Statement   string   `json:"statement"`
	Severity    string   `json:"severity"`
	Assets      []string `json:"assets"`
	Roles       []string `json:"roles"`
	Assumptions []string `json:"assumptions"`
	Sources     []string `json:"sources"`
}

type IntentManifest struct {
	Version     int                `json:"version"`
	Scope       string             `json:"scope"`
	Assets      []IntentAsset      `json:"assets"`
	Roles       []IntentRole       `json:"roles"`
	Assumptions []IntentAssumption `json:"assumptions"`
	Invariants  []IntentInvariant  `json:"invariants"`
}

type AssuranceTest struct {
	Suite         string `json:"suite"`
	Test          string `json:"test"`
	Claim         string `json:"claim"`
	Status        string `json:"status"`
	SubjectSource string `json:"subject_source"`
	SubjectSHA256 string `json:"subject_sha256"`
	HarnessSHA256 string `json:"harness_sha256,omitempty"`
	Replay        string `json:"replay"`
}

type TestProposal struct {
	Name    string `json:"name"`
	Outline string `json:"outline"`
}

type InvariantAssessment struct {
	ID             string          `json:"id"`
	Title          string          `json:"title"`
	Statement      string          `json:"statement"`
	Severity       string          `json:"severity"`
	Assets         []string        `json:"assets"`
	Roles          []string        `json:"roles"`
	Assumptions    []string        `json:"assumptions"`
	Sources        []string        `json:"sources"`
	MissingSources []string        `json:"missing_sources"`
	Status         string          `json:"status"`
	Tests          []AssuranceTest `json:"tests"`
	Proposal       *TestProposal   `json:"proposal,omitempty"`
}

type AssuranceResult struct {
	Version      int                   `json:"version"`
	Scope        string                `json:"scope"`
	Revision     string                `json:"revision,omitempty"`
	ReportSHA256 string                `json:"report_sha256"`
	IntentSHA256 string                `json:"intent_sha256"`
	PlanSHA256   string                `json:"plan_sha256,omitempty"`
	ForgeVersion string                `json:"forge_version,omitempty"`
	RiskProject  string                `json:"risk_project,omitempty"`
	Assets       []IntentAsset         `json:"assets"`
	Roles        []IntentRole          `json:"roles"`
	Assumptions  []IntentAssumption    `json:"assumptions"`
	Invariants   []InvariantAssessment `json:"invariants"`
}

func readIntent(path string, scope string) (IntentManifest, string, error) {
	var manifest IntentManifest
	b, err := os.ReadFile(path)
	if err != nil {
		return manifest, "", err
	}
	if len(b) > 1024*1024 {
		return manifest, "", fmt.Errorf("intent file exceeds 1 MiB")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&manifest); err != nil {
		return manifest, "", fmt.Errorf("invalid intent file: %w", err)
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return manifest, "", fmt.Errorf("trailing intent data")
	}
	if err := validateIntent(manifest, scope); err != nil {
		return manifest, "", err
	}
	return manifest, digest(string(b)), nil
}

func validateIntent(m IntentManifest, scope string) error {
	if m.Version != 1 || m.Scope != scope || len(m.Invariants) == 0 {
		return fmt.Errorf("intent requires version 1, matching scope and at least one invariant")
	}
	assets, roles, assumptions, invariants := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, a := range m.Assets {
		if !validIntentID(a.ID) || assets[a.ID] || strings.TrimSpace(a.Description) == "" {
			return fmt.Errorf("invalid or duplicate asset %q", a.ID)
		}
		assets[a.ID] = true
	}
	for _, role := range m.Roles {
		if !validIntentID(role.ID) || roles[role.ID] || strings.TrimSpace(role.Description) == "" {
			return fmt.Errorf("invalid or duplicate role %q", role.ID)
		}
		roles[role.ID] = true
	}
	for _, a := range m.Assumptions {
		if !validIntentID(a.ID) || assumptions[a.ID] || strings.TrimSpace(a.Statement) == "" {
			return fmt.Errorf("invalid or duplicate assumption %q", a.ID)
		}
		assumptions[a.ID] = true
	}
	for _, inv := range m.Invariants {
		if !validIntentID(inv.ID) || invariants[inv.ID] || !validSeverity(inv.Severity) || strings.TrimSpace(inv.Title) == "" || strings.TrimSpace(inv.Statement) == "" || len(inv.Sources) == 0 {
			return fmt.Errorf("invalid or duplicate invariant %q", inv.ID)
		}
		invariants[inv.ID] = true
		if err := validReferences(inv.Assets, assets, "asset"); err != nil {
			return fmt.Errorf("%s: %w", inv.ID, err)
		}
		if err := validReferences(inv.Roles, roles, "role"); err != nil {
			return fmt.Errorf("%s: %w", inv.ID, err)
		}
		if err := validReferences(inv.Assumptions, assumptions, "assumption"); err != nil {
			return fmt.Errorf("%s: %w", inv.ID, err)
		}
		seen := map[string]bool{}
		for _, source := range inv.Sources {
			if !safeSourcePath(source) || seen[source] {
				return fmt.Errorf("%s: invalid or duplicate source %q", inv.ID, source)
			}
			seen[source] = true
		}
	}
	return nil
}

func validReferences(refs []string, known map[string]bool, kind string) error {
	seen := map[string]bool{}
	for _, id := range refs {
		if !known[id] || seen[id] {
			return fmt.Errorf("unknown or duplicate %s reference %q", kind, id)
		}
		seen[id] = true
	}
	return nil
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }

func replayCommand(suite, test string) (string, error) {
	parts := strings.Split(suite, ":")
	if len(parts) != 2 || !safeSourcePath(parts[0]) || !solidityNamePattern.MatchString(parts[1]) {
		return "", fmt.Errorf("invalid Foundry suite %q", suite)
	}
	name := strings.SplitN(test, "(", 2)[0]
	if name == "" || strings.ContainsAny(name, "/\\\x00") {
		return "", fmt.Errorf("invalid Foundry test %q", test)
	}
	return "forge test --offline --match-path " + shellQuote(parts[0]) + " --match-contract " + shellQuote("^"+regexp.QuoteMeta(parts[1])+"$") + " --match-test " + shellQuote("^"+regexp.QuoteMeta(name)+"$"), nil
}

func assessIntent(r Report, m IntentManifest, reportHash, intentHash string) (AssuranceResult, error) {
	result := AssuranceResult{Version: 1, Scope: r.Scope, Revision: r.Revision, ReportSHA256: reportHash, IntentSHA256: intentHash, Assets: m.Assets, Roles: m.Roles, Assumptions: m.Assumptions, Invariants: []InvariantAssessment{}}
	if err := validateIntent(m, r.Scope); err != nil {
		return result, err
	}
	known := map[string]bool{}
	for _, inv := range m.Invariants {
		known[inv.ID] = true
	}
	if r.Risk != nil {
		result.PlanSHA256, result.ForgeVersion, result.RiskProject = r.Risk.PlanSHA256, r.Risk.ForgeVersion, r.Risk.Project
		for _, e := range r.Risk.Evidence {
			for _, id := range e.InvariantIDs {
				if !known[id] {
					return result, fmt.Errorf("risk evidence references unknown invariant %q", id)
				}
			}
		}
	}
	for _, inv := range m.Invariants {
		a := InvariantAssessment{ID: inv.ID, Title: inv.Title, Statement: inv.Statement, Severity: inv.Severity, Assets: inv.Assets, Roles: inv.Roles, Assumptions: inv.Assumptions, Sources: inv.Sources, MissingSources: []string{}, Tests: []AssuranceTest{}}
		for _, source := range inv.Sources {
			if _, ok := r.Sources[source]; !ok {
				a.MissingSources = append(a.MissingSources, source)
			}
		}
		if r.Risk != nil {
			for _, e := range r.Risk.Evidence {
				if !containsString(e.InvariantIDs, inv.ID) {
					continue
				}
				if !containsString(inv.Sources, e.SubjectSource) {
					return result, fmt.Errorf("test %s subject_source is not mapped to invariant %s", e.Test, inv.ID)
				}
				if _, ok := r.Sources[e.SubjectSource]; !ok {
					return result, fmt.Errorf("test %s subject_source is not in report", e.Test)
				}
				if len(r.Risk.PlanSHA256) != 64 {
					return result, fmt.Errorf("risk plan hash missing for invariant test %s", e.Test)
				}
				if r.Risk.Project == "" || (r.Risk.Project != "." && !safeSourcePath(r.Risk.Project)) {
					return result, fmt.Errorf("risk project path missing for invariant test %s", e.Test)
				}
				if e.Status != "Success" && e.Status != "Failure" && e.Status != "Skipped" {
					return result, fmt.Errorf("invalid test status for %s", e.Test)
				}
				replay, err := replayCommand(e.Suite, e.Test)
				if err != nil {
					return result, err
				}
				if r.Risk.Project != "." {
					replay = "cd " + shellQuote(r.Risk.Project) + " && " + replay
				}
				file := strings.SplitN(e.Suite, ":", 2)[0]
				harnessHash := r.Risk.HarnessHashes[file]
				if len(harnessHash) != 64 {
					return result, fmt.Errorf("harness hash missing for invariant test %s", e.Test)
				}
				a.Tests = append(a.Tests, AssuranceTest{Suite: e.Suite, Test: e.Test, Claim: e.Claim, Status: e.Status, SubjectSource: e.SubjectSource, SubjectSHA256: r.Sources[e.SubjectSource].SHA256, HarnessSHA256: harnessHash, Replay: replay})
			}
		}
		sort.Slice(a.Tests, func(i, j int) bool { return a.Tests[i].Suite+a.Tests[i].Test < a.Tests[j].Suite+a.Tests[j].Test })
		a.Status = assuranceStatus(r, a)
		if a.Status == "untested" || a.Status == "unmapped" {
			a.Proposal = &TestProposal{Name: "test_" + strings.ReplaceAll(inv.ID, "-", "_"), Outline: "Human-reviewed Foundry assertion: " + inv.Statement + ". Exercise relevant roles and asset flows; map the exact test in the risk plan using invariant_ids and subject_source."}
		}
		result.Invariants = append(result.Invariants, a)
	}
	sort.Slice(result.Invariants, func(i, j int) bool { return result.Invariants[i].ID < result.Invariants[j].ID })
	return result, nil
}

func containsString(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}

func assuranceStatus(r Report, a InvariantAssessment) string {
	if len(a.MissingSources) > 0 {
		return "out-of-scope"
	}
	if r.Risk == nil {
		return "untested"
	}
	if r.Risk.Status != "passed" {
		return "test-stage-error"
	}
	if len(a.Tests) == 0 {
		return "unmapped"
	}
	hasFailed, hasSkipped, hasCounterexample := false, false, false
	for _, test := range a.Tests {
		if test.Status == "Failure" {
			hasFailed = true
		}
		if test.Status == "Skipped" {
			hasSkipped = true
		}
		if test.Status == "Success" && test.Claim == "exploit-reproduced" {
			hasCounterexample = true
		}
	}
	if hasCounterexample {
		return "counterexample-local"
	}
	if hasFailed {
		return "test-failed"
	}
	if hasSkipped {
		return "test-skipped"
	}
	return "checked-local"
}

func saveAssurance(dir string, result AssuranceResult) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "assurance.json"), append(b, '\n'), 0600); err != nil {
		return err
	}
	var md strings.Builder
	fmt.Fprintf(&md, "# Protocol assurance map\n\nScope: `%s` · Revision: `%s`\n\nIntent SHA-256: `%s` · Report SHA-256: `%s`\n\nLocal test outcomes describe only the recorded harness. A checked property is not a formal proof of all reachable states.\n\n", result.Scope, result.Revision, result.IntentSHA256, result.ReportSHA256)
	if result.PlanSHA256 != "" {
		fmt.Fprintf(&md, "Risk plan SHA-256: `%s` · Forge: `%s` · Project: `%s`\n\n", result.PlanSHA256, result.ForgeVersion, result.RiskProject)
	}
	for _, a := range result.Invariants {
		fmt.Fprintf(&md, "## %s — %s\n\n%s\n\nSeverity: **%s** · Status: **%s**\n\nAssets: %s · Roles: %s · Assumptions: %s\n\nSources: %s\n\n", a.ID, a.Title, a.Statement, a.Severity, a.Status, strings.Join(a.Assets, ", "), strings.Join(a.Roles, ", "), strings.Join(a.Assumptions, ", "), strings.Join(a.Sources, ", "))
		if len(a.MissingSources) > 0 {
			fmt.Fprintf(&md, "Missing from audited source bundle: %s\n\n", strings.Join(a.MissingSources, ", "))
		}
		for _, test := range a.Tests {
			fmt.Fprintf(&md, "- `%s:%s` — %s; claim: %s; subject: `%s` (`%s`); harness SHA-256: `%s`\n  Targeted replay from the source root: `%s`\n", test.Suite, test.Test, test.Status, test.Claim, test.SubjectSource, test.SubjectSHA256, test.HarnessSHA256, test.Replay)
		}
		if a.Proposal != nil {
			fmt.Fprintf(&md, "\nSuggested test outline for human review: **%s** — %s\n", a.Proposal.Name, a.Proposal.Outline)
		}
		md.WriteString("\n")
	}
	return os.WriteFile(filepath.Join(dir, "assurance.md"), []byte(md.String()), 0600)
}

func assureCommand(args []string, w io.Writer) error {
	f := flags("assure", w)
	reportPath := f.String("report", "reports/report.json", "Audited report JSON")
	intentPath := f.String("intent", "", "Reviewed protocol intent JSON (required)")
	out := f.String("out", "", "Output directory; defaults to report directory")
	if err := parse(f, args); err != nil {
		return err
	}
	if *intentPath == "" {
		return fmt.Errorf("assure requires --intent")
	}
	r, err := loadReport(*reportPath)
	if err != nil {
		return err
	}
	b, err := os.ReadFile(*reportPath)
	if err != nil {
		return err
	}
	m, intentHash, err := readIntent(*intentPath, r.Scope)
	if err != nil {
		return err
	}
	result, err := assessIntent(r, m, digest(string(b)), intentHash)
	if err != nil {
		return err
	}
	dir := *out
	if dir == "" {
		dir = filepath.Dir(*reportPath)
	}
	if err := saveAssurance(dir, result); err != nil {
		return err
	}
	for _, a := range result.Invariants {
		fmt.Fprintf(w, "%s %s\n", a.ID, a.Status)
	}
	return nil
}
