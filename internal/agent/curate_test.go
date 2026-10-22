package agent

import (
	"encoding/json"
	"testing"
)

func TestCurateSourceBoundFindingAndDeduplicateDiscovery(t *testing.T) {
	source := "contract Escrow {\n    if (deals[id].state != None) revert Exists(id);\n}\n"
	r := Report{Version: 1, Scope: "owner/repo:contracts", Findings: []Finding{}, Sources: map[string]Source{
		"contracts/Escrow.sol": {Content: source, SHA256: digest(source)},
	}}
	excerpt := "if (deals[id].state != None) revert Exists(id);"
	check := "ai-global-id-denial-of-service"
	id := digest(r.Scope + "\x00" + check + "\x00contracts/Escrow.sol\x002\x00" + excerpt)
	entry := curatedFinding{ID: id, Check: check, Severity: "Medium", Description: "A stranger can reserve an id", File: "contracts/Escrow.sol", Line: 2, SourceExcerpt: excerpt, ExploitScenario: "Attacker reserves the id before the payer", Remediation: "Bind ids to the payer", Validation: "Run the reservation test"}
	manifest := curatedManifest{Version: 1, Scope: r.Scope, SourceSetSHA256: sourceSetDigest(r), Findings: []curatedFinding{entry}}
	data, _ := json.Marshal(manifest)
	if err := applyCuratedFindings(&r, data); err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 1 || r.Findings[0].ID != id || r.Findings[0].Origin != "curated-discovery" || r.Findings[0].Review != nil {
		t.Fatalf("unexpected curated finding: %+v", r.Findings)
	}
	layers := findingEvidenceLayers(r, r.Findings[0])
	if layers[0].Stage != "curation" || layers[0].Status != "retained-candidate" {
		t.Fatalf("curation provenance lost: %+v", layers)
	}
	response := []byte(`{"findings":[{"check":"global-id-denial-of-service","title":"Same issue","severity":"Medium","description":"duplicate","file":"contracts/Escrow.sol","line":2,"source_excerpt":"if (deals[id].state != None) revert Exists(id);","exploit_scenario":"front-run","remediation":"payer scope","validation":"test"}]}`)
	newFindings, err := parseDiscoveries(r.Scope, r.Sources, r.Findings, response)
	if err != nil || len(newFindings) != 0 {
		t.Fatalf("duplicate discovery was not suppressed: %v, %+v", err, newFindings)
	}
	if err := applyCuratedFindings(&r, data); err == nil {
		t.Fatal("duplicate curated finding accepted")
	}
}

func TestCurateRejectsChangedSourceAndForgedID(t *testing.T) {
	source := "contract Escrow {}\n"
	r := Report{Version: 1, Scope: "owner/repo:contracts", Findings: []Finding{}, Sources: map[string]Source{
		"contracts/Escrow.sol": {Content: source, SHA256: digest(source)},
	}}
	entry := curatedFinding{ID: digest("wrong"), Check: "ai-id-collision", Severity: "Medium", Description: "Collision", File: "contracts/Escrow.sol", Line: 1, SourceExcerpt: "contract Escrow {}", ExploitScenario: "front-run", Remediation: "payer scope", Validation: "test"}
	manifest := curatedManifest{Version: 1, Scope: r.Scope, SourceSetSHA256: sourceSetDigest(r), Findings: []curatedFinding{entry}}
	data, _ := json.Marshal(manifest)
	if err := applyCuratedFindings(&r, data); err == nil {
		t.Fatal("forged finding ID accepted")
	}
	manifest.Findings[0].ID = digest(r.Scope + "\x00" + entry.Check + "\x00" + entry.File + "\x001\x00" + entry.SourceExcerpt)
	manifest.SourceSetSHA256 = digest("old source set")
	data, _ = json.Marshal(manifest)
	if err := applyCuratedFindings(&r, data); err == nil {
		t.Fatal("changed source set accepted")
	}
}
