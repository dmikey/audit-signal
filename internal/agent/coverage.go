package agent

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Coverage is based on compilation units emitted by the same Slither process
// as the detector results. It records compilation, not proof that a detector
// explored every path or that a property holds.
type CoverageReceipt struct {
	Version             int                 `json:"version"`
	Status              string              `json:"status"`
	SlitherOutputSHA256 string              `json:"slither_output_sha256"`
	TargetSources       []CoverageTarget    `json:"target_sources"`
	CompiledSources     []CoverageSource    `json:"compiled_sources"`
	CompilationUnits    []CoverageUnit      `json:"compilation_units"`
	Exclusions          []CoverageExclusion `json:"exclusions"`
	Unresolved          []string            `json:"unresolved"`
}

type CoverageTarget struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type CoverageSource struct {
	Path      string   `json:"path"`
	SHA256    string   `json:"sha256"`
	Role      string   `json:"role"`
	Units     []string `json:"units"`
	Contracts []string `json:"contracts"`
}

type CoverageUnit struct {
	ID              string   `json:"id"`
	Compiler        string   `json:"compiler"`
	CompilerVersion string   `json:"compiler_version"`
	Sources         []string `json:"sources"`
}

type CoverageExclusion struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

type compileFilename struct {
	Absolute string `json:"absolute"`
	Relative string `json:"relative"`
}

type compileSourceUnit struct {
	AST       json.RawMessage            `json:"ast"`
	Contracts map[string]json.RawMessage `json:"contracts"`
}

type compileUnit struct {
	Compiler struct {
		Compiler string `json:"compiler"`
		Version  string `json:"version"`
	} `json:"compiler"`
	Filenames   []compileFilename            `json:"filenames"`
	SourceUnits map[string]compileSourceUnit `json:"source_units"`
}

func buildCoverage(data []byte, root, target string, sources map[string]Source, imported bool) (*CoverageReceipt, error) {
	c := &CoverageReceipt{Version: 1, Status: "incomplete", SlitherOutputSHA256: digest(string(data)), TargetSources: []CoverageTarget{}, CompiledSources: []CoverageSource{}, CompilationUnits: []CoverageUnit{}, Exclusions: []CoverageExclusion{}, Unresolved: []string{}}
	for path, src := range sources {
		c.TargetSources = append(c.TargetSources, CoverageTarget{Path: path, SHA256: src.SHA256})
	}
	sort.Slice(c.TargetSources, func(i, j int) bool { return c.TargetSources[i].Path < c.TargetSources[j].Path })
	if err := inventoryExclusions(root, target, c); err != nil {
		return nil, err
	}
	if imported {
		c.Status = "unavailable"
		c.Unresolved = append(c.Unresolved, "compilation coverage unavailable for imported Slither results")
		return c, nil
	}
	var envelope struct {
		Results struct {
			Compilations []struct {
				CompilationUnits map[string]compileUnit `json:"compilation_units"`
			} `json:"compilations"`
		} `json:"results"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, err
	}
	if len(envelope.Results.Compilations) == 0 {
		c.Unresolved = append(c.Unresolved, "Slither returned no compilation-unit export")
		return c, nil
	}
	type sourceRecord struct {
		source    CoverageSource
		units     map[string]bool
		contracts map[string]bool
	}
	compiled := map[string]*sourceRecord{}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	for index, compilation := range envelope.Results.Compilations {
		keys := make([]string, 0, len(compilation.CompilationUnits))
		for key := range compilation.CompilationUnits {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			unit := compilation.CompilationUnits[key]
			id := fmt.Sprintf("%d:%s", index, key)
			entry := CoverageUnit{ID: id, Compiler: unit.Compiler.Compiler, CompilerVersion: unit.Compiler.Version, Sources: []string{}}
			if entry.Compiler == "" || entry.CompilerVersion == "" || len(unit.SourceUnits) == 0 {
				c.Unresolved = append(c.Unresolved, "compilation unit "+id+" lacks compiler, version, or source units")
			}
			byRelative := map[string]string{}
			for _, filename := range unit.Filenames {
				byRelative[filename.Relative] = filename.Absolute
			}
			names := make([]string, 0, len(unit.SourceUnits))
			for name := range unit.SourceUnits {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				path, abs, reason := compilationPath(rootAbs, name, byRelative[name])
				if reason != "" {
					c.Unresolved = append(c.Unresolved, id+": "+reason)
					continue
				}
				entry.Sources = append(entry.Sources, path)
				sourceUnit := unit.SourceUnits[name]
				if len(sourceUnit.AST) == 0 || string(sourceUnit.AST) == "null" {
					c.Unresolved = append(c.Unresolved, id+": missing AST for "+path)
				}
				body, err := os.ReadFile(abs)
				if err != nil {
					c.Unresolved = append(c.Unresolved, id+": cannot read compiled source "+path)
					continue
				}
				hash := digest(string(body))
				if prior := compiled[path]; prior != nil && prior.source.SHA256 != hash {
					c.Unresolved = append(c.Unresolved, id+": source changed between compilation units: "+path)
					continue
				}
				rec := compiled[path]
				if rec == nil {
					role := "dependency"
					if _, ok := sources[path]; ok {
						role = "target"
					}
					rec = &sourceRecord{source: CoverageSource{Path: path, SHA256: hash, Role: role, Units: []string{}, Contracts: []string{}}, units: map[string]bool{}, contracts: map[string]bool{}}
					compiled[path] = rec
				}
				rec.units[id] = true
				for contract := range sourceUnit.Contracts {
					rec.contracts[contract] = true
				}
			}
			sort.Strings(entry.Sources)
			c.CompilationUnits = append(c.CompilationUnits, entry)
		}
	}
	if len(c.CompilationUnits) == 0 {
		c.Unresolved = append(c.Unresolved, "Slither exported no compilation units")
	}
	for _, targetSource := range c.TargetSources {
		rec := compiled[targetSource.Path]
		if rec == nil {
			c.Unresolved = append(c.Unresolved, "target source absent from compilation: "+targetSource.Path)
		} else if rec.source.SHA256 != targetSource.SHA256 {
			c.Unresolved = append(c.Unresolved, "target source changed during scan: "+targetSource.Path)
		}
	}
	for _, rec := range compiled {
		for id := range rec.units {
			rec.source.Units = append(rec.source.Units, id)
		}
		for name := range rec.contracts {
			rec.source.Contracts = append(rec.source.Contracts, name)
		}
		sort.Strings(rec.source.Units)
		sort.Strings(rec.source.Contracts)
		c.CompiledSources = append(c.CompiledSources, rec.source)
	}
	sort.Slice(c.CompiledSources, func(i, j int) bool { return c.CompiledSources[i].Path < c.CompiledSources[j].Path })
	sort.Strings(c.Unresolved)
	if len(c.Unresolved) == 0 {
		c.Status = "complete"
	}
	return c, nil
}

func compilationPath(root, relative, absolute string) (string, string, string) {
	if absolute == "" && safeSourcePath(filepath.ToSlash(relative)) {
		absolute = filepath.Join(root, filepath.FromSlash(relative))
	}
	if absolute == "" || !filepath.IsAbs(absolute) {
		return "", "", "source path unavailable: " + relative
	}
	clean := filepath.Clean(absolute)
	rel, err := filepath.Rel(root, clean)
	if err != nil {
		return "", "", "cannot resolve source: " + relative
	}
	rel = filepath.ToSlash(rel)
	if safeSourcePath(rel) {
		return rel, clean, ""
	}
	return "external/" + digest(clean)[:16] + "/" + filepath.Base(clean), clean, ""
}

func inventoryExclusions(root, target string, c *CoverageReceipt) error {
	info, err := os.Lstat(target)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return nil
	}
	vendor := map[string]bool{"node_modules": true, "lib": true}
	generated := map[string]bool{"out": true, "cache": true, "artifacts": true, ".slither-venv": true, ".solc-select": true, "reports": true}
	return filepath.WalkDir(target, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == target {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			if vendor[d.Name()] {
				c.Exclusions = append(c.Exclusions, CoverageExclusion{Path: rel, Reason: "source bundle skips this directory; compiled dependencies are still listed separately"})
				return filepath.SkipDir
			}
			if generated[d.Name()] {
				return filepath.SkipDir
			}
		}
		if d.Type()&os.ModeSymlink != 0 {
			c.Exclusions = append(c.Exclusions, CoverageExclusion{Path: rel, Reason: "symlink not followed"})
		}
		return nil
	})
}

func validateCoverage(c CoverageReceipt, sources map[string]Source) error {
	if c.Version != 1 || (c.Status != "complete" && c.Status != "incomplete" && c.Status != "unavailable") || !validSHA256(c.SlitherOutputSHA256) {
		return fmt.Errorf("invalid coverage receipt")
	}
	seen := map[string]bool{}
	for _, target := range c.TargetSources {
		if !safeSourcePath(target.Path) || !validSHA256(target.SHA256) || seen[target.Path] || sources[target.Path].SHA256 != target.SHA256 {
			return fmt.Errorf("coverage target source mismatch: %s", target.Path)
		}
		seen[target.Path] = true
	}
	if len(seen) != len(sources) {
		return fmt.Errorf("coverage target inventory is incomplete")
	}
	compiled := map[string]CoverageSource{}
	for _, source := range c.CompiledSources {
		if !safeSourcePath(source.Path) || !validSHA256(source.SHA256) || len(source.Units) == 0 || compiled[source.Path].Path != "" || (source.Role != "target" && source.Role != "dependency") {
			return fmt.Errorf("invalid compiled source in coverage receipt")
		}
		if _, target := seen[source.Path]; target != (source.Role == "target") {
			return fmt.Errorf("compiled source role mismatch: %s", source.Path)
		}
		compiled[source.Path] = source
	}
	units := map[string]CoverageUnit{}
	for _, unit := range c.CompilationUnits {
		if unit.ID == "" || units[unit.ID].ID != "" {
			return fmt.Errorf("invalid compilation unit in coverage receipt")
		}
		if c.Status == "complete" && (unit.Compiler == "" || unit.CompilerVersion == "" || len(unit.Sources) == 0) {
			return fmt.Errorf("complete coverage has incomplete compilation unit")
		}
		units[unit.ID] = unit
		for _, path := range unit.Sources {
			if _, ok := compiled[path]; !ok && c.Status == "complete" {
				return fmt.Errorf("compilation unit references unknown source: %s", path)
			}
		}
	}
	for _, source := range c.CompiledSources {
		for _, unitID := range source.Units {
			unit, ok := units[unitID]
			if !ok || !containsString(unit.Sources, source.Path) {
				return fmt.Errorf("compiled source has invalid unit mapping: %s", source.Path)
			}
		}
	}
	for _, target := range c.TargetSources {
		if source, ok := compiled[target.Path]; !ok || source.SHA256 != target.SHA256 || source.Role != "target" {
			if c.Status == "complete" {
				return fmt.Errorf("complete coverage lacks target %s", target.Path)
			}
		}
	}
	if c.Status == "complete" && (len(c.Unresolved) > 0 || len(c.CompilationUnits) == 0) {
		return fmt.Errorf("complete coverage has unresolved compilation")
	}
	if c.Status != "complete" && len(c.Unresolved) == 0 {
		return fmt.Errorf("incomplete coverage lacks reason")
	}
	for _, e := range c.Exclusions {
		if !safeSourcePath(e.Path) || strings.TrimSpace(e.Reason) == "" {
			return fmt.Errorf("invalid coverage exclusion")
		}
	}
	return nil
}

func validSHA256(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func saveCoverage(dir string, c CoverageReceipt) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "coverage.json"), append(b, '\n'), 0600); err != nil {
		return err
	}
	var md strings.Builder
	fmt.Fprintf(&md, "# Compilation coverage receipt\n\nStatus: **%s** · Target sources: %d · Compiled sources: %d · Compilation units: %d\n\nSlither output SHA-256: `%s`\n\nThis records compiler input in the same Slither run as the findings. It does not prove detector path coverage or protocol safety.\n\n", c.Status, len(c.TargetSources), len(c.CompiledSources), len(c.CompilationUnits), c.SlitherOutputSHA256)
	for _, source := range c.CompiledSources {
		fmt.Fprintf(&md, "- `%s` (%s; `%s`) — units: %s; contracts: %s\n", source.Path, source.Role, source.SHA256, strings.Join(source.Units, ", "), strings.Join(source.Contracts, ", "))
	}
	if len(c.Exclusions) > 0 {
		md.WriteString("\n## Exclusions from the AI source bundle\n\n")
		for _, e := range c.Exclusions {
			fmt.Fprintf(&md, "- `%s`: %s\n", e.Path, e.Reason)
		}
	}
	if len(c.Unresolved) > 0 {
		md.WriteString("\n## Unresolved\n\n")
		for _, reason := range c.Unresolved {
			fmt.Fprintf(&md, "- %s\n", reason)
		}
	}
	return os.WriteFile(filepath.Join(dir, "coverage.md"), []byte(md.String()), 0600)
}
