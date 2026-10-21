package agent

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const Version = "0.9.0"
const SlitherVersion = "0.11.6"
const SolcSelectVersion = "1.2.0"

func Run(ctx context.Context, args []string, w io.Writer) error {
	if len(args) == 0 {
		help(w)
		return nil
	}
	switch args[0] {
	case "help", "--help", "-h":
		help(w)
		return nil
	case "version", "--version":
		fmt.Fprintln(w, Version)
		return nil
	case "setup":
		return setup(ctx, args[1:], w)
	case "audit":
		return audit(ctx, args[1:], w)
	case "review":
		return reviewCommand(ctx, args[1:], w)
	case "discover":
		return discoverCommand(ctx, args[1:], w)
	case "risk":
		return riskCommand(ctx, args[1:], w)
	case "assure":
		return assureCommand(args[1:], w)
	case "render":
		return renderCommand(args[1:], w)
	case "gate":
		return gateCommand(args[1:], w)
	case "publish":
		return publishCommand(ctx, args[1:], w)
	default:
		return fmt.Errorf("unknown command %q; use --help", args[0])
	}
}
func help(w io.Writer) {
	fmt.Fprintln(w, `audit-signal: Slither + AI smart contract audits

Commands (use COMMAND --help for flags):
  setup    Install pinned Slither and solc-select into a local Python environment
  audit    Run Slither, bundle sources, optionally review with AI, save report
  review   AI-review an existing report
  discover Search source for flaws that Slither may miss
  risk     Execute a mapped Foundry exploit/fuzz/risk test plan in a local EVM
  assure   Map protocol invariants to audited sources and local test evidence
  render   Rebuild Markdown and evidence-layer JSON from a saved report
  gate     Apply a versioned merge policy and accepted-finding baseline
  publish  Create/update deduplicated security issues from a reviewed report
  version  Print binary version

Example:
  audit-signal setup --solc-version 0.8.28
  audit-signal audit --target contracts --scope owner/private-contracts --ai copilot
  audit-signal publish --report reports/report.json --repo owner/private-contracts

No issues are written until publish runs. AI providers: copilot, openai, anthropic.`)
}

func flags(name string, w io.Writer) *flag.FlagSet {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(w)
	return f
}
func parse(f *flag.FlagSet, args []string) error {
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() > 0 {
		return fmt.Errorf("unexpected arguments: %v", f.Args())
	}
	return nil
}
func envBin(dir, name string) string {
	if runtime.GOOS == "windows" {
		if name == "python" {
			return filepath.Join(dir, "Scripts", "python.exe")
		}
		return filepath.Join(dir, "Scripts", name+".exe")
	}
	return filepath.Join(dir, "bin", name)
}
func absolute(path string) string { p, _ := filepath.Abs(path); return p }
func setEnv(env []string, k, v string) []string {
	out := []string{}
	for _, s := range env {
		if !strings.HasPrefix(s, k+"=") {
			out = append(out, s)
		}
	}
	return append(out, k+"="+v)
}
func toolEnv(venv, solcVersion string) []string {
	env := os.Environ()
	env = setEnv(env, "PATH", filepath.Dir(envBin(absolute(venv), "python"))+string(os.PathListSeparator)+os.Getenv("PATH"))
	env = setEnv(env, "VIRTUAL_ENV", absolute(venv))
	if solcVersion != "" {
		env = setEnv(env, "SOLC_VERSION", solcVersion)
	}
	return env
}
func runTool(ctx context.Context, env []string, w io.Writer, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = env
	cmd.Stdout = w
	cmd.Stderr = w
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s failed: %w", filepath.Base(name), err)
	}
	return nil
}
func setup(ctx context.Context, args []string, w io.Writer) error {
	f := flags("setup", w)
	venv := f.String("venv", ".slither-venv", "Python environment directory")
	solc := f.String("solc-version", "", "Compiler version to download (e.g. 0.8.28)")
	python := f.String("python", "3.12", "Python version or interpreter for uv")
	if err := parse(f, args); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	env := toolEnv(*venv, *solc)
	if _, err := exec.LookPath("uv"); err != nil {
		return fmt.Errorf("setup requires uv; see https://docs.astral.sh/uv/getting-started/installation/")
	}
	if _, err := os.Stat(envBin(*venv, "python")); os.IsNotExist(err) {
		if err = runTool(ctx, env, w, "uv", "venv", "--python", *python, *venv); err != nil {
			return err
		}
	}
	if err := runTool(ctx, env, w, "uv", "pip", "install", "--python", envBin(absolute(*venv), "python"), "slither-analyzer=="+SlitherVersion, "solc-select=="+SolcSelectVersion); err != nil {
		return err
	}
	if *solc != "" {
		if err := runTool(ctx, env, w, envBin(absolute(*venv), "solc-select"), "install", *solc); err != nil {
			return err
		}
	}
	fmt.Fprintf(w, "Installed Slither %s. Install Copilot CLI separately: npm install -g @github/copilot@1.0.97\n", SlitherVersion)
	return nil
}

func audit(ctx context.Context, args []string, w io.Writer) error {
	f := flags("audit", w)
	target := f.String("target", ".", "Contract file or project directory")
	scope := f.String("scope", "", "Stable identity, e.g. owner/repo:contracts (required)")
	out := f.String("out", "reports", "Report directory")
	input := f.String("input", "", "Import existing Slither JSON instead of executing Slither")
	ai := f.String("ai", "copilot", "copilot or none (legacy alias for --provider copilot)")
	provider := f.String("provider", "copilot", "AI provider: copilot, openai, anthropic")
	model := f.String("model", "auto", "Model ID; auto only for Copilot")
	copilot := f.String("copilot", "copilot", "Copilot CLI executable")
	venv := f.String("venv", ".slither-venv", "Python environment directory")
	slither := f.String("slither", "", "Slither executable; defaults to local venv then PATH")
	solc := f.String("solc-version", "", "SOLC_VERSION for this audit")
	sourceLimit := f.Int("max-source-bytes", 48000, "Maximum source bundle bytes; excess fails instead of truncating")
	timeout := f.Duration("timeout", 10*time.Minute, "Overall audit timeout")
	if err := parse(f, args); err != nil {
		return err
	}
	if *scope == "" || (*ai != "none" && *ai != "copilot") || *sourceLimit < 1 || *timeout <= 0 {
		return fmt.Errorf("require --scope, --ai copilot|none, and positive limits")
	}
	if *ai != "none" {
		if err := validateProvider(*provider, *model); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	tgt, err := filepath.Abs(*target)
	if err != nil {
		return err
	}
	info, err := os.Lstat(tgt)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("target must not be a symlink")
	}
	root := tgt
	if !info.IsDir() {
		root = filepath.Dir(tgt)
	}
	// Use the Git root for consistent relative source paths and revision metadata.
	gitRoot := exec.CommandContext(ctx, "git", "-C", root, "rev-parse", "--show-toplevel")
	if b, e := gitRoot.Output(); e == nil {
		root = strings.TrimSpace(string(b))
	}
	sources, err := collectSources(root, tgt, *sourceLimit)
	if err != nil {
		return err
	}
	if len(sources) == 0 {
		return fmt.Errorf("no Solidity/Vyper source found in target")
	}
	r := Report{Version: 1, Scope: *scope, Target: *target, CreatedAt: time.Now().UTC().Format(time.RFC3339), Sources: sources, Imported: *input != ""}
	if b, e := exec.CommandContext(ctx, "git", "-C", root, "rev-parse", "HEAD").Output(); e == nil {
		r.Revision = strings.TrimSpace(string(b))
	}
	if b, e := exec.CommandContext(ctx, "git", "-C", root, "status", "--porcelain").Output(); e == nil {
		r.Dirty = len(b) > 0
	} else {
		r.Dirty = true
	}
	var data []byte
	if *input != "" {
		data, err = os.ReadFile(*input)
		r.SlitherVersion = "imported/unknown"
	} else {
		executable := *slither
		if executable == "" {
			executable = envBin(absolute(*venv), "slither")
			if _, e := os.Stat(executable); e != nil {
				executable = "slither"
			}
		}
		env := toolEnv(*venv, *solc)
		vcmd := exec.CommandContext(ctx, executable, "--version")
		vcmd.Env = env
		b, e := vcmd.Output()
		if e != nil {
			return fmt.Errorf("Slither unavailable; run setup or pass --slither")
		}
		r.SlitherVersion = strings.TrimSpace(string(b))
		tmp, e := os.MkdirTemp("", "slither-audit-")
		if e != nil {
			return e
		}
		defer os.RemoveAll(tmp)
		jsonPath := filepath.Join(tmp, "slither.json")
		if e = os.MkdirAll(*out, 0700); e != nil {
			return e
		}
		log, e := os.OpenFile(filepath.Join(*out, "slither.log"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		rel, e := filepath.Rel(root, tgt)
		if e != nil {
			log.Close()
			return e
		}
		cmd := exec.CommandContext(ctx, executable, rel, "--json", jsonPath, "--fail-none")
		cmd.Dir = root
		cmd.Env = env
		cmd.Stdout = log
		cmd.Stderr = log
		e = cmd.Run()
		log.Close()
		if e != nil {
			return fmt.Errorf("Slither failed: %w; inspect %s", e, filepath.Join(*out, "slither.log"))
		}
		data, err = os.ReadFile(jsonPath)
	}
	if err != nil {
		return err
	}
	r.Findings, err = parseSlither(data, *scope, root)
	if err != nil {
		return err
	}
	if err = saveReport(*out, r); err != nil {
		return err
	}
	fmt.Fprintf(w, "Slither: %d findings. Reports saved to %s\n", len(r.Findings), *out)
	if *ai == "copilot" {
		if err = reviewReportWithProvider(ctx, &r, *provider, *copilot, *model); err != nil {
			return err
		}
		if err = saveReport(*out, r); err != nil {
			return err
		}
		fmt.Fprintf(w, "%s review complete.\n", *provider)
	}
	return nil
}

func reviewCommand(ctx context.Context, args []string, w io.Writer) error {
	f := flags("review", w)
	path := f.String("report", "reports/report.json", "Input report")
	out := f.String("out", "reports", "Output directory")
	model := f.String("model", "auto", "Model ID; auto only for Copilot")
	provider := f.String("provider", "copilot", "AI provider: copilot, openai, anthropic")
	copilot := f.String("copilot", "copilot", "Copilot CLI executable")
	timeout := f.Duration("timeout", 10*time.Minute, "Review timeout")
	if err := parse(f, args); err != nil {
		return err
	}
	if *timeout <= 0 {
		return fmt.Errorf("timeout must be positive")
	}
	r, err := loadReport(*path)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	if err = reviewReportWithProvider(ctx, &r, *provider, *copilot, *model); err != nil {
		return err
	}
	if err = saveReport(*out, r); err != nil {
		return err
	}
	fmt.Fprintf(w, "%s reviewed %d findings; saved to %s\n", *provider, len(r.Findings), *out)
	return nil
}

func discoverCommand(ctx context.Context, args []string, w io.Writer) error {
	f := flags("discover", w)
	path := f.String("report", "reports/report.json", "Input Slither report")
	out := f.String("out", "reports", "Output directory")
	model := f.String("model", "auto", "Model ID; auto only for Copilot")
	provider := f.String("provider", "copilot", "AI provider: copilot, openai, anthropic")
	copilot := f.String("copilot", "copilot", "Copilot CLI executable")
	timeout := f.Duration("timeout", 10*time.Minute, "Discovery timeout")
	if err := parse(f, args); err != nil {
		return err
	}
	if *timeout <= 0 {
		return fmt.Errorf("timeout must be positive")
	}
	r, err := loadReport(*path)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	if err = discoverReportWithProvider(ctx, &r, *provider, *copilot, *model); err != nil {
		return err
	}
	if err = saveReport(*out, r); err != nil {
		return err
	}
	fmt.Fprintf(w, "AI discovery complete: %d total findings; saved to %s\n", len(r.Findings), *out)
	return nil
}

func renderCommand(args []string, w io.Writer) error {
	f := flags("render", w)
	path := f.String("report", "reports/report.json", "Existing report JSON")
	out := f.String("out", "", "Output directory (defaults to the report directory)")
	if err := parse(f, args); err != nil {
		return err
	}
	r, err := loadReport(*path)
	if err != nil {
		return err
	}
	dir := *out
	if dir == "" {
		dir = filepath.Dir(*path)
	}
	if err := saveReport(dir, r); err != nil {
		return err
	}
	fmt.Fprintf(w, "Rendered %d findings with evidence layers to %s\n", len(r.Findings), dir)
	return nil
}
