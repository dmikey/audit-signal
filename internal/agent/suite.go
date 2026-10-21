package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ProjectTestRun records a project-wide regression command. It deliberately has
// no finding IDs or exploit claim; only a mapped risk plan can make those claims.
type ProjectTestRun struct {
	Status       string   `json:"status"`
	Project      string   `json:"project"`
	Command      []string `json:"command"`
	StartedAt    string   `json:"started_at"`
	DurationMs   int64    `json:"duration_ms"`
	ExitCode     int      `json:"exit_code"`
	LogFile      string   `json:"log_file"`
	LogSHA256    string   `json:"log_sha256"`
	Truncated    bool     `json:"truncated,omitempty"`
	ResultFormat string   `json:"result_format,omitempty"`
	PassedTests  int      `json:"passed_tests"`
	PendingTests int      `json:"pending_tests"`
	FailedTests  int      `json:"failed_tests"`
	ResultError  string   `json:"result_error,omitempty"`
}

var (
	mochaANSI    = regexp.MustCompile(`\x1b\[[0-9;]*m`)
	mochaSummary = regexp.MustCompile(`^\s*([0-9]+) (passing|pending|failing)(?: \([^\r\n]*\))?\s*$`)
)

func mochaSpecResults(log []byte) (passed, pending, failed int, err error) {
	seen := map[string]bool{}
	for _, line := range strings.Split(mochaANSI.ReplaceAllString(string(log), ""), "\n") {
		match := mochaSummary.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		kind := match[2]
		if seen[kind] {
			return 0, 0, 0, fmt.Errorf("ambiguous Mocha %s summaries", kind)
		}
		seen[kind] = true
		n, parseErr := strconv.Atoi(match[1])
		if parseErr != nil {
			return 0, 0, 0, fmt.Errorf("invalid Mocha test count")
		}
		switch kind {
		case "passing":
			passed = n
		case "pending":
			pending = n
		case "failing":
			failed = n
		}
	}
	if !seen["passing"] {
		return 0, 0, 0, fmt.Errorf("Mocha passing summary missing")
	}
	if passed == 0 {
		return 0, pending, failed, fmt.Errorf("Mocha ran zero passing tests")
	}
	if failed > 0 {
		return passed, pending, failed, fmt.Errorf("Mocha reported failing tests")
	}
	return passed, pending, failed, nil
}

type boundedLog struct {
	mu        sync.Mutex
	w         io.Writer
	remaining int
	truncated bool
}

func (b *boundedLog) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	if b.remaining <= 0 {
		b.truncated = true
		return n, nil
	}
	part := p
	if len(part) > b.remaining {
		part = part[:b.remaining]
		b.truncated = true
	}
	if _, err := b.w.Write(part); err != nil {
		return 0, err
	}
	b.remaining -= len(part)
	return n, nil
}

func suiteCommand(ctx context.Context, args []string, w io.Writer) error {
	f := flags("suite", w)
	reportPath := f.String("report", "reports/report.json", "Input audit report")
	sourceRoot := f.String("source-root", ".", "Audited source root; hashes must match")
	project := f.String("project", ".", "Trusted test project inside the source root")
	out := f.String("out", "reports", "Output report and test log directory")
	commandJSON := f.String("command-json", "", "JSON array of executable and arguments; no shell")
	resultFormat := f.String("result-format", "exit-only", "Result evidence: exit-only or mocha-spec")
	timeout := f.Duration("timeout", 10*time.Minute, "Test command timeout")
	if err := parse(f, args); err != nil {
		return err
	}
	if *timeout <= 0 || len(*commandJSON) > 8192 {
		return fmt.Errorf("invalid suite timeout or command length")
	}
	if *resultFormat != "exit-only" && *resultFormat != "mocha-spec" {
		return fmt.Errorf("unsupported suite result format: %s", *resultFormat)
	}
	var command []string
	if err := json.Unmarshal([]byte(*commandJSON), &command); err != nil || len(command) == 0 || len(command) > 64 {
		return fmt.Errorf("suite requires --command-json as a nonempty JSON string array")
	}
	for _, arg := range command {
		if arg == "" || strings.ContainsRune(arg, '\x00') || len(arg) > 2048 {
			return fmt.Errorf("invalid suite command argument")
		}
	}
	r, err := loadReport(*reportPath)
	if err != nil {
		return err
	}
	if len(r.ProjectTests) > 0 {
		priorDir, err := filepath.Abs(filepath.Dir(*reportPath))
		if err != nil {
			return err
		}
		outDir, err := filepath.Abs(*out)
		if err != nil {
			return err
		}
		if priorDir != outDir {
			return fmt.Errorf("append project tests in the report's existing directory to retain prior logs")
		}
		for _, prior := range r.ProjectTests {
			if filepath.Base(prior.LogFile) != prior.LogFile {
				return fmt.Errorf("invalid prior project test log path")
			}
			b, readErr := os.ReadFile(filepath.Join(priorDir, prior.LogFile))
			if readErr != nil || digest(string(b)) != prior.LogSHA256 {
				return fmt.Errorf("prior project test log missing or changed: %s", prior.LogFile)
			}
		}
	}
	if len(r.Sources) == 0 {
		return fmt.Errorf("suite requires audited source evidence")
	}
	rootAbs, err := filepath.Abs(*sourceRoot)
	if err != nil {
		return err
	}
	projectAbs, err := filepath.Abs(*project)
	if err != nil {
		return err
	}
	projectRel, err := filepath.Rel(rootAbs, projectAbs)
	if err != nil || projectRel == ".." || strings.HasPrefix(projectRel, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("test project must be inside audited source root")
	}
	if err := verifySuiteSources(rootAbs, r.Sources); err != nil {
		return err
	}
	if err := os.MkdirAll(*out, 0700); err != nil {
		return err
	}
	log, err := os.CreateTemp(*out, "project-suite-*.log")
	if err != nil {
		return err
	}
	logPath := log.Name()
	logName := filepath.Base(logPath)
	bounded := &boundedLog{w: log, remaining: 2 * 1024 * 1024}
	start := time.Now().UTC()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	executable := command[0]
	if strings.HasPrefix(executable, "."+string(os.PathSeparator)) {
		executable = filepath.Join(projectAbs, executable)
	}
	cmd := exec.CommandContext(ctx, executable, command[1:]...)
	cmd.Dir = projectAbs
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "CI=true", "HARDHAT_DISABLE_TELEMETRY_PROMPT=true", "FOUNDRY_FFI=false", "FOUNDRY_FS_PERMISSIONS=[]"}
	if tmp := os.Getenv("TMPDIR"); tmp != "" {
		cmd.Env = append(cmd.Env, "TMPDIR="+tmp)
	}
	cmd.Stdout, cmd.Stderr = bounded, bounded
	runErr := cmd.Run()
	if closeErr := log.Close(); closeErr != nil {
		return closeErr
	}
	logData, err := os.ReadFile(logPath)
	if err != nil {
		return err
	}
	status, exitCode := "completed", 0
	if runErr != nil {
		status, exitCode = "failed", -1
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		}
		if ctx.Err() != nil {
			status = "error"
		}
	}
	passed, pending, failed := 0, 0, 0
	var resultErr error
	if *resultFormat == "mocha-spec" {
		if bounded.truncated {
			resultErr = fmt.Errorf("test log truncated before result verification")
		} else {
			passed, pending, failed, resultErr = mochaSpecResults(logData)
		}
		if runErr == nil {
			if resultErr != nil {
				status = "error"
			} else {
				status = "passed"
			}
		}
	}
	sourceErr := verifySuiteSources(rootAbs, r.Sources)
	if sourceErr != nil {
		status = "error"
	}
	resultError := ""
	if resultErr != nil {
		resultError = resultErr.Error()
	}
	r.ProjectTests = append(r.ProjectTests, ProjectTestRun{
		Status: status, Project: filepath.ToSlash(projectRel), Command: command,
		StartedAt: start.Format(time.RFC3339), DurationMs: time.Since(start).Milliseconds(),
		ExitCode: exitCode, LogFile: logName, LogSHA256: digest(string(logData)), Truncated: bounded.truncated,
		ResultFormat: *resultFormat, PassedTests: passed, PendingTests: pending, FailedTests: failed, ResultError: resultError,
	})
	if err := saveReport(*out, r); err != nil {
		return err
	}
	fmt.Fprintf(w, "Project suite %s; saved report and %s to %s\n", status, logName, *out)
	if sourceErr != nil {
		return sourceErr
	}
	if runErr != nil {
		return fmt.Errorf("project suite %s: %w; inspect %s", status, runErr, logPath)
	}
	if resultErr != nil {
		return fmt.Errorf("project suite result unverified: %w; inspect %s", resultErr, logPath)
	}
	return nil
}

func verifySuiteSources(root string, sources map[string]Source) error {
	for name, source := range sources {
		if !safeSourcePath(name) {
			return fmt.Errorf("invalid audited source path")
		}
		b, readErr := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		if readErr != nil || digest(string(b)) != source.SHA256 {
			return fmt.Errorf("audited source changed or unavailable: %s; rerun audit", name)
		}
	}
	return nil
}
