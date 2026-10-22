package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type githubClient struct {
	base, token string
	http        *http.Client
}
type githubIssue struct {
	Number      int             `json:"number"`
	Body        string          `json:"body"`
	Title       string          `json:"title"`
	URL         string          `json:"html_url"`
	State       string          `json:"state"`
	PullRequest json.RawMessage `json:"pull_request"`
}
type Publication struct {
	ID     string `json:"finding_id"`
	URL    string `json:"url"`
	Action string `json:"action"`
}

var repoPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

func (c *githubClient) call(ctx context.Context, method, path string, body, result any) error {
	var b []byte
	var err error
	if body != nil {
		b, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Content-Type", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("GitHub %s %s returned HTTP %d (check repository access, permissions or rate limits)", method, path, res.StatusCode)
	}
	if result != nil {
		return json.NewDecoder(io.LimitReader(res.Body, 8*1024*1024)).Decode(result)
	}
	return nil
}

func githubToken(ctx context.Context) (string, error) {
	for _, k := range []string{"GH_TOKEN", "GITHUB_TOKEN"} {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v, nil
		}
	}
	// Capture, never print, an existing local gh credential.
	b, err := exec.CommandContext(ctx, "gh", "auth", "token", "--hostname", "github.com").Output()
	if err != nil || strings.TrimSpace(string(b)) == "" {
		return "", fmt.Errorf("publishing requires GH_TOKEN/GITHUB_TOKEN or gh auth login")
	}
	return strings.TrimSpace(string(b)), nil
}

func publishCommand(ctx context.Context, args []string, w io.Writer) error {
	f := flags("publish", w)
	report := f.String("report", "reports/report.json", "Reviewed report JSON")
	repo := f.String("repo", "", "Destination owner/repo (required)")
	min := f.String("min-severity", "Medium", "High, Medium, Low, Informational or Optimization")
	findingID := f.String("finding-id", "", "Publish only one exact finding ID")
	verdict := f.String("verdict", "likely-valid", "AI verdict to publish: likely-valid, needs-review, or all")
	cap := f.Int("max-issues", 20, "Maximum selected findings; excess fails before writing")
	allowPublic := f.Bool("allow-public-destination", false, "Explicitly allow disclosure in a public repository")
	allowUnreviewed := f.Bool("allow-unreviewed", false, "Explicitly publish Slither-only candidates")
	triageFile := f.String("triage-file", "", "Require source-bound human triage decisions before publication")
	allowUntriaged := f.Bool("allow-untriaged", false, "Explicitly bypass the human triage gate")
	if err := parse(f, args); err != nil {
		return err
	}
	if !repoPattern.MatchString(*repo) || !validSeverity(*min) || *cap < 1 || (*verdict != "likely-valid" && *verdict != "needs-review" && *verdict != "all") {
		return fmt.Errorf("require --repo owner/repo, a valid --min-severity, valid --verdict and positive --max-issues")
	}
	if (*triageFile == "") == (!*allowUntriaged) {
		return fmt.Errorf("provide --triage-file or explicitly --allow-untriaged")
	}
	r, err := loadReport(*report)
	if err != nil {
		return err
	}
	if !r.Reviewed && !*allowUnreviewed {
		return fmt.Errorf("report has not completed AI review; run review or explicitly --allow-unreviewed")
	}
	if r.Risk != nil && r.Risk.Status != "passed" {
		return fmt.Errorf("risk stage did not pass; publication blocked")
	}
	selected, err := selectFindings(r, *min, *findingID, *verdict)
	if err != nil {
		return err
	}
	if *triageFile != "" {
		t, err := loadTriage(*triageFile)
		if err != nil {
			return err
		}
		if err := validateTriage(r, t); err != nil {
			return err
		}
		allowed := map[string]bool{}
		for _, d := range t.Decisions {
			allowed[d.FindingID] = d.Disposition == "publish"
		}
		approved := selected[:0]
		for _, finding := range selected {
			if allowed[finding.ID] {
				approved = append(approved, finding)
			}
		}
		selected = approved
	}
	if len(selected) > *cap {
		return fmt.Errorf("%d findings exceed --max-issues %d; no issues written", len(selected), *cap)
	}
	if len(selected) == 0 {
		fmt.Fprintln(w, "No findings meet publication threshold.")
		return nil
	}
	token, err := githubToken(ctx)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	client := githubClient{base: "https://api.github.com", token: token, http: &http.Client{Timeout: 30 * time.Second}}
	receipts, err := client.publish(ctx, *repo, r, selected, *allowPublic)
	// Persist completed operations even if a later API request fails.
	if receipts != nil {
		b, e := json.MarshalIndent(receipts, "", "  ")
		if e == nil {
			e = os.WriteFile(filepath.Join(filepath.Dir(*report), "publication.json"), append(b, '\n'), 0600)
		}
		if e != nil {
			return fmt.Errorf("could not save publication receipt: %w", e)
		}
	}
	for _, p := range receipts {
		fmt.Fprintf(w, "%s %s\n", p.Action, p.URL)
	}
	return err
}

func selectFindings(r Report, min, findingID, verdict string) ([]Finding, error) {
	selected := []Finding{}
	for _, finding := range r.Findings {
		if rank(finding.Severity) < rank(min) || (findingID != "" && finding.ID != findingID) {
			continue
		}
		if r.Reviewed && verdict != "all" && (finding.Review == nil || finding.Review.Verdict != verdict) {
			continue
		}
		selected = append(selected, finding)
	}
	if findingID != "" && len(selected) == 0 {
		return nil, fmt.Errorf("finding ID not found or filtered by severity/verdict")
	}
	return selected, nil
}

func (c *githubClient) publish(ctx context.Context, repo string, r Report, findings []Finding, allowPublic bool) ([]Publication, error) {
	path := "/repos/" + repo
	var meta struct {
		Private bool `json:"private"`
	}
	if err := c.call(ctx, "GET", path, nil, &meta); err != nil {
		return nil, err
	}
	if !meta.Private && !allowPublic {
		return nil, fmt.Errorf("destination is public; use a private destination or explicitly --allow-public-destination")
	}
	existing := map[string]githubIssue{}
	for page := 1; ; page++ {
		var issues []githubIssue
		if err := c.call(ctx, "GET", fmt.Sprintf("%s/issues?state=all&per_page=100&page=%d", path, page), nil, &issues); err != nil {
			return nil, err
		}
		for _, issue := range issues {
			if len(issue.PullRequest) > 0 && string(issue.PullRequest) != "null" {
				continue
			}
			if id := issueMarkerID(issue.Body); id != "" {
				existing[id] = issue
			}
		}
		if len(issues) < 100 {
			break
		}
	}
	labels := map[string]string{"security": "b60205", "audit-signal": "5319e7"}
	for _, f := range findings {
		labels["severity:"+strings.ToLower(f.Severity)] = "d93f0b"
	}
	// List and create only missing labels; do not change existing repository labels.
	known := map[string]bool{}
	for page := 1; ; page++ {
		var ls []struct {
			Name string `json:"name"`
		}
		if err := c.call(ctx, "GET", fmt.Sprintf("%s/labels?per_page=100&page=%d", path, page), nil, &ls); err != nil {
			return nil, err
		}
		for _, l := range ls {
			known[l.Name] = true
		}
		if len(ls) < 100 {
			break
		}
	}
	for name, color := range labels {
		if !known[name] {
			if err := c.call(ctx, "POST", path+"/labels", map[string]string{"name": name, "color": color}, nil); err != nil {
				return nil, err
			}
		}
	}
	receipts := []Publication{}
	for _, finding := range findings {
		title := fmt.Sprintf("[Security][%s] %s", finding.Severity, finding.Check)
		body := issueBody(r, finding)
		if len(body) > 60000 {
			return receipts, fmt.Errorf("issue body too large for %s", finding.ID)
		}
		labels := []string{"security", "audit-signal", "severity:" + strings.ToLower(finding.Severity)}
		old, ok := existing[finding.ID]
		if ok {
			if old.State == "closed" {
				receipts = append(receipts, Publication{finding.ID, old.URL, "closed-existing"})
				continue
			}
			if old.Body == body && old.Title == title {
				receipts = append(receipts, Publication{finding.ID, old.URL, "unchanged"})
				continue
			}
			var updated githubIssue
			// Preserve human labels by only adding our labels using the labels endpoint.
			if err := c.call(ctx, "PATCH", fmt.Sprintf("%s/issues/%d", path, old.Number), map[string]string{"title": title, "body": body}, &updated); err != nil {
				return receipts, err
			}
			receipts = append(receipts, Publication{finding.ID, updated.URL, "updated"})
			if err := c.call(ctx, "POST", fmt.Sprintf("%s/issues/%d/labels", path, old.Number), map[string]any{"labels": labels}, nil); err != nil {
				return receipts, err
			}
		} else {
			var created githubIssue
			if err := c.call(ctx, "POST", path+"/issues", map[string]any{"title": title, "body": body, "labels": labels}, &created); err != nil {
				return receipts, err
			}
			receipts = append(receipts, Publication{finding.ID, created.URL, "created"})
			existing[finding.ID] = created
		}
	}
	return receipts, nil
}

// Keep recognizing issues created before the product rename, so a new release
// updates them instead of opening a duplicate for the same finding ID.
func issueMarkerID(body string) string {
	for _, prefix := range []string{"<!-- audit-signal:", "<!-- slither-agent:"} {
		if !strings.HasPrefix(body, prefix) {
			continue
		}
		end := strings.Index(body, " -->")
		if end < 0 {
			return ""
		}
		id := strings.TrimPrefix(body[:end], prefix)
		if len(id) == 64 {
			return id
		}
	}
	return ""
}
