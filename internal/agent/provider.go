package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

const maxProviderResponse = 1024 * 1024

func validateProvider(provider, model string) error {
	if strings.TrimSpace(model) == "" || strings.ContainsAny(model, "\r\n") {
		return fmt.Errorf("a valid model is required")
	}
	switch provider {
	case "copilot":
		return nil
	case "openai", "anthropic":
		if model == "auto" {
			return fmt.Errorf("--model must name a model for %s", provider)
		}
		return nil
	default:
		return fmt.Errorf("--provider must be copilot, openai, or anthropic")
	}
}

func runProvider(ctx context.Context, provider, executable, model, prompt string) ([]byte, error) {
	if err := validateProvider(provider, model); err != nil {
		return nil, err
	}
	if provider == "copilot" {
		return runCopilot(ctx, executable, model, prompt)
	}
	endpoint := "https://api.openai.com/v1/responses"
	keyName := "OPENAI_API_KEY"
	if provider == "anthropic" {
		endpoint = "https://api.anthropic.com/v1/messages"
		keyName = "ANTHROPIC_API_KEY"
	}
	key := os.Getenv(keyName)
	if key == "" {
		return nil, fmt.Errorf("%s is required for %s; set it in the environment or GitHub Actions secrets", keyName, provider)
	}
	return callProvider(ctx, http.DefaultClient, endpoint, provider, key, model, prompt)
}

// callProvider accepts an endpoint only for offline HTTP tests. User input cannot
// redirect private source or credentials away from the provider's fixed API host.
func callProvider(ctx context.Context, client *http.Client, endpoint, provider, key, model, prompt string) ([]byte, error) {
	var payload any
	switch provider {
	case "openai":
		payload = map[string]any{"model": model, "input": prompt, "store": false, "tool_choice": "none", "max_output_tokens": 8192, "text": map[string]any{"format": map[string]any{"type": "json_object"}}}
	case "anthropic":
		payload = map[string]any{"model": model, "max_tokens": 8192, "messages": []map[string]string{{"role": "user", "content": prompt}}}
	default:
		return nil, fmt.Errorf("unsupported provider")
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if provider == "openai" {
		req.Header.Set("Authorization", "Bearer "+key)
	} else {
		req.Header.Set("x-api-key", key)
		req.Header.Set("anthropic-version", "2023-06-01")
	}
	// Redirects may disclose both the key and private source to another host.
	copyClient := *client
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := copyClient.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("%s request failed; verify connectivity and provider configuration", provider)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		// Provider error bodies can echo submitted source or credentials.
		return nil, fmt.Errorf("%s returned HTTP %d; verify model, key, access and credits", provider, res.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, maxProviderResponse+1))
	if err != nil {
		return nil, fmt.Errorf("%s response could not be read", provider)
	}
	if len(data) > maxProviderResponse {
		return nil, fmt.Errorf("%s response exceeds 1 MB", provider)
	}
	if provider == "openai" {
		var out struct {
			Status string `json:"status"`
			Output []struct {
				Type    string `json:"type"`
				Content []struct {
					Type string `json:"type"`
					Text string `json:"text"`
				} `json:"content"`
			} `json:"output"`
		}
		if json.Unmarshal(data, &out) != nil || out.Status != "completed" {
			return nil, fmt.Errorf("openai response was incomplete or malformed")
		}
		var texts []string
		for _, item := range out.Output {
			if item.Type != "message" {
				continue
			}
			for _, part := range item.Content {
				if part.Type == "output_text" {
					texts = append(texts, part.Text)
				}
			}
		}
		if len(texts) != 1 || strings.TrimSpace(texts[0]) == "" {
			return nil, fmt.Errorf("openai response did not contain one text result")
		}
		return []byte(texts[0]), nil
	}
	var out struct {
		StopReason string `json:"stop_reason"`
		Content    []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if json.Unmarshal(data, &out) != nil || out.StopReason != "end_turn" || len(out.Content) != 1 || out.Content[0].Type != "text" || strings.TrimSpace(out.Content[0].Text) == "" {
		return nil, fmt.Errorf("anthropic response was incomplete or malformed")
	}
	return []byte(out.Content[0].Text), nil
}
