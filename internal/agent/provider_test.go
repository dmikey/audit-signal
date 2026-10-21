package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestProviderRequestsAndResponses(t *testing.T) {
	for _, tc := range []struct {
		provider string
		response string
	}{
		{"openai", `{"status":"completed","output":[{"type":"message","content":[{"type":"output_text","text":"{\"findings\":[]}"}]}]}`},
		{"anthropic", `{"stop_reason":"end_turn","content":[{"type":"text","text":"{\"findings\":[]}"}]}`},
	} {
		t.Run(tc.provider, func(t *testing.T) {
			const key = "secret-test-provider-key"
			client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.Method != http.MethodPost || req.Header.Get("Content-Type") != "application/json" {
					t.Fatal("bad request")
				}
				if tc.provider == "openai" && req.Header.Get("Authorization") != "Bearer "+key {
					t.Fatal("OpenAI key missing")
				}
				if tc.provider == "anthropic" && (req.Header.Get("x-api-key") != key || req.Header.Get("anthropic-version") == "") {
					t.Fatal("Anthropic headers missing")
				}
				body, _ := io.ReadAll(req.Body)
				var payload map[string]any
				if err := json.Unmarshal(body, &payload); err != nil {
					t.Fatal(err)
				}
				if payload["model"] != "chosen-model" || strings.Contains(string(body), key) || !strings.Contains(string(body), "private Solidity source") {
					t.Fatal("incorrect provider payload")
				}
				if _, ok := payload["tools"]; ok {
					t.Fatal("tools must not be exposed")
				}
				if tc.provider == "openai" && (payload["store"] != false || payload["tool_choice"] != "none") {
					t.Fatal("OpenAI safety options missing")
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(tc.response)), Header: make(http.Header)}, nil
			})}
			got, err := callProvider(context.Background(), client, "https://example.test/api", tc.provider, key, "chosen-model", "private Solidity source")
			if err != nil || string(got) != `{"findings":[]}` {
				t.Fatalf("response: %q, %v", got, err)
			}
		})
	}
}

func TestProviderFailsClosedWithoutExposingSecrets(t *testing.T) {
	for _, tc := range []struct {
		provider, response string
		status             int
	}{
		{"openai", `{"status":"incomplete","output":[{"type":"message","content":[{"type":"output_text","text":"{}"}]}]}`, 200},
		{"anthropic", `{"stop_reason":"max_tokens","content":[{"type":"text","text":"{}"}]}`, 200},
		{"openai", `secret-test-provider-key private source`, 401},
	} {
		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.response)), Header: make(http.Header)}, nil
		})}
		_, err := callProvider(context.Background(), client, "https://example.test/api", tc.provider, "secret-test-provider-key", "chosen-model", "private source")
		if err == nil || strings.Contains(err.Error(), "secret-test-provider-key") || strings.Contains(err.Error(), "private source") {
			t.Fatalf("unsafe error: %v", err)
		}
	}
	if err := validateProvider("openai", "auto"); err == nil {
		t.Fatal("OpenAI auto model accepted")
	}
}

func TestEvidenceLayersUseSelectedProviders(t *testing.T) {
	r := Report{Provider: "anthropic", Model: "chosen-review", DiscoveryProvider: "openai", DiscoveryModel: "chosen-discovery"}
	f := Finding{Origin: "ai-discovery", Review: &Review{Verdict: "needs-review"}}
	layers := findingEvidenceLayers(r, f)
	if layers[0].Tool != "openai" || layers[0].Model != "chosen-discovery" || layers[1].Tool != "anthropic" || layers[1].Model != "chosen-review" {
		t.Fatalf("incorrect layers: %+v", layers)
	}
	// Legacy reports without explicit provider fields retain their original Copilot attribution.
	r.Provider, r.DiscoveryProvider = "", ""
	layers = findingEvidenceLayers(r, f)
	if layers[0].Tool != "copilot" || layers[1].Tool != "copilot" {
		t.Fatalf("legacy layers changed: %+v", layers)
	}
}
