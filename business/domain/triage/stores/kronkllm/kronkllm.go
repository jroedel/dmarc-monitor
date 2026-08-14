// Package kronkllm implements the triage Explainer against a local model
// served by kronk (github.com/ardanlabs/kronk).
//
// Kronk serves models on localhost with an OpenAI-compatible Chat Completions
// API, so this is a small HTTP client rather than a dependency: one struct in,
// one string out, no SDK, no vendored model runtime, and the same code works
// against llama.cpp's server or Ollama if the model moves.
//
// What it is allowed to do is deliberately tiny. The verdict handed to Explain
// is already final — severities graded, findings chosen, cooldowns applied —
// and the only thing that comes back is a paragraph of prose that gets printed
// above the findings. The model cannot raise an alert, silence one, or change
// what an alert says happened. That constraint is the reason a local model is
// safe to put in this path at all: the worst failure is an alert with a clumsy
// opening paragraph, which is strictly better than the same alert without one.
//
// Nothing sent here leaves the machine. The prompt contains domain names, IP
// addresses and message counts from the reports — which is why the endpoint
// defaults to loopback and this package has no notion of an API key.
package kronkllm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jroedel/dmarc-monitor/business/domain/triage/triagebus"
)

// Config is where the model is and how patient to be with it.
type Config struct {
	// Endpoint is the server's base URL — http://127.0.0.1:11435 for a local
	// kronk. The chat-completions path is appended.
	Endpoint string

	// Model is the served model's id, as kronk knows it.
	Model string

	// Timeout bounds one request. A local model on CPU is slow; a model that is
	// slower than this is one the alert goes out without.
	Timeout time.Duration
}

// Client is an Explainer backed by a local model.
type Client struct {
	cfg  Config
	http *http.Client
}

const (
	defaultTimeout = 2 * time.Minute
	chatPath       = "/v1/chat/completions"

	// maxNarrative bounds what is pasted into an email. A model that decides to
	// write an essay must not be able to turn a high-signal alert into a wall
	// of text — the findings below it are what matter.
	maxNarrative = 1500
)

// NewClient constructs the explainer. It does not contact the server; a model
// that is not running should cost the program a warning at alert time, not a
// failure at startup.
func NewClient(cfg Config) *Client {
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}
	cfg.Endpoint = strings.TrimSuffix(cfg.Endpoint, "/")

	return &Client{
		cfg:  cfg,
		http: &http.Client{Timeout: cfg.Timeout},
	}
}

// Explain asks the model to write the opening paragraph of the alert.
func (c *Client) Explain(ctx context.Context, v triagebus.Verdict) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()

	body, err := json.Marshal(chatRequest{
		Model:       c.cfg.Model,
		Temperature: 0.2,
		Stream:      false,
		Messages: []chatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: toPrompt(v)},
		},
	})
	if err != nil {
		return "", fmt.Errorf("kronkllm: encoding request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.Endpoint+chatPath, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("kronkllm: building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("kronkllm: calling %s: %w", c.cfg.Endpoint, err)
	}
	defer resp.Body.Close()

	payload, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("kronkllm: reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("kronkllm: %s returned %s: %s", c.cfg.Endpoint, resp.Status, truncate(string(payload), 200))
	}

	var decoded chatResponse
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return "", fmt.Errorf("kronkllm: decoding response: %w", err)
	}

	if len(decoded.Choices) == 0 {
		return "", fmt.Errorf("kronkllm: model returned no choices")
	}

	narrative := strings.TrimSpace(decoded.Choices[0].Message.Content)
	if narrative == "" {
		return "", fmt.Errorf("kronkllm: model returned an empty narrative")
	}

	return truncate(narrative, maxNarrative), nil
}

// Check verifies the server answers, so an operator can find out the model is
// down at a moment of their choosing rather than during an incident.
func (c *Client) Check(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.Endpoint+"/v1/models", nil)
	if err != nil {
		return fmt.Errorf("kronkllm: building request: %w", err)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("kronkllm: calling %s: %w", c.cfg.Endpoint, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("kronkllm: %s/v1/models returned %s", c.cfg.Endpoint, resp.Status)
	}

	return nil
}

type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Temperature float64       `json:"temperature"`
	Stream      bool          `json:"stream"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatResponse struct {
	Choices []struct {
		Message chatMessage `json:"message"`
	} `json:"choices"`
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}

	return s[:n] + "…"
}
