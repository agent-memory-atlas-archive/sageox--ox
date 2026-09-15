package attestpublication

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const maxControlBytes = 7168

type CreateRequest struct {
	SourceRunID      string `json:"source_run_id"`
	CorpusKey        string `json:"corpus_key"`
	PackageVersion   string `json:"package_version"`
	ManifestSHA256   string `json:"manifest_sha256"`
	ArchiveSHA256    string `json:"archive_sha256"`
	ArchiveSizeBytes int64  `json:"archive_size_bytes"`
}
type Credentials struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token"`
}
type Grant struct {
	Bucket          string      `json:"bucket"`
	Key             string      `json:"key"`
	Region          string      `json:"region"`
	Credentials     Credentials `json:"credentials"`
	ExpiresAt       time.Time   `json:"expires_at"`
	IntentExpiresAt time.Time   `json:"intent_expires_at"`
	Binding         Binding     `json:"binding"`
}
type Binding struct {
	ManifestSHA256   string `json:"manifest_sha256"`
	ArchiveSHA256    string `json:"archive_sha256"`
	ArchiveSizeBytes int64  `json:"archive_size_bytes"`
}
type Run struct {
	RunID       string       `json:"run_id"`
	Status      string       `json:"status"`
	SourceRunID string       `json:"source_run_id"`
	CorpusKey   string       `json:"corpus_key"`
	URL         *string      `json:"url,omitempty"`
	Diagnostics []Diagnostic `json:"diagnostics"`
	Upload      *Grant       `json:"upload,omitempty"`
}
type Diagnostic struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
type APIError struct {
	Status     int
	Code       string
	Message    string
	RetryAfter time.Duration
}

func (e *APIError) Error() string {
	return fmt.Sprintf("attest API %d %s: %s", e.Status, e.Code, e.Message)
}

type ControlClient struct {
	BaseURL, Token string
	HTTP           *http.Client
}

func (c *ControlClient) Create(ctx context.Context, repoID, key string, input CreateRequest) (Run, error) {
	var out struct {
		Data Run `json:"data"`
	}
	err := c.request(ctx, http.MethodPost, fmt.Sprintf("/api/v1/repos/%s/attest/runs", repoID), input, key, &out)
	return out.Data, err
}
func (c *ControlClient) Renew(ctx context.Context, repoID, runID string) (Grant, error) {
	var out struct {
		Data Grant `json:"data"`
	}
	err := c.request(ctx, http.MethodPost, fmt.Sprintf("/api/v1/repos/%s/attest/runs/%s/upload-grants", repoID, runID), nil, "", &out)
	return out.Data, err
}
func (c *ControlClient) Complete(ctx context.Context, repoID, runID string) (Run, error) {
	var out struct {
		Data Run `json:"data"`
	}
	err := c.request(ctx, http.MethodPost, fmt.Sprintf("/api/v1/repos/%s/attest/runs/%s/completions", repoID, runID), nil, "", &out)
	return out.Data, err
}
func (c *ControlClient) Get(ctx context.Context, repoID, runID string) (Run, error) {
	var out struct {
		Data Run `json:"data"`
	}
	err := c.request(ctx, http.MethodGet, fmt.Sprintf("/api/v1/repos/%s/attest/runs/%s", repoID, runID), nil, "", &out)
	return out.Data, err
}
func (c *ControlClient) request(ctx context.Context, method, path string, body any, idempotencyKey string, out any) error {
	var raw []byte
	var err error
	if body != nil {
		raw, err = json.Marshal(body)
		if err != nil {
			return err
		}
		if len(raw) > maxControlBytes {
			return fmt.Errorf("attest control body is %d bytes, exceeds %d-byte limit", len(raw), maxControlBytes)
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(c.BaseURL, "/")+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	responseRaw, err := io.ReadAll(io.LimitReader(resp.Body, maxControlBytes+1))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var payload struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.Unmarshal(responseRaw, &payload)
		apiErr := &APIError{Status: resp.StatusCode, Code: payload.Error.Code, Message: payload.Error.Message}
		if retry, err := time.ParseDuration(resp.Header.Get("Retry-After") + "s"); err == nil {
			apiErr.RetryAfter = retry
		}
		return apiErr
	}
	if out != nil && len(responseRaw) > 0 {
		if err := json.Unmarshal(responseRaw, out); err != nil {
			return fmt.Errorf("decode attest API response: %w", err)
		}
	}
	return nil
}
