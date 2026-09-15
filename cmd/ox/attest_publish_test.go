package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sageox/ox/internal/auth"
	"github.com/sageox/ox/internal/config"
	"github.com/spf13/cobra"
)

func TestRunAttestPublishUsesCommandContext(t *testing.T) {
	serverRequests := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		serverRequests <- struct{}{}
	}))
	t.Cleanup(server.Close)

	t.Setenv("SAGEOX_TOKEN", "")
	t.Setenv("SAGEOX_ENDPOINT", server.URL)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	projectRoot := testGitRepo(t)
	requireSageoxDir(t, projectRoot)
	if err := config.SaveProjectConfig(projectRoot, &config.ProjectConfig{RepoID: "repo_attest_context", Endpoint: server.URL}); err != nil {
		t.Fatal(err)
	}
	if err := auth.SaveTokenForEndpoint(server.URL, &auth.StoredToken{AccessToken: "test-access-token", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}

	export := filepath.Join(t.TempDir(), "frozen-export")
	if err := os.MkdirAll(filepath.Join(export, "report"), 0o755); err != nil {
		t.Fatal(err)
	}
	source := repoPath("..", "..", "internal", "attestpublication", "contract", "testdata", "conformance", "valid", "run-all-outcomes.json")
	contents, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(export, "run.json"), contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(export, "report", "index.html"), []byte("<h1>frozen</h1>"), 0o600); err != nil {
		t.Fatal(err)
	}

	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(projectRoot); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cmd := &cobra.Command{}
	cmd.SetContext(ctx)
	cmd.Flags().String("from", export, "")
	cmd.Flags().String("out", filepath.Join(t.TempDir(), "publication"), "")
	if err := runAttestPublish(cmd, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("runAttestPublish() error = %v, want context canceled", err)
	}
	select {
	case <-serverRequests:
		t.Fatal("publish control request ignored the canceled command context")
	default:
	}
}
