package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/sageox/ox/internal/constants"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExtractOxCommands_AgentHookFallback proves the off-PATH diagnostic added
// to every hook command's else-branch (internal/constants/agent.go's
// oxNotOnPathFallback) does not introduce a false positive in the doctor's
// hook-command validator. Before this test existed, the constraint was
// checked by hand; this pins it so a future edit to the fallback text can't
// silently reintroduce a false "invalid command" warning.
func TestExtractOxCommands_AgentHookFallback(t *testing.T) {
	commands := []string{
		constants.OxPrimeCommand,
		constants.OxPrimeCommandClaudeCode,
		constants.OxPrimeCommandClaudeCodeIdempotent,
		constants.OxPrimeCommandGemini,
		constants.OxPrimeCommandAmp,
		constants.OxPrimeCommandPi,
		fmt.Sprintf(constants.OxHookCommandClaudeCodeTemplate, "SessionStart"),
		fmt.Sprintf(constants.OxHookCommandCodexTemplate, "SessionStart"),
		fmt.Sprintf(constants.OxHookCommandGeminiTemplate, "SessionStart"),
	}

	for _, cmd := range commands {
		extracted := extractOxCommands(cmd)
		require.NotEmpty(t, extracted, "expected at least one ox command extracted from %q", cmd)
		for _, e := range extracted {
			assert.True(t, isValidOxCommand(e),
				"hook command fallback text produced a false-positive invalid command %q from %q", e, cmd)
		}
	}
}

// TestCheckHookCommands_AgentHookFallback drives the real checkHookCommands
// doctor check end-to-end against a settings.json using the updated
// Claude Code hook constant, proving the longer off-PATH else-branch still
// reads as a clean, valid hook to `ox doctor`.
func TestCheckHookCommands_AgentHookFallback(t *testing.T) {
	tempHome := t.TempDir()
	claudeDir := filepath.Join(tempHome, ".claude")
	require.NoError(t, os.MkdirAll(claudeDir, 0755))

	settings := map[string]interface{}{
		"hooks": map[string]interface{}{
			"SessionStart": []interface{}{
				map[string]interface{}{
					"matcher": "",
					"hooks": []interface{}{
						map[string]interface{}{
							"type":    "command",
							"command": constants.OxPrimeCommandClaudeCode,
						},
					},
				},
			},
		},
	}
	data, err := json.MarshalIndent(settings, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(claudeDir, "settings.json"), data, 0644))

	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tempHome)
	defer os.Setenv("HOME", originalHome)

	result := checkHookCommands()

	assert.True(t, result.passed, "expected passed result, got passed=%v warning=%v detail=%s", result.passed, result.warning, result.detail)
	assert.False(t, result.warning, "expected no warning for the off-PATH fallback text, got detail=%s", result.detail)
}

func TestOffPathFallback_DoesNotRecommendMutableInstaller(t *testing.T) {
	fallbacks := map[string]string{
		"agent hook": constants.OxPrimeCommandClaudeCode,
		"git hook":   oxGitHookNotOnPathFallback,
	}

	for name, fallback := range fallbacks {
		t.Run(name, func(t *testing.T) {
			assert.Contains(t, fallback, "brew install sageox/tap/ox")
			assert.NotContains(t, fallback, "curl")
			assert.NotContains(t, fallback, "github.com/sageox/ox#install")
		})
	}
}

// TestOffPathFallback_FishRecoveryLineSurvivesSpaces runs both off-PATH
// fallbacks under a fish $SHELL with ox installed in a directory containing a
// space. The zsh/bash branches interpolate inside `export PATH="..."`, so a
// spaced directory survives being copied; the fish branch emitted the
// directory bare, so fish received three arguments and added two wrong
// directories — the one recovery instruction an off-PATH user is given
// silently failed for exactly the user who needed it. Drives `sh` rather than
// asserting on the constant so the shell's own quoting is what's tested.
func TestOffPathFallback_FishRecoveryLineSurvivesSpaces(t *testing.T) {
	binDir := filepath.Join(t.TempDir(), "Go Tools", "bin")
	require.NoError(t, os.MkdirAll(binDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(binDir, "ox"), []byte("#!/bin/sh\n"), 0755))

	cases := []struct {
		name   string
		script string
	}{
		{"agent hook", constants.OxPrimeCommandClaudeCode},
		// The git-hook fallback is an else-branch; give it the `if` it expects.
		{"git hook", "if command -v ox >/dev/null 2>&1; then :\n" + oxGitHookNotOnPathFallback},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("sh", "-c", tc.script)
			cmd.Env = []string{
				// no ox on PATH: this is the branch under test
				"PATH=/usr/bin:/bin",
				"HOME=" + t.TempDir(),
				"GOBIN=" + binDir,
				"SHELL=/usr/bin/fish",
			}
			out, err := cmd.CombinedOutput()
			require.NoError(t, err, "fallback exited non-zero: %s", out)

			assert.Contains(t, string(out), `fish_add_path -- "`+binDir+`"`,
				"fish recovery line must pass the install directory to fish as one argument, got:\n%s", out)
		})
	}
}
