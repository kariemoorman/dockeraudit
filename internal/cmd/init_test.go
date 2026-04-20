package cmd

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUserConfigPath_XDG(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/custom/xdg")

	got, err := userConfigPath()
	if err != nil {
		t.Fatalf("userConfigPath() error: %v", err)
	}
	want := filepath.Join("/custom/xdg", "dockeraudit", "dockeraudit.yaml")
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestUserConfigPath_HomeFallback(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "/fake/home")

	got, err := userConfigPath()
	if err != nil {
		t.Fatalf("userConfigPath() error: %v", err)
	}
	want := filepath.Join("/fake/home", ".config", "dockeraudit", "dockeraudit.yaml")
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// runInit executes the init command with the given args and returns captured
// stdout plus any RunE error. The command writes using c.OutOrStdout(), so
// SetOut fully captures the success message without touching the real stdout.
func runInit(t *testing.T, args ...string) (string, error) {
	t.Helper()
	c := NewInitCmd()
	var buf bytes.Buffer
	c.SetOut(&buf)
	c.SetErr(io.Discard)
	c.SetArgs(args)
	err := c.Execute()
	return buf.String(), err
}

func TestInitCmd_FreshWrite(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	out, err := runInit(t)
	if err != nil {
		t.Fatalf("init failed: %v", err)
	}

	path := filepath.Join(dir, "dockeraudit", "dockeraudit.yaml")
	got, err := os.ReadFile(path) // #nosec G304 -- test-constructed path
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if !bytes.Equal(got, embeddedExampleConfig) {
		t.Errorf("written config does not match embedded example (%d vs %d bytes)", len(got), len(embeddedExampleConfig))
	}
	if !strings.Contains(out, path) {
		t.Errorf("success message does not mention path; got: %s", out)
	}
}

func TestInitCmd_CreatesParentDir(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "a", "b", "c") // does not exist yet
	t.Setenv("XDG_CONFIG_HOME", nested)

	if _, err := runInit(t); err != nil {
		t.Fatalf("init failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(nested, "dockeraudit", "dockeraudit.yaml")); err != nil {
		t.Errorf("expected config at nested XDG path, got: %v", err)
	}
}

func TestInitCmd_RefuseOverwrite(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	// First run succeeds.
	if _, err := runInit(t); err != nil {
		t.Fatalf("first init failed: %v", err)
	}

	// Stamp the file so we can detect whether a second run overwrote it.
	path := filepath.Join(dir, "dockeraudit", "dockeraudit.yaml")
	sentinel := []byte("# user edits — do not clobber\n")
	if err := os.WriteFile(path, sentinel, 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := runInit(t)
	if err == nil {
		t.Fatal("expected error when config already exists, got nil")
	}
	if !strings.Contains(err.Error(), "--force") {
		t.Errorf("error should mention --force, got: %v", err)
	}

	got, err := os.ReadFile(path) // #nosec G304 -- test-constructed path
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, sentinel) {
		t.Error("refused run still overwrote the file")
	}
}

func TestInitCmd_Force(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	path := filepath.Join(dir, "dockeraudit", "dockeraudit.yaml")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("# stale\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := runInit(t, "--force"); err != nil {
		t.Fatalf("init --force failed: %v", err)
	}

	got, err := os.ReadFile(path) // #nosec G304 -- test-constructed path
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, embeddedExampleConfig) {
		t.Error("--force did not replace file contents with embedded example")
	}
}

func TestInitCmd_HonorsHomeFallback(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", "") // force HOME fallback
	t.Setenv("HOME", dir)

	if _, err := runInit(t); err != nil {
		t.Fatalf("init failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".config", "dockeraudit", "dockeraudit.yaml")); err != nil {
		t.Errorf("expected config under HOME fallback path, got: %v", err)
	}
}
