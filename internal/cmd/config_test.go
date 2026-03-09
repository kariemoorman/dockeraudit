package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
)

func TestLoadConfig_ExplicitPath(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "custom.yaml")
	content := `
format: json
fail-on: medium
exclude-check:
  - IMAGE-001
  - K8S-003
include-check:
  - IMAGE-001
  - IMAGE-005
eol-file: /tmp/eol.json
verbose: true
`
	if err := os.WriteFile(cfgPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig(%q) error: %v", cfgPath, err)
	}
	if cfg == nil {
		t.Fatal("LoadConfig returned nil config")
	}

	if cfg.Format != "json" {
		t.Errorf("Format = %q, want %q", cfg.Format, "json")
	}
	if cfg.FailOn != "medium" {
		t.Errorf("FailOn = %q, want %q", cfg.FailOn, "medium")
	}
	if len(cfg.ExcludeCheck) != 2 {
		t.Errorf("ExcludeCheck has %d entries, want 2", len(cfg.ExcludeCheck))
	}
	if len(cfg.IncludeCheck) != 2 {
		t.Errorf("IncludeCheck has %d entries, want 2", len(cfg.IncludeCheck))
	}
	if cfg.EOLFile != "/tmp/eol.json" {
		t.Errorf("EOLFile = %q, want %q", cfg.EOLFile, "/tmp/eol.json")
	}
	if !cfg.Verbose {
		t.Error("Verbose = false, want true")
	}
}

func TestLoadConfig_DefaultPath(t *testing.T) {
	// Create a temp directory with a .dockeraudit.yaml and chdir into it.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".dockeraudit.yaml")
	content := `format: sarif
fail-on: critical
`
	if err := os.WriteFile(cfgPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	// Save and restore cwd.
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(origDir) })

	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig(\"\") error: %v", err)
	}
	if cfg == nil {
		t.Fatal("LoadConfig returned nil — should have found .dockeraudit.yaml")
	}
	if cfg.Format != "sarif" {
		t.Errorf("Format = %q, want %q", cfg.Format, "sarif")
	}
	if cfg.FailOn != "critical" {
		t.Errorf("FailOn = %q, want %q", cfg.FailOn, "critical")
	}
}

func TestLoadConfig_YMLExtension(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".dockeraudit.yml")
	content := `format: markdown
`
	if err := os.WriteFile(cfgPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(origDir) })

	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig(\"\") error: %v", err)
	}
	if cfg == nil {
		t.Fatal("LoadConfig returned nil — should have found .dockeraudit.yml")
	}
	if cfg.Format != "markdown" {
		t.Errorf("Format = %q, want %q", cfg.Format, "markdown")
	}
}

func TestLoadConfig_NoConfigFile(t *testing.T) {
	dir := t.TempDir()

	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(origDir) })

	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig(\"\") error: %v", err)
	}
	if cfg != nil {
		t.Error("LoadConfig should return nil when no config file exists")
	}
}

func TestLoadConfig_MissingExplicitPath(t *testing.T) {
	_, err := LoadConfig("/nonexistent/path/config.yaml")
	if err == nil {
		t.Error("LoadConfig should return error for missing explicit path")
	}
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bad.yaml")
	// Use a YAML document that cannot be unmarshalled into Config (mapping where scalar expected).
	if err := os.WriteFile(cfgPath, []byte("format:\n  - nested:\n      bad: [}"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadConfig(cfgPath)
	if err == nil {
		t.Error("LoadConfig should return error for invalid YAML")
	}
}

func TestLoadConfig_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "empty.yaml")
	if err := os.WriteFile(cfgPath, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig error: %v", err)
	}
	if cfg == nil {
		t.Fatal("LoadConfig returned nil for empty file")
	}
	// All fields should be zero values.
	if cfg.Format != "" {
		t.Errorf("Format = %q, want empty", cfg.Format)
	}
	if cfg.Verbose {
		t.Error("Verbose should be false for empty file")
	}
}

func TestLoadConfig_PartialConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "partial.yaml")
	content := `fail-on: low
`
	if err := os.WriteFile(cfgPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig error: %v", err)
	}
	if cfg.FailOn != "low" {
		t.Errorf("FailOn = %q, want %q", cfg.FailOn, "low")
	}
	// Unset fields should be zero values.
	if cfg.Format != "" {
		t.Errorf("Format = %q, want empty", cfg.Format)
	}
	if len(cfg.ExcludeCheck) != 0 {
		t.Errorf("ExcludeCheck = %v, want empty", cfg.ExcludeCheck)
	}
}

func TestApplyConfigDefaults(t *testing.T) {
	// Save and restore LoadedConfig.
	origConfig := LoadedConfig
	t.Cleanup(func() { LoadedConfig = origConfig })

	t.Run("nil config is no-op", func(t *testing.T) {
		LoadedConfig = nil
		format, failOn := "table", "high"
		var exclude, include []string

		// Create a minimal cobra command to test.
		cmd := &cobra.Command{}
		cmd.Flags().String("format", "table", "")
		cmd.Flags().String("fail-on", "high", "")
		cmd.Flags().StringSlice("exclude-check", nil, "")
		cmd.Flags().StringSlice("include-check", nil, "")

		applyConfigDefaults(cmd, &format, &failOn, &exclude, &include)
		if format != "table" {
			t.Errorf("format = %q, want table", format)
		}
		if failOn != "high" {
			t.Errorf("failOn = %q, want high", failOn)
		}
	})

	t.Run("config applied when flags unchanged", func(t *testing.T) {
		LoadedConfig = &Config{
			Format:       "json",
			FailOn:       "low",
			ExcludeCheck: []string{"IMAGE-001"},
			IncludeCheck: []string{"K8S-001"},
		}
		format, failOn := "table", "high"
		var exclude, include []string

		cmd := &cobra.Command{}
		cmd.Flags().String("format", "table", "")
		cmd.Flags().String("fail-on", "high", "")
		cmd.Flags().StringSlice("exclude-check", nil, "")
		cmd.Flags().StringSlice("include-check", nil, "")

		applyConfigDefaults(cmd, &format, &failOn, &exclude, &include)
		if format != "json" {
			t.Errorf("format = %q, want json", format)
		}
		if failOn != "low" {
			t.Errorf("failOn = %q, want low", failOn)
		}
		if len(exclude) != 1 || exclude[0] != "IMAGE-001" {
			t.Errorf("exclude = %v, want [IMAGE-001]", exclude)
		}
		if len(include) != 1 || include[0] != "K8S-001" {
			t.Errorf("include = %v, want [K8S-001]", include)
		}
	})

	t.Run("CLI flags override config", func(t *testing.T) {
		LoadedConfig = &Config{
			Format: "json",
			FailOn: "low",
		}
		format, failOn := "sarif", "critical"
		var exclude, include []string

		cmd := &cobra.Command{}
		cmd.Flags().String("format", "table", "")
		cmd.Flags().String("fail-on", "high", "")
		cmd.Flags().StringSlice("exclude-check", nil, "")
		cmd.Flags().StringSlice("include-check", nil, "")
		// Mark flags as changed (simulating CLI input).
		_ = cmd.Flags().Set("format", "sarif")
		_ = cmd.Flags().Set("fail-on", "critical")

		applyConfigDefaults(cmd, &format, &failOn, &exclude, &include)
		if format != "sarif" {
			t.Errorf("format = %q, want sarif (CLI override)", format)
		}
		if failOn != "critical" {
			t.Errorf("failOn = %q, want critical (CLI override)", failOn)
		}
	})

	t.Run("empty config values are not applied", func(t *testing.T) {
		LoadedConfig = &Config{
			// All zero values — nothing to apply.
		}
		format, failOn := "table", "high"
		var exclude, include []string

		cmd := &cobra.Command{}
		cmd.Flags().String("format", "table", "")
		cmd.Flags().String("fail-on", "high", "")
		cmd.Flags().StringSlice("exclude-check", nil, "")
		cmd.Flags().StringSlice("include-check", nil, "")

		applyConfigDefaults(cmd, &format, &failOn, &exclude, &include)
		if format != "table" {
			t.Errorf("format = %q, want table (zero-value not applied)", format)
		}
		if failOn != "high" {
			t.Errorf("failOn = %q, want high (zero-value not applied)", failOn)
		}
	})
}

func TestConfig_Validate_InvalidFormat(t *testing.T) {
	cfg := &Config{Format: "xml"}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for invalid format 'xml'")
	}
}

func TestConfig_Validate_InvalidFailOn(t *testing.T) {
	cfg := &Config{FailOn: "extreme"}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for invalid fail-on 'extreme'")
	}
}

func TestConfig_Validate_Valid(t *testing.T) {
	cfg := &Config{Format: "json", FailOn: "high"}
	if err := cfg.Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestConfig_Validate_Empty(t *testing.T) {
	cfg := &Config{}
	if err := cfg.Validate(); err != nil {
		t.Errorf("empty config should be valid: %v", err)
	}
}
