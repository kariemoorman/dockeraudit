package cmd

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config represents the contents of a .dockeraudit.yaml configuration file.
// CLI flags always override values from the config file.
type Config struct {
	Format       string   `yaml:"format"`
	FailOn       string   `yaml:"fail-on"`
	ExcludeCheck []string `yaml:"exclude-check"`
	IncludeCheck []string `yaml:"include-check"`
	EOLFile      string   `yaml:"eol-file"`
	Verbose      bool     `yaml:"verbose"`
	Scanner      []string `yaml:"scanner"`
}

// LoadedConfig holds the config loaded during PersistentPreRunE.
// Subcommand RunE handlers read from this to apply config-file defaults
// when the corresponding CLI flag was not explicitly set.
var LoadedConfig *Config

// LoadConfig reads the configuration from the given path, or falls back to
// the user-level XDG config path ($XDG_CONFIG_HOME/dockeraudit/dockeraudit.yaml,
// or ~/.config/dockeraudit/dockeraudit.yaml) when path is empty. Returns nil
// (no error) if no config file is found.
func LoadConfig(path string) (*Config, error) {
	if path != "" {
		return loadConfigFile(path)
	}
	userPath, err := userConfigPath()
	if err != nil {
		return nil, nil //nolint:nilerr // home-dir lookup failure just means no global config
	}
	if _, err := os.Stat(userPath); err != nil {
		return nil, nil //nolint:nilerr // missing global config is not an error
	}
	return loadConfigFile(userPath)
}

func loadConfigFile(path string) (*Config, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- user-supplied config path
	if err != nil {
		return nil, fmt.Errorf("read config file %s: %w", path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config file %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config file %s: %w", path, err)
	}
	return &cfg, nil
}

// Validate checks that the Config fields contain valid values.
// It reuses the validFormats and validFailOn maps declared in commands.go.
func (c *Config) Validate() error {
	if c.Format != "" {
		if !validFormats[strings.ToLower(c.Format)] {
			return fmt.Errorf("invalid format %q; must be one of: table, json, markdown, sarif, junit", c.Format)
		}
	}
	if c.FailOn != "" {
		if !validFailOn[strings.ToLower(c.FailOn)] {
			return fmt.Errorf("invalid fail-on %q; must be one of: critical, high, medium, low", c.FailOn)
		}
	}
	for _, s := range c.Scanner {
		if !validScanners[strings.ToLower(s)] {
			return fmt.Errorf("invalid scanner %q; must be one of: trivy, snyk, none", s)
		}
	}
	return nil
}
