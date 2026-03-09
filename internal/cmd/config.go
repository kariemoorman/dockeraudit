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

// defaultConfigPaths is the ordered list of paths to search for a config file.
var defaultConfigPaths = []string{
	".dockeraudit.yaml",
	".dockeraudit.yml",
}

// LoadConfig reads the configuration from the given path, or searches
// defaultConfigPaths if path is empty. Returns nil (no error) if no config
// file is found.
func LoadConfig(path string) (*Config, error) {
	if path != "" {
		return loadConfigFile(path)
	}
	// Search default paths
	for _, p := range defaultConfigPaths {
		if _, err := os.Stat(p); err == nil {
			return loadConfigFile(p)
		}
	}
	return nil, nil // no config file found, not an error
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
