package cmd

import (
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

//go:embed dockeraudit.example.yaml
var embeddedExampleConfig []byte

// userConfigPath returns the XDG-style path for the global dockeraudit config:
// $XDG_CONFIG_HOME/dockeraudit/dockeraudit.yaml, falling back to
// $HOME/.config/dockeraudit/dockeraudit.yaml. 
func userConfigPath() (string, error) {
	if base := os.Getenv("XDG_CONFIG_HOME"); base != "" {
		return filepath.Join(base, "dockeraudit", "dockeraudit.yaml"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	return filepath.Join(home, ".config", "dockeraudit", "dockeraudit.yaml"), nil
}

func NewInitCmd() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Write a default dockeraudit config to ~/.config/dockeraudit/dockeraudit.yaml",
		Long: `Create a default dockeraudit configuration file at
$XDG_CONFIG_HOME/dockeraudit/dockeraudit.yaml (or ~/.config/dockeraudit/dockeraudit.yaml
when XDG_CONFIG_HOME is unset). The file contents are the annotated example bundled
with the binary, so users installing via ` + "`go install`" + ` or a release archive get
the same reference config as the repository.

The config is picked up automatically whenever --config is not passed.`,
		Example: `  dockeraudit init
  dockeraudit init --force`,
		RunE: func(c *cobra.Command, _ []string) error {
			path, err := userConfigPath()
			if err != nil {
				return err
			}
			if _, err := os.Stat(path); err == nil && !force {
				return fmt.Errorf("config already exists at %s (use --force to overwrite)", path)
			} else if err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("stat %s: %w", path, err)
			}
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				return fmt.Errorf("create config directory: %w", err)
			}
			if err := os.WriteFile(path, embeddedExampleConfig, 0o600); err != nil {
				return fmt.Errorf("write %s: %w", path, err)
			}
			out := c.OutOrStdout()
			fmt.Println("")
			//nolint:errcheck // stdout write; broken pipe not recoverable
			fmt.Fprintf(out, "Wrote configuration file to:\n  %s\n\n", path)
			//nolint:errcheck
			fmt.Fprintf(out, "This file is loaded automatically when --config is not specified.\n")
			//nolint:errcheck
			fmt.Fprintf(out, "Edit this file to customize default settings.\n")
			fmt.Println("")
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "Overwrite an existing config file")
	return cmd
}
