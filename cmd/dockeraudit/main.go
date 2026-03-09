package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/kariemoorman/dockeraudit/internal/cmd"
)

var rootCmd = &cobra.Command{
	Use:     "dockeraudit",
	Short:   "\ndockerAudit: A container security auditing toolkit",
	SilenceUsage: true,
	SilenceErrors: true,
}

func init() {
	rootCmd.Version = Version
}

func main() {
	// Persistent flags available on all subcommands.
	rootCmd.PersistentFlags().Bool("verbose", false, "Print scan progress to stderr")
	rootCmd.PersistentFlags().String("config", "", "Path to config file (default: .dockeraudit.yaml)")

	// Set cmd.Verbose, cmd.Version, and load config before any subcommand runs.
	rootCmd.PersistentPreRunE = func(c *cobra.Command, _ []string) error {
		v, _ := c.Root().PersistentFlags().GetBool("verbose")
		cmd.Verbose = v
		cmd.Version = Version

		// Load config file (from --config flag or default paths).
		cfgPath, _ := c.Root().PersistentFlags().GetString("config")
		cfg, err := cmd.LoadConfig(cfgPath)
		if err != nil {
			return err
		}
		if cfg != nil {
			cmd.LoadedConfig = cfg
			if cfg.Verbose && !v {
				cmd.Verbose = true
			}
		}

		return nil
	}

	rootCmd.AddCommand(cmd.NewScanCmd())
	rootCmd.AddCommand(cmd.NewImageCmd())
	rootCmd.AddCommand(cmd.NewDockerCmd())
	rootCmd.AddCommand(cmd.NewK8sCmd())
	rootCmd.AddCommand(cmd.NewTerraformCmd())
	rootCmd.AddCommand(cmd.NewReportCmd())

	// Shell completion — generates scripts for bash/zsh/fish/powershell.
	// Usage: dockeraudit completion bash > /etc/bash_completion.d/dockeraudit
	rootCmd.AddCommand(newCompletionCmd(rootCmd))

	if err := rootCmd.Execute(); err != nil {
		// ExitCodeError signals a policy-based non-zero exit (--fail-on threshold exceeded).
		// The scan output was already rendered; just exit with the code silently.
		var exitErr *cmd.ExitCodeError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.Code)
		}
		// For all other errors (invalid flags, missing args, etc.) print and exit.
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// newCompletionCmd returns a cobra.Command that generates shell completion scripts.
func newCompletionCmd(root *cobra.Command) *cobra.Command {
	return &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate shell completion scripts",
		Long: `Generate shell completion scripts for dockeraudit.

Bash:
  dockeraudit completion bash > /etc/bash_completion.d/dockeraudit
  # or for current user:
  dockeraudit completion bash > ~/.bash_completion

Zsh:
  dockeraudit completion zsh > "${fpath[1]}/_dockeraudit"

Fish:
  dockeraudit completion fish > ~/.config/fish/completions/dockeraudit.fish

PowerShell:
  dockeraudit completion powershell > dockeraudit.ps1`,
		DisableFlagsInUseLine: true,
		ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
		Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return root.GenBashCompletion(os.Stdout)
			case "zsh":
				return root.GenZshCompletion(os.Stdout)
			case "fish":
				return root.GenFishCompletion(os.Stdout, true)
			case "powershell":
				return root.GenPowerShellCompletionWithDesc(os.Stdout)
			default:
				return fmt.Errorf("unsupported shell: %s", args[0])
			}
		},
	}
}
