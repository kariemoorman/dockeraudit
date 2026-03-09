package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"dockeraudit/internal/reporter"
	"dockeraudit/internal/scanner"
	"dockeraudit/internal/types"
)

// Verbose enables per-check progress output to stderr when the --verbose flag is set.
var Verbose bool

// Version is the build version injected from main.go. Used in SARIF output.
var Version string

// defaultFailOn is the default --fail-on threshold used consistently across all subcommands.
const defaultFailOn = "high"

// ExitCodeError is returned from RunE handlers to signal a non-zero exit code
// without bypassing deferred cleanup. main.go should check for this type and
// call os.Exit with the code.
type ExitCodeError struct {
	Code int
}

func (e *ExitCodeError) Error() string {
	return fmt.Sprintf("exit code %d", e.Code)
}

// logVerbose prints msg to stderr when Verbose is true.
func logVerbose(format string, a ...any) {
	if Verbose {
		fmt.Fprintf(os.Stderr, format+"\n", a...)
	}
}

// ── scan (all) ────────────────────────────────────────────────────────────────

func NewScanCmd() *cobra.Command {
	var (
		images        []string
		dockerPaths   []string
		k8sPaths      []string
		tfPaths       []string
		format        string
		output        string
		failOn        string
		timeout       int
		excludeChecks []string
		includeChecks []string
		scanners      []string
	)

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Run all applicable scanners",
		Long: `scan runs Docker image, Dockerfile/Compose, Kubernetes manifest, Terraform,
and daemon checks in a single pass.

Examples:
  # Scan a specific image
  dockeraudit scan --images nginx:latest

  # Scan Dockerfiles and Compose files
  dockeraudit scan --docker ./

  # Scan K8s manifests and Terraform in CI
  dockeraudit scan --k8s ./k8s/ --tf ./terraform/ --format sarif

  # Scan all running containers and daemon
  dockeraudit scan --daemon`,
		RunE: func(cmd *cobra.Command, args []string) error {
			applyConfigDefaults(cmd, &format, &failOn, &excludeChecks, &includeChecks)
			applyScannerDefault(cmd, &scanners)

			if err := validateFormat(format); err != nil {
				return err
			}
			if err := validateFailOn(failOn); err != nil {
				return err
			}
			if err := validateScanners(scanners); err != nil {
				return err
			}
			scanner.VulnScannerPref = scanners

			ctx, cancel := context.WithTimeout(context.Background(),
				time.Duration(timeout)*time.Second)
			defer cancel()

			var results []*types.ScanResult
			var errs []string

			// Daemon scan
			daemonFlag, _ := cmd.Flags().GetBool("daemon")
			if daemonFlag {
				r, err := scanner.ScanDaemon(ctx)
				if err != nil {
					errs = append(errs, fmt.Sprintf("daemon: %v", err))
				} else {
					results = append(results, r)
				}
			}

			// Running containers
			runtimeFlag, _ := cmd.Flags().GetBool("runtime")
			if runtimeFlag {
				r, err := scanner.ScanRunningContainers(ctx)
				if err != nil {
					errs = append(errs, fmt.Sprintf("runtime: %v", err))
				} else {
					results = append(results, r)
				}
			}

			// Image scans
			for _, img := range images {
				logVerbose("→ Scanning image: %s", img)
				s := scanner.NewImageScanner(img)
				r, err := s.Scan(ctx)
				if err != nil {
					errs = append(errs, fmt.Sprintf("image %s: %v", img, err))
					logVerbose("  ✗ error: %v", err)
					continue
				}
				logVerbose("  ✓ %d pass  %d fail  %d warn", r.Pass, r.Fail, r.Warn)
				results = append(results, r)
			}

			// Docker (Dockerfiles + Compose files)
			for _, dp := range dockerPaths {
				logVerbose("→ Scanning Docker files: %s", dp)
				d := scanner.NewDockerScanner(dp)
				r, err := d.Scan(ctx)
				if err != nil {
					errs = append(errs, fmt.Sprintf("docker %s: %v", dp, err))
					logVerbose("  ✗ ERROR: %v", err)
					continue
				}
				logVerbose("\n  ✓ %d PASS  %d FAIL  %d WARN", r.Pass, r.Fail, r.Warn)
				results = append(results, r)
			}

			// K8s manifests
			if len(k8sPaths) > 0 {
				logVerbose("→ Scanning Kubernetes manifests: %v", k8sPaths)
				k := scanner.NewK8sScanner()
				k.ManifestPaths = k8sPaths
				r, err := k.Scan(ctx)
				if err != nil {
					errs = append(errs, fmt.Sprintf("k8s: %v", err))
					logVerbose("  ✗ ERROR: %v", err)
				} else {
					logVerbose("\n  ✓ %d PASS  %d FAIL  %d WARN", r.Pass, r.Fail, r.Warn)
					results = append(results, r)
				}
			}

			// Terraform
			if len(tfPaths) > 0 {
				logVerbose("→ Scanning Terraform: %v", tfPaths)
				t := scanner.NewTerraformScanner(tfPaths)
				r, err := t.Scan(ctx)
				if err != nil {
					errs = append(errs, fmt.Sprintf("terraform: %v", err))
					logVerbose("  ✗ ERROR: %v", err)
				} else {
					logVerbose("\n  ✓ %d PASS  %d FAIL  %d WARN", r.Pass, r.Fail, r.Warn)
					results = append(results, r)
				}
			}

			if len(errs) > 0 {
				fmt.Fprintln(os.Stderr, "Errors encountered:")
				for _, e := range errs {
					fmt.Fprintln(os.Stderr, " ", e)
				}
			}

			if len(results) == 0 {
				return fmt.Errorf("no scan results — specify at least one of: --images, --docker, --k8s, --tf, --daemon, --runtime")
			}

			filterFindings(results, includeChecks, excludeChecks)

			if err := renderAndSave(results, format, output, "scan"); err != nil {
				return err
			}

			// Return non-zero exit code based on fail-on threshold
			if code := computeExitCode(results, failOn); code != 0 {
				return &ExitCodeError{Code: code}
			}
			return nil
		},
	}

	cmd.Flags().StringSliceVarP(&images, "images", "i", nil,
		"Docker image(s) to scan (e.g. --images nginx:latest,myapp:v1.0)")
	cmd.Flags().StringSliceVarP(&dockerPaths, "docker", "d", nil,
		"Dockerfile(s), docker-compose file(s) or directories to scan")
	cmd.Flags().StringSliceVarP(&k8sPaths, "k8s", "k", nil,
		"Kubernetes manifest file(s) or directories to scan")
	cmd.Flags().StringSliceVarP(&tfPaths, "tf", "t", nil,
		"Terraform file(s) or directories to scan")
	cmd.Flags().StringVarP(&format, "format", "f", "table",
		"Output format: table, json, markdown, sarif, junit")
	cmd.Flags().StringVarP(&output, "output", "o", "",
		"Write results to file (default: stdout)")
	cmd.Flags().StringVar(&failOn, "fail-on", defaultFailOn,
		"Exit non-zero if failures at this severity or above: critical, high, medium, low, any")
	cmd.Flags().IntVar(&timeout, "timeout", 300,
		"Scan timeout in seconds")
	cmd.Flags().Bool("daemon", false,
		"Scan local Docker daemon configuration")
	cmd.Flags().Bool("runtime", false,
		"Scan all running containers for runtime misconfigurations")
	cmd.Flags().StringSliceVar(&excludeChecks, "exclude-check", nil,
		"Exclude specific control IDs from results (e.g. --exclude-check IMAGE-001,RUNTIME-010)")
	cmd.Flags().StringSliceVar(&includeChecks, "include-check", nil,
		"Include only specific control IDs in results (e.g. --include-check IMAGE-001,IMAGE-005)")
	cmd.Flags().StringSliceVarP(&scanners, "scanner", "s", []string{"trivy", "snyk"},
		"Vulnerability scanners to use (trivy, snyk, none)")

	return cmd
}

// ── image ─────────────────────────────────────────────────────────────────────

func NewImageCmd() *cobra.Command {
	var (
		format        string
		output        string
		failOn        string
		timeout       int
		excludeChecks []string
		includeChecks []string
		eolFile       string
		scanners      []string
	)

	cmd := &cobra.Command{
		Use:   "image [IMAGE...]",
		Short: "Scan Docker images",
		Long: `Scan one or more Docker images for hardening issues.

The scanner checks:
  - Digest pinning                           (IMAGE-001)
  - Non-root USER in Dockerfile              (IMAGE-005)
  - Secrets baked into image history         (IMAGE-002)
  - Secret/credential files in filesystem    (IMAGE-007)
  - SUID/SGID/world-writable files           (IMAGE-004)
  - End-of-life base image detection         (IMAGE-008)
  - Crypto miner artifacts                   (IMAGE-009)
  - xz-utils backdoor (CVE-2024-3094)        (IMAGE-010)
  - SSH daemon in Entrypoint/Cmd             (RUNTIME-010)
  - Privileged ports (< 1024)               (RUNTIME-011)
  - Database admin tools in image            (DB-IMAGE-001)
  - Dangerous DB startup flags               (DB-IMAGE-002)
  - ADD with remote URLs                     (IMAGE-006)
  - Vulnerability scan via trivy             (IMAGE-003)

Examples:
  dockeraudit image nginx:latest
  dockeraudit image myapp:v1.0 --format json -o results.json`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			applyConfigDefaults(c, &format, &failOn, &excludeChecks, &includeChecks)
			applyScannerDefault(c, &scanners)
			if err := validateScanners(scanners); err != nil {
				return err
			}
			scanner.VulnScannerPref = scanners
			// Apply eol-file config default.
			if !c.Flags().Changed("eol-file") && LoadedConfig != nil && LoadedConfig.EOLFile != "" {
				eolFile = LoadedConfig.EOLFile
			}

			if err := validateFormat(format); err != nil {
				return err
			}
			if err := validateFailOn(failOn); err != nil {
				return err
			}

			// Load custom EOL images if specified.
			var customEOL []scanner.EOLEntry
			if eolFile != "" {
				var err error
				customEOL, err = scanner.LoadEOLFile(eolFile)
				if err != nil {
					return err
				}
				logVerbose("→ Loaded %d custom EOL entries from %s", len(customEOL), eolFile)
			}

			ctx, cancel := context.WithTimeout(context.Background(),
				time.Duration(timeout)*time.Second)
			defer cancel()

			// Scan images in parallel when multiple are provided.
			type imgResult struct {
				result *types.ScanResult
				err    error
				image  string
			}
			ch := make(chan imgResult, len(args))
			for _, img := range args {
				logVerbose("→ Scanning image: %s", img)
				go func(image string) {
					s := scanner.NewImageScanner(image)
					s.CustomEOLImages = customEOL
					r, err := s.Scan(ctx)
					ch <- imgResult{result: r, err: err, image: image}
				}(img)
			}

			var results []*types.ScanResult
			for range args {
				ir := <-ch
				if ir.err != nil {
					fmt.Fprintf(os.Stderr, "error scanning %s: %v\n", ir.image, ir.err)
					logVerbose("  ✗ error: %v", ir.err)
					continue
				}
				logVerbose("  ✓ %s: %d pass  %d fail  %d warn", ir.image, ir.result.Pass, ir.result.Fail, ir.result.Warn)
				results = append(results, ir.result)
			}

			filterFindings(results, includeChecks, excludeChecks)

			if err := renderAndSave(results, format, output, "image"); err != nil {
				return err
			}

			if code := computeExitCode(results, failOn); code != 0 {
				return &ExitCodeError{Code: code}
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "table", "Output format: table, json, markdown, sarif, junit")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Write results to file")
	cmd.Flags().StringVar(&failOn, "fail-on", defaultFailOn, "Exit non-zero on: critical, high, medium, low, any")
	cmd.Flags().IntVar(&timeout, "timeout", 180, "Timeout in seconds per image")
	cmd.Flags().StringSliceVar(&excludeChecks, "exclude-check", nil,
		"Exclude specific control IDs from results (e.g. --exclude-check IMAGE-001,RUNTIME-010)")
	cmd.Flags().StringSliceVar(&includeChecks, "include-check", nil,
		"Include only specific control IDs in results (e.g. --include-check IMAGE-001,IMAGE-005)")
	cmd.Flags().StringVar(&eolFile, "eol-file", "",
		"Path to JSON file with custom end-of-life image definitions (overrides built-in list)")
	cmd.Flags().StringSliceVarP(&scanners, "scanner", "s", []string{"trivy", "snyk"},
		"Vulnerability scanners to use (trivy, snyk, none)")
	return cmd
}

// ── k8s ───────────────────────────────────────────────────────────────────────

func NewK8sCmd() *cobra.Command {
	var (
		format        string
		output        string
		failOn        string
		excludeChecks []string
		includeChecks []string
		scanners      []string
	)

	cmd := &cobra.Command{
		Use:   "k8s [PATH...]",
		Short: "Scan Kubernetes manifests for security misconfigurations",
		Long: `Scan Kubernetes YAML/JSON manifests against container hardening controls.

Checks include privileged containers, capabilities, read-only filesystem,
non-root users, resource limits, host namespace sharing, sensitive hostPaths,
plaintext secrets in env vars, and image digest pinning.

Examples:
  dockeraudit k8s ./manifests/
  dockeraudit k8s deployment.yaml service.yaml --format markdown`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			applyConfigDefaults(c, &format, &failOn, &excludeChecks, &includeChecks)
			applyScannerDefault(c, &scanners)

			if err := validateFormat(format); err != nil {
				return err
			}
			if err := validateFailOn(failOn); err != nil {
				return err
			}
			if err := validateScanners(scanners); err != nil {
				return err
			}
			scanner.VulnScannerPref = scanners

			ctx := context.Background()
			logVerbose("→ Scanning Kubernetes manifests: %v", args)
			k := scanner.NewK8sScanner()
			k.ManifestPaths = args
			r, err := k.Scan(ctx)
			if err != nil {
				return err
			}
			logVerbose("  ✓ %d pass  %d fail  %d warn", r.Pass, r.Fail, r.Warn)

			results := []*types.ScanResult{r}
			filterFindings(results, includeChecks, excludeChecks)

			if err := renderAndSave(results, format, output, "k8s"); err != nil {
				return err
			}

			if code := computeExitCode(results, failOn); code != 0 {
				return &ExitCodeError{Code: code}
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "table", "Output format: table, json, markdown, sarif, junit")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Write results to file")
	cmd.Flags().StringVar(&failOn, "fail-on", defaultFailOn, "Exit non-zero on: critical, high, medium, low, any")
	cmd.Flags().StringSliceVar(&excludeChecks, "exclude-check", nil,
		"Exclude specific control IDs from results (e.g. --exclude-check K8S-001,K8S-003)")
	cmd.Flags().StringSliceVar(&includeChecks, "include-check", nil,
		"Include only specific control IDs in results (e.g. --include-check K8S-001,K8S-005)")
	cmd.Flags().StringSliceVarP(&scanners, "scanner", "s", []string{"trivy", "snyk"},
		"Vulnerability scanners to use (trivy, snyk, none)")
	return cmd
}

// ── terraform ─────────────────────────────────────────────────────────────────

func NewTerraformCmd() *cobra.Command {
	var (
		format        string
		output        string
		failOn        string
		excludeChecks []string
		includeChecks []string
		scanners      []string
	)

	cmd := &cobra.Command{
		Use:   "terraform [PATH...]",
		Short: "Scan Terraform files for container security misconfigurations",
		Long: `Scan Terraform .tf files for container-security related issues.

Checks include:
  - ECR immutable tags and scan-on-push
  - EKS audit logging and Bottlerocket AMI type
  - IMDSv2 enforcement (hop limit=1)
  - GKE network policy and database encryption
  - Security groups allowing port 2375
  - Hardcoded secrets/credentials

Examples:
  dockeraudit terraform ./infrastructure/
  dockeraudit terraform ./aws/ ./gcp/ --format json`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			applyConfigDefaults(c, &format, &failOn, &excludeChecks, &includeChecks)
			applyScannerDefault(c, &scanners)

			if err := validateFormat(format); err != nil {
				return err
			}
			if err := validateFailOn(failOn); err != nil {
				return err
			}
			if err := validateScanners(scanners); err != nil {
				return err
			}
			scanner.VulnScannerPref = scanners

			ctx := context.Background()
			logVerbose("→ Scanning Terraform: %v", args)
			t := scanner.NewTerraformScanner(args)
			r, err := t.Scan(ctx)
			if err != nil {
				return err
			}
			logVerbose("  ✓ %d pass  %d fail  %d warn", r.Pass, r.Fail, r.Warn)

			results := []*types.ScanResult{r}
			filterFindings(results, includeChecks, excludeChecks)

			if err := renderAndSave(results, format, output, "terraform"); err != nil {
				return err
			}

			if code := computeExitCode(results, failOn); code != 0 {
				return &ExitCodeError{Code: code}
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "table", "Output format: table, json, markdown, sarif, junit")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Write results to file")
	cmd.Flags().StringVar(&failOn, "fail-on", defaultFailOn, "Exit non-zero on: critical, high, medium, low, any")
	cmd.Flags().StringSliceVar(&excludeChecks, "exclude-check", nil,
		"Exclude specific control IDs from results (e.g. --exclude-check TF-001,TF-003)")
	cmd.Flags().StringSliceVar(&includeChecks, "include-check", nil,
		"Include only specific control IDs in results (e.g. --include-check TF-001,TF-005)")
	cmd.Flags().StringSliceVarP(&scanners, "scanner", "s", []string{"trivy", "snyk"},
		"Vulnerability scanners to use (trivy, snyk, none)")
	return cmd
}

// ── docker ────────────────────────────────────────────────────────────────────

func NewDockerCmd() *cobra.Command {
	var (
		format        string
		output        string
		failOn        string
		excludeChecks []string
		includeChecks []string
		scanners      []string
	)

	cmd := &cobra.Command{
		Use:   "docker [PATH...]",
		Short: "Scan Dockerfiles and Docker Compose files",
		Long: `Scan Dockerfiles and Docker Compose files for security misconfigurations.

Checks include non-root USER, digest pinning, HEALTHCHECK, secrets in ENV,
privileged mode, capabilities, resource limits, host namespaces, and more.

Automatically detects file type:
  - Dockerfile, Dockerfile.*, *.dockerfile, Containerfile
  - docker-compose*.yml/yaml, compose.yml/yaml

Examples:
  dockeraudit docker ./
  dockeraudit docker Dockerfile docker-compose.yml --format json
  dockeraudit docker ./app/ ./infra/ --fail-on critical`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			applyConfigDefaults(c, &format, &failOn, &excludeChecks, &includeChecks)
			applyScannerDefault(c, &scanners)

			if err := validateFormat(format); err != nil {
				return err
			}
			if err := validateFailOn(failOn); err != nil {
				return err
			}
			if err := validateScanners(scanners); err != nil {
				return err
			}
			scanner.VulnScannerPref = scanners

			ctx := context.Background()
			var results []*types.ScanResult
			var errs []string

			for _, dp := range args {
				logVerbose("→ Scanning Docker files: %s", dp)
				d := scanner.NewDockerScanner(dp)
				r, err := d.Scan(ctx)
				if err != nil {
					errs = append(errs, fmt.Sprintf("docker %s: %v", dp, err))
					logVerbose("  ✗ ERROR: %v", err)
					continue
				}
				logVerbose("  ✓ %d pass  %d fail  %d warn", r.Pass, r.Fail, r.Warn)
				results = append(results, r)
			}

			if len(errs) > 0 {
				fmt.Fprintln(os.Stderr, "Errors encountered:")
				for _, e := range errs {
					fmt.Fprintln(os.Stderr, " ", e)
				}
			}

			if len(results) == 0 {
				return fmt.Errorf("no scan results — check that the paths contain Dockerfiles or Compose files")
			}

			filterFindings(results, includeChecks, excludeChecks)

			if err := renderAndSave(results, format, output, "docker"); err != nil {
				return err
			}

			if code := computeExitCode(results, failOn); code != 0 {
				return &ExitCodeError{Code: code}
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "table", "Output format: table, json, markdown, sarif, junit")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Write results to file")
	cmd.Flags().StringVar(&failOn, "fail-on", defaultFailOn, "Exit non-zero on: critical, high, medium, low, any")
	cmd.Flags().StringSliceVar(&excludeChecks, "exclude-check", nil,
		"Exclude specific control IDs from results (e.g. --exclude-check IMAGE-001,RUNTIME-010)")
	cmd.Flags().StringSliceVar(&includeChecks, "include-check", nil,
		"Include only specific control IDs in results (e.g. --include-check IMAGE-001,IMAGE-005)")
	cmd.Flags().StringSliceVarP(&scanners, "scanner", "s", []string{"trivy", "snyk"},
		"Vulnerability scanners to use (trivy, snyk, none)")
	return cmd
}

// ── report ────────────────────────────────────────────────────────────────────

func NewReportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate compliance reports",
		Long: `Generate compliance mapping reports.

Examples:
  dockeraudit report controls
  dockeraudit report controls --domain Image`,
	}

	cmd.AddCommand(newListControlsCmd())
	return cmd
}

func newListControlsCmd() *cobra.Command {
	var domain string
	const (
		blue  = "\033[34m"
		reset = "\033[0m"
	)

	cmd := &cobra.Command{
		Use:   "controls",
		Short: "List all hardening controls",
		RunE: func(_ *cobra.Command, _ []string) error {
			w := os.Stdout
			//nolint:errcheck // stdout write; broken pipe not recoverable
			fmt.Fprintln(w)
			fmt.Fprintf(w, "%s%-14s %-12s %-50s %-10s %-12s %-12s %-20s%s\n",
				blue, "ID", "Domain", "Title", "Severity", "Type", "CIS", "NIST 800-53", reset)
			fmt.Fprintln(w, blue + strings.Repeat("─", 140) + reset) //nolint:errcheck

			sorted := make([]types.Control, len(types.AllControls))
			copy(sorted, types.AllControls)
			sort.Slice(sorted, func(i, j int) bool {
				if sorted[i].Domain != sorted[j].Domain {
					return sorted[i].Domain < sorted[j].Domain
				}
				return sorted[i].ID < sorted[j].ID
			})

			for _, c := range sorted {
				if domain != "" && !strings.EqualFold(c.Domain, domain) {
					continue
				}
				//nolint:errcheck // stdout write; broken pipe not recoverable
				fmt.Fprintf(w, "%-14s %-12s %-50s %-10s %-12s %-12s %-20s\n",
					c.ID, c.Domain, truncateStr(c.Title, 48),
					string(c.Severity), string(c.Type),
					c.Compliance.CISDockerSection,
					c.Compliance.NIST80053)
			}
			fmt.Fprintln(w, blue + strings.Repeat("─", 140) + reset) //nolint:errcheck
			fmt.Fprintln(w)
			return nil
		},
	}

	cmd.Flags().StringVar(&domain, "domain", "", "Filter by domain: Host, Daemon, Image, Runtime, Network, Secrets, SupplyChain, Monitoring")
	return cmd
}

// ── utilities ─────────────────────────────────────────────────────────────────

func outputWriter(path string) (w *os.File, cleanup func(), err error) {
	if path == "" {
		return os.Stdout, func() {}, nil
	}
	f, err := os.Create(path) // #nosec G304 -- path is a user-supplied path from --output flag
	if err != nil {
		return nil, nil, fmt.Errorf("create output file %s: %w", path, err)
	}
	return f, func() {
		if cerr := f.Close(); cerr != nil {
			_, _ = fmt.Fprintf(os.Stderr, "warning: close output file: %v\n", cerr)
		}
	}, nil
}

// formatExt returns the canonical file extension for an output format.
func formatExt(format string) string {
	switch strings.ToLower(format) {
	case "json":
		return ".json"
	case "markdown":
		return ".md"
	case "sarif":
		return ".sarif.json"
	case "junit":
		return ".xml"
	default: // table
		return ".txt"
	}
}

// autoSave renders results (without ANSI colour) to
// scans/dockerAudit_report_<scannerName>_<YYYYMMDD_HHMMSS><ext> and prints
// the path to stderr. Errors are non-fatal; the caller should log and continue.
func autoSave(results []*types.ScanResult, format, scannerName string) error {
	const dir = "scans"
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	ts := time.Now().Format("20060102_150405")
	filename := filepath.Join(dir,
		fmt.Sprintf("dockerAudit_report_%s_%s%s", scannerName, ts, formatExt(format)))

	f, err := os.Create(filename) // #nosec G304 -- path is constructed internally
	if err != nil {
		return fmt.Errorf("create %s: %w", filename, err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			_, _ = fmt.Fprintf(os.Stderr, "warning: close %s: %v\n", filename, cerr)
		}
	}()

	rep := newReporter(format)
	rep.Output = f
	rep.Color = false // no ANSI escape codes in saved file
	if err := rep.Render(results); err != nil {
		return fmt.Errorf("render to %s: %w", filename, err)
	}
	fmt.Fprintf(os.Stderr, "\033[34;1m → Saved report:\033[0m %s\n\n", filename)
	return nil
}

// renderAndSave renders results to the requested output writer and — when no
// explicit --output path was given — also auto-saves a copy under scans/.
func renderAndSave(results []*types.ScanResult, format, output, scannerName string) error {
	w, cleanup, err := outputWriter(output)
	if err != nil {
		return err
	}
	defer cleanup()

	rep := newReporter(format)
	rep.Output = w
	rep.Color = output == "" // ANSI colour only for interactive stdout
	if err := rep.Render(results); err != nil {
		return err
	}

	// Auto-save to scans/ whenever the user has not redirected output to a file.
	if output == "" {
		if saveErr := autoSave(results, format, scannerName); saveErr != nil {
			fmt.Fprintf(os.Stderr, "warning: auto-save failed: %v\n", saveErr)
			// Non-fatal: the report was already printed to stdout.
		}
	}
	return nil
}

func computeExitCode(results []*types.ScanResult, failOn string) int {
	failOn = strings.ToLower(failOn)

	for _, r := range results {
		switch failOn {
		case "any":
			if r.Fail > 0 {
				return 1
			}
		case "low":
			if r.Critical+r.High+r.Medium+r.Low > 0 {
				return 1
			}
		case "medium":
			if r.Critical+r.High+r.Medium > 0 {
				return 1
			}
		case "high":
			if r.Critical+r.High > 0 {
				return 1
			}
		default: // critical
			if r.Critical > 0 {
				return 1
			}
		}
	}
	return 0
}

// newReporter creates a Reporter with the configured version.
func newReporter(format string) *reporter.Reporter {
	rep := reporter.New(reporter.Format(format))
	rep.Version = Version
	return rep
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

// validFormats is the set of supported output formats.
var validFormats = map[string]bool{
	"table": true, "json": true, "markdown": true, "sarif": true, "junit": true,
}

// validFailOn is the set of supported --fail-on threshold values.
var validFailOn = map[string]bool{
	"critical": true, "high": true, "medium": true, "low": true, "any": true,
}

// validateFormat returns an error if the format string is unsupported.
func validateFormat(format string) error {
	if !validFormats[strings.ToLower(format)] {
		return fmt.Errorf("unsupported --format %q: valid values are table, json, markdown, sarif, junit", format)
	}
	return nil
}

// validateFailOn returns an error if the failOn string is unsupported.
func validateFailOn(failOn string) error {
	if !validFailOn[strings.ToLower(failOn)] {
		return fmt.Errorf("unsupported --fail-on %q: valid values are critical, high, medium, low, any", failOn)
	}
	return nil
}

// validScanners is the set of supported --scanner values.
var validScanners = map[string]bool{
	"trivy": true, "snyk": true, "none": true,
}

// validateScanners returns an error if any scanner value is unsupported.
func validateScanners(scanners []string) error {
	for _, s := range scanners {
		if !validScanners[strings.ToLower(s)] {
			return fmt.Errorf("unsupported --scanner %q: valid values are trivy, snyk, none", s)
		}
	}
	return nil
}

// applyScannerDefault applies the scanner config-file value when the
// --scanner CLI flag was not explicitly set.
func applyScannerDefault(c *cobra.Command, scanners *[]string) {
	if !c.Flags().Changed("scanner") && LoadedConfig != nil && len(LoadedConfig.Scanner) > 0 {
		*scanners = LoadedConfig.Scanner
	}
}

// applyConfigDefaults applies values from the loaded config file to local
// variables when the corresponding CLI flag was not explicitly set.
// This ensures CLI flags always override config-file values.
func applyConfigDefaults(c *cobra.Command, format, failOn *string, excludeChecks, includeChecks *[]string) {
	cfg := LoadedConfig
	if cfg == nil {
		return
	}

	if !c.Flags().Changed("format") && cfg.Format != "" {
		*format = cfg.Format
	}
	if !c.Flags().Changed("fail-on") && cfg.FailOn != "" {
		*failOn = cfg.FailOn
	}
	if !c.Flags().Changed("exclude-check") && len(cfg.ExcludeCheck) > 0 {
		*excludeChecks = cfg.ExcludeCheck
	}
	if !c.Flags().Changed("include-check") && len(cfg.IncludeCheck) > 0 {
		*includeChecks = cfg.IncludeCheck
	}
}

// filterFindings removes findings based on --exclude-check and --include-check flags.
// If includeChecks is non-empty, only findings matching those control IDs are kept.
// excludeChecks removes findings matching those control IDs.
func filterFindings(results []*types.ScanResult, includeChecks, excludeChecks []string) {
	if len(includeChecks) == 0 && len(excludeChecks) == 0 {
		return
	}

	includeSet := make(map[string]bool, len(includeChecks))
	for _, id := range includeChecks {
		includeSet[strings.ToUpper(id)] = true
	}
	excludeSet := make(map[string]bool, len(excludeChecks))
	for _, id := range excludeChecks {
		excludeSet[strings.ToUpper(id)] = true
	}

	for _, r := range results {
		filtered := r.Findings[:0]
		for _, f := range r.Findings {
			cid := strings.ToUpper(f.Control.ID)
			if len(includeSet) > 0 && !includeSet[cid] {
				continue
			}
			if excludeSet[cid] {
				continue
			}
			filtered = append(filtered, f)
		}
		r.Findings = filtered
		r.Tally()
	}
}
