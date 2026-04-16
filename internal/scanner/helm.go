package scanner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// errHelmNotInstalled is returned by renderHelmChart when the `helm` binary is
// not on PATH. Callers use errors.Is to detect this case and emit a SKIPPED
// finding rather than an ERROR finding.
var errHelmNotInstalled = errors.New("helm binary not found on PATH")

// isHelmChart reports whether dir is the root of a Helm chart. A Helm chart
// must contain a Chart.yaml file plus either a templates/ subdirectory (own
// templates) or a charts/ subdirectory (subchart dependencies only — valid for
// umbrella charts such as bitnami/cloudnative-pg). Requiring at least one of
// those siblings avoids false positives from ordinary directories that happen
// to contain a file named Chart.yaml.
func isHelmChart(dir string) bool {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return false
	}
	chartInfo, err := os.Stat(filepath.Join(dir, "Chart.yaml"))
	if err != nil || chartInfo.IsDir() {
		return false
	}
	if tmplInfo, err := os.Stat(filepath.Join(dir, "templates")); err == nil && tmplInfo.IsDir() {
		return true
	}
	if chartsInfo, err := os.Stat(filepath.Join(dir, "charts")); err == nil && chartsInfo.IsDir() {
		return true
	}
	return false
}

// renderHelmChart runs `helm template <chartDir>` and writes the rendered
// multi-document YAML to a file inside a newly-created tmp directory. The
// caller must invoke the returned cleanup func (typically via defer) to
// remove the tmp directory once scanning completes.
//
// If helm is not installed, the sentinel errHelmNotInstalled is returned.
// For any other failure, the returned error contains helm's combined stdout
// and stderr so the user can diagnose chart-level problems (missing required
// values, template errors, etc.).
func renderHelmChart(ctx context.Context, chartDir string) (string, func(), error) {
	if _, err := exec.LookPath("helm"); err != nil {
		return "", func() {}, errHelmNotInstalled
	}

	cmd := exec.CommandContext(ctx, // #nosec G204 -- fixed executable "helm"
		"helm", "template", chartDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", func() {}, fmt.Errorf("helm template failed: %w: %s", err, string(out))
	}

	tmpDir, err := os.MkdirTemp("", "dockeraudit-helm-*")
	if err != nil {
		return "", func() {}, fmt.Errorf("failed to create tmp dir for rendered chart: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(tmpDir) }

	renderedFile := filepath.Join(tmpDir, "rendered.yaml")
	if err := os.WriteFile(renderedFile, out, 0o600); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("failed to write rendered chart: %w", err)
	}
	return tmpDir, cleanup, nil
}
