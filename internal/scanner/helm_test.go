package scanner

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/kariemoorman/dockeraudit/internal/types"
)

func TestIsHelmChart(t *testing.T) {
	tests := []struct {
		name  string
		build func(t *testing.T, dir string)
		want  bool
	}{
		{
			name: "chart with Chart.yaml and templates/",
			build: func(t *testing.T, dir string) {
				if err := os.WriteFile(filepath.Join(dir, "Chart.yaml"), []byte("apiVersion: v2\nname: x\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(filepath.Join(dir, "templates"), 0o755); err != nil {
					t.Fatal(err)
				}
			},
			want: true,
		},
		{
			name: "only Chart.yaml (no templates/ or charts/)",
			build: func(t *testing.T, dir string) {
				if err := os.WriteFile(filepath.Join(dir, "Chart.yaml"), []byte("apiVersion: v2\nname: x\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			want: false,
		},
		{
			name: "umbrella chart (Chart.yaml + charts/, no templates/)",
			build: func(t *testing.T, dir string) {
				if err := os.WriteFile(filepath.Join(dir, "Chart.yaml"), []byte("apiVersion: v2\nname: x\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(filepath.Join(dir, "charts"), 0o755); err != nil {
					t.Fatal(err)
				}
			},
			want: true,
		},
		{
			name: "only templates/ (no Chart.yaml)",
			build: func(t *testing.T, dir string) {
				if err := os.Mkdir(filepath.Join(dir, "templates"), 0o755); err != nil {
					t.Fatal(err)
				}
			},
			want: false,
		},
		{
			name:  "empty dir",
			build: func(t *testing.T, dir string) {},
			want:  false,
		},
		{
			name: "Chart.yaml is a directory, not a file",
			build: func(t *testing.T, dir string) {
				if err := os.Mkdir(filepath.Join(dir, "Chart.yaml"), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(filepath.Join(dir, "templates"), 0o755); err != nil {
					t.Fatal(err)
				}
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			tt.build(t, dir)
			if got := isHelmChart(dir); got != tt.want {
				t.Errorf("isHelmChart(%q) = %v, want %v", dir, got, tt.want)
			}
		})
	}
}

func TestIsHelmChart_NonExistentPath(t *testing.T) {
	if isHelmChart(filepath.Join(t.TempDir(), "does-not-exist")) {
		t.Error("isHelmChart should return false for non-existent path")
	}
}

func TestIsHelmChart_FileNotDir(t *testing.T) {
	f := filepath.Join(t.TempDir(), "a-file.yaml")
	if err := os.WriteFile(f, []byte("kind: Pod\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if isHelmChart(f) {
		t.Error("isHelmChart should return false for a file path")
	}
}

func TestRenderHelmChart_HelmMissing(t *testing.T) {
	// Clear PATH so exec.LookPath("helm") fails regardless of host config.
	t.Setenv("PATH", "")

	_, cleanup, err := renderHelmChart(context.Background(), t.TempDir())
	if cleanup != nil {
		cleanup()
	}
	if !errors.Is(err, errHelmNotInstalled) {
		t.Errorf("expected errHelmNotInstalled, got %v", err)
	}
}

// TestK8sScanner_HelmChart_RunsPodChecks verifies that scanning a Helm chart
// directory renders the chart via `helm template` and then runs the full suite
// of pod/container checks on the rendered output. Skipped if helm is not
// available on PATH (e.g. in CI without helm installed).
func TestK8sScanner_HelmChart_RunsPodChecks(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm binary not available on PATH — skipping integration test")
	}

	td := testdataDir(t)
	chartDir := filepath.Join(td, "manifests", "helm-test-chart")

	result, err := k8sScanner(chartDir).Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// The fixture deployment declares privileged: true and allowPrivilegeEscalation: true,
	// lacks resource limits, and uses a tag-only image — so these controls must surface
	// findings after the chart is rendered. Without helm rendering these would not appear.
	mustHave := []string{
		"RUNTIME-002", // privileged: true
		"RUNTIME-003", // capabilities.drop not set
		"RUNTIME-004", // allowPrivilegeEscalation: true
		"RUNTIME-007", // resource limits missing
		"IMAGE-001",   // image not pinned by digest
	}
	for _, id := range mustHave {
		if findFinding(result.Findings, id) == nil {
			t.Errorf("expected finding for %s after helm rendering; got none", id)
		}
	}

	// Ensure no ERROR findings surfaced — a successful helm render should produce
	// valid YAML.
	for _, f := range result.Findings {
		if f.Status == types.StatusError {
			t.Errorf("unexpected ERROR finding after helm rendering: %+v", f)
		}
	}
}

// TestK8sScanner_HelmChart_HelmMissing_EmitsSkipped verifies the graceful fallback
// when the helm binary is not installed: a single SKIPPED finding is emitted under
// K8S-003 and the scan does not crash.
func TestK8sScanner_HelmChart_HelmMissing_EmitsSkipped(t *testing.T) {
	t.Setenv("PATH", "")

	td := testdataDir(t)
	chartDir := filepath.Join(td, "manifests", "helm-test-chart")

	result, err := k8sScanner(chartDir).Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	var found bool
	for _, f := range result.Findings {
		if f.Control.ID == "K8S-003" && f.Status == types.StatusSkipped {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected K8S-003 SKIPPED finding when helm is missing; got findings: %+v", result.Findings)
	}
}
