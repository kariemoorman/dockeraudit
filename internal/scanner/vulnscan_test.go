package scanner

import (
	"os"
	"testing"

	"github.com/kariemoorman/dockeraudit/internal/types"
)

func TestTrivyConfigToFindings_MultipleResults(t *testing.T) {
	report := trivyConfigReport{
		Results: []trivyConfigResult{
			{
				Target: "main.tf",
				Misconfigurations: []trivyMisconfiguration{
					{
						ID:         "AVD-AWS-0086",
						Title:      "S3 bucket is publicly accessible",
						Message:    "Bucket has public access enabled",
						Severity:   "HIGH",
						Resolution: "Set block_public_acls = true",
						CauseMeta:  struct{ StartLine int `json:"StartLine"` }{StartLine: 10},
					},
					{
						ID:         "AVD-AWS-0089",
						Title:      "S3 bucket versioning not enabled",
						Message:    "Versioning is not configured",
						Severity:   "MEDIUM",
						Resolution: "Enable versioning on the bucket",
						CauseMeta:  struct{ StartLine int `json:"StartLine"` }{StartLine: 15},
					},
				},
			},
		},
	}

	ctrl := controlByID("TF-009")
	findings := trivyConfigToFindings(report, ctrl)

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	for _, f := range findings {
		if f.Control.ID != "TF-009" {
			t.Errorf("expected control TF-009, got %s", f.Control.ID)
		}
		if f.Status != types.StatusFail {
			t.Errorf("expected FAIL status, got %s", f.Status)
		}
		if f.SourceFile != "main.tf" {
			t.Errorf("expected SourceFile main.tf, got %s", f.SourceFile)
		}
	}
	if findings[0].SourceLine != 10 {
		t.Errorf("expected line 10 for first finding, got %d", findings[0].SourceLine)
	}
	if findings[1].SourceLine != 15 {
		t.Errorf("expected line 15 for second finding, got %d", findings[1].SourceLine)
	}
}

func TestTrivyConfigToFindings_Empty(t *testing.T) {
	report := trivyConfigReport{
		Results: []trivyConfigResult{
			{Target: "clean.tf", Misconfigurations: nil},
		},
	}
	findings := trivyConfigToFindings(report, controlByID("TF-009"))
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean file, got %d", len(findings))
	}
}

func TestSnykContainerToFindings_Vulns(t *testing.T) {
	report := snykContainerReport{
		OK: false,
		Vulnerabilities: []snykContainerVuln{
			{ID: "SNYK-LINUX-OPENSSL-123", Title: "Buffer overflow", Severity: "critical", PkgName: "openssl", Version: "1.1.1"},
			{ID: "SNYK-LINUX-CURL-456", Title: "SSRF vulnerability", Severity: "high", PkgName: "curl", Version: "7.68"},
			{ID: "SNYK-LINUX-ZLIB-789", Title: "Memory leak", Severity: "medium", PkgName: "zlib", Version: "1.2.11"},
		},
	}

	ctrl := controlByID("IMAGE-003")
	findings := snykContainerToFindings(report, ctrl, "nginx:latest")

	if len(findings) != 1 {
		t.Fatalf("expected 1 aggregated finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Status != types.StatusFail {
		t.Errorf("expected FAIL, got %s", f.Status)
	}
	if f.Control.ID != "IMAGE-003" {
		t.Errorf("expected IMAGE-003, got %s", f.Control.ID)
	}
	// medium should not be counted
	if !contains(f.Detail, "1 CRITICAL") || !contains(f.Detail, "1 HIGH") {
		t.Errorf("unexpected detail: %s", f.Detail)
	}
}

func TestSnykContainerToFindings_Clean(t *testing.T) {
	report := snykContainerReport{OK: true}
	findings := snykContainerToFindings(report, controlByID("IMAGE-003"), "myapp:latest")

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Status != types.StatusPass {
		t.Errorf("expected PASS, got %s", findings[0].Status)
	}
}

func TestSnykContainerToFindings_OnlyMedium(t *testing.T) {
	report := snykContainerReport{
		OK: false,
		Vulnerabilities: []snykContainerVuln{
			{ID: "SNYK-1", Title: "Minor issue", Severity: "medium", PkgName: "pkg", Version: "1.0"},
		},
	}
	findings := snykContainerToFindings(report, controlByID("IMAGE-003"), "img:latest")

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	// medium-only should pass since we only count critical+high
	if findings[0].Status != types.StatusPass {
		t.Errorf("expected PASS for medium-only vulns, got %s", findings[0].Status)
	}
}

func TestDetectVulnTools(t *testing.T) {
	// Just verify the function runs without panic; actual results depend on environment
	avail := detectVulnTools()
	_ = avail.HasTrivy
	_ = avail.HasSnyk
}

func TestDetectVulnTools_PrefNone(t *testing.T) {
	orig := VulnScannerPref
	defer func() { VulnScannerPref = orig }()

	VulnScannerPref = []string{"none"}
	avail := detectVulnTools()
	if avail.HasTrivy || avail.HasSnyk {
		t.Errorf("expected both false with pref=none, got trivy=%v snyk=%v",
			avail.HasTrivy, avail.HasSnyk)
	}
}

func TestDetectVulnTools_PrefTrivyOnly(t *testing.T) {
	orig := VulnScannerPref
	defer func() { VulnScannerPref = orig }()

	VulnScannerPref = []string{"trivy"}
	avail := detectVulnTools()
	// snyk must be false regardless of PATH
	if avail.HasSnyk {
		t.Error("expected HasSnyk=false with pref=[trivy]")
	}
}

func TestDetectVulnTools_PrefSnykOnly(t *testing.T) {
	orig := VulnScannerPref
	defer func() { VulnScannerPref = orig }()

	VulnScannerPref = []string{"snyk"}
	avail := detectVulnTools()
	// trivy must be false regardless of PATH
	if avail.HasTrivy {
		t.Error("expected HasTrivy=false with pref=[snyk]")
	}
}

func TestDetectVulnTools_PrefBoth(t *testing.T) {
	orig := VulnScannerPref
	defer func() { VulnScannerPref = orig }()

	// Explicit both — same as default nil behavior
	VulnScannerPref = []string{"trivy", "snyk"}
	avail := detectVulnTools()
	// We can't assert true (tools may not be installed), but verify no panic
	_ = avail
}

func TestDetectVulnTools_PrefNil(t *testing.T) {
	orig := VulnScannerPref
	defer func() { VulnScannerPref = orig }()

	// nil means both enabled (default behavior)
	VulnScannerPref = nil
	avail := detectVulnTools()
	_ = avail // just verify no panic
}

func TestLastFROMImage(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected string
	}{
		{
			name:     "single FROM",
			content:  "FROM nginx:1.25\nRUN echo hello\n",
			expected: "nginx:1.25",
		},
		{
			name:     "multi-stage returns last",
			content:  "FROM golang:1.22 AS builder\nRUN go build\nFROM alpine:3.19\nCOPY --from=builder /app /app\n",
			expected: "alpine:3.19",
		},
		{
			name:     "no FROM",
			content:  "RUN echo hello\n",
			expected: "",
		},
		{
			name:     "FROM with digest",
			content:  "FROM nginx@sha256:abc123\n",
			expected: "nginx@sha256:abc123",
		},
		{
			name:     "empty file",
			content:  "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmp := t.TempDir()
			path := tmp + "/Dockerfile"
			if err := os.WriteFile(path, []byte(tt.content), 0644); err != nil {
				t.Fatal(err)
			}
			got := lastFROMImage(path)
			if got != tt.expected {
				t.Errorf("lastFROMImage() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestLastFROMImage_MissingFile(t *testing.T) {
	got := lastFROMImage("/nonexistent/Dockerfile")
	if got != "" {
		t.Errorf("expected empty string for missing file, got %q", got)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
