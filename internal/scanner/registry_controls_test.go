package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/kariemoorman/dockeraudit/internal/types"
)

// ── REGISTRY-002 classifyRegistryRef (pure helper) ───────────────────────── //

func TestClassifyRegistryRef(t *testing.T) {
	cases := []struct {
		ref         string
		wantPosture string
	}{
		// Explicit insecure scheme
		{"http://registry.local/myapp:1.0", "insecure"},

		// Anonymous (Docker Hub)
		{"nginx:latest", "anonymous"},
		{"library/nginx:latest", "anonymous"},
		{"docker.io/library/nginx:latest", "anonymous"},

		// Private (cloud)
		{"123456789012.dkr.ecr.us-east-1.amazonaws.com/app:v1", "private"},
		{"us-docker.pkg.dev/proj/repo/app:v1", "private"},
		{"gcr.io/proj/app:v1", "private"},
		{"myreg.azurecr.io/app:v1", "private"},
		{"ghcr.io/org/app:v1", "private"},

		// Custom private registry
		{"myreg.local:5000/app:v1", "private"},

		// Empty
		{"", "unknown"},
	}
	for _, tc := range cases {
		got, _, _ := classifyRegistryRef(tc.ref)
		if got != tc.wantPosture {
			t.Errorf("classifyRegistryRef(%q) posture = %q, want %q", tc.ref, got, tc.wantPosture)
		}
	}
}

// ── REGISTRY-001: insecure-registries in daemon.json ─────────────────────── //
//
// checkDaemonJSON() reads /etc/docker/daemon.json directly, so we cannot unit-
// test it without root. Instead we assert that the REGISTRY-001 control exists
// in the registry and that the lookup returns a properly-populated Control.

func TestRegistry001_ControlDefined(t *testing.T) {
	c := controlByID("REGISTRY-001")
	if c.ID != "REGISTRY-001" {
		t.Fatalf("controlByID(REGISTRY-001).ID = %q", c.ID)
	}
	if c.Title == "" || c.Remediation == "" {
		t.Error("REGISTRY-001 has empty Title or Remediation")
	}
	if c.Compliance.NIST800190 == "" {
		t.Error("REGISTRY-001 has empty NIST800190 citation")
	}
}

// ── REGISTRY-002: unauthenticated registry refs (Dockerfile + Compose + k8s) ── //

func TestRegistry002_DockerfileInsecureHTTP(t *testing.T) {
	tmp := t.TempDir()
	df := filepath.Join(tmp, "Dockerfile")
	if err := os.WriteFile(df, []byte("FROM http://registry.local/myapp:1.0\n"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	s := NewDockerScanner(df)
	r, err := s.Scan(context.Background())
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	assertFail(t, r.Findings, "REGISTRY-002")
}

func TestRegistry002_DockerfileAnonymousDockerHub(t *testing.T) {
	tmp := t.TempDir()
	df := filepath.Join(tmp, "Dockerfile")
	if err := os.WriteFile(df, []byte("FROM nginx:1.25\n"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	s := NewDockerScanner(df)
	r, err := s.Scan(context.Background())
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	// Docker Hub anonymous pull is WARN, not FAIL.
	f := findFinding(r.Findings, "REGISTRY-002")
	if f == nil {
		t.Fatal("no REGISTRY-002 finding for FROM nginx:1.25")
		return
	}
	if f.Status != types.StatusWarn {
		t.Errorf("REGISTRY-002 status = %s, want WARN for docker.io anonymous pull", f.Status)
	}
}

func TestRegistry002_DockerfileAuthenticatedRegistryPasses(t *testing.T) {
	tmp := t.TempDir()
	df := filepath.Join(tmp, "Dockerfile")
	content := "FROM 123456789012.dkr.ecr.us-east-1.amazonaws.com/app:v1@sha256:" +
		"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\n"
	if err := os.WriteFile(df, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	s := NewDockerScanner(df)
	r, err := s.Scan(context.Background())
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	assertPass(t, r.Findings, "REGISTRY-002")
}

func TestRegistry002_ComposeInsecure(t *testing.T) {
	tmp := t.TempDir()
	cf := filepath.Join(tmp, "docker-compose.yml")
	content := "services:\n  web:\n    image: http://internal.registry/web:latest\n"
	if err := os.WriteFile(cf, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	s := NewDockerScanner(cf)
	r, err := s.Scan(context.Background())
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	assertFail(t, r.Findings, "REGISTRY-002")
}

// ── REGISTRY-003: cloud registry IAM ─────────────────────────────────────── //

func TestRegistry003_ECRPublicPolicyFails(t *testing.T) {
	tmp := t.TempDir()
	tf := filepath.Join(tmp, "main.tf")
	content := `
resource "aws_ecr_repository" "app" { name = "app" }
resource "aws_ecr_repository_policy" "app" {
  repository = aws_ecr_repository.app.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "ecr:GetDownloadUrlForLayer"
    }]
  })
}
`
	if err := os.WriteFile(tf, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	r, err := NewTerraformScanner([]string{tf}).Scan(context.Background())
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	assertFail(t, r.Findings, "REGISTRY-003")
}

func TestRegistry003_GARAllUsersFails(t *testing.T) {
	tmp := t.TempDir()
	tf := filepath.Join(tmp, "main.tf")
	content := `
resource "google_artifact_registry_repository" "repo" {
  location      = "us"
  repository_id = "my-repo"
  format        = "DOCKER"
}
resource "google_artifact_registry_repository_iam_member" "public" {
  repository = google_artifact_registry_repository.repo.name
  role       = "roles/artifactregistry.reader"
  member     = "allUsers"
}
`
	if err := os.WriteFile(tf, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	r, err := NewTerraformScanner([]string{tf}).Scan(context.Background())
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	assertFail(t, r.Findings, "REGISTRY-003")
}

func TestRegistry003_ACRAnonymousPullFails(t *testing.T) {
	tmp := t.TempDir()
	tf := filepath.Join(tmp, "main.tf")
	content := `
resource "azurerm_container_registry" "acr" {
  name                    = "myacr"
  resource_group_name     = "rg"
  location                = "eastus"
  sku                     = "Premium"
  anonymous_pull_enabled  = true
}
`
	if err := os.WriteFile(tf, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	r, err := NewTerraformScanner([]string{tf}).Scan(context.Background())
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	assertFail(t, r.Findings, "REGISTRY-003")
}

func TestRegistry003_NoRegistryResourcesSkipped(t *testing.T) {
	tmp := t.TempDir()
	tf := filepath.Join(tmp, "main.tf")
	content := `resource "aws_s3_bucket" "b" { bucket = "x" }`
	if err := os.WriteFile(tf, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	r, err := NewTerraformScanner([]string{tf}).Scan(context.Background())
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	f := findFinding(r.Findings, "REGISTRY-003")
	if f == nil || f.Status != types.StatusSkipped {
		t.Fatalf("REGISTRY-003 with no registry resources should SKIP; got %+v", f)
	}
}

// ── REGISTRY-004: cloud registry lifecycle ───────────────────────────────── //

func TestRegistry004_ECRNoLifecycleWarns(t *testing.T) {
	tmp := t.TempDir()
	tf := filepath.Join(tmp, "main.tf")
	content := `resource "aws_ecr_repository" "app" { name = "app" }`
	if err := os.WriteFile(tf, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	r, err := NewTerraformScanner([]string{tf}).Scan(context.Background())
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	f := findFinding(r.Findings, "REGISTRY-004")
	if f == nil || f.Status != types.StatusWarn {
		t.Fatalf("REGISTRY-004 should WARN when ECR has no lifecycle policy; got %+v", f)
	}
}

func TestRegistry004_ECRWithLifecyclePasses(t *testing.T) {
	tmp := t.TempDir()
	tf := filepath.Join(tmp, "main.tf")
	content := `
resource "aws_ecr_repository" "app" { name = "app" }
resource "aws_ecr_lifecycle_policy" "app" {
  repository = aws_ecr_repository.app.name
  policy     = "{}"
}
`
	if err := os.WriteFile(tf, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	r, err := NewTerraformScanner([]string{tf}).Scan(context.Background())
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	assertPass(t, r.Findings, "REGISTRY-004")
}

func TestRegistry004_GARWithCleanupPasses(t *testing.T) {
	tmp := t.TempDir()
	tf := filepath.Join(tmp, "main.tf")
	content := `
resource "google_artifact_registry_repository" "repo" {
  location      = "us"
  repository_id = "my-repo"
  format        = "DOCKER"
  cleanup_policies {
    id     = "keep-minimum-versions"
    action = "KEEP"
  }
}
`
	if err := os.WriteFile(tf, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	r, err := NewTerraformScanner([]string{tf}).Scan(context.Background())
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	assertPass(t, r.Findings, "REGISTRY-004")
}

func TestRegistry004_ACRRetentionEnabledPasses(t *testing.T) {
	tmp := t.TempDir()
	tf := filepath.Join(tmp, "main.tf")
	content := `
resource "azurerm_container_registry" "acr" {
  name                = "myacr"
  resource_group_name = "rg"
  location            = "eastus"
  sku                 = "Premium"
  retention_policy {
    days    = 30
    enabled = true
  }
}
`
	if err := os.WriteFile(tf, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	r, err := NewTerraformScanner([]string{tf}).Scan(context.Background())
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	assertPass(t, r.Findings, "REGISTRY-004")
}
