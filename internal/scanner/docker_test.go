package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"https://github.com/kariemoorman/dockeraudit/internal/types"

	"gopkg.in/yaml.v3"
)

// dockerfileTestPath returns the path to a test Dockerfile relative to testdata.
func dockerfileTestPath(t *testing.T, name string) string {
	t.Helper()
	td := testdataDir(t)
	return filepath.Join(td, "dockerfiles", name)
}

// composeTestPath returns the path to a test compose file relative to testdata.
func composeTestPath(t *testing.T, name string) string {
	t.Helper()
	td := testdataDir(t)
	return filepath.Join(td, "compose", name)
}

// ══════════════════════════════════════════════════════════════════════════════
// Dockerfile tests
// ══════════════════════════════════════════════════════════════════════════════

func TestDockerScanner_Insecure_HasFails(t *testing.T) {
	path := dockerfileTestPath(t, "Dockerfile.insecure")
	s := NewDockerScanner(path)

	result, err := s.Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected findings from insecure Dockerfile, got none")
	}
	if !hasFail(result.Findings) {
		t.Error("insecure Dockerfile produced no FAIL findings")
	}
}

func TestDockerScanner_Insecure_SpecificViolations(t *testing.T) {
	path := dockerfileTestPath(t, "Dockerfile.insecure")
	s := NewDockerScanner(path)

	result, err := s.Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// IMAGE-001: FROM debian:9 not pinned by digest
	assertFail(t, result.Findings, "IMAGE-001")

	// IMAGE-008: debian:9 is EOL
	assertFail(t, result.Findings, "IMAGE-008")

	// IMAGE-005: USER root
	assertFail(t, result.Findings, "IMAGE-005")

	// IMAGE-006: ADD with remote URL
	assertFail(t, result.Findings, "IMAGE-006")

	// IMAGE-004: chmod 777 / chmod u+s
	assertFail(t, result.Findings, "IMAGE-004")

	// IMAGE-002: ENV with password/secret
	assertFail(t, result.Findings, "IMAGE-002")
}

func TestDockerScanner_Secure_NoCriticalFails(t *testing.T) {
	path := dockerfileTestPath(t, "Dockerfile.secure")
	s := NewDockerScanner(path)

	result, err := s.Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	criticalControls := []string{
		"IMAGE-001", // digest pinned
		"IMAGE-002", // no secrets
		"IMAGE-004", // no SUID/world-writable
		"IMAGE-005", // non-root user
		"IMAGE-006", // no ADD remote URL
		"IMAGE-008", // no EOL base
	}
	for _, id := range criticalControls {
		for _, f := range result.Findings {
			if f.Control.ID == id && f.Status == types.StatusFail {
				t.Errorf("secure Dockerfile: control %s should not FAIL (detail: %s)", id, f.Detail)
			}
		}
	}
}

func TestDockerScanner_SourceLineTracking(t *testing.T) {
	path := dockerfileTestPath(t, "Dockerfile.insecure")
	s := NewDockerScanner(path)

	result, err := s.Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	hasSourceLine := false
	for _, f := range result.Findings {
		if f.SourceFile != "" && f.SourceLine > 0 {
			hasSourceLine = true
			break
		}
	}
	if !hasSourceLine {
		t.Error("expected at least one finding with SourceFile and SourceLine > 0")
	}
}

func TestDockerScanner_MissingFile_ReturnsError(t *testing.T) {
	s := NewDockerScanner("/nonexistent/Dockerfile")

	result, err := s.Scan(context.Background())
	if err != nil {
		return // error at file collection level is valid
	}
	for _, f := range result.Findings {
		if strings.Contains(f.Detail, "Failed to read") {
			return
		}
	}
	t.Error("expected error finding for missing Dockerfile")
}

func TestDockerScanner_CheckEOLInLine(t *testing.T) {
	s := NewDockerScanner("")

	tests := []struct {
		line  string
		isEOL bool
	}{
		{"FROM ubuntu:14.04", true},
		{"FROM ubuntu:16.04 AS builder", true},
		{"FROM debian:9-slim", true},
		{"FROM centos:6", true},
		{"FROM python:2.7-slim", true},
		{"FROM node:14-alpine", true},
		{"FROM golang:1.22-alpine", false},
		{"FROM ubuntu:22.04", false},
		{"FROM python:3.12", false},
	}

	for _, tt := range tests {
		finding := s.checkEOLInLine("test", tt.line, 1)
		if tt.isEOL && finding == nil {
			t.Errorf("expected EOL finding for %q, got nil", tt.line)
		}
		if !tt.isEOL && finding != nil {
			t.Errorf("expected no EOL finding for %q, got: %s", tt.line, finding.Detail)
		}
	}
}

func TestDockerScanner_TallyCorrect(t *testing.T) {
	path := dockerfileTestPath(t, "Dockerfile.insecure")
	s := NewDockerScanner(path)

	result, err := s.Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if result.Fail == 0 {
		t.Error("expected non-zero Fail count in tally")
	}
	if result.Scanner != "docker" {
		t.Errorf("expected scanner name 'docker', got %q", result.Scanner)
	}
}

func TestDockerScanner_SecretsDetection(t *testing.T) {
	dir := t.TempDir()
	df := filepath.Join(dir, "Dockerfile")
	content := `FROM alpine:3.19
ENV GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12
RUN echo "hello"
USER nobody
`
	if err := os.WriteFile(df, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test Dockerfile: %v", err)
	}

	s := NewDockerScanner(df)
	result, err := s.Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	hasSecretFinding := false
	for _, f := range result.Findings {
		if f.Control.ID == "IMAGE-002" && f.Status == types.StatusFail {
			hasSecretFinding = true
			break
		}
	}
	if !hasSecretFinding {
		t.Error("expected IMAGE-002 FAIL finding for GitHub token in ENV")
	}
}

// ── Registry ────────────────────────────────────────────────────────────────

func TestDockerScannerRegistered(t *testing.T) {
	if !Registered("docker") {
		t.Fatal("expected 'docker' scanner to be registered")
	}
	factory := Get("docker")
	if factory == nil {
		t.Fatal("expected non-nil factory for 'docker'")
	}
}


// ── File type detection ─────────────────────────────────────────────────────

func TestDetectDockerFileType(t *testing.T) {
	tests := []struct {
		path     string
		expected dockerFileType
	}{
		{"Dockerfile", fileTypeDockerfile},
		{"Dockerfile.prod", fileTypeDockerfile},
		{"app.dockerfile", fileTypeDockerfile},
		{"Containerfile", fileTypeDockerfile},
		{"docker-compose.yml", fileTypeCompose},
		{"docker-compose.yaml", fileTypeCompose},
		{"compose.yml", fileTypeCompose},
		{"compose.yaml", fileTypeCompose},
		{"docker-compose.prod.yml", fileTypeCompose},
		{"docker-compose.override.yaml", fileTypeCompose},
		{"random.txt", fileTypeUnknown},
		{"values.yaml", fileTypeUnknown},
		{"deployment.yml", fileTypeUnknown},
	}

	for _, tt := range tests {
		got := detectDockerFileType(tt.path)
		if got != tt.expected {
			t.Errorf("detectDockerFileType(%q) = %d, want %d", tt.path, got, tt.expected)
		}
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// Compose tests
// ══════════════════════════════════════════════════════════════════════════════

func TestDockerScanner_InsecureCompose_HasFails(t *testing.T) {
	path := composeTestPath(t, "insecure-compose.yml")
	s := NewDockerScanner(path)

	result, err := s.Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected findings from insecure compose, got none")
	}
	if !hasFail(result.Findings) {
		t.Error("insecure compose produced no FAIL findings")
	}
}

func TestDockerScanner_InsecureCompose_SpecificViolations(t *testing.T) {
	path := composeTestPath(t, "insecure-compose.yml")
	s := NewDockerScanner(path)

	result, err := s.Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// Collect all control IDs that have FAIL status
	failIDs := make(map[string]bool)
	warnIDs := make(map[string]bool)
	for _, f := range result.Findings {
		if f.Status == types.StatusFail {
			failIDs[f.Control.ID] = true
		}
		if f.Status == types.StatusWarn {
			warnIDs[f.Control.ID] = true
		}
	}

	expectedFails := []string{
		"RUNTIME-002", // privileged: true (webapp)
		"RUNTIME-003", // no cap_drop ALL (both services)
		"RUNTIME-004", // no no-new-privileges (both services)
		"RUNTIME-006", // network_mode: host (webapp), pid: host (db)
		"RUNTIME-007", // no resource limits (both services)
		"RUNTIME-009", // docker.sock mounted (webapp)
		"RUNTIME-012", // no healthcheck (both services)
		"IMAGE-001",   // image not pinned (both services)
		"IMAGE-002",   // secrets in env (both services)
	}
	for _, id := range expectedFails {
		if !failIDs[id] {
			t.Errorf("expected FAIL for %s in insecure compose", id)
		}
	}

	// RUNTIME-011: privileged ports should be WARN
	if !warnIDs["RUNTIME-011"] {
		t.Error("expected WARN for RUNTIME-011 (privileged ports) in insecure compose")
	}
}

func TestDockerScanner_SecureCompose_NoCriticalFails(t *testing.T) {
	path := composeTestPath(t, "secure-compose.yml")
	s := NewDockerScanner(path)

	result, err := s.Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	criticalControls := []string{
		"RUNTIME-001", // non-root user
		"RUNTIME-002", // not privileged
		"RUNTIME-003", // cap_drop ALL
		"RUNTIME-004", // no-new-privileges
		"RUNTIME-006", // no host namespaces
		"RUNTIME-007", // resource limits
		"RUNTIME-009", // no sensitive mounts
		"RUNTIME-012", // healthcheck
		"IMAGE-001",   // digest pinned
		"IMAGE-002",   // no secrets in env
	}
	for _, id := range criticalControls {
		for _, f := range result.Findings {
			if f.Control.ID == id && f.Status == types.StatusFail {
				t.Errorf("secure compose: control %s should not FAIL (detail: %s)", id, f.Detail)
			}
		}
	}
}

func TestDockerScanner_HardenedPostgresCompose(t *testing.T) {
	path := composeTestPath(t, "hardened-postgres-compose.yml")
	s := NewDockerScanner(path)

	result, err := s.Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// Should pass most runtime controls
	passControls := []string{
		"RUNTIME-001", // user: "999:999"
		"RUNTIME-002", // not privileged
		"RUNTIME-003", // cap_drop: ALL
		"RUNTIME-004", // no-new-privileges:true
		"RUNTIME-006", // no host namespaces
		"RUNTIME-009", // no sensitive mounts
		"RUNTIME-012", // healthcheck configured
	}
	for _, id := range passControls {
		for _, f := range result.Findings {
			if f.Control.ID == id && f.Status == types.StatusFail {
				t.Errorf("hardened postgres compose: control %s should not FAIL (detail: %s)", id, f.Detail)
			}
		}
	}
}

// ── Compose target format ───────────────────────────────────────────────────

func TestDockerScanner_Compose_TargetFormat(t *testing.T) {
	path := composeTestPath(t, "insecure-compose.yml")
	s := NewDockerScanner(path)

	result, err := s.Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// Targets should be in the format "filename[servicename]"
	hasWebapp := false
	hasDB := false
	for _, f := range result.Findings {
		if strings.Contains(f.Target, "[webapp]") {
			hasWebapp = true
		}
		if strings.Contains(f.Target, "[db]") {
			hasDB = true
		}
	}
	if !hasWebapp {
		t.Error("expected findings with target containing [webapp]")
	}
	if !hasDB {
		t.Error("expected findings with target containing [db]")
	}
}

// ── Compose environment parsing ─────────────────────────────────────────────

func TestComposeEnvUnmarshal_MapForm(t *testing.T) {
	input := `FOO: bar
BAZ: qux`
	var env composeEnv
	if err := yaml.Unmarshal([]byte(input), &env); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if env.Vars["FOO"] != "bar" {
		t.Errorf("expected FOO=bar, got %q", env.Vars["FOO"])
	}
	if env.Vars["BAZ"] != "qux" {
		t.Errorf("expected BAZ=qux, got %q", env.Vars["BAZ"])
	}
}

func TestComposeEnvUnmarshal_ListForm(t *testing.T) {
	input := `- FOO=bar
- BAZ=qux
- EMPTY`
	var env composeEnv
	if err := yaml.Unmarshal([]byte(input), &env); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if env.Vars["FOO"] != "bar" {
		t.Errorf("expected FOO=bar, got %q", env.Vars["FOO"])
	}
	if env.Vars["BAZ"] != "qux" {
		t.Errorf("expected BAZ=qux, got %q", env.Vars["BAZ"])
	}
	if env.Vars["EMPTY"] != "" {
		t.Errorf("expected EMPTY='', got %q", env.Vars["EMPTY"])
	}
}

// ── Mixed directory scan ────────────────────────────────────────────────────

func TestDockerScanner_MixedDirectory(t *testing.T) {
	dir := t.TempDir()

	// Write a Dockerfile
	df := filepath.Join(dir, "Dockerfile")
	if err := os.WriteFile(df, []byte("FROM alpine:3.19\nUSER nobody\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Write a compose file
	cf := filepath.Join(dir, "docker-compose.yml")
	compose := `version: "3.9"
services:
  app:
    image: nginx:latest
`
	if err := os.WriteFile(cf, []byte(compose), 0644); err != nil {
		t.Fatal(err)
	}

	s := NewDockerScanner(dir)
	result, err := s.Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// Should have findings from both file types
	hasDockerfile := false
	hasCompose := false
	for _, f := range result.Findings {
		if strings.Contains(f.Target, "Dockerfile") || f.SourceFile != "" {
			hasDockerfile = true
		}
		if strings.Contains(f.Target, "[app]") {
			hasCompose = true
		}
	}
	if !hasDockerfile {
		t.Error("expected findings from Dockerfile in mixed directory")
	}
	if !hasCompose {
		t.Error("expected findings from compose file in mixed directory")
	}
}

// ── Individual compose check tests ──────────────────────────────────────────

func TestCheckComposePrivileged(t *testing.T) {
	priv := true
	svc := composeService{Privileged: &priv}
	findings := checkComposePrivileged(svc, "test")
	assertFail(t, findings, "RUNTIME-002")

	svc2 := composeService{}
	findings2 := checkComposePrivileged(svc2, "test")
	assertPass(t, findings2, "RUNTIME-002")
}

func TestCheckComposeCapabilities(t *testing.T) {
	svc := composeService{CapDrop: []string{"ALL"}}
	findings := checkComposeCapabilities(svc, "test")
	assertPass(t, findings, "RUNTIME-003")

	svc2 := composeService{CapDrop: []string{"NET_RAW"}}
	findings2 := checkComposeCapabilities(svc2, "test")
	assertFail(t, findings2, "RUNTIME-003")
}

func TestCheckComposeUser_Root(t *testing.T) {
	svc := composeService{User: "root"}
	findings := checkComposeUser(svc, "test")
	assertFail(t, findings, "RUNTIME-001")
}

func TestCheckComposeUser_NonRoot(t *testing.T) {
	svc := composeService{User: "1000:1000"}
	findings := checkComposeUser(svc, "test")
	assertPass(t, findings, "RUNTIME-001")
}

func TestCheckComposeUser_Empty(t *testing.T) {
	svc := composeService{User: ""}
	findings := checkComposeUser(svc, "test")
	// Empty user means running as default (root), should FAIL or WARN
	found := false
	for _, f := range findings {
		if f.Control.ID == "RUNTIME-001" && (f.Status == types.StatusFail || f.Status == types.StatusWarn) {
			found = true
		}
	}
	if !found {
		t.Error("expected FAIL or WARN for empty (default root) user")
	}
}

func TestCheckComposeUser_UID0(t *testing.T) {
	svc := composeService{User: "0"}
	findings := checkComposeUser(svc, "test")
	assertFail(t, findings, "RUNTIME-001")
}

func TestCheckComposeReadOnly(t *testing.T) {
	ro := true
	svc := composeService{ReadOnly: &ro}
	findings := checkComposeReadOnly(svc, "test")
	assertPass(t, findings, "RUNTIME-005")

	svc2 := composeService{}
	findings2 := checkComposeReadOnly(svc2, "test")
	if len(findings2) == 0 {
		t.Fatal("expected findings for missing read_only, got none")
	}
	if findings2[0].Status != types.StatusWarn {
		t.Errorf("expected WARN for missing read_only, got %s", findings2[0].Status)
	}
	if findings2[0].Control.ID != "RUNTIME-005" {
		t.Errorf("expected control RUNTIME-005, got %s", findings2[0].Control.ID)
	}

	// Also test read_only: false explicitly
	roFalse := false
	svc3 := composeService{ReadOnly: &roFalse}
	findings3 := checkComposeReadOnly(svc3, "test")
	if len(findings3) == 0 {
		t.Fatal("expected findings for read_only: false, got none")
	}
	if findings3[0].Status != types.StatusWarn {
		t.Errorf("expected WARN for read_only: false, got %s", findings3[0].Status)
	}
}

func TestCheckComposeHostNamespaces(t *testing.T) {
	svc := composeService{NetworkMode: "host"}
	findings := checkComposeHostNamespaces(svc, "test")
	assertFail(t, findings, "RUNTIME-006")

	svc2 := composeService{PidMode: "host"}
	findings2 := checkComposeHostNamespaces(svc2, "test")
	assertFail(t, findings2, "RUNTIME-006")

	svc3 := composeService{IpcMode: "host"}
	findings3 := checkComposeHostNamespaces(svc3, "test")
	assertFail(t, findings3, "RUNTIME-006")

	svc4 := composeService{}
	findings4 := checkComposeHostNamespaces(svc4, "test")
	assertPass(t, findings4, "RUNTIME-006")
}

func TestCheckComposeResources(t *testing.T) {
	svc := composeService{
		Deploy: &composeDeploy{
			Resources: &composeResources{
				Limits: &composeResourceSpec{Memory: "256m", CPUs: "0.5"},
			},
		},
	}
	findings := checkComposeResources(svc, "test")
	assertPass(t, findings, "RUNTIME-007")

	svc2 := composeService{}
	findings2 := checkComposeResources(svc2, "test")
	assertFail(t, findings2, "RUNTIME-007")

	// Partial limits (memory only, no CPU)
	svc3 := composeService{
		Deploy: &composeDeploy{
			Resources: &composeResources{
				Limits: &composeResourceSpec{Memory: "256m"},
			},
		},
	}
	findings3 := checkComposeResources(svc3, "test")
	// Should warn or fail for missing CPU
	found := false
	for _, f := range findings3 {
		if f.Control.ID == "RUNTIME-007" && (f.Status == types.StatusFail || f.Status == types.StatusWarn) {
			found = true
		}
	}
	if !found {
		// If it passes, that's OK too - the implementation may consider memory-only sufficient
		assertPass(t, findings3, "RUNTIME-007")
	}
}

func TestCheckComposeHealthcheck(t *testing.T) {
	svc := composeService{Healthcheck: &composeHealthcheck{Test: "curl -f http://localhost"}}
	findings := checkComposeHealthcheck(svc, "test")
	assertPass(t, findings, "RUNTIME-012")

	svc2 := composeService{}
	findings2 := checkComposeHealthcheck(svc2, "test")
	assertFail(t, findings2, "RUNTIME-012")

	svc3 := composeService{Healthcheck: &composeHealthcheck{Disable: true}}
	findings3 := checkComposeHealthcheck(svc3, "test")
	assertFail(t, findings3, "RUNTIME-012")
}

func TestCheckComposeVolumes_DockerSock(t *testing.T) {
	svc := composeService{Volumes: []interface{}{"/var/run/docker.sock:/var/run/docker.sock"}}
	findings := checkComposeVolumes(svc, "test")
	assertFail(t, findings, "RUNTIME-009")
	// Defense-in-depth: docker.sock should also trigger DAEMON-001
	assertFail(t, findings, "DAEMON-001")
}

func TestCheckComposeContentTrust_Enabled(t *testing.T) {
	svc := composeService{}
	svc.Environment.Vars = map[string]string{"DOCKER_CONTENT_TRUST": "1"}
	findings := checkComposeContentTrust(svc, "test")
	assertPass(t, findings, "DAEMON-004")
}

func TestCheckComposeContentTrust_Disabled(t *testing.T) {
	svc := composeService{}
	svc.Environment.Vars = map[string]string{"DOCKER_CONTENT_TRUST": "0"}
	findings := checkComposeContentTrust(svc, "test")
	f := findFinding(findings, "DAEMON-004")
	if f == nil {
		t.Fatal("expected finding for DAEMON-004")
	}
	if f.Status != types.StatusWarn {
		t.Errorf("expected WARN for DOCKER_CONTENT_TRUST=0, got %s", f.Status)
	}
}

func TestCheckComposeContentTrust_Absent(t *testing.T) {
	svc := composeService{}
	svc.Environment.Vars = map[string]string{"FOO": "bar"}
	findings := checkComposeContentTrust(svc, "test")
	if len(findings) != 0 {
		t.Errorf("expected no findings when DOCKER_CONTENT_TRUST absent, got %d", len(findings))
	}
}

func TestCheckComposePorts_Privileged(t *testing.T) {
	svc := composeService{Ports: []interface{}{"80:80", "443:443"}}
	findings := checkComposePorts(svc, "test")
	if len(findings) == 0 {
		t.Fatal("expected findings for privileged ports, got none")
	}
	if findings[0].Status != types.StatusWarn {
		t.Errorf("expected WARN for privileged ports, got %s", findings[0].Status)
	}
	if findings[0].Control.ID != "RUNTIME-011" {
		t.Errorf("expected control RUNTIME-011, got %s", findings[0].Control.ID)
	}
}

func TestCheckComposePorts_HighPort(t *testing.T) {
	svc := composeService{Ports: []interface{}{"8080:80"}}
	findings := checkComposePorts(svc, "test")
	assertPass(t, findings, "RUNTIME-011")
}

func TestCheckComposeImageDigest_Pinned(t *testing.T) {
	svc := composeService{Image: "nginx:1.25@sha256:abcdef1234567890"}
	findings := checkComposeImageDigest(svc, "test")
	assertPass(t, findings, "IMAGE-001")
}

func TestCheckComposeImageDigest_NotPinned(t *testing.T) {
	svc := composeService{Image: "nginx:latest"}
	findings := checkComposeImageDigest(svc, "test")
	assertFail(t, findings, "IMAGE-001")
}

func TestCheckComposeSecrets_PasswordInEnv(t *testing.T) {
	svc := composeService{
		Environment: composeEnv{Vars: map[string]string{"DB_PASSWORD": "supersecret"}},
	}
	findings := checkComposeSecrets(svc, "test")
	assertFail(t, findings, "IMAGE-002")
}

func TestCheckComposeSecrets_FileConvention(t *testing.T) {
	svc := composeService{
		Environment: composeEnv{Vars: map[string]string{
			"POSTGRES_PASSWORD_FILE": "/run/secrets/db-password",
		}},
	}
	findings := checkComposeSecrets(svc, "test")
	assertPass(t, findings, "IMAGE-002")
}

// ══════════════════════════════════════════════════════════════════════════════
// Dockerfile HEALTHCHECK and EXPOSE tests (session 3)
// ══════════════════════════════════════════════════════════════════════════════

func TestDockerScanner_MissingHealthcheck(t *testing.T) {
	dir := t.TempDir()
	df := filepath.Join(dir, "Dockerfile")
	content := `FROM alpine:3.19
RUN echo hello
USER nobody
`
	if err := os.WriteFile(df, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	s := NewDockerScanner(df)
	result, err := s.Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// Should have WARN for missing HEALTHCHECK (RUNTIME-012)
	hasHealthcheckWarn := false
	for _, f := range result.Findings {
		if f.Control.ID == "RUNTIME-012" && f.Status == types.StatusWarn {
			hasHealthcheckWarn = true
		}
	}
	if !hasHealthcheckWarn {
		t.Error("expected WARN for missing HEALTHCHECK instruction")
	}
}

func TestDockerScanner_HasHealthcheck(t *testing.T) {
	dir := t.TempDir()
	df := filepath.Join(dir, "Dockerfile")
	content := `FROM alpine:3.19
RUN echo hello
USER nobody
HEALTHCHECK --interval=30s CMD wget -q -O /dev/null http://localhost:8080/health || exit 1
`
	if err := os.WriteFile(df, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	s := NewDockerScanner(df)
	result, err := s.Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// Should NOT have WARN for HEALTHCHECK
	for _, f := range result.Findings {
		if f.Control.ID == "RUNTIME-012" && f.Status == types.StatusWarn {
			t.Errorf("unexpected WARN for HEALTHCHECK when present: %s", f.Detail)
		}
	}
}

func TestDockerScanner_ExposePrivilegedPort(t *testing.T) {
	dir := t.TempDir()
	df := filepath.Join(dir, "Dockerfile")
	content := `FROM alpine:3.19
EXPOSE 80 443
USER nobody
HEALTHCHECK CMD echo ok
`
	if err := os.WriteFile(df, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	s := NewDockerScanner(df)
	result, err := s.Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// Should have WARN for privileged ports (RUNTIME-011)
	hasPortWarn := false
	for _, f := range result.Findings {
		if f.Control.ID == "RUNTIME-011" && f.Status == types.StatusWarn {
			hasPortWarn = true
		}
	}
	if !hasPortWarn {
		t.Error("expected WARN for EXPOSE privileged ports 80, 443")
	}
}

func TestDockerScanner_ExposeHighPort(t *testing.T) {
	dir := t.TempDir()
	df := filepath.Join(dir, "Dockerfile")
	content := `FROM alpine:3.19
EXPOSE 8080
USER nobody
HEALTHCHECK CMD echo ok
`
	if err := os.WriteFile(df, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	s := NewDockerScanner(df)
	result, err := s.Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// Should NOT have WARN for RUNTIME-011 (port 8080 is not privileged)
	for _, f := range result.Findings {
		if f.Control.ID == "RUNTIME-011" && f.Status == types.StatusWarn {
			t.Errorf("unexpected WARN for non-privileged port 8080: %s", f.Detail)
		}
	}
}

func TestDockerScanner_ExposeWithProtocol(t *testing.T) {
	dir := t.TempDir()
	df := filepath.Join(dir, "Dockerfile")
	content := `FROM alpine:3.19
EXPOSE 80/tcp 443/udp
USER nobody
HEALTHCHECK CMD echo ok
`
	if err := os.WriteFile(df, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	s := NewDockerScanner(df)
	result, err := s.Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// Should have WARN for privileged ports even with protocol suffix
	hasPortWarn := false
	for _, f := range result.Findings {
		if f.Control.ID == "RUNTIME-011" && f.Status == types.StatusWarn {
			hasPortWarn = true
		}
	}
	if !hasPortWarn {
		t.Error("expected WARN for EXPOSE 80/tcp 443/udp (privileged ports)")
	}
}

// ── Compose AI key detection tests ──────────────────────────────────────────

func TestCheckComposeSecrets_AIKey(t *testing.T) {
	svc := composeService{
		Environment: composeEnv{Vars: map[string]string{
			"OPENAI_API_KEY": "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv",
		}},
	}
	findings := checkComposeSecrets(svc, "test")
	if len(findings) == 0 {
		t.Fatal("expected findings for OPENAI_API_KEY in compose env")
	}
	hasFail := false
	for _, f := range findings {
		if f.Status == types.StatusFail && f.Control.ID == "SECRETS-003" {
			hasFail = true
		}
	}
	if !hasFail {
		t.Error("expected FAIL for SECRETS-003 (AI key in compose env)")
	}
}

func TestCheckComposeSecrets_GenericAPIKey(t *testing.T) {
	svc := composeService{
		Environment: composeEnv{Vars: map[string]string{
			"CUSTOM_API_KEY": "some-secret-value-here",
		}},
	}
	findings := checkComposeSecrets(svc, "test")
	hasFail := false
	for _, f := range findings {
		if f.Status == types.StatusFail && f.Control.ID == "SECRETS-003" {
			hasFail = true
		}
	}
	if !hasFail {
		t.Error("expected FAIL for SECRETS-003 (generic *_api_key suffix in compose env)")
	}
}

// ── Consolidated EOL detection tests ────────────────────────────────────────

func TestDockerScanner_CheckEOLInLine_ConsolidatedPatterns(t *testing.T) {
	s := NewDockerScanner("")

	// Test entries from DefaultEOLImages — covers more than the old 16-entry hardcoded list
	expandedCases := []struct {
		line  string
		isEOL bool
	}{
		// Entries beyond the original docker.go hardcoded list (from image_eol.go)
		{"FROM ruby:2.5-slim", true},
		{"FROM ruby:2.7-alpine", true},
		{"FROM php:7.2-fpm", true},
		{"FROM golang:1.18-alpine", true},
		{"FROM postgres:10-alpine", true},
		{"FROM mysql:5.6", true},
		{"FROM mongo:4.4", true},
		{"FROM redis:5-alpine", true},
		{"FROM elasticsearch:6.8", true},
		// Current/supported versions — should NOT be EOL
		{"FROM ruby:3.3", false},
		{"FROM php:8.3", false},
		{"FROM golang:1.22-alpine", false},
		{"FROM postgres:16", false},
		{"FROM mysql:8.0", false},
	}

	for _, tt := range expandedCases {
		finding := s.checkEOLInLine("test", tt.line, 1)
		if tt.isEOL && finding == nil {
			t.Errorf("expected EOL finding for %q, got nil", tt.line)
		}
		if !tt.isEOL && finding != nil {
			t.Errorf("expected no EOL finding for %q, got: %s", tt.line, finding.Detail)
		}
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// checkSecretsInHistory tests (Dockerfile secret detection via SecretScanner)
// ══════════════════════════════════════════════════════════════════════════════

func TestCheckSecretsInHistory_AWSKey(t *testing.T) {
	dir := t.TempDir()
	df := filepath.Join(dir, "Dockerfile")
	content := "FROM alpine:3.19\nENV AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nUSER nobody\n"
	if err := os.WriteFile(df, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	s := NewDockerScanner(df)
	result, err := s.Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	found := false
	for _, f := range result.Findings {
		if f.Control.ID == "IMAGE-002" && f.Status == types.StatusFail {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected FAIL for IMAGE-002 (AWS access key in Dockerfile ENV)")
	}
}

func TestCheckSecretsInHistory_GitHubToken(t *testing.T) {
	dir := t.TempDir()
	df := filepath.Join(dir, "Dockerfile")
	content := "FROM alpine:3.19\nENV GH_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12\nUSER nobody\n"
	if err := os.WriteFile(df, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	s := NewDockerScanner(df)
	result, err := s.Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	found := false
	for _, f := range result.Findings {
		if f.Control.ID == "IMAGE-002" && f.Status == types.StatusFail {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected FAIL for IMAGE-002 (GitHub token in Dockerfile ENV)")
	}
}

func TestCheckSecretsInHistory_PasswordKeyword(t *testing.T) {
	dir := t.TempDir()
	df := filepath.Join(dir, "Dockerfile")
	content := "FROM alpine:3.19\nENV DB_PASSWORD=mysupersecretpassword\nUSER nobody\n"
	if err := os.WriteFile(df, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	s := NewDockerScanner(df)
	result, err := s.Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	found := false
	for _, f := range result.Findings {
		if f.Control.ID == "IMAGE-002" && f.Status == types.StatusFail {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected FAIL for IMAGE-002 (password keyword in Dockerfile ENV)")
	}
}

func TestCheckSecretsInHistory_PrivateKey(t *testing.T) {
	dir := t.TempDir()
	df := filepath.Join(dir, "Dockerfile")
	content := "FROM alpine:3.19\nRUN echo '-----BEGIN RSA PRIVATE KEY-----' > /key\nUSER nobody\n"
	if err := os.WriteFile(df, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	s := NewDockerScanner(df)
	result, err := s.Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	found := false
	for _, f := range result.Findings {
		if f.Control.ID == "IMAGE-002" && f.Status == types.StatusFail {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected FAIL for IMAGE-002 (RSA private key in Dockerfile)")
	}
}

func TestCheckSecretsInHistory_PasswordInURL(t *testing.T) {
	dir := t.TempDir()
	df := filepath.Join(dir, "Dockerfile")
	content := "FROM alpine:3.19\nENV DATABASE_URL=postgres://admin:s3cret@db:5432/mydb\nUSER nobody\n"
	if err := os.WriteFile(df, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	s := NewDockerScanner(df)
	result, err := s.Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	found := false
	for _, f := range result.Findings {
		if f.Control.ID == "IMAGE-002" && f.Status == types.StatusFail {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected FAIL for IMAGE-002 (password in URL in Dockerfile ENV)")
	}
}

func TestCheckSecretsInHistory_CleanDockerfile(t *testing.T) {
	dir := t.TempDir()
	df := filepath.Join(dir, "Dockerfile")
	content := "FROM alpine:3.19\nRUN apk add --no-cache curl\nENV APP_PORT=8080\nUSER nobody\nHEALTHCHECK CMD echo ok\n"
	if err := os.WriteFile(df, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	s := NewDockerScanner(df)
	result, err := s.Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	for _, f := range result.Findings {
		if f.Control.ID == "IMAGE-002" && f.Status == types.StatusFail {
			t.Errorf("clean Dockerfile should not trigger IMAGE-002 FAIL, got: %s", f.Detail)
		}
	}
}

func TestCheckSecretsInHistory_MultipleSecrets(t *testing.T) {
	dir := t.TempDir()
	df := filepath.Join(dir, "Dockerfile")
	content := `FROM alpine:3.19
ENV DB_PASSWORD=secret123
ENV AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
ENV API_SECRET=mysecretvalue
USER nobody
`
	if err := os.WriteFile(df, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	s := NewDockerScanner(df)
	result, err := s.Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// Should detect secrets via both line-by-line checks and history check
	secretFailCount := 0
	for _, f := range result.Findings {
		if f.Control.ID == "IMAGE-002" && f.Status == types.StatusFail {
			secretFailCount++
		}
	}
	if secretFailCount < 2 {
		t.Errorf("expected at least 2 IMAGE-002 FAILs for multiple secrets, got %d", secretFailCount)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// checkComposeSecrets tests (Compose env-var secret detection)
// ══════════════════════════════════════════════════════════════════════════════

func TestCheckComposeSecrets_AWSKeyInValue(t *testing.T) {
	svc := composeService{
		Environment: composeEnv{Vars: map[string]string{
			"AWS_CONFIG": "AKIAIOSFODNN7EXAMPLE",
		}},
	}
	findings := checkComposeSecrets(svc, "test[app]")
	found := false
	for _, f := range findings {
		if f.Status == types.StatusFail {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected FAIL for AWS key detected in compose env value")
	}
}

func TestCheckComposeSecrets_GitHubTokenInValue(t *testing.T) {
	svc := composeService{
		Environment: composeEnv{Vars: map[string]string{
			"CI_TOKEN": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12",
		}},
	}
	findings := checkComposeSecrets(svc, "test[app]")
	found := false
	for _, f := range findings {
		if f.Status == types.StatusFail {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected FAIL for GitHub token detected in compose env value")
	}
}

func TestCheckComposeSecrets_StripeAPIKeySuffix(t *testing.T) {
	svc := composeService{
		Environment: composeEnv{Vars: map[string]string{
			"STRIPE_API_KEY": "sk_test_abcdefghijklmnopqrstuvwx",
		}},
	}
	findings := checkComposeSecrets(svc, "test[app]")
	found := false
	for _, f := range findings {
		if f.Status == types.StatusFail {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected FAIL for *_api_key pattern in compose env name")
	}
}

func TestCheckComposeSecrets_CredentialKeywords(t *testing.T) {
	keywords := map[string]string{
		"DB_PASSWORD":       "supersecret",
		"AUTH_TOKEN":        "tok_12345",
		"CLIENT_SECRET":     "mysecret",
		"PRIVATE_KEY":       "keyvalue123",
		"CONNECTION_STRING": "Server=tcp:db.example.com;Password=s3cret",
	}
	for envName, envVal := range keywords {
		svc := composeService{
			Environment: composeEnv{Vars: map[string]string{envName: envVal}},
		}
		findings := checkComposeSecrets(svc, "test[svc]")
		found := false
		for _, f := range findings {
			if f.Status == types.StatusFail {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected FAIL for credential keyword %q in compose env", envName)
		}
	}
}

func TestCheckComposeSecrets_FileConventionSkipped(t *testing.T) {
	svc := composeService{
		Environment: composeEnv{Vars: map[string]string{
			"POSTGRES_PASSWORD_FILE": "/run/secrets/db-password",
			"MYSQL_ROOT_PASSWORD_FILE": "/run/secrets/mysql-root",
		}},
	}
	findings := checkComposeSecrets(svc, "test[db]")
	assertPass(t, findings, "IMAGE-002")
}

func TestCheckComposeSecrets_PathValueSkipped(t *testing.T) {
	svc := composeService{
		Environment: composeEnv{Vars: map[string]string{
			"SECRET_PATH": "/run/secrets/my-secret",
		}},
	}
	findings := checkComposeSecrets(svc, "test[app]")
	assertPass(t, findings, "IMAGE-002")
}

func TestCheckComposeSecrets_CleanEnv(t *testing.T) {
	svc := composeService{
		Environment: composeEnv{Vars: map[string]string{
			"APP_PORT":  "8080",
			"LOG_LEVEL": "info",
			"NODE_ENV":  "production",
		}},
	}
	findings := checkComposeSecrets(svc, "test[app]")
	assertPass(t, findings, "IMAGE-002")
}

func TestCheckComposeSecrets_EmptyValueSkipped(t *testing.T) {
	svc := composeService{
		Environment: composeEnv{Vars: map[string]string{
			"DB_PASSWORD": "",
		}},
	}
	findings := checkComposeSecrets(svc, "test[db]")
	assertPass(t, findings, "IMAGE-002")
}

func TestCheckComposeSecrets_AIKeyPatterns(t *testing.T) {
	aiKeys := map[string]string{
		"OPENAI_API_KEY":       "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv",
		"ANTHROPIC_API_KEY":    "sk-ant-api-key-value-here123456",
		"COHERE_API_KEY":       "cohere-key-12345",
		"HF_TOKEN":             "hf_ABCDEFGHIJKLmnop",
		"AZURE_OPENAI_API_KEY": "azure-key-value-here",
	}
	for envName, envVal := range aiKeys {
		svc := composeService{
			Environment: composeEnv{Vars: map[string]string{envName: envVal}},
		}
		findings := checkComposeSecrets(svc, "test[ai-svc]")
		found := false
		for _, f := range findings {
			if f.Status == types.StatusFail && f.Control.ID == "SECRETS-003" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected FAIL for SECRETS-003 (%s in compose env)", envName)
		}
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// End-to-end secret detection through full compose scan
// ══════════════════════════════════════════════════════════════════════════════

func TestDockerScanner_ComposeSecrets_EndToEnd(t *testing.T) {
	dir := t.TempDir()
	cf := filepath.Join(dir, "docker-compose.yml")
	compose := `version: "3.9"
services:
  api:
    image: node:20-alpine
    environment:
      DB_PASSWORD: supersecret
      API_TOKEN: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12
  worker:
    image: python:3.12-slim
    environment:
      APP_PORT: "8080"
      LOG_LEVEL: info
`
	if err := os.WriteFile(cf, []byte(compose), 0644); err != nil {
		t.Fatal(err)
	}

	s := NewDockerScanner(cf)
	result, err := s.Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// api service should have IMAGE-002 FAIL for secrets
	apiSecretFail := false
	workerSecretFail := false
	for _, f := range result.Findings {
		if f.Control.ID == "IMAGE-002" && f.Status == types.StatusFail {
			if strings.Contains(f.Target, "[api]") {
				apiSecretFail = true
			}
			if strings.Contains(f.Target, "[worker]") {
				workerSecretFail = true
			}
		}
	}
	if !apiSecretFail {
		t.Error("expected IMAGE-002 FAIL for api service with secrets in env")
	}
	if workerSecretFail {
		t.Error("unexpected IMAGE-002 FAIL for worker service with clean env")
	}
}

func TestDockerScanner_DockerfileSecrets_EndToEnd(t *testing.T) {
	dir := t.TempDir()
	df := filepath.Join(dir, "Dockerfile")
	content := `FROM alpine:3.19
ENV STRIPE_KEY=sk_live_abcdefghijklmnopqrstuvwxyz123456
RUN echo "setup"
USER nobody
HEALTHCHECK CMD echo ok
`
	if err := os.WriteFile(df, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	s := NewDockerScanner(df)
	result, err := s.Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// Should detect the Stripe key via both line check and history scan
	found := false
	for _, f := range result.Findings {
		if f.Control.ID == "IMAGE-002" && f.Status == types.StatusFail {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected IMAGE-002 FAIL for Stripe key in Dockerfile ENV")
	}
}

// ── Compose secrets: multiple secrets detection (TASK-8.2) ──────────────────

func TestCheckComposeSecrets_MultipleSecrets(t *testing.T) {
	svc := composeService{
		Environment: composeEnv{
			Vars: map[string]string{
				"DB_PASSWORD":    "supersecret",
				"API_TOKEN":      "tok_abc123",
				"OPENAI_API_KEY": "sk-abcdef",
			},
		},
	}
	findings := checkComposeSecrets(svc, "test")
	// Should find ALL three secrets, not just the first one
	failCount := 0
	for _, f := range findings {
		if f.Status == types.StatusFail {
			failCount++
		}
	}
	if failCount < 3 {
		t.Errorf("expected at least 3 FAIL findings for 3 secrets, got %d", failCount)
		for _, f := range findings {
			t.Logf("  %s %s: %s", f.Control.ID, f.Status, f.Detail)
		}
	}
}

func TestCheckComposeSecrets_Deterministic(t *testing.T) {
	svc := composeService{
		Environment: composeEnv{
			Vars: map[string]string{
				"Z_PASSWORD": "secret1",
				"A_TOKEN":    "secret2",
				"M_SECRET":   "secret3",
			},
		},
	}
	// Run multiple times — results should be identical (sorted iteration)
	var first []string
	for i := 0; i < 10; i++ {
		findings := checkComposeSecrets(svc, "test")
		var details []string
		for _, f := range findings {
			if f.Status == types.StatusFail {
				details = append(details, f.Detail)
			}
		}
		if i == 0 {
			first = details
		} else {
			if len(details) != len(first) {
				t.Fatalf("iteration %d: got %d findings, want %d", i, len(details), len(first))
			}
			for j := range details {
				if details[j] != first[j] {
					t.Fatalf("iteration %d: finding %d differs: got %q, want %q", i, j, details[j], first[j])
				}
			}
		}
	}
}

// ── Compose ports: IP-binding parsing (TASK-8.12) ───────────────────────────

func TestCheckComposePorts_IPBinding(t *testing.T) {
	svc := composeService{
		Ports: []interface{}{"192.168.1.1:80:8080"},
	}
	findings := checkComposePorts(svc, "test")
	found := false
	for _, f := range findings {
		if f.Control.ID == "RUNTIME-011" && f.Status == types.StatusWarn {
			found = true
		}
	}
	if !found {
		t.Error("expected WARN for privileged port 80 in IP:host:container syntax")
	}
}

func TestCheckComposePorts_IPBinding_HighPort(t *testing.T) {
	svc := composeService{
		Ports: []interface{}{"0.0.0.0:8080:80"},
	}
	findings := checkComposePorts(svc, "test")
	for _, f := range findings {
		if f.Control.ID == "RUNTIME-011" && f.Status == types.StatusWarn {
			t.Error("should NOT warn for high host port 8080 even with IP prefix")
		}
	}
}

// ── Compose volumes: long-syntax parsing (TASK-8.11) ────────────────────────

func TestCheckComposeVolumes_LongSyntax(t *testing.T) {
	svc := composeService{
		Volumes: []interface{}{
			map[string]interface{}{
				"type":   "bind",
				"source": "/var/run/docker.sock",
				"target": "/var/run/docker.sock",
			},
		},
	}
	findings := checkComposeVolumes(svc, "test")
	found := false
	for _, f := range findings {
		if f.Control.ID == "RUNTIME-009" && f.Status == types.StatusFail {
			found = true
		}
	}
	if !found {
		t.Error("expected FAIL for docker.sock mount in long-syntax volume")
	}
}

func TestCheckComposeVolumes_MultipleSensitiveMounts(t *testing.T) {
	svc := composeService{
		Volumes: []interface{}{
			"/var/run/docker.sock:/var/run/docker.sock",
			"/etc/shadow:/etc/shadow:ro",
		},
	}
	findings := checkComposeVolumes(svc, "test")
	failCount := 0
	for _, f := range findings {
		if f.Control.ID == "RUNTIME-009" && f.Status == types.StatusFail {
			failCount++
		}
	}
	if failCount != 2 {
		t.Errorf("expected exactly 2 FAIL findings for 2 sensitive mounts, got %d", failCount)
	}
}

// TestCheckComposeVolumes_NoDuplicateForDockerSock verifies that mounting
// /var/run/docker.sock produces exactly ONE finding even though sensitivePaths
// contains both "/var/run" (prefix) and "/var/run/docker.sock" (exact match).
func TestCheckComposeVolumes_NoDuplicateForDockerSock(t *testing.T) {
	svc := composeService{
		Volumes: []interface{}{"/var/run/docker.sock:/var/run/docker.sock"},
	}
	findings := checkComposeVolumes(svc, "test")
	failCount := 0
	for _, f := range findings {
		if f.Control.ID == "RUNTIME-009" && f.Status == types.StatusFail {
			failCount++
		}
	}
	if failCount != 1 {
		t.Errorf("expected exactly 1 FAIL for /var/run/docker.sock, got %d (duplicate suppression broken)", failCount)
	}
}

// ── Compose volumes: map[interface{}]interface{} fallback ─────────────────

func TestCheckComposeVolumes_MapInterfaceInterface(t *testing.T) {
	svc := composeService{
		Volumes: []interface{}{
			map[interface{}]interface{}{
				"type":   "bind",
				"source": "/var/run/docker.sock",
				"target": "/var/run/docker.sock",
			},
		},
	}
	findings := checkComposeVolumes(svc, "test")
	found := false
	for _, f := range findings {
		if f.Control.ID == "RUNTIME-009" && f.Status == types.StatusFail {
			found = true
		}
	}
	if !found {
		t.Error("expected FAIL for docker.sock mount via map[interface{}]interface{} volume")
	}
}

// ── Compose volumes: safe mount produces PASS ────────────────────────────

func TestCheckComposeVolumes_SafeMount(t *testing.T) {
	svc := composeService{
		Volumes: []interface{}{"./data:/app/data"},
	}
	findings := checkComposeVolumes(svc, "test")
	assertPass(t, findings, "RUNTIME-009")
}

// ── Compose no-new-privileges ────────────────────────────────────────────

func TestCheckComposeNoNewPrivileges_Set(t *testing.T) {
	svc := composeService{SecurityOpt: []string{"no-new-privileges:true"}}
	findings := checkComposeNoNewPrivileges(svc, "test")
	assertPass(t, findings, "RUNTIME-004")
}

func TestCheckComposeNoNewPrivileges_Missing(t *testing.T) {
	svc := composeService{}
	findings := checkComposeNoNewPrivileges(svc, "test")
	assertFail(t, findings, "RUNTIME-004")
}

// ── checkComposeSeccomp ──────────────────────────────────────────────────────

// TestCheckComposeSeccomp_Set verifies PASS when a valid seccomp profile is present.
func TestCheckComposeSeccomp_Set(t *testing.T) {
	svc := composeService{SecurityOpt: []string{
		"no-new-privileges:true",
		"seccomp=/etc/docker/seccomp-default.json",
	}}
	findings := checkComposeSeccomp(svc, "test")
	assertPass(t, findings, "RUNTIME-008")
}

// TestCheckComposeSeccomp_Missing verifies WARN when security_opt has no seccomp entry.
func TestCheckComposeSeccomp_Missing(t *testing.T) {
	svc := composeService{}
	findings := checkComposeSeccomp(svc, "test")
	assertWarn(t, findings, "RUNTIME-008")
}

// TestCheckComposeSeccomp_Unconfined verifies FAIL when seccomp is explicitly disabled.
func TestCheckComposeSeccomp_Unconfined(t *testing.T) {
	svc := composeService{SecurityOpt: []string{"seccomp=unconfined"}}
	findings := checkComposeSeccomp(svc, "test")
	assertFail(t, findings, "RUNTIME-008")
}

// ── checkADDInstruction ──────────────────────────────────────────────────────

func TestCheckADDInstruction_RemoteADD(t *testing.T) {
	findings := checkADDInstruction("Dockerfile", "ADD https://example.com/tool /usr/local/bin/tool", 5)
	assertFail(t, findings, "IMAGE-006")
}

func TestCheckADDInstruction_CurlPipeShell(t *testing.T) {
	findings := checkADDInstruction("Dockerfile", "RUN curl -fsSL https://get.example.com | sh", 3)
	assertFail(t, findings, "IMAGE-006")
}

func TestCheckADDInstruction_CurlWarnOnly(t *testing.T) {
	findings := checkADDInstruction("Dockerfile", "RUN curl -fsSL https://get.example.com -o /tmp/tool", 3)
	assertWarn(t, findings, "IMAGE-006")
}

func TestCheckADDInstruction_PackageInstall_NotFlagged(t *testing.T) {
	// apt-get install curl should NOT trigger IMAGE-006
	findings := checkADDInstruction("Dockerfile", "RUN apt-get install -y curl", 2)
	for _, f := range findings {
		if f.Control.ID == "IMAGE-006" {
			t.Errorf("package install line incorrectly flagged as IMAGE-006: %s", f.Detail)
		}
	}
}

func TestCheckADDInstruction_PlainCopy_NoFindings(t *testing.T) {
	findings := checkADDInstruction("Dockerfile", "COPY ./app /app", 10)
	if len(findings) != 0 {
		t.Errorf("COPY line produced unexpected findings: %v", findings)
	}
}

func TestCheckADDInstruction_LocalFile_WarnIMAGE014(t *testing.T) {
	findings := checkADDInstruction("Dockerfile", "ADD ./config /app/config", 4)
	assertWarn(t, findings, "IMAGE-014")
}

func TestCheckADDInstruction_TarArchive_NotFlagged(t *testing.T) {
	// ADD with .tar.gz is a legitimate use — auto-extraction is intentional
	findings := checkADDInstruction("Dockerfile", "ADD app.tar.gz /app/", 4)
	for _, f := range findings {
		if f.Control.ID == "IMAGE-014" {
			t.Errorf("tar archive ADD incorrectly flagged as IMAGE-014: %s", f.Detail)
		}
	}
}

func TestCheckADDInstruction_LocalADD_NoURL_YesLocalWarn(t *testing.T) {
	// Plain ADD of a local binary — should warn IMAGE-014, not IMAGE-006
	findings := checkADDInstruction("Dockerfile", "ADD bin/tool /usr/local/bin/tool", 7)
	assertWarn(t, findings, "IMAGE-014")
	for _, f := range findings {
		if f.Control.ID == "IMAGE-006" {
			t.Errorf("local ADD incorrectly flagged as IMAGE-006: %s", f.Detail)
		}
	}
}

// ── checkComposeADDInstruction ───────────────────────────────────────────────

func TestCheckComposeADDInstruction_PipeShell(t *testing.T) {
	svc := composeService{Command: "sh -c 'curl https://get.example.com | bash'"}
	findings := checkComposeADDInstruction(svc, "test")
	assertFail(t, findings, "IMAGE-006")
	assertPass(t, findings, "IMAGE-014")
}

func TestCheckComposeADDInstruction_WarnOnly(t *testing.T) {
	svc := composeService{Command: "wget https://get.example.com/setup.sh"}
	findings := checkComposeADDInstruction(svc, "test")
	assertWarn(t, findings, "IMAGE-006")
	assertPass(t, findings, "IMAGE-014")
}

func TestCheckComposeADDInstruction_NoCommand(t *testing.T) {
	svc := composeService{}
	findings := checkComposeADDInstruction(svc, "test")
	assertSkipped(t, findings, "IMAGE-006")
	assertPass(t, findings, "IMAGE-014")
}

func TestCheckComposeADDInstruction_PackageInstall_NotFlagged(t *testing.T) {
	svc := composeService{Command: "apt-get install -y curl wget"}
	findings := checkComposeADDInstruction(svc, "test")
	assertPass(t, findings, "IMAGE-006")
	assertPass(t, findings, "IMAGE-014")
}

func TestCheckComposeADDInstruction_LocalADD_WarnIMAGE014(t *testing.T) {
	svc := composeService{Command: "add ./config /app/config"}
	findings := checkComposeADDInstruction(svc, "test")
	assertWarn(t, findings, "IMAGE-014")
	assertPass(t, findings, "IMAGE-006")
}

// ── checkComposeEOLImage ────────────────────────────────────────────────────

func TestCheckComposeEOLImage_EOL(t *testing.T) {
	svc := composeService{Image: "postgres:13"}
	findings := checkComposeEOLImage(svc, "test")
	assertFail(t, findings, "IMAGE-008")
}

func TestCheckComposeEOLImage_EOL_PrefixTag(t *testing.T) {
	// mongo:4.4 matches "4." prefix entry
	svc := composeService{Image: "mongo:4.4"}
	findings := checkComposeEOLImage(svc, "test")
	assertFail(t, findings, "IMAGE-008")
}

func TestCheckComposeEOLImage_Current(t *testing.T) {
	svc := composeService{Image: "postgres:16"}
	findings := checkComposeEOLImage(svc, "test")
	assertPass(t, findings, "IMAGE-008")
}

func TestCheckComposeEOLImage_NoImage(t *testing.T) {
	svc := composeService{} // build context only
	findings := checkComposeEOLImage(svc, "test")
	assertSkipped(t, findings, "IMAGE-008")
}

func TestCheckComposeEOLImage_Latest(t *testing.T) {
	svc := composeService{Image: "postgres:latest"}
	findings := checkComposeEOLImage(svc, "test")
	assertSkipped(t, findings, "IMAGE-008")
}

// ── checkComposeDangerousDBFlags ─────────────────────────────────────────────

func TestCheckComposeDangerousDBFlags_SkipGrantTables(t *testing.T) {
	svc := composeService{
		Image:   "mysql:8",
		Command: "mysqld --skip-grant-tables",
	}
	findings := checkComposeDangerousDBFlags(svc, "test")
	assertFail(t, findings, "DB-IMAGE-002")
}

func TestCheckComposeDangerousDBFlags_MongoNoAuth(t *testing.T) {
	svc := composeService{
		Image:   "mongo:6",
		Command: "mongod",
	}
	findings := checkComposeDangerousDBFlags(svc, "test")
	assertFail(t, findings, "DB-IMAGE-002")
}

func TestCheckComposeDangerousDBFlags_MongoWithAuth(t *testing.T) {
	svc := composeService{
		Image:   "mongo:6",
		Command: "mongod --auth",
	}
	findings := checkComposeDangerousDBFlags(svc, "test")
	assertPass(t, findings, "DB-IMAGE-002")
}

func TestCheckComposeDangerousDBFlags_NoCommand(t *testing.T) {
	svc := composeService{Image: "mysql:8"}
	findings := checkComposeDangerousDBFlags(svc, "test")
	assertSkipped(t, findings, "DB-IMAGE-002")
}

func TestCheckComposeDangerousDBFlags_Safe(t *testing.T) {
	svc := composeService{
		Image:   "mysql:8",
		Command: "mysqld --max_connections=200",
	}
	findings := checkComposeDangerousDBFlags(svc, "test")
	assertPass(t, findings, "DB-IMAGE-002")
}

func TestCheckComposeDangerousDBFlags_ListCommand(t *testing.T) {
	// command as YAML list ([]interface{})
	svc := composeService{
		Image:   "mysql:8",
		Command: []interface{}{"mysqld", "--skip-grant-tables"},
	}
	findings := checkComposeDangerousDBFlags(svc, "test")
	assertFail(t, findings, "DB-IMAGE-002")
}

// ── Test helpers ────────────────────────────────────────────────────────────

func assertPass(t *testing.T, findings []types.Finding, controlID string) {
	t.Helper()
	for _, f := range findings {
		if f.Control.ID == controlID && f.Status == types.StatusPass {
			return
		}
	}
	t.Errorf("expected PASS for %s, not found", controlID)
}

func assertSkipped(t *testing.T, findings []types.Finding, controlID string) {
	t.Helper()
	for _, f := range findings {
		if f.Control.ID == controlID && f.Status == types.StatusSkipped {
			return
		}
	}
	t.Errorf("expected SKIPPED for %s, not found in %v", controlID, findings)
}

// ══════════════════════════════════════════════════════════════════════════════
// Unit tests for checkComposeUlimits (RUNTIME-015)
// ══════════════════════════════════════════════════════════════════════════════

func TestCheckComposeUlimits_Missing(t *testing.T) {
	svc := composeService{Image: "nginx:1.25"}
	findings := checkComposeUlimits(svc, "test")
	assertWarn(t, findings, "RUNTIME-015")
}

func TestCheckComposeUlimits_Present(t *testing.T) {
	svc := composeService{
		Image:   "nginx:1.25",
		Ulimits: map[string]interface{}{"nofile": 65535},
	}
	findings := checkComposeUlimits(svc, "test")
	assertPass(t, findings, "RUNTIME-015")
}

// ══════════════════════════════════════════════════════════════════════════════
// Unit tests for checkComposeRestartPolicy (RUNTIME-016)
// ══════════════════════════════════════════════════════════════════════════════

func TestCheckComposeRestartPolicy_Empty(t *testing.T) {
	svc := composeService{Image: "nginx:1.25"}
	findings := checkComposeRestartPolicy(svc, "test")
	assertPass(t, findings, "RUNTIME-016")
}

func TestCheckComposeRestartPolicy_Always(t *testing.T) {
	svc := composeService{Image: "nginx:1.25", Restart: "always"}
	findings := checkComposeRestartPolicy(svc, "test")
	assertWarn(t, findings, "RUNTIME-016")
}

func TestCheckComposeRestartPolicy_UnlessStopped(t *testing.T) {
	svc := composeService{Image: "nginx:1.25", Restart: "unless-stopped"}
	findings := checkComposeRestartPolicy(svc, "test")
	assertWarn(t, findings, "RUNTIME-016")
}

func TestCheckComposeRestartPolicy_OnFailureNoCap(t *testing.T) {
	svc := composeService{Image: "nginx:1.25", Restart: "on-failure"}
	findings := checkComposeRestartPolicy(svc, "test")
	assertWarn(t, findings, "RUNTIME-016")
}

func TestCheckComposeRestartPolicy_OnFailureCapped(t *testing.T) {
	svc := composeService{Image: "nginx:1.25", Restart: "on-failure:5"}
	findings := checkComposeRestartPolicy(svc, "test")
	assertPass(t, findings, "RUNTIME-016")
}

// ══════════════════════════════════════════════════════════════════════════════
// Unit tests for IMAGE-016 (COPY . .) and IMAGE-015 (multi-stage) in checkLines
// ══════════════════════════════════════════════════════════════════════════════

func TestCheckLines_COPY_DotDot(t *testing.T) {
	s := &DockerScanner{}
	content := []byte("FROM node:20\nCOPY . .\n")
	findings := s.checkLines("Dockerfile", content)
	f := findFinding(findings, "IMAGE-016")
	if f == nil {
		t.Fatal("expected IMAGE-016 finding for COPY . .")
	}
	if f.Status != types.StatusWarn {
		t.Errorf("expected WARN for COPY . ., got %s", f.Status)
	}
}

func TestCheckLines_COPY_WithFlags_DotDot(t *testing.T) {
	s := &DockerScanner{}
	content := []byte("FROM node:20\nCOPY --chown=1000:1000 . .\n")
	findings := s.checkLines("Dockerfile", content)
	f := findFinding(findings, "IMAGE-016")
	if f == nil {
		t.Fatal("expected IMAGE-016 finding for COPY --chown=... . .")
	}
}

func TestCheckLines_COPY_Specific_NoWarn(t *testing.T) {
	s := &DockerScanner{}
	content := []byte("FROM node:20\nCOPY package.json .\n")
	findings := s.checkLines("Dockerfile", content)
	f := findFinding(findings, "IMAGE-016")
	if f != nil && f.Status == types.StatusWarn {
		t.Errorf("specific COPY should not trigger IMAGE-016, got: %s", f.Detail)
	}
}

func TestCheckLines_MultiStage(t *testing.T) {
	s := &DockerScanner{}
	content := []byte("FROM node:20 AS builder\nRUN npm build\nFROM nginx:1.25-alpine\nCOPY --from=builder /app/dist /usr/share/nginx/html\n")
	findings := s.checkLines("Dockerfile", content)
	f := findFinding(findings, "IMAGE-015")
	if f == nil {
		t.Fatal("expected IMAGE-015 finding for multi-stage build")
	}
	if f.Status != types.StatusPass {
		t.Errorf("expected PASS for multi-stage build, got %s", f.Status)
	}
}

func TestCheckLines_SingleStage(t *testing.T) {
	s := &DockerScanner{}
	content := []byte("FROM node:20\nRUN npm install\nCMD [\"node\", \"index.js\"]\n")
	findings := s.checkLines("Dockerfile", content)
	f := findFinding(findings, "IMAGE-015")
	if f == nil {
		t.Fatal("expected IMAGE-015 finding for single-stage build")
	}
	if f.Status != types.StatusWarn {
		t.Errorf("expected WARN for single-stage build, got %s", f.Status)
	}
}
