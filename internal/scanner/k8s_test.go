package scanner

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/kariemoorman/dockeraudit/internal/types"
)

// testdataDir returns the absolute path to the testdata directory,
// resolved relative to this test file so it works regardless of CWD.
func testdataDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "../..", "testdata")
}

// findFinding returns the first finding matching controlID, or nil.
func findFinding(findings []types.Finding, controlID string) *types.Finding {
	for i := range findings {
		if findings[i].Control.ID == controlID {
			return &findings[i]
		}
	}
	return nil
}

// assertFail asserts that the given control ID has status FAIL in findings.
func assertFail(t *testing.T, findings []types.Finding, controlID string) {
	t.Helper()
	f := findFinding(findings, controlID)
	if f == nil {
		t.Errorf("expected finding for %s but none found", controlID)
		return
	}
	if f.Status != types.StatusFail {
		t.Errorf("%s: got status %q, want FAIL (detail: %s)", controlID, f.Status, f.Detail)
	}
}

// k8sScanner builds a K8sScanner with the given manifest paths.
func k8sScanner(paths ...string) *K8sScanner {
	s := NewK8sScanner()
	s.ManifestPaths = paths
	return s
}

// ── Bad pod (test-pods.yaml — insecure Deployment) ────────────────────────────

func TestK8sScanner_InsecurePod_Violations(t *testing.T) {
	td := testdataDir(t)
	manifest := filepath.Join(td, "manifests", "test-pods.yaml")

	result, err := k8sScanner(manifest).Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// These are all declared violations in test-pods.yaml for "insecure-app"
	assertFail(t, result.Findings, "RUNTIME-002") // privileged: true
	assertFail(t, result.Findings, "RUNTIME-001") // runAsUser: 0
	assertFail(t, result.Findings, "RUNTIME-004") // allowPrivilegeEscalation: true
	assertFail(t, result.Findings, "RUNTIME-006") // hostPID / hostNetwork
}

// ── Good pod (test-pods.yaml — hardened Pod) ──────────────────────────────────

func TestK8sScanner_HardenedPod_NoCriticalFails(t *testing.T) {
	td := testdataDir(t)
	manifest := filepath.Join(td, "manifests", "test-pods.yaml")

	result, err := k8sScanner(manifest).Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// Collect only findings for the hardened pod target
	var hardenedFindings []types.Finding
	for _, f := range result.Findings {
		if strings.Contains(f.Target, "hardened-app") {
			hardenedFindings = append(hardenedFindings, f)
		}
	}

	// These critical controls must not FAIL for the hardened pod
	criticalControls := []string{
		"RUNTIME-001", // non-root user
		"RUNTIME-002", // not privileged
		"RUNTIME-004", // allowPrivilegeEscalation: false
		"RUNTIME-006", // no host namespaces
	}
	for _, id := range criticalControls {
		f := findFinding(hardenedFindings, id)
		if f != nil && f.Status == types.StatusFail {
			t.Errorf("hardened pod: %s should not FAIL (detail: %s)", id, f.Detail)
		}
	}
}

// ── Insecure DB manifest ───────────────────────────────────────────────────────

func TestK8sScanner_InsecureDB_HasFails(t *testing.T) {
	td := testdataDir(t)
	manifest := filepath.Join(td, "manifests", "db-insecure-postgres.yaml")

	result, err := k8sScanner(manifest).Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected findings from insecure DB manifest, got none")
	}

	hasFails := false
	for _, f := range result.Findings {
		if f.Status == types.StatusFail {
			hasFails = true
			break
		}
	}
	if !hasFails {
		t.Error("insecure DB manifest produced no FAIL findings")
	}
}

// ── Hardened DB manifest ──────────────────────────────────────────────────────

func TestK8sScanner_HardenedDB_NoCriticalFails(t *testing.T) {
	td := testdataDir(t)
	manifest := filepath.Join(td, "manifests", "db-hardened-postgres.yaml")

	result, err := k8sScanner(manifest).Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// These critical controls must not FAIL for a hardened DB manifest
	criticalControls := []string{
		"RUNTIME-002", // not privileged
		"RUNTIME-001", // non-root
		"RUNTIME-004", // no priv escalation
		"RUNTIME-006", // no host namespaces
	}
	for _, id := range criticalControls {
		f := findFinding(result.Findings, id)
		if f != nil && f.Status == types.StatusFail {
			t.Errorf("hardened DB manifest: control %s should not FAIL (detail: %s)", id, f.Detail)
		}
	}
}

// ── Non-existent path returns error ───────────────────────────────────────────

func TestK8sScanner_MissingFile_ReturnsError(t *testing.T) {
	_, err := k8sScanner("/nonexistent/path/manifest.yaml").Scan(context.Background())
	if err == nil {
		t.Fatal("expected error scanning non-existent path, got nil")
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// Unit tests for individual K8s check functions (session 3)
// ══════════════════════════════════════════════════════════════════════════════

// ── imagePullPolicy check ────────────────────────────────────────────────────

func TestCheckK8sImagePullPolicy_Always(t *testing.T) {
	c := container{Name: "app", Image: "nginx:1.25", ImagePullPolicy: "Always"}
	findings := checkK8sImagePullPolicy(c, "test")
	assertPass(t, findings, "IMAGE-001")
}

func TestCheckK8sImagePullPolicy_Never(t *testing.T) {
	c := container{Name: "app", Image: "nginx:1.25", ImagePullPolicy: "Never"}
	findings := checkK8sImagePullPolicy(c, "test")
	assertFail(t, findings, "IMAGE-001")
}

func TestCheckK8sImagePullPolicy_Unset_Latest(t *testing.T) {
	c := container{Name: "app", Image: "nginx:latest"}
	findings := checkK8sImagePullPolicy(c, "test")
	if len(findings) == 0 {
		t.Fatal("expected findings for unset imagePullPolicy on :latest")
	}
	if findings[0].Status != types.StatusWarn {
		t.Errorf("expected WARN for unset policy on :latest, got %s", findings[0].Status)
	}
}

func TestCheckK8sImagePullPolicy_Unset_Tagged(t *testing.T) {
	c := container{Name: "app", Image: "nginx:1.25"}
	findings := checkK8sImagePullPolicy(c, "test")
	if len(findings) == 0 {
		t.Fatal("expected findings for unset imagePullPolicy on tagged image")
	}
	if findings[0].Status != types.StatusWarn {
		t.Errorf("expected WARN for unset policy on tagged image, got %s", findings[0].Status)
	}
}

func TestCheckK8sImagePullPolicy_IfNotPresent(t *testing.T) {
	c := container{Name: "app", Image: "nginx:1.25", ImagePullPolicy: "IfNotPresent"}
	findings := checkK8sImagePullPolicy(c, "test")
	assertPass(t, findings, "IMAGE-001")
}

// ── Annotation secret detection with SecretScanner ───────────────────────────

func TestCheckAnnotationsForSecrets_PostgresURL(t *testing.T) {
	meta := kubeObjectMeta{
		Annotations: map[string]string{
			"db-connection": "postgres://admin:s3cretP@ss@db.host.com:5432/mydb",
		},
	}
	findings := checkAnnotationsForSecrets(meta, "test")
	if len(findings) == 0 {
		t.Fatal("expected findings for Postgres URL in annotation")
	}
	if findings[0].Status != types.StatusFail {
		t.Errorf("expected FAIL for Postgres URL in annotation, got %s", findings[0].Status)
	}
}

func TestCheckAnnotationsForSecrets_KeywordMatch(t *testing.T) {
	meta := kubeObjectMeta{
		Annotations: map[string]string{
			"config": "password=supersecret123",
		},
	}
	findings := checkAnnotationsForSecrets(meta, "test")
	if len(findings) == 0 {
		t.Fatal("expected findings for password= in annotation")
	}
	if findings[0].Status != types.StatusFail {
		t.Errorf("expected FAIL for password= in annotation, got %s", findings[0].Status)
	}
}

func TestCheckAnnotationsForSecrets_AWSKeyInAnnotation(t *testing.T) {
	meta := kubeObjectMeta{
		Annotations: map[string]string{
			"aws-key": "AKIAIOSFODNN7ABCDEFG",
		},
	}
	findings := checkAnnotationsForSecrets(meta, "test")
	if len(findings) == 0 {
		t.Fatal("expected findings for AWS key in annotation via SecretScanner")
	}
	if findings[0].Status != types.StatusFail {
		t.Errorf("expected FAIL for AWS key in annotation, got %s", findings[0].Status)
	}
}

func TestCheckAnnotationsForSecrets_CleanAnnotation(t *testing.T) {
	meta := kubeObjectMeta{
		Annotations: map[string]string{
			"description": "This is a regular application",
			"version":     "1.0.0",
		},
	}
	findings := checkAnnotationsForSecrets(meta, "test")
	assertPass(t, findings, "DB-K8S-006")
}

func TestCheckAnnotationsForSecrets_URLWithoutCreds(t *testing.T) {
	meta := kubeObjectMeta{
		Annotations: map[string]string{
			"docs": "https://docs.example.com/api/v1",
		},
	}
	findings := checkAnnotationsForSecrets(meta, "test")
	assertPass(t, findings, "DB-K8S-006")
}

func TestCheckAnnotationsForSecrets_GitHubTokenViaRegex(t *testing.T) {
	meta := kubeObjectMeta{
		Annotations: map[string]string{
			"ci-token": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12",
		},
	}
	findings := checkAnnotationsForSecrets(meta, "test")
	if len(findings) == 0 {
		t.Fatal("expected findings for GitHub token in annotation via SecretScanner regex")
	}
}

// ── Shared credentialKeywords usage in K8s ────────────────────────────────────

func TestCheckK8sSecrets_UsesSharedCredentialKeywords(t *testing.T) {
	// "connection_string" is in shared credentialKeywords but was NOT in old local credPatterns
	c := container{
		Name:  "app",
		Image: "myapp:latest",
		Env: []envVar{
			{Name: "CONNECTION_STRING", Value: "Server=mydb;Database=test;User=admin;Password=pass123"},
		},
	}
	findings := checkK8sSecrets(c, "test")
	hasFail := false
	for _, f := range findings {
		if f.Status == types.StatusFail && f.Control.ID == "IMAGE-002" {
			hasFail = true
		}
	}
	if !hasFail {
		t.Error("expected FAIL for CONNECTION_STRING env var using shared credentialKeywords")
	}
}

func TestCheckK8sSecrets_DatabaseURL(t *testing.T) {
	// "database_url" is in shared credentialKeywords
	c := container{
		Name:  "app",
		Image: "myapp:latest",
		Env: []envVar{
			{Name: "DATABASE_URL", Value: "postgres://admin:secret@host:5432/db"},
		},
	}
	findings := checkK8sSecrets(c, "test")
	hasFail := false
	for _, f := range findings {
		if f.Status == types.StatusFail {
			hasFail = true
		}
	}
	if !hasFail {
		t.Error("expected FAIL for DATABASE_URL env var")
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// Unit tests for K8s EOL image detection (checkK8sEOLImage)
// ══════════════════════════════════════════════════════════════════════════════

func TestCheckK8sEOLImage_PostgresEOL(t *testing.T) {
	c := container{Name: "db", Image: "postgres:13-alpine"}
	findings := checkK8sEOLImage(c, "test")
	assertFail(t, findings, "IMAGE-008")
	if !strings.Contains(findings[0].Detail, "PostgreSQL 13") {
		t.Errorf("expected detail to mention PostgreSQL 13, got: %s", findings[0].Detail)
	}
}

func TestCheckK8sEOLImage_PostgresCurrent(t *testing.T) {
	c := container{Name: "db", Image: "postgres:16-alpine"}
	findings := checkK8sEOLImage(c, "test")
	assertPass(t, findings, "IMAGE-008")
}

func TestCheckK8sEOLImage_NodeEOL(t *testing.T) {
	c := container{Name: "app", Image: "node:14-slim"}
	findings := checkK8sEOLImage(c, "test")
	assertFail(t, findings, "IMAGE-008")
	if !strings.Contains(findings[0].Detail, "Node.js 14") {
		t.Errorf("expected detail to mention Node.js 14, got: %s", findings[0].Detail)
	}
}

func TestCheckK8sEOLImage_NodeCurrent(t *testing.T) {
	c := container{Name: "app", Image: "node:20-alpine"}
	findings := checkK8sEOLImage(c, "test")
	assertPass(t, findings, "IMAGE-008")
}

func TestCheckK8sEOLImage_PythonEOL(t *testing.T) {
	c := container{Name: "ml", Image: "python:3.7-slim"}
	findings := checkK8sEOLImage(c, "test")
	assertFail(t, findings, "IMAGE-008")
}

func TestCheckK8sEOLImage_PythonCurrent(t *testing.T) {
	c := container{Name: "ml", Image: "python:3.12-slim"}
	findings := checkK8sEOLImage(c, "test")
	assertPass(t, findings, "IMAGE-008")
}

func TestCheckK8sEOLImage_RedisEOL(t *testing.T) {
	c := container{Name: "cache", Image: "redis:5-alpine"}
	findings := checkK8sEOLImage(c, "test")
	assertFail(t, findings, "IMAGE-008")
}

func TestCheckK8sEOLImage_RedisCurrent(t *testing.T) {
	c := container{Name: "cache", Image: "redis:7-alpine"}
	findings := checkK8sEOLImage(c, "test")
	assertPass(t, findings, "IMAGE-008")
}

func TestCheckK8sEOLImage_RegistryPrefix(t *testing.T) {
	// Full registry path should still detect EOL
	c := container{Name: "db", Image: "docker.io/library/postgres:10-alpine"}
	findings := checkK8sEOLImage(c, "test")
	assertFail(t, findings, "IMAGE-008")
}

func TestCheckK8sEOLImage_LatestTag_Skip(t *testing.T) {
	// :latest should not trigger EOL (can't determine version)
	c := container{Name: "app", Image: "postgres:latest"}
	findings := checkK8sEOLImage(c, "test")
	assertSkipped(t, findings, "IMAGE-008")
}

func TestCheckK8sEOLImage_NoTag_Skip(t *testing.T) {
	// No tag (defaults to :latest) should not trigger EOL
	c := container{Name: "app", Image: "postgres"}
	findings := checkK8sEOLImage(c, "test")
	assertSkipped(t, findings, "IMAGE-008")
}

func TestCheckK8sEOLImage_EmptyImage_Skip(t *testing.T) {
	c := container{Name: "app", Image: ""}
	findings := checkK8sEOLImage(c, "test")
	assertSkipped(t, findings, "IMAGE-008")
}

func TestCheckK8sEOLImage_UbuntuEOL(t *testing.T) {
	c := container{Name: "base", Image: "ubuntu:18.04"}
	findings := checkK8sEOLImage(c, "test")
	assertFail(t, findings, "IMAGE-008")
	if !strings.Contains(findings[0].Detail, "Ubuntu 18.04") {
		t.Errorf("expected detail to mention Ubuntu 18.04, got: %s", findings[0].Detail)
	}
}

func TestCheckK8sEOLImage_MysqlEOL(t *testing.T) {
	c := container{Name: "db", Image: "mysql:5.7"}
	findings := checkK8sEOLImage(c, "test")
	assertFail(t, findings, "IMAGE-008")
}

func TestCheckK8sEOLImage_ElasticsearchEOL(t *testing.T) {
	c := container{Name: "search", Image: "elasticsearch:7.17.0"}
	findings := checkK8sEOLImage(c, "test")
	assertFail(t, findings, "IMAGE-008")
}

func TestCheckK8sEOLImage_GolangEOL(t *testing.T) {
	c := container{Name: "build", Image: "golang:1.18-alpine"}
	findings := checkK8sEOLImage(c, "test")
	assertFail(t, findings, "IMAGE-008")
}

func TestCheckK8sEOLImage_GolangCurrent(t *testing.T) {
	c := container{Name: "build", Image: "golang:1.22-alpine"}
	findings := checkK8sEOLImage(c, "test")
	assertPass(t, findings, "IMAGE-008")
}

// ── CronJob nesting (TASK-8.1) ────────────────────────────────────────────────

func TestK8sScanner_CronJob_DetectsPrivileged(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "cronjob.yaml")
	content := `apiVersion: batch/v1
kind: CronJob
metadata:
  name: insecure-cron
  namespace: default
spec:
  schedule: "*/5 * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: worker
            image: busybox:latest
            securityContext:
              privileged: true
`
	if err := os.WriteFile(manifest, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	result, err := k8sScanner(manifest).Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	assertFail(t, result.Findings, "RUNTIME-002") // privileged: true
	assertFail(t, result.Findings, "IMAGE-001")   // unpinned image
}

func TestK8sScanner_CronJob_Secure(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "cronjob-secure.yaml")
	content := `apiVersion: batch/v1
kind: CronJob
metadata:
  name: secure-cron
  namespace: default
spec:
  schedule: "*/5 * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          securityContext:
            runAsNonRoot: true
            runAsUser: 1000
          containers:
          - name: worker
            image: busybox@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
            securityContext:
              allowPrivilegeEscalation: false
              readOnlyRootFilesystem: true
              capabilities:
                drop: ["ALL"]
            resources:
              limits:
                memory: "128Mi"
                cpu: "250m"
              requests:
                memory: "64Mi"
                cpu: "100m"
`
	if err := os.WriteFile(manifest, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	result, err := k8sScanner(manifest).Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	// Secure CronJob should pass key runtime controls
	assertPass(t, result.Findings, "RUNTIME-002") // not privileged
	assertPass(t, result.Findings, "RUNTIME-003") // cap_drop ALL
	assertPass(t, result.Findings, "RUNTIME-005") // readOnlyRootFilesystem
	assertPass(t, result.Findings, "IMAGE-001")   // pinned by digest
}

// ══════════════════════════════════════════════════════════════════════════════
// Unit tests for K8s DB / Service check functions
// ══════════════════════════════════════════════════════════════════════════════

// assertWarn asserts that the given control ID has status WARN in findings.
func assertWarn(t *testing.T, findings []types.Finding, controlID string) {
	t.Helper()
	f := findFinding(findings, controlID)
	if f == nil {
		t.Errorf("expected finding for %s but none found", controlID)
		return
	}
	if f.Status != types.StatusWarn {
		t.Errorf("%s: got status %q, want WARN (detail: %s)", controlID, f.Status, f.Detail)
	}
}

// ── checkServiceExposure ─────────────────────────────────────────────────────

func TestCheckServiceExposure_ClusterIP(t *testing.T) {
	svc := serviceSpec{
		Type: "ClusterIP",
		Ports: []servicePort{
			{Port: 5432, TargetPort: 5432},
		},
	}
	findings := checkServiceExposure(svc, "test")
	assertPass(t, findings, "DB-K8S-003")
}

func TestCheckServiceExposure_NodePort_DBPort(t *testing.T) {
	svc := serviceSpec{
		Type: "NodePort",
		Ports: []servicePort{
			{Port: 5432, TargetPort: 5432, NodePort: 30432},
		},
	}
	findings := checkServiceExposure(svc, "test")
	assertFail(t, findings, "DB-K8S-003")
}

// ── checkDBAuthDisabledEnv ───────────────────────────────────────────────────

func TestCheckDBAuthDisabledEnv_TrustAuth(t *testing.T) {
	c := container{
		Name:  "pg",
		Image: "postgres:16",
		Env: []envVar{
			{Name: "POSTGRES_HOST_AUTH_METHOD", Value: "trust"},
		},
	}
	findings := checkDBAuthDisabledEnv(c, "test")
	assertFail(t, findings, "DB-K8S-001")
}

func TestCheckDBAuthDisabledEnv_NoAuthFlag(t *testing.T) {
	c := container{
		Name:    "mongo",
		Image:   "mongo:7",
		Command: []string{"mongod"},
		Args:    []string{"--noauth"},
	}
	findings := checkDBAuthDisabledEnv(c, "test")
	assertFail(t, findings, "DB-K8S-001")
}

func TestCheckDBAuthDisabledEnv_Clean(t *testing.T) {
	c := container{
		Name:  "pg",
		Image: "postgres:16",
		Env: []envVar{
			{Name: "POSTGRES_PASSWORD", Value: "s3cret"},
		},
	}
	findings := checkDBAuthDisabledEnv(c, "test")
	assertPass(t, findings, "DB-K8S-001")
}

// ── checkDBMissingAuthConfig ─────────────────────────────────────────────────

func TestCheckDBMissingAuthConfig_Missing(t *testing.T) {
	c := container{
		Name:  "qdrant",
		Image: "qdrant/qdrant:latest",
		Env:   []envVar{},
	}
	findings := checkDBMissingAuthConfig(c, "test")
	assertFail(t, findings, "DB-K8S-002")
}

func TestCheckDBMissingAuthConfig_Present(t *testing.T) {
	c := container{
		Name:  "qdrant",
		Image: "qdrant/qdrant:latest",
		Env: []envVar{
			{Name: "QDRANT__SERVICE__API_KEY", Value: "my-secret-key"},
		},
	}
	findings := checkDBMissingAuthConfig(c, "test")
	assertPass(t, findings, "DB-K8S-002")
}

func TestCheckDBMissingAuthConfig_NotDBImage(t *testing.T) {
	c := container{
		Name:  "app",
		Image: "nginx:1.25",
		Env:   []envVar{},
	}
	findings := checkDBMissingAuthConfig(c, "test")
	assertSkipped(t, findings, "DB-K8S-002")
}

// ── checkNeo4jApocSSRF ───────────────────────────────────────────────────────

func TestCheckNeo4jApocSSRF_Unrestricted(t *testing.T) {
	c := container{
		Name:  "neo4j",
		Image: "neo4j:5-community",
		Env: []envVar{
			{Name: "NEO4J_PLUGINS", Value: "[\"apoc\"]"},
		},
	}
	findings := checkNeo4jApocSSRF(c, "test")
	assertFail(t, findings, "DB-K8S-007")
}

func TestCheckNeo4jApocSSRF_Restricted(t *testing.T) {
	c := container{
		Name:  "neo4j",
		Image: "neo4j:5-community",
		Env: []envVar{
			{Name: "NEO4J_PLUGINS", Value: "[\"apoc\"]"},
			{Name: "NEO4J_LABS_APOC_IMPORT_FILE_ENABLED", Value: "false"},
			{Name: "NEO4J_dbms_security_procedures_unrestricted_ALLOW__CSV__IMPORT", Value: "false"},
		},
	}
	findings := checkNeo4jApocSSRF(c, "test")
	assertPass(t, findings, "DB-K8S-007")
}

func TestCheckNeo4jApocSSRF_NotNeo4j(t *testing.T) {
	c := container{
		Name:  "app",
		Image: "nginx:1.25",
		Env:   []envVar{},
	}
	findings := checkNeo4jApocSSRF(c, "test")
	assertSkipped(t, findings, "DB-K8S-007")
}

// ── checkDBEmptyDirData ──────────────────────────────────────────────────────

func TestCheckDBEmptyDirData_DataOnEmptyDir(t *testing.T) {
	spec := podSpec{
		Containers: []container{
			{
				Name:  "pg",
				Image: "postgres:16",
				VolumeMounts: []volumeMount{
					{Name: "pgdata", MountPath: "/var/lib/postgresql/data"},
				},
			},
		},
		Volumes: []volume{
			{Name: "pgdata", EmptyDir: &emptyDir{}},
		},
	}
	findings := checkDBEmptyDirData(spec, "test")
	assertFail(t, findings, "DB-K8S-004")
}

func TestCheckDBEmptyDirData_DataOnPVC(t *testing.T) {
	spec := podSpec{
		Containers: []container{
			{
				Name:  "pg",
				Image: "postgres:16",
				VolumeMounts: []volumeMount{
					{Name: "pgdata", MountPath: "/var/lib/postgresql/data"},
				},
			},
		},
		Volumes: []volume{
			{Name: "pgdata"}, // no EmptyDir — assume PVC
		},
	}
	findings := checkDBEmptyDirData(spec, "test")
	assertSkipped(t, findings, "DB-K8S-004")
}

// ── checkDBFsGroup ───────────────────────────────────────────────────────────

func TestCheckDBFsGroup_Missing(t *testing.T) {
	spec := podSpec{
		Containers: []container{
			{Name: "pg", Image: "postgres:16"},
		},
	}
	findings := checkDBFsGroup(spec, "test")
	assertWarn(t, findings, "DB-K8S-005")
}

func TestCheckDBFsGroup_Present(t *testing.T) {
	gid := int64(999)
	spec := podSpec{
		Containers: []container{
			{Name: "pg", Image: "postgres:16"},
		},
		SecurityContext: &podSecCtx{
			FSGroup: &gid,
		},
	}
	findings := checkDBFsGroup(spec, "test")
	assertPass(t, findings, "DB-K8S-005")
}

func TestCheckDBFsGroup_NotDBImage(t *testing.T) {
	spec := podSpec{
		Containers: []container{
			{Name: "app", Image: "nginx:1.25"},
		},
	}
	findings := checkDBFsGroup(spec, "test")
	assertSkipped(t, findings, "DB-K8S-005")
}

// ══════════════════════════════════════════════════════════════════════════════
// Unit tests for checkK8sAppArmorSELinux (RUNTIME-013)
// ══════════════════════════════════════════════════════════════════════════════

func TestCheckK8sAppArmorSELinux_AppArmorSet(t *testing.T) {
	c := container{Name: "app"}
	meta := kubeObjectMeta{
		Annotations: map[string]string{
			"container.apparmor.security.beta.kubernetes.io/app": "runtime/default",
		},
	}
	findings := checkK8sAppArmorSELinux(c, meta, podSpec{}, "test")
	assertPass(t, findings, "RUNTIME-013")
}

func TestCheckK8sAppArmorSELinux_SELinuxContainer(t *testing.T) {
	c := container{
		Name: "app",
		SecurityContext: &containerSecCtx{
			SELinuxOptions: &seLinuxOptions{Type: "spc_t"},
		},
	}
	findings := checkK8sAppArmorSELinux(c, kubeObjectMeta{}, podSpec{}, "test")
	assertPass(t, findings, "RUNTIME-013")
}

func TestCheckK8sAppArmorSELinux_SELinuxPodLevel(t *testing.T) {
	c := container{Name: "app"}
	spec := podSpec{
		SecurityContext: &podSecCtx{
			SELinuxOptions: &seLinuxOptions{Type: "container_t"},
		},
	}
	findings := checkK8sAppArmorSELinux(c, kubeObjectMeta{}, spec, "test")
	assertPass(t, findings, "RUNTIME-013")
}

func TestCheckK8sAppArmorSELinux_None(t *testing.T) {
	c := container{Name: "app"}
	findings := checkK8sAppArmorSELinux(c, kubeObjectMeta{}, podSpec{}, "test")
	assertWarn(t, findings, "RUNTIME-013")
}

// ══════════════════════════════════════════════════════════════════════════════
// Unit tests for checkK8sAutomountSA (RUNTIME-014)
// ══════════════════════════════════════════════════════════════════════════════

func TestCheckK8sAutomountSA_False(t *testing.T) {
	f := false
	spec := podSpec{AutomountServiceAccountToken: &f}
	findings := checkK8sAutomountSA(spec, "test")
	assertPass(t, findings, "RUNTIME-014")
}

func TestCheckK8sAutomountSA_True(t *testing.T) {
	tr := true
	spec := podSpec{AutomountServiceAccountToken: &tr}
	findings := checkK8sAutomountSA(spec, "test")
	assertWarn(t, findings, "RUNTIME-014")
}

func TestCheckK8sAutomountSA_Unset(t *testing.T) {
	findings := checkK8sAutomountSA(podSpec{}, "test")
	assertWarn(t, findings, "RUNTIME-014")
}

// ══════════════════════════════════════════════════════════════════════════════
// Unit tests for checkK8sNamespace (K8S-001)
// ══════════════════════════════════════════════════════════════════════════════

func TestCheckK8sNamespace_Default(t *testing.T) {
	findings := checkK8sNamespace(kubeObjectMeta{Namespace: "default"}, "test")
	assertWarn(t, findings, "K8S-001")
}

func TestCheckK8sNamespace_Empty(t *testing.T) {
	findings := checkK8sNamespace(kubeObjectMeta{Namespace: ""}, "test")
	assertWarn(t, findings, "K8S-001")
}

func TestCheckK8sNamespace_Custom(t *testing.T) {
	findings := checkK8sNamespace(kubeObjectMeta{Namespace: "production"}, "test")
	assertPass(t, findings, "K8S-001")
}

// ══════════════════════════════════════════════════════════════════════════════
// Unit tests for checkK8sAntiAffinity (K8S-002)
// ══════════════════════════════════════════════════════════════════════════════

func TestCheckK8sAntiAffinity_TopologySpread(t *testing.T) {
	spec := podSpec{
		TopologySpreadConstraints: []interface{}{map[string]interface{}{"maxSkew": 1}},
	}
	findings := checkK8sAntiAffinity(spec, "test")
	assertPass(t, findings, "K8S-002")
}

func TestCheckK8sAntiAffinity_PodAntiAffinity(t *testing.T) {
	paa := interface{}(map[string]interface{}{"preferredDuringSchedulingIgnoredDuringExecution": []interface{}{}})
	spec := podSpec{
		Affinity: &affinity{PodAntiAffinity: &paa},
	}
	findings := checkK8sAntiAffinity(spec, "test")
	assertPass(t, findings, "K8S-002")
}

func TestCheckK8sAntiAffinity_None(t *testing.T) {
	findings := checkK8sAntiAffinity(podSpec{}, "test")
	assertWarn(t, findings, "K8S-002")
}

// ══════════════════════════════════════════════════════════════════════════════
// Unit tests for checkEOLFromHistory (IMAGE-008) via ImageScanner
// ══════════════════════════════════════════════════════════════════════════════

func TestCheckEOLFromHistory_Empty(t *testing.T) {
	s := &ImageScanner{Image: "myapp:latest"}
	findings := s.checkEOLFromHistory("")
	assertSkipped(t, findings, "IMAGE-008")
}

func TestCheckEOLFromHistory_EOLDetected(t *testing.T) {
	s := &ImageScanner{Image: "myapp:latest"}
	history := "FROM python:3.7-slim AS builder"
	findings := s.checkEOLFromHistory(history)
	assertFail(t, findings, "IMAGE-008")
}

func TestCheckEOLFromHistory_CurrentImage(t *testing.T) {
	s := &ImageScanner{Image: "myapp:latest"}
	history := "FROM python:3.12-slim AS builder"
	findings := s.checkEOLFromHistory(history)
	// No EOL findings — should return empty slice (not fail)
	for _, f := range findings {
		if f.Status == types.StatusFail {
			t.Errorf("unexpected FAIL for current image in history: %s", f.Detail)
		}
	}
}

func TestCheckEOLFromHistory_Scratch(t *testing.T) {
	s := &ImageScanner{Image: "myapp:latest"}
	history := "FROM scratch"
	findings := s.checkEOLFromHistory(history)
	for _, f := range findings {
		if f.Status == types.StatusFail {
			t.Errorf("scratch should not trigger EOL: %s", f.Detail)
		}
	}
}

func TestCheckEOLFromHistory_MultipleStages(t *testing.T) {
	s := &ImageScanner{Image: "myapp:latest"}
	history := `FROM node:14-alpine AS build
FROM nginx:1.25-alpine`
	findings := s.checkEOLFromHistory(history)
	// Should detect node:14 as EOL
	assertFail(t, findings, "IMAGE-008")
	if !strings.Contains(findings[0].Detail, "Node.js 14") {
		t.Errorf("expected detail to mention Node.js 14, got: %s", findings[0].Detail)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// Phase 2+3: New K8s control tests
// ══════════════════════════════════════════════════════════════════════════════

// ── NETWORK-001: NetworkPolicy ──────────────────────────────────────────────

func TestNetworkPolicy_DefaultDenyIngress(t *testing.T) {
	manifest := writeTestManifest(t, `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Ingress
`)
	result, err := k8sScanner(manifest).Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	assertPass(t, result.Findings, "NETWORK-001")
}

func TestNetworkPolicy_NoNetworkPolicy(t *testing.T) {
	manifest := writeTestManifest(t, `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
  namespace: production
spec:
  replicas: 1
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
      - name: app
        image: nginx:1.25@sha256:abc123
        securityContext:
          privileged: false
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          runAsNonRoot: true
          runAsUser: 1000
          capabilities:
            drop: ["ALL"]
          seccompProfile:
            type: RuntimeDefault
        resources:
          limits:
            memory: "128Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
`)
	result, err := k8sScanner(manifest).Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	// Should have a WARN because no NetworkPolicy found
	f := findFinding(result.Findings, "NETWORK-001")
	if f == nil {
		t.Fatal("expected NETWORK-001 finding from aggregation")
	}
	if f.Status != types.StatusWarn {
		t.Errorf("expected WARN for missing NetworkPolicy, got %s", f.Status)
	}
}

// ── NETWORK-002: Cloud Metadata Endpoint Blocked ────────────────────────────

func TestNetworkPolicy_MetadataBlock_Pass(t *testing.T) {
	manifest := writeTestManifest(t, `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: block-metadata
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - ipBlock:
        cidr: 0.0.0.0/0
        except:
        - 169.254.169.254/32
`)
	result, err := k8sScanner(manifest).Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	assertPass(t, result.Findings, "NETWORK-002")
}

func TestNetworkPolicy_DefaultDenyEgress_MetadataBlocked(t *testing.T) {
	manifest := writeTestManifest(t, `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all-egress
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Egress
`)
	result, err := k8sScanner(manifest).Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	// Default-deny egress blocks ALL outbound including metadata
	assertPass(t, result.Findings, "NETWORK-002")
}

func TestNetworkPolicy_NoMetadataBlock_Warn(t *testing.T) {
	manifest := writeTestManifest(t, `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns-only
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Ingress
`)
	result, err := k8sScanner(manifest).Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	// Ingress-only policy — no egress metadata block, aggregation should warn
	f := findFinding(result.Findings, "NETWORK-002")
	if f == nil {
		t.Fatal("expected NETWORK-002 finding from aggregation")
	}
	if f.Status != types.StatusWarn {
		t.Errorf("expected WARN for missing metadata block, got %s", f.Status)
	}
}

// ── SECRETS-001: External Secrets ───────────────────────────────────────────

func TestK8s_ExternalSecret_Pass(t *testing.T) {
	manifest := writeTestManifest(t, `
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: db-creds
  namespace: production
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secretsmanager
    kind: ClusterSecretStore
`)
	result, err := k8sScanner(manifest).Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	assertPass(t, result.Findings, "SECRETS-001")
}

func TestK8s_SealedSecret_Pass(t *testing.T) {
	manifest := writeTestManifest(t, `
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: db-creds
  namespace: production
spec:
  encryptedData:
    password: AgBf2...
`)
	result, err := k8sScanner(manifest).Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	assertPass(t, result.Findings, "SECRETS-001")
}

func TestK8s_PlaintextSecret_StringData_Fail(t *testing.T) {
	manifest := writeTestManifest(t, `
apiVersion: v1
kind: Secret
metadata:
  name: db-creds
  namespace: production
type: Opaque
stringData:
  password: mysecretpassword
`)
	result, err := k8sScanner(manifest).Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	assertFail(t, result.Findings, "SECRETS-001")
}

func TestK8s_SecretProviderClass_Pass(t *testing.T) {
	manifest := writeTestManifest(t, `
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: vault-database
  namespace: production
spec:
  provider: vault
  parameters:
    vaultAddress: https://vault.example.com
`)
	result, err := k8sScanner(manifest).Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	assertPass(t, result.Findings, "SECRETS-001")
}

// ── SECRETS-002: RBAC Secret Access ─────────────────────────────────────────

func TestK8s_ClusterRole_WildcardSecrets_Fail(t *testing.T) {
	manifest := writeTestManifest(t, `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: secret-admin
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["*"]
`)
	result, err := k8sScanner(manifest).Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	assertFail(t, result.Findings, "SECRETS-002")
}

func TestK8s_Role_NamedSecrets_Pass(t *testing.T) {
	manifest := writeTestManifest(t, `
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: db-reader
  namespace: production
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get"]
  resourceNames: ["db-creds"]
`)
	result, err := k8sScanner(manifest).Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	assertPass(t, result.Findings, "SECRETS-002")
}

func TestK8s_Role_WildcardResources_Fail(t *testing.T) {
	manifest := writeTestManifest(t, `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: super-admin
rules:
- apiGroups: [""]
  resources: ["*"]
  verbs: ["*"]
`)
	result, err := k8sScanner(manifest).Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	assertFail(t, result.Findings, "SECRETS-002")
}

// ── SUPPLY-001: Kyverno Image Verification ──────────────────────────────────

func TestK8s_KyvernoVerifyImages_Pass(t *testing.T) {
	manifest := writeTestManifest(t, `
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-image-signatures
spec:
  validationFailureAction: Enforce
  rules:
  - name: verify-signature
    match:
      any:
      - resources:
          kinds: ["Pod"]
    verifyImages:
    - imageReferences: ["ghcr.io/myorg/*"]
      attestors:
      - entries:
        - keyless:
            rekor:
              url: https://rekor.sigstore.dev
`)
	result, err := k8sScanner(manifest).Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	assertPass(t, result.Findings, "SUPPLY-001")
}

// ── MONITOR-001: Runtime Detection Agent ────────────────────────────────────

func TestK8s_FalcoDaemonSet_Pass(t *testing.T) {
	manifest := writeTestManifest(t, `
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: falco
  namespace: falco-system
spec:
  selector:
    matchLabels:
      app: falco
  template:
    metadata:
      labels:
        app: falco
    spec:
      containers:
      - name: falco
        image: falcosecurity/falco:0.37.0
        securityContext:
          privileged: true
          capabilities:
            drop: ["ALL"]
        resources:
          limits:
            memory: "512Mi"
            cpu: "1000m"
`)
	result, err := k8sScanner(manifest).Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	assertPass(t, result.Findings, "MONITOR-001")
}

// ── MONITOR-002: Kubernetes API Server Audit Logging ─────────────────────────

func TestK8s_AuditPolicy_Pass(t *testing.T) {
	manifest := writeTestManifest(t, `
apiVersion: audit.k8s.io/v1
kind: Policy
metadata:
  name: audit-policy
spec:
  rules:
  - level: Metadata
    resources:
    - group: ""
      resources: ["secrets", "configmaps"]
  - level: RequestResponse
    resources:
    - group: ""
      resources: ["pods"]
`)
	result, err := k8sScanner(manifest).Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	assertPass(t, result.Findings, "MONITOR-002")
}

func TestK8s_AuditPolicy_EmptySpec_Warn(t *testing.T) {
	manifest := writeTestManifest(t, `
apiVersion: audit.k8s.io/v1
kind: Policy
metadata:
  name: empty-audit-policy
spec: {}
`)
	result, err := k8sScanner(manifest).Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	assertWarn(t, result.Findings, "MONITOR-002")
}

func TestK8s_KyvernoPolicy_StillWorks(t *testing.T) {
	// Ensure Kyverno Policy (not ClusterPolicy) with verifyImages still triggers SUPPLY-001
	manifest := writeTestManifest(t, `
apiVersion: kyverno.io/v1
kind: Policy
metadata:
  name: ns-verify-images
  namespace: production
spec:
  validationFailureAction: Enforce
  rules:
  - name: verify-signature
    match:
      any:
      - resources:
          kinds: ["Pod"]
    verifyImages:
    - imageReferences: ["ghcr.io/myorg/*"]
`)
	result, err := k8sScanner(manifest).Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	assertPass(t, result.Findings, "SUPPLY-001")
}

func TestK8s_NoAuditPolicy_AggregationWarn(t *testing.T) {
	// A manifest with workloads but no audit policy should trigger MONITOR-002 warn
	manifest := writeTestManifest(t, `
apiVersion: v1
kind: Pod
metadata:
  name: simple-app
  namespace: default
spec:
  containers:
  - name: app
    image: nginx:latest
    securityContext:
      runAsNonRoot: true
      readOnlyRootFilesystem: true
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
    resources:
      limits:
        memory: "256Mi"
        cpu: "500m"
`)
	result, err := k8sScanner(manifest).Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	assertWarn(t, result.Findings, "MONITOR-002")
}

// ── Defense-in-depth tests ───────────────────────────────────────────────────

func TestK8s_DockerSockHostPath_DualFinding(t *testing.T) {
	manifest := writeTestManifest(t, `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: dind-agent
  namespace: ci
spec:
  selector:
    matchLabels:
      app: dind
  template:
    metadata:
      labels:
        app: dind
    spec:
      containers:
      - name: agent
        image: docker:24-dind@sha256:abc123
        securityContext:
          runAsNonRoot: true
          readOnlyRootFilesystem: true
          allowPrivilegeEscalation: false
          capabilities:
            drop: ["ALL"]
        resources:
          limits:
            memory: "256Mi"
            cpu: "500m"
      volumes:
      - name: docker-sock
        hostPath:
          path: /var/run/docker.sock
`)
	result, err := k8sScanner(manifest).Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	// Both RUNTIME-009 and DAEMON-001 should fire for docker.sock
	assertFail(t, result.Findings, "RUNTIME-009")
	assertFail(t, result.Findings, "DAEMON-001")
}

// ── Parse error surfacing ────────────────────────────────────────────────────

// TestK8sScanner_ParseError_EmitsErrorFinding verifies that YAML parse errors
// (commonly caused by un-rendered Helm templates containing `{{ .Values.foo }}`)
// produce an ERROR finding rather than being silently swallowed.
func TestK8sScanner_ParseError_EmitsErrorFinding(t *testing.T) {
	// Deliberately invalid YAML: Go template braces trip yaml.v3's decoder.
	path := writeTestManifest(t, `apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Values.name }}
spec:
  replicas: {{ .Values.replicas }}
`)

	result, err := k8sScanner(path).Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	var found bool
	for _, f := range result.Findings {
		if f.Status == types.StatusError && strings.Contains(f.Detail, "YAML parse error") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected an ERROR finding for YAML parse failure; got findings: %+v", result.Findings)
	}
}

// ── Test helper ──────────────────────────────────────────────────────────────

func writeTestManifest(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test manifest: %v", err)
	}
	return path
}

