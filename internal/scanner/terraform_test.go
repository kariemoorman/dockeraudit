package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kariemoorman/dockeraudit/internal/types"
)

// ── helpers (shared with k8s_test.go via same package) ─────────────────────── //
// findFinding, assertFail, assertPass, testdataDir are defined in k8s_test.go.

// hasFail returns true if any finding in the slice has status FAIL.
func hasFail(findings []types.Finding) bool {
	for _, f := range findings {
		if f.Status == types.StatusFail {
			return true
		}
	}
	return false
}

// ── insecure.tf — should produce FAILs ──────────────────────────────────────── //

func TestTerraformScanner_InsecureTF_HasFails(t *testing.T) {
	td := testdataDir(t)
	path := filepath.Join(td, "terraform", "insecure.tf")

	result, err := NewTerraformScanner([]string{path}).Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected findings from insecure.tf, got none")
	}
	if !hasFail(result.Findings) {
		t.Error("insecure.tf produced no FAIL findings")
	}
}

func TestTerraformScanner_InsecureTF_SpecificViolations(t *testing.T) {
	td := testdataDir(t)
	path := filepath.Join(td, "terraform", "insecure.tf")

	result, err := NewTerraformScanner([]string{path}).Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// insecure.tf declares these violations explicitly in comments
	assertFail(t, result.Findings, "SUPPLY-003")  // ECR tag mutability not set
	assertFail(t, result.Findings, "MONITOR-002") // EKS no audit logs
	assertFail(t, result.Findings, "NETWORK-002") // IMDSv1 http_tokens=optional
	assertFail(t, result.Findings, "IMAGE-002")   // hardcoded DB password (terraform scanner maps to IMAGE-002)
}

// ── secure.tf — should produce no FAILs ────────────────────────────────────── //

func TestTerraformScanner_SecureTF_NoFails(t *testing.T) {
	td := testdataDir(t)
	path := filepath.Join(td, "terraform", "secure.tf")

	result, err := NewTerraformScanner([]string{path}).Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected findings from secure.tf, got none")
	}
	for _, f := range result.Findings {
		// TF-009 findings come from trivy/snyk which may flag issues beyond
		// our regex checks — exclude them from the secure-file assertion.
		if f.Status == types.StatusFail && f.Control.ID != "TF-009" {
			t.Errorf("secure.tf should not produce FAIL for %s: %s", f.Control.ID, f.Detail)
		}
	}
}

// ── db-insecure.tf — should trigger DB-TF findings ─────────────────────────── //

func TestTerraformScanner_InsecureDBTF_HasFails(t *testing.T) {
	td := testdataDir(t)
	path := filepath.Join(td, "terraform", "db-insecure.tf")

	result, err := NewTerraformScanner([]string{path}).Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected findings from db-insecure.tf, got none")
	}
	if !hasFail(result.Findings) {
		t.Error("db-insecure.tf produced no FAIL findings")
	}
}

// ── Connection URL patterns (session 3) ────────────────────────────────────── //

func TestTerraformScanner_ConnectionURLPatterns(t *testing.T) {
	dir := t.TempDir()
	tf := filepath.Join(dir, "main.tf")
	content := `
resource "aws_db_instance" "example" {
  identifier     = "mydb"
  connection_url = "postgres://admin:secret@db.host.com:5432/mydb"
}
`
	if err := os.WriteFile(tf, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := NewTerraformScanner([]string{tf}).Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	assertFail(t, result.Findings, "IMAGE-002")
}

func TestTerraformScanner_DatabaseURLPattern(t *testing.T) {
	dir := t.TempDir()
	tf := filepath.Join(dir, "main.tf")
	content := `
resource "null_resource" "config" {
  provisioner "local-exec" {
    command = "echo done"
    environment = {
      database_url = "mysql://root:password@localhost:3306/app"
    }
  }
}
`
	if err := os.WriteFile(tf, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := NewTerraformScanner([]string{tf}).Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	assertFail(t, result.Findings, "IMAGE-002")
}

func TestTerraformScanner_JdbcURLPattern(t *testing.T) {
	dir := t.TempDir()
	tf := filepath.Join(dir, "main.tf")
	content := `
resource "aws_lambda_function" "app" {
  function_name = "myapp"
  handler       = "index.handler"
  runtime       = "java11"

  environment {
    variables = {
      jdbc_url = "jdbc:mysql://root:password@db.host:3306/app"
    }
  }
}
`
	if err := os.WriteFile(tf, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := NewTerraformScanner([]string{tf}).Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	assertFail(t, result.Findings, "IMAGE-002")
}

func TestTerraformScanner_VariableRef_NoFalsePositive(t *testing.T) {
	dir := t.TempDir()
	tf := filepath.Join(dir, "main.tf")
	// Variable references (${var.xxx}) should NOT trigger HCL pattern false positives
	content := `
resource "aws_lambda_function" "app" {
  function_name = "myapp"
  handler       = "index.handler"
  runtime       = "python3.9"

  environment {
    variables = {
      database_url   = "${var.database_url}"
      connection_url = "${var.conn_url}"
    }
  }
}
`
	if err := os.WriteFile(tf, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := NewTerraformScanner([]string{tf}).Scan(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	for _, f := range result.Findings {
		if f.Status == types.StatusFail && f.Control.ID == "IMAGE-002" &&
			(strings.Contains(f.Detail, "database_url") || strings.Contains(f.Detail, "connection_url")) {
			t.Errorf("false positive: variable references should not trigger FAIL: %s", f.Detail)
		}
	}
}

// ── non-existent path returns error ────────────────────────────────────────── //

func TestTerraformScanner_MissingPath_ReturnsError(t *testing.T) {
	_, err := NewTerraformScanner([]string{"/nonexistent/does-not-exist.tf"}).Scan(context.Background())
	if err == nil {
		t.Fatal("expected error scanning non-existent path, got nil")
	}
}

// ── empty path list returns empty result ───────────────────────────────────── //

func TestTerraformScanner_EmptyPaths_ReturnsEmptyFindings(t *testing.T) {
	result, err := NewTerraformScanner([]string{}).Scan(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// With trivy/snyk installed, TF-009 may produce a SKIP or PASS finding
	// even for empty paths. Only non-TF-009 findings should be absent.
	for _, f := range result.Findings {
		if f.Control.ID != "TF-009" {
			t.Errorf("expected no non-TF-009 findings for empty path list, got %s: %s",
				f.Control.ID, f.Detail)
		}
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// Unit tests for individual Terraform check closures
// ══════════════════════════════════════════════════════════════════════════════

// tfRunCheck is a helper that runs a named check from buildChecks() against content.
func tfRunCheck(t *testing.T, checkName, content string) []types.Finding {
	t.Helper()
	s := NewTerraformScanner(nil)
	checks := s.buildChecks()
	for _, c := range checks {
		if c.name == checkName {
			return c.run("test.tf", content)
		}
	}
	t.Fatalf("check %q not found in buildChecks()", checkName)
	return nil
}

// ── ECR checks ────────────────────────────────────────────────────────────── //

func TestTF_ECRImmutableTags_Missing(t *testing.T) {
	content := `resource "aws_ecr_repository" "app" {
  name = "myapp"
}`
	findings := tfRunCheck(t, "ECR Immutable Tags", content)
	assertFail(t, findings, "SUPPLY-003")
}

func TestTF_ECRImmutableTags_Set(t *testing.T) {
	content := `resource "aws_ecr_repository" "app" {
  name                 = "myapp"
  image_tag_mutability = "IMMUTABLE"
}`
	findings := tfRunCheck(t, "ECR Immutable Tags", content)
	assertPass(t, findings, "SUPPLY-003")
}

func TestTF_ECRImmutableTags_NoResource(t *testing.T) {
	findings := tfRunCheck(t, "ECR Immutable Tags", `resource "aws_s3_bucket" "b" {}`)
	assertSkipped(t, findings, "SUPPLY-003")
}

func TestTF_ECRScanOnPush_Missing(t *testing.T) {
	content := `resource "aws_ecr_repository" "app" { name = "myapp" }`
	findings := tfRunCheck(t, "ECR Scan on Push", content)
	assertFail(t, findings, "IMAGE-003")
}

func TestTF_ECRScanOnPush_Enabled(t *testing.T) {
	content := `resource "aws_ecr_repository" "app" {
  name = "myapp"
  image_scanning_configuration { scan_on_push = true }
}`
	findings := tfRunCheck(t, "ECR Scan on Push", content)
	assertPass(t, findings, "IMAGE-003")
}

// ── EKS checks ────────────────────────────────────────────────────────────── //

func TestTF_EKSAuditLogging_Missing(t *testing.T) {
	content := `resource "aws_eks_cluster" "main" { name = "prod" }`
	findings := tfRunCheck(t, "EKS Audit Logging", content)
	assertFail(t, findings, "MONITOR-002")
}

func TestTF_EKSAuditLogging_Enabled(t *testing.T) {
	content := `resource "aws_eks_cluster" "main" {
  name = "prod"
  enabled_cluster_log_types = ["audit", "api"]
}`
	findings := tfRunCheck(t, "EKS Audit Logging", content)
	assertPass(t, findings, "MONITOR-002")
}

func TestTF_EKSPrivateEndpoint_PublicNoRestriction(t *testing.T) {
	content := `resource "aws_eks_cluster" "main" {
  vpc_config { endpoint_public_access = true }
}`
	findings := tfRunCheck(t, "EKS Private Endpoint", content)
	assertWarn(t, findings, "HOST-003")
}

func TestTF_EKSPrivateEndpoint_OK(t *testing.T) {
	content := `resource "aws_eks_cluster" "main" {
  vpc_config {
    endpoint_public_access = true
    public_access_cidrs    = ["10.0.0.0/8"]
  }
}`
	findings := tfRunCheck(t, "EKS Private Endpoint", content)
	assertPass(t, findings, "HOST-003")
}

// ── IMDSv2 ────────────────────────────────────────────────────────────────── //

func TestTF_IMDSv2_NotRequired(t *testing.T) {
	content := `resource "aws_launch_template" "main" {
  metadata_options { http_tokens = "optional" }
}`
	findings := tfRunCheck(t, "IMDSv2 Required", content)
	assertFail(t, findings, "NETWORK-002")
}

func TestTF_IMDSv2_RequiredWithHop(t *testing.T) {
	content := `resource "aws_launch_template" "main" {
  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }
}`
	findings := tfRunCheck(t, "IMDSv2 Required", content)
	assertPass(t, findings, "NETWORK-002")
}

// ── Security Group Port 2375 ──────────────────────────────────────────────── //

func TestTF_SGPort2375_Exposed(t *testing.T) {
	content := `resource "aws_security_group" "docker" {
  ingress { from_port = 2375 to_port = 2375 protocol = "tcp" }
}`
	findings := tfRunCheck(t, "Security Group: No Port 2375 Open", content)
	assertFail(t, findings, "DAEMON-002")
}

func TestTF_SGPort2375_NotExposed(t *testing.T) {
	content := `resource "aws_security_group" "web" {
  ingress { from_port = 443 to_port = 443 protocol = "tcp" }
}`
	findings := tfRunCheck(t, "Security Group: No Port 2375 Open", content)
	assertPass(t, findings, "DAEMON-002")
}

// ── RDS checks (DB-TF-001) ───────────────────────────────────────────────── //

func TestTF_RDSEncryption_False(t *testing.T) {
	content := `resource "aws_db_instance" "main" {
  storage_encrypted = false
}`
	findings := tfRunCheck(t, "RDS Encryption at Rest", content)
	assertFail(t, findings, "DB-TF-001")
}

func TestTF_RDSEncryption_True(t *testing.T) {
	content := `resource "aws_db_instance" "main" {
  storage_encrypted = true
}`
	findings := tfRunCheck(t, "RDS Encryption at Rest", content)
	assertPass(t, findings, "DB-TF-001")
}

func TestTF_RDSPubliclyAccessible(t *testing.T) {
	content := `resource "aws_db_instance" "main" {
  publicly_accessible = true
}`
	findings := tfRunCheck(t, "RDS Not Publicly Accessible", content)
	assertFail(t, findings, "DB-TF-001")
}

func TestTF_RDSDeletionProtection_Missing(t *testing.T) {
	content := `resource "aws_db_instance" "main" { identifier = "prod" }`
	findings := tfRunCheck(t, "RDS Deletion Protection", content)
	assertWarn(t, findings, "DB-TF-001")
}

func TestTF_RDSBackupRetention_Zero(t *testing.T) {
	content := `resource "aws_db_instance" "main" {
  backup_retention_period = 0
}`
	findings := tfRunCheck(t, "RDS Backup Retention", content)
	assertFail(t, findings, "DB-TF-001")
}

func TestTF_RDSSkipFinalSnapshot_True(t *testing.T) {
	content := `resource "aws_db_instance" "main" {
  skip_final_snapshot = true
}`
	findings := tfRunCheck(t, "RDS Skip Final Snapshot", content)
	assertFail(t, findings, "DB-TF-001")
}

// ── ElastiCache checks (DB-TF-002) ───────────────────────────────────────── //

func TestTF_ElastiCacheEncryption_False(t *testing.T) {
	content := `resource "aws_elasticache_replication_group" "redis" {
  at_rest_encryption_enabled = false
}`
	findings := tfRunCheck(t, "ElastiCache Encryption at Rest", content)
	assertFail(t, findings, "DB-TF-002")
}

func TestTF_ElastiCacheTransit_False(t *testing.T) {
	content := `resource "aws_elasticache_replication_group" "redis" {
  transit_encryption_enabled = false
}`
	findings := tfRunCheck(t, "ElastiCache Transit Encryption", content)
	assertFail(t, findings, "DB-TF-002")
}

func TestTF_ElastiCacheAuth_Missing(t *testing.T) {
	content := `resource "aws_elasticache_replication_group" "redis" {
  description = "my redis"
}`
	findings := tfRunCheck(t, "ElastiCache Auth Token Required", content)
	assertFail(t, findings, "DB-TF-002")
}

func TestTF_ElastiCacheAuth_Present(t *testing.T) {
	content := `resource "aws_elasticache_replication_group" "redis" {
  auth_token = var.redis_password
}`
	findings := tfRunCheck(t, "ElastiCache Auth Token Required", content)
	assertPass(t, findings, "DB-TF-002")
}

// ── DocumentDB/DynamoDB checks (DB-TF-003) ────────────────────────────────── //

func TestTF_DocumentDBEncryption_False(t *testing.T) {
	content := `resource "aws_docdb_cluster" "main" {
  storage_encrypted = false
}`
	findings := tfRunCheck(t, "DocumentDB Encryption", content)
	assertFail(t, findings, "DB-TF-003")
}

func TestTF_DynamoDBSSE_Missing(t *testing.T) {
	content := `resource "aws_dynamodb_table" "main" {
  name = "orders"
}`
	findings := tfRunCheck(t, "DynamoDB Server-Side Encryption", content)
	assertFail(t, findings, "DB-TF-003")
}

func TestTF_DynamoDBSSE_Present(t *testing.T) {
	content := `resource "aws_dynamodb_table" "main" {
  name = "orders"
  server_side_encryption { enabled = true }
}`
	findings := tfRunCheck(t, "DynamoDB Server-Side Encryption", content)
	assertPass(t, findings, "DB-TF-003")
}

func TestTF_DynamoDBPITR_Missing(t *testing.T) {
	content := `resource "aws_dynamodb_table" "main" { name = "orders" }`
	findings := tfRunCheck(t, "DynamoDB Point-in-Time Recovery", content)
	assertWarn(t, findings, "DB-TF-003")
}

// ── S3 checks (TF-001, TF-002) ───────────────────────────────────────────── //

func TestTF_S3PublicACL(t *testing.T) {
	content := `resource "aws_s3_bucket" "data" {
  acl = "public-read"
}`
	findings := tfRunCheck(t, "S3 Public Access", content)
	assertFail(t, findings, "TF-001")
}

func TestTF_S3Versioning_Disabled(t *testing.T) {
	content := `resource "aws_s3_bucket" "data" {
  versioning { enabled = false }
}`
	findings := tfRunCheck(t, "S3 Versioning", content)
	assertFail(t, findings, "TF-002")
}

func TestTF_S3Versioning_Enabled(t *testing.T) {
	content := `resource "aws_s3_bucket" "data" {
  versioning { enabled = true }
}`
	findings := tfRunCheck(t, "S3 Versioning", content)
	assertPass(t, findings, "TF-002")
}

// ── ECS checks (TF-003, TF-004, TF-005) ──────────────────────────────────── //

func TestTF_ECSPrivileged(t *testing.T) {
	content := `resource "aws_ecs_task_definition" "app" {
  container_definitions = <<JSON
[{"name":"app","image":"nginx","privileged": true}]
JSON
}`
	findings := tfRunCheck(t, "ECS Privileged Mode", content)
	assertFail(t, findings, "TF-003")
}

func TestTF_ECSNonRoot_Missing(t *testing.T) {
	content := `resource "aws_ecs_task_definition" "app" {
  container_definitions = <<JSON
[{"name":"app","image":"nginx"}]
JSON
}`
	findings := tfRunCheck(t, "ECS Non-Root User", content)
	assertFail(t, findings, "TF-004")
}

func TestTF_ECSNonRoot_Set(t *testing.T) {
	content := `resource "aws_ecs_task_definition" "app" {
  container_definitions = <<JSON
[{"name":"app","image":"nginx","user":"1000"}]
JSON
}`
	findings := tfRunCheck(t, "ECS Non-Root User", content)
	assertPass(t, findings, "TF-004")
}

func TestTF_ECSReadOnlyFS_Missing(t *testing.T) {
	content := `resource "aws_ecs_task_definition" "app" {
  container_definitions = <<JSON
[{"name":"app","image":"nginx"}]
JSON
}`
	findings := tfRunCheck(t, "ECS Read-Only Root FS", content)
	assertFail(t, findings, "TF-005")
}

func TestTF_ECSReadOnlyFS_Set(t *testing.T) {
	content := `resource "aws_ecs_task_definition" "app" {
  container_definitions = <<JSON
[{"name":"app","image":"nginx","readonlyRootFilesystem": true}]
JSON
}`
	findings := tfRunCheck(t, "ECS Read-Only Root FS", content)
	assertPass(t, findings, "TF-005")
}

// ── Security Group Unrestricted Ingress (TF-006) ──────────────────────────── //

func TestTF_SGUnrestrictedIngress_SSH(t *testing.T) {
	content := `resource "aws_security_group" "web" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}`
	findings := tfRunCheck(t, "Security Group Unrestricted Ingress", content)
	assertFail(t, findings, "TF-006")
}

func TestTF_SGUnrestrictedIngress_PrivateCIDR(t *testing.T) {
	content := `resource "aws_security_group" "web" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}`
	findings := tfRunCheck(t, "Security Group Unrestricted Ingress", content)
	assertPass(t, findings, "TF-006")
}

// ── KMS Encryption (TF-007) ──────────────────────────────────────────────── //

func TestTF_KMS_EBSUnencrypted(t *testing.T) {
	content := `resource "aws_ebs_volume" "data" {
  encrypted = false
}`
	findings := tfRunCheck(t, "KMS Encryption", content)
	assertFail(t, findings, "TF-007")
}

func TestTF_KMS_EBSEncrypted(t *testing.T) {
	content := `resource "aws_ebs_volume" "data" {
  encrypted = true
}`
	findings := tfRunCheck(t, "KMS Encryption", content)
	assertPass(t, findings, "TF-007")
}

// ── CloudTrail Logging (TF-008) ──────────────────────────────────────────── //

func TestTF_CloudTrail_LoggingDisabled(t *testing.T) {
	content := `resource "aws_cloudtrail" "main" {
  enable_logging = false
}`
	findings := tfRunCheck(t, "CloudTrail Logging", content)
	assertFail(t, findings, "TF-008")
}

func TestTF_CloudTrail_SingleRegion(t *testing.T) {
	content := `resource "aws_cloudtrail" "main" {
  is_multi_region_trail = false
}`
	findings := tfRunCheck(t, "CloudTrail Logging", content)
	assertWarn(t, findings, "TF-008")
}

func TestTF_CloudTrail_OK(t *testing.T) {
	content := `resource "aws_cloudtrail" "main" {
  is_multi_region_trail = true
  enable_logging        = true
}`
	findings := tfRunCheck(t, "CloudTrail Logging", content)
	assertPass(t, findings, "TF-008")
}

// ── GKE checks ────────────────────────────────────────────────────────────── //

func TestTF_GKENetworkPolicy_Missing(t *testing.T) {
	content := `resource "google_container_cluster" "main" { name = "prod" }`
	findings := tfRunCheck(t, "GKE Network Policy", content)
	assertFail(t, findings, "NETWORK-001")
}

func TestTF_GKENetworkPolicy_Enabled(t *testing.T) {
	content := `resource "google_container_cluster" "main" {
  network_policy { enabled = true }
}`
	findings := tfRunCheck(t, "GKE Network Policy", content)
	assertPass(t, findings, "NETWORK-001")
}

func TestTF_GKEDatabaseEncryption_Missing(t *testing.T) {
	content := `resource "google_container_cluster" "main" { name = "prod" }`
	findings := tfRunCheck(t, "GKE Database Encryption", content)
	assertFail(t, findings, "SECRETS-001")
}

func TestTF_GKEDatabaseEncryption_Set(t *testing.T) {
	content := `resource "google_container_cluster" "main" {
  database_encryption { state = "ENCRYPTED" }
}`
	findings := tfRunCheck(t, "GKE Database Encryption", content)
	assertPass(t, findings, "SECRETS-001")
}

// ── Bottlerocket ──────────────────────────────────────────────────────────── //

func TestTF_Bottlerocket_NotUsed(t *testing.T) {
	content := `resource "aws_eks_node_group" "main" {
  ami_type = "AL2_x86_64"
}`
	findings := tfRunCheck(t, "EKS Bottlerocket Nodes", content)
	assertWarn(t, findings, "HOST-001")
}

func TestTF_Bottlerocket_Used(t *testing.T) {
	content := `resource "aws_eks_node_group" "main" {
  ami_type = "BOTTLEROCKET_x86_64"
}`
	findings := tfRunCheck(t, "EKS Bottlerocket Nodes", content)
	assertPass(t, findings, "HOST-001")
}
