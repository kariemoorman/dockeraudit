package scanner

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"

	"https://github.com/kariemoorman/dockeraudit/internal/types"
)

// TerraformScanner checks Terraform HCL files for container-security misconfigurations.
// It uses regex/string matching on the raw HCL text, which is reliable for common patterns
// without requiring a full HCL parser dependency.
type TerraformScanner struct {
	Paths []string
}

func NewTerraformScanner(paths []string) *TerraformScanner {
	return &TerraformScanner{Paths: paths}
}

type tfCheck struct {
	name string
	run  func(path, content string) []types.Finding
}

func (s *TerraformScanner) Scan(ctx context.Context) (*types.ScanResult, error) {
	result := &types.ScanResult{
		Target:  strings.Join(s.Paths, ", "),
		Scanner: "terraform",
	}

	checks := s.buildChecks()

	for _, p := range s.Paths {
		files, err := collectFiles(p, []string{".tf"})
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			data, err := os.ReadFile(f) // #nosec G304 -- f is a .tf file path from user-supplied --path flag
			relF := relPath(p, f)
			if err != nil {
				result.Findings = append(result.Findings, types.Finding{
					Status: types.StatusError,
					Target: relF,
					Detail: err.Error(),
				})
				continue
			}
			content := string(data)
			for _, check := range checks {
				findings := check.run(relF, content)
				result.Findings = append(result.Findings, findings...)
			}
		}
	}

	// TF-009: IaC vulnerability scan using trivy/snyk
	result.Findings = append(result.Findings, runIaCVulnScan(ctx, s.Paths, controlByID("TF-009"))...)

	result.Tally()
	return result, nil
}

func (s *TerraformScanner) buildChecks() []tfCheck {
	return []tfCheck{
		{
			name: "ECR Immutable Tags",
			run: func(path, content string) []types.Finding {
				ctrl := controlByID("SUPPLY-003")
				if !strings.Contains(content, "aws_ecr_repository") {
					return []types.Finding{skipped(ctrl, path, "No aws_ecr_repository resource in file")}
				}
				if !hasPattern(content, `image_tag_mutability\s*=\s*"IMMUTABLE"`) {
					line := findStringLine(content, "aws_ecr_repository")
					return []types.Finding{withSource(fail(ctrl, path,
						"ECR repository does not set image_tag_mutability = \"IMMUTABLE\"",
						"aws_ecr_repository resource found without IMMUTABLE tag mutability",
						ctrl.Remediation), path, line)}
				}
				return []types.Finding{pass(ctrl, path, "ECR repository uses IMMUTABLE tags")}
			},
		},
		{
			name: "ECR Scan on Push",
			run: func(path, content string) []types.Finding {
				ctrl := controlByID("IMAGE-003")
				if !strings.Contains(content, "aws_ecr_repository") {
					return []types.Finding{skipped(ctrl, path, "No aws_ecr_repository resource in file")}
				}
				if !hasPattern(content, `scan_on_push\s*=\s*true`) {
					line := findStringLine(content, "aws_ecr_repository")
					return []types.Finding{withSource(fail(ctrl, path,
						"ECR repository does not enable scan_on_push",
						"aws_ecr_repository found without scan_on_push = true",
						ctrl.Remediation), path, line)}
				}
				return []types.Finding{pass(ctrl, path, "ECR scan_on_push enabled")}
			},
		},
		{
			name: "EKS Audit Logging",
			run: func(path, content string) []types.Finding {
				ctrl := controlByID("MONITOR-002")
				if !strings.Contains(content, "aws_eks_cluster") {
					return []types.Finding{skipped(ctrl, path, "No aws_eks_cluster resource in file")}
				}
				if !strings.Contains(content, "enabled_cluster_log_types") ||
					!strings.Contains(content, `"audit"`) {
					line := findStringLine(content, "aws_eks_cluster")
					return []types.Finding{withSource(fail(ctrl, path,
						"EKS cluster does not enable audit logging",
						"aws_eks_cluster found without enabled_cluster_log_types containing 'audit'",
						ctrl.Remediation), path, line)}
				}
				return []types.Finding{pass(ctrl, path, "EKS audit logging enabled")}
			},
		},
		{
			name: "IMDSv2 Required",
			run: func(path, content string) []types.Finding {
				ctrl := controlByID("NETWORK-002")
				if !strings.Contains(content, "aws_launch_template") &&
					!strings.Contains(content, "aws_instance") {
					return []types.Finding{skipped(ctrl, path, "No aws_launch_template or aws_instance resource in file")}
				}
				if !hasPattern(content, `http_tokens\s*=\s*"required"`) {
					line := findStringLine(content, "aws_launch_template")
					if line == 0 {
						line = findStringLine(content, "aws_instance")
					}
					return []types.Finding{withSource(fail(ctrl, path,
						"Launch template/instance does not enforce IMDSv2 (http_tokens = required)",
						"metadata_options.http_tokens != required — SSRF can reach IMDS v1",
						ctrl.Remediation), path, line)}
				}
				if !hasPattern(content, `http_put_response_hop_limit\s*=\s*1`) {
					line := findPatternLine(content, `http_put_response_hop_limit`)
					return []types.Finding{withSource(warn(ctrl, path,
						"IMDSv2 required but hop limit is not 1 — containers may reach IMDS",
						"http_put_response_hop_limit should be 1 to block container SSRF"), path, line)}
				}
				return []types.Finding{pass(ctrl, path, "IMDSv2 required with hop_limit=1")}
			},
		},
		{
			name: "EKS Private Endpoint",
			run: func(path, content string) []types.Finding {
				ctrl := controlByID("HOST-003")
				if !strings.Contains(content, "aws_eks_cluster") {
					return []types.Finding{skipped(ctrl, path, "No aws_eks_cluster resource in file")}
				}
				if hasPattern(content, `endpoint_public_access\s*=\s*true`) &&
					!strings.Contains(content, "public_access_cidrs") {
					line := findPatternLine(content, `endpoint_public_access\s*=\s*true`)
					return []types.Finding{withSource(warn(ctrl, path,
						"EKS public endpoint enabled without CIDR restriction",
						"endpoint_public_access = true without public_access_cidrs narrows exposure"), path, line)}
				}
				return []types.Finding{pass(ctrl, path, "EKS endpoint configuration looks acceptable")}
			},
		},
		{
			name: "GKE Network Policy",
			run: func(path, content string) []types.Finding {
				ctrl := controlByID("NETWORK-001")
				if !strings.Contains(content, "google_container_cluster") {
					return []types.Finding{skipped(ctrl, path, "No google_container_cluster resource in file")}
				}
				if !hasPattern(content, `enabled\s*=\s*true`) || !strings.Contains(content, "network_policy") {
					line := findStringLine(content, "google_container_cluster")
					return []types.Finding{withSource(fail(ctrl, path,
						"GKE cluster does not enable network_policy",
						"google_container_cluster found without network_policy { enabled = true }",
						ctrl.Remediation), path, line)}
				}
				return []types.Finding{pass(ctrl, path, "GKE network policy enabled")}
			},
		},
		{
			name: "GKE Database Encryption",
			run: func(path, content string) []types.Finding {
				ctrl := controlByID("SECRETS-001")
				if !strings.Contains(content, "google_container_cluster") {
					return []types.Finding{skipped(ctrl, path, "No google_container_cluster resource in file")}
				}
				if !strings.Contains(content, "database_encryption") ||
					!hasPattern(content, `state\s*=\s*"ENCRYPTED"`) {
					line := findStringLine(content, "google_container_cluster")
					return []types.Finding{withSource(fail(ctrl, path,
						"GKE cluster does not enable database_encryption for Kubernetes Secrets",
						"google_container_cluster found without database_encryption { state = ENCRYPTED }",
						ctrl.Remediation), path, line)}
				}
				return []types.Finding{pass(ctrl, path, "GKE database encryption enabled")}
			},
		},
		{
			name: "EKS Bottlerocket Nodes",
			run: func(path, content string) []types.Finding {
				ctrl := controlByID("HOST-001")
				if !strings.Contains(content, "aws_eks_node_group") {
					return []types.Finding{skipped(ctrl, path, "No aws_eks_node_group resource in file")}
				}
				if !hasPattern(content, `ami_type\s*=\s*"BOTTLEROCKET`) {
					line := findStringLine(content, "aws_eks_node_group")
					return []types.Finding{withSource(warn(ctrl, path,
						"EKS node group does not use Bottlerocket AMI",
						"Consider BOTTLEROCKET_x86_64 for minimal, container-optimized OS"), path, line)}
				}
				return []types.Finding{pass(ctrl, path, "EKS node group uses Bottlerocket")}
			},
		},
		{
			name: "Security Group: No Port 2375 Open",
			run: func(path, content string) []types.Finding {
				ctrl := controlByID("DAEMON-002")
				if !strings.Contains(content, "aws_security_group") {
					return []types.Finding{skipped(ctrl, path, "No aws_security_group resource in file")}
				}
				pat2375from := `from_port\s*=\s*2375`
				pat2375to := `to_port\s*=\s*2375`
				if hasPattern(content, pat2375from) || hasPattern(content, pat2375to) {
					line := findPatternLine(content, pat2375from)
					if line == 0 {
						line = findPatternLine(content, pat2375to)
					}
					return []types.Finding{withSource(fail(ctrl, path,
						"Security group has a rule involving port 2375 (Docker unauthenticated API)",
						"Inbound rule for port 2375 found in aws_security_group",
						ctrl.Remediation), path, line)}
				}
				return []types.Finding{pass(ctrl, path, "Security group does not expose port 2375")}
			},
		},
		{
			name: "Hardcoded Secrets",
			run: func(path, content string) []types.Finding {
				ctrl := controlByID("IMAGE-002")

				// HCL assignment patterns (password = "...", secret = "...", etc.)
				hclPatterns := []struct {
					re  string
					msg string
				}{
					{`(?i)password\s*=\s*"[^"${}]`, "Hardcoded password value"},
					{`(?i)secret\s*=\s*"[^"${}]`, "Hardcoded secret value"},
					{`(?i)api_key\s*=\s*"[^"${}]`, "Hardcoded API key"},
					{`(?i)access_key\s*=\s*"AKIA`, "Hardcoded AWS access key"},
					{`(?i)private_key\s*=\s*"-----BEGIN`, "Hardcoded private key"},
					{`(?i)auth_token\s*=\s*"[^"${}]`, "Hardcoded auth token"},
					{`(?i)client_secret\s*=\s*"[^"${}]`, "Hardcoded client secret"},
					{`(?i)connection_string\s*=\s*"[^"${}]`, "Hardcoded connection string"},
					{`(?i)connection_url\s*=\s*"[^"${}]`, "Hardcoded connection URL"},
					{`(?i)database_url\s*=\s*"[^"${}]`, "Hardcoded database URL"},
					{`(?i)jdbc_url\s*=\s*"[^"${}]`, "Hardcoded JDBC URL"},
					{`(?i)redis_url\s*=\s*"[^"${}]`, "Hardcoded Redis URL"},
					{`(?i)mongo_url\s*=\s*"[^"${}]`, "Hardcoded MongoDB URL"},
					{`(?i)mongodb_uri\s*=\s*"[^"${}]`, "Hardcoded MongoDB URI"},
				}

				var findings []types.Finding
				for _, p := range hclPatterns {
					if hasPattern(content, p.re) {
						line := findPatternLine(content, p.re)
						findings = append(findings, withSource(fail(ctrl, path,
							p.msg+" detected in Terraform file",
							fmt.Sprintf("Matched pattern: %s", p.re),
							"Use variables with sensitive=true and inject via environment or Vault provider."), path, line))
					}
				}

				// Regex-based value detection using SecretScanner patterns.
				// Scan string literals in the Terraform content for known secret formats.
				secretScanner := NewSecretScanner(path, ctrl)
				stringLiteralRe := regexp.MustCompile(`"([^"${}]{16,})"`)
				for _, loc := range stringLiteralRe.FindAllStringIndex(content, -1) {
					literal := content[loc[0]+1 : loc[1]-1]
					matches := secretScanner.CheckLine(literal)
					for _, m := range matches {
						if m.PatternName == "HIGH_ENTROPY" {
							continue // skip entropy-only matches in Terraform — too noisy
						}
						line := strings.Count(content[:loc[0]], "\n") + 1
						findings = append(findings, withSource(fail(ctrl, path,
							fmt.Sprintf("Detected %s pattern in Terraform string literal", m.PatternName),
							fmt.Sprintf("line %d: value matches %s", line, m.PatternName),
							"Use variables with sensitive=true and inject via environment or Vault provider."), path, line))
						break // one finding per literal
					}
				}

				if len(findings) == 0 {
					return []types.Finding{pass(ctrl, path, "No obvious hardcoded secrets in Terraform")}
				}
				return findings
			},
		},

		// ── Database: RDS (DB-TF-001) ─────────────────────────────────────────
		{
			name: "RDS Encryption at Rest",
			run: func(path, content string) []types.Finding {
				ctrl := controlByID("DB-TF-001")
				if !strings.Contains(content, "aws_db_instance") {
					return []types.Finding{skipped(ctrl, path, "No aws_db_instance resource in file")}
				}
				if hasPattern(content, `storage_encrypted\s*=\s*false`) {
					line := findPatternLine(content, `storage_encrypted\s*=\s*false`)
					return []types.Finding{withSource(fail(ctrl, path,
						"RDS instance has storage_encrypted = false — data at rest is unencrypted",
						"aws_db_instance: storage_encrypted = false",
						ctrl.Remediation), path, line)}
				}
				if !hasPattern(content, `storage_encrypted\s*=\s*true`) {
					line := findStringLine(content, "aws_db_instance")
					return []types.Finding{withSource(warn(ctrl, path,
						"RDS instance does not explicitly set storage_encrypted — verify encryption is enabled",
						"aws_db_instance: storage_encrypted not set"), path, line)}
				}
				return []types.Finding{pass(ctrl, path, "RDS storage_encrypted = true")}
			},
		},
		{
			name: "RDS Not Publicly Accessible",
			run: func(path, content string) []types.Finding {
				ctrl := controlByID("DB-TF-001")
				if !strings.Contains(content, "aws_db_instance") {
					return []types.Finding{skipped(ctrl, path, "No aws_db_instance resource in file")}
				}
				if hasPattern(content, `publicly_accessible\s*=\s*true`) {
					line := findPatternLine(content, `publicly_accessible\s*=\s*true`)
					return []types.Finding{withSource(fail(ctrl, path,
						"RDS instance has publicly_accessible = true — database port exposed to Internet",
						"aws_db_instance: publicly_accessible = true",
						ctrl.Remediation), path, line)}
				}
				return []types.Finding{pass(ctrl, path, "RDS publicly_accessible is false or unset (default false)")}
			},
		},
		{
			name: "RDS Deletion Protection",
			run: func(path, content string) []types.Finding {
				ctrl := controlByID("DB-TF-001")
				if !strings.Contains(content, "aws_db_instance") {
					return []types.Finding{skipped(ctrl, path, "No aws_db_instance resource in file")}
				}
				if !hasPattern(content, `deletion_protection\s*=\s*true`) {
					line := findStringLine(content, "aws_db_instance")
					return []types.Finding{withSource(warn(ctrl, path,
						"RDS instance does not set deletion_protection = true — accidental or malicious deletion possible",
						"aws_db_instance: deletion_protection not true"), path, line)}
				}
				return []types.Finding{pass(ctrl, path, "RDS deletion_protection = true")}
			},
		},
		{
			name: "RDS Backup Retention",
			run: func(path, content string) []types.Finding {
				ctrl := controlByID("DB-TF-001")
				if !strings.Contains(content, "aws_db_instance") {
					return []types.Finding{skipped(ctrl, path, "No aws_db_instance resource in file")}
				}
				if hasPattern(content, `backup_retention_period\s*=\s*0`) {
					line := findPatternLine(content, `backup_retention_period\s*=\s*0`)
					return []types.Finding{withSource(fail(ctrl, path,
						"RDS backup_retention_period = 0 — no point-in-time recovery possible",
						"aws_db_instance: backup_retention_period = 0",
						ctrl.Remediation), path, line)}
				}
				return []types.Finding{pass(ctrl, path, "RDS backup retention is configured")}
			},
		},
		{
			name: "RDS Skip Final Snapshot",
			run: func(path, content string) []types.Finding {
				ctrl := controlByID("DB-TF-001")
				if !strings.Contains(content, "aws_db_instance") {
					return []types.Finding{skipped(ctrl, path, "No aws_db_instance resource in file")}
				}
				if hasPattern(content, `skip_final_snapshot\s*=\s*true`) {
					line := findPatternLine(content, `skip_final_snapshot\s*=\s*true`)
					return []types.Finding{withSource(fail(ctrl, path,
						"RDS skip_final_snapshot = true — no snapshot taken before deletion, data permanently lost",
						"aws_db_instance: skip_final_snapshot = true",
						ctrl.Remediation), path, line)}
				}
				return []types.Finding{pass(ctrl, path, "RDS final snapshot will be taken on deletion")}
			},
		},

		// ── Database: ElastiCache / Redis (DB-TF-002) ─────────────────────────
		{
			name: "ElastiCache Encryption at Rest",
			run: func(path, content string) []types.Finding {
				ctrl := controlByID("DB-TF-002")
				if !strings.Contains(content, "aws_elasticache_replication_group") &&
					!strings.Contains(content, "aws_elasticache_cluster") {
					return []types.Finding{skipped(ctrl, path, "No ElastiCache resource in file")}
				}
				if hasPattern(content, `at_rest_encryption_enabled\s*=\s*false`) {
					line := findPatternLine(content, `at_rest_encryption_enabled\s*=\s*false`)
					return []types.Finding{withSource(fail(ctrl, path,
						"ElastiCache at_rest_encryption_enabled = false — cached data unencrypted",
						"at_rest_encryption_enabled = false",
						ctrl.Remediation), path, line)}
				}
				if !hasPattern(content, `at_rest_encryption_enabled\s*=\s*true`) {
					line := findStringLine(content, "aws_elasticache_replication_group")
					if line == 0 {
						line = findStringLine(content, "aws_elasticache_cluster")
					}
					return []types.Finding{withSource(warn(ctrl, path,
						"ElastiCache does not explicitly enable at_rest_encryption",
						"at_rest_encryption_enabled not set to true"), path, line)}
				}
				return []types.Finding{pass(ctrl, path, "ElastiCache at_rest_encryption_enabled = true")}
			},
		},
		{
			name: "ElastiCache Transit Encryption",
			run: func(path, content string) []types.Finding {
				ctrl := controlByID("DB-TF-002")
				if !strings.Contains(content, "aws_elasticache_replication_group") {
					return []types.Finding{skipped(ctrl, path, "No aws_elasticache_replication_group resource in file")}
				}
				if hasPattern(content, `transit_encryption_enabled\s*=\s*false`) {
					line := findPatternLine(content, `transit_encryption_enabled\s*=\s*false`)
					return []types.Finding{withSource(fail(ctrl, path,
						"ElastiCache transit_encryption_enabled = false — Redis traffic in plaintext",
						"transit_encryption_enabled = false",
						ctrl.Remediation), path, line)}
				}
				if !hasPattern(content, `transit_encryption_enabled\s*=\s*true`) {
					line := findStringLine(content, "aws_elasticache_replication_group")
					return []types.Finding{withSource(warn(ctrl, path,
						"ElastiCache replication group does not enable transit_encryption",
						"transit_encryption_enabled not set"), path, line)}
				}
				return []types.Finding{pass(ctrl, path, "ElastiCache transit_encryption_enabled = true")}
			},
		},
		{
			name: "ElastiCache Auth Token Required",
			run: func(path, content string) []types.Finding {
				ctrl := controlByID("DB-TF-002")
				if !strings.Contains(content, "aws_elasticache_replication_group") {
					return []types.Finding{skipped(ctrl, path, "No aws_elasticache_replication_group resource in file")}
				}
				if !strings.Contains(content, "auth_token") {
					line := findStringLine(content, "aws_elasticache_replication_group")
					return []types.Finding{withSource(fail(ctrl, path,
						"ElastiCache replication group has no auth_token — unauthenticated Redis access enables CONFIG SET exploit chain",
						"auth_token not configured in aws_elasticache_replication_group",
						ctrl.Remediation), path, line)}
				}
				return []types.Finding{pass(ctrl, path, "ElastiCache auth_token configured")}
			},
		},

		// ── Database: DocumentDB / DynamoDB (DB-TF-003) ───────────────────────
		{
			name: "DocumentDB Encryption",
			run: func(path, content string) []types.Finding {
				ctrl := controlByID("DB-TF-003")
				if !strings.Contains(content, "aws_docdb_cluster") {
					return []types.Finding{skipped(ctrl, path, "No aws_docdb_cluster resource in file")}
				}
				if hasPattern(content, `storage_encrypted\s*=\s*false`) {
					line := findPatternLine(content, `storage_encrypted\s*=\s*false`)
					return []types.Finding{withSource(fail(ctrl, path,
						"DocumentDB cluster has storage_encrypted = false — document data unencrypted at rest",
						"aws_docdb_cluster: storage_encrypted = false",
						ctrl.Remediation), path, line)}
				}
				return []types.Finding{pass(ctrl, path, "DocumentDB storage encryption configured")}
			},
		},
		{
			name: "DocumentDB Backup Retention",
			run: func(path, content string) []types.Finding {
				ctrl := controlByID("DB-TF-003")
				if !strings.Contains(content, "aws_docdb_cluster") {
					return []types.Finding{skipped(ctrl, path, "No aws_docdb_cluster resource in file")}
				}
				if hasPattern(content, `backup_retention_period\s*=\s*0`) {
					line := findPatternLine(content, `backup_retention_period\s*=\s*0`)
					return []types.Finding{withSource(fail(ctrl, path,
						"DocumentDB backup_retention_period = 0 — no point-in-time recovery",
						"aws_docdb_cluster: backup_retention_period = 0",
						ctrl.Remediation), path, line)}
				}
				return []types.Finding{pass(ctrl, path, "DocumentDB backup retention configured")}
			},
		},
		{
			name: "DynamoDB Server-Side Encryption",
			run: func(path, content string) []types.Finding {
				ctrl := controlByID("DB-TF-003")
				if !strings.Contains(content, "aws_dynamodb_table") {
					return []types.Finding{skipped(ctrl, path, "No aws_dynamodb_table resource in file")}
				}
				if !strings.Contains(content, "server_side_encryption") {
					line := findStringLine(content, "aws_dynamodb_table")
					return []types.Finding{withSource(fail(ctrl, path,
						"DynamoDB table has no server_side_encryption block — data not encrypted with customer-managed key",
						"aws_dynamodb_table: server_side_encryption not configured",
						ctrl.Remediation), path, line)}
				}
				return []types.Finding{pass(ctrl, path, "DynamoDB server_side_encryption configured")}
			},
		},
		{
			name: "DynamoDB Point-in-Time Recovery",
			run: func(path, content string) []types.Finding {
				ctrl := controlByID("DB-TF-003")
				if !strings.Contains(content, "aws_dynamodb_table") {
					return []types.Finding{skipped(ctrl, path, "No aws_dynamodb_table resource in file")}
				}
				if !strings.Contains(content, "point_in_time_recovery") {
					line := findStringLine(content, "aws_dynamodb_table")
					return []types.Finding{withSource(warn(ctrl, path,
						"DynamoDB table does not configure point_in_time_recovery — no 35-day recovery window",
						"aws_dynamodb_table: point_in_time_recovery block not found"), path, line)}
				}
				return []types.Finding{pass(ctrl, path, "DynamoDB point_in_time_recovery configured")}
			},
		},

		// ── TF-001: S3 Bucket Not Publicly Accessible (Critical) ─────────────
		{
			name: "S3 Public Access",
			run: func(path, content string) []types.Finding {
				ctrl := controlByID("TF-001")
				if !strings.Contains(content, "aws_s3_bucket") {
					return []types.Finding{skipped(ctrl, path, "No aws_s3_bucket resource in file")}
				}
				var findings []types.Finding

				// Check for public ACL
				if hasPattern(content, `acl\s*=\s*"public-read`) {
					line := findPatternLine(content, `acl\s*=\s*"public-read`)
					findings = append(findings, withSource(fail(ctrl, path,
						"S3 bucket uses a public ACL (public-read or public-read-write)",
						"acl = \"public-read*\" detected",
						ctrl.Remediation), path, line))
				}

				// Check for Block Public Access disabled
				if hasPattern(content, `block_public_acls\s*=\s*false`) {
					line := findPatternLine(content, `block_public_acls\s*=\s*false`)
					findings = append(findings, withSource(fail(ctrl, path,
						"S3 Block Public Access: block_public_acls = false",
						"block_public_acls = false",
						ctrl.Remediation), path, line))
				}
				if hasPattern(content, `block_public_policy\s*=\s*false`) {
					line := findPatternLine(content, `block_public_policy\s*=\s*false`)
					findings = append(findings, withSource(fail(ctrl, path,
						"S3 Block Public Access: block_public_policy = false",
						"block_public_policy = false",
						ctrl.Remediation), path, line))
				}
				if hasPattern(content, `restrict_public_buckets\s*=\s*false`) {
					line := findPatternLine(content, `restrict_public_buckets\s*=\s*false`)
					findings = append(findings, withSource(fail(ctrl, path,
						"S3 Block Public Access: restrict_public_buckets = false",
						"restrict_public_buckets = false",
						ctrl.Remediation), path, line))
				}

				// Check for aws_s3_bucket_public_access_block resource
				if strings.Contains(content, "aws_s3_bucket") &&
					!strings.Contains(content, "aws_s3_bucket_public_access_block") {
					line := findStringLine(content, "aws_s3_bucket")
					findings = append(findings, withSource(warn(ctrl, path,
						"No aws_s3_bucket_public_access_block resource found — S3 bucket may be publicly accessible",
						"aws_s3_bucket_public_access_block not defined"), path, line))
				}

				if len(findings) == 0 {
					return []types.Finding{pass(ctrl, path, "S3 bucket public access controls configured")}
				}
				return findings
			},
		},

		// ── TF-002: S3 Bucket Versioning Enabled (Medium) ────────────────────
		{
			name: "S3 Versioning",
			run: func(path, content string) []types.Finding {
				ctrl := controlByID("TF-002")
				if !strings.Contains(content, "aws_s3_bucket") {
					return []types.Finding{skipped(ctrl, path, "No aws_s3_bucket resource in file")}
				}
				// Check for explicit versioning disabled
				if hasPattern(content, `versioning\s*\{[^}]*enabled\s*=\s*false`) ||
					hasPattern(content, `status\s*=\s*"Suspended"`) {
					line := findPatternLine(content, `versioning`)
					if line == 0 {
						line = findPatternLine(content, `status\s*=\s*"Suspended"`)
					}
					return []types.Finding{withSource(fail(ctrl, path,
						"S3 bucket versioning is explicitly disabled",
						"versioning { enabled = false } or status = Suspended",
						ctrl.Remediation), path, line)}
				}
				// Check for versioning enabled
				if hasPattern(content, `versioning\s*\{[^}]*enabled\s*=\s*true`) ||
					hasPattern(content, `status\s*=\s*"Enabled"`) ||
					strings.Contains(content, "aws_s3_bucket_versioning") {
					return []types.Finding{pass(ctrl, path, "S3 bucket versioning enabled")}
				}
				line := findStringLine(content, "aws_s3_bucket")
				return []types.Finding{withSource(warn(ctrl, path,
					"S3 bucket does not explicitly enable versioning",
					"No versioning block found in aws_s3_bucket"), path, line)}
			},
		},

		// ── TF-003: ECS Task Definition Not Privileged (High) ────────────────
		{
			name: "ECS Privileged Mode",
			run: func(path, content string) []types.Finding {
				ctrl := controlByID("TF-003")
				if !strings.Contains(content, "aws_ecs_task_definition") {
					return []types.Finding{skipped(ctrl, path, "No aws_ecs_task_definition resource in file")}
				}
				// Check for privileged: true in container_definitions JSON
				if hasPattern(content, `"privileged"\s*:\s*true`) {
					line := findPatternLine(content, `"privileged"\s*:\s*true`)
					return []types.Finding{withSource(fail(ctrl, path,
						"ECS task definition has privileged container — full host access enabled",
						"container_definitions contains \"privileged\": true",
						ctrl.Remediation), path, line)}
				}
				return []types.Finding{pass(ctrl, path, "ECS task definitions do not use privileged mode")}
			},
		},

		// ── TF-004: ECS Task Uses Non-Root User (Medium) ─────────────────────
		{
			name: "ECS Non-Root User",
			run: func(path, content string) []types.Finding {
				ctrl := controlByID("TF-004")
				if !strings.Contains(content, "aws_ecs_task_definition") {
					return []types.Finding{skipped(ctrl, path, "No aws_ecs_task_definition resource in file")}
				}
				if !strings.Contains(content, "container_definitions") {
					return []types.Finding{skipped(ctrl, path, "No container_definitions in ECS task definition")}
				}
				// Check if "user" key is present in container_definitions
				if !hasPattern(content, `"user"\s*:`) {
					line := findStringLine(content, "aws_ecs_task_definition")
					return []types.Finding{withSource(fail(ctrl, path,
						"ECS container definitions do not specify a user — containers may run as root",
						"No \"user\" key in container_definitions",
						ctrl.Remediation), path, line)}
				}
				return []types.Finding{pass(ctrl, path, "ECS task definitions specify a user")}
			},
		},

		// ── TF-005: ECS Task Has Read-Only Root Filesystem (Medium) ──────────
		{
			name: "ECS Read-Only Root FS",
			run: func(path, content string) []types.Finding {
				ctrl := controlByID("TF-005")
				if !strings.Contains(content, "aws_ecs_task_definition") {
					return []types.Finding{skipped(ctrl, path, "No aws_ecs_task_definition resource in file")}
				}
				if hasPattern(content, `"readonlyRootFilesystem"\s*:\s*false`) {
					line := findPatternLine(content, `"readonlyRootFilesystem"\s*:\s*false`)
					return []types.Finding{withSource(fail(ctrl, path,
						"ECS container has readonlyRootFilesystem = false — writable root filesystem",
						"container_definitions contains \"readonlyRootFilesystem\": false",
						ctrl.Remediation), path, line)}
				}
				if !hasPattern(content, `"readonlyRootFilesystem"\s*:\s*true`) {
					line := findStringLine(content, "aws_ecs_task_definition")
					return []types.Finding{withSource(fail(ctrl, path,
						"ECS container definitions do not set readonlyRootFilesystem — defaults to writable",
						"No \"readonlyRootFilesystem\": true in container_definitions",
						ctrl.Remediation), path, line)}
				}
				return []types.Finding{pass(ctrl, path, "ECS containers use read-only root filesystem")}
			},
		},

		// ── TF-006: Security Group Allows Unrestricted Ingress (High) ────────
		{
			name: "Security Group Unrestricted Ingress",
			run: func(path, content string) []types.Finding {
				ctrl := controlByID("TF-006")
				if !strings.Contains(content, "aws_security_group") {
					return []types.Finding{skipped(ctrl, path, "No aws_security_group resource in file")}
				}
				var findings []types.Finding
				// Check for 0.0.0.0/0 in ingress CIDR blocks
				if hasPattern(content, `cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]`) {
					// Check if this is on sensitive ports
					sensitivePorts := []struct {
						port    string
						service string
					}{
						{"22", "SSH"},
						{"3389", "RDP"},
						{"3306", "MySQL"},
						{"5432", "PostgreSQL"},
						{"6379", "Redis"},
						{"27017", "MongoDB"},
						{"9200", "Elasticsearch"},
					}
					for _, sp := range sensitivePorts {
						fromPat := fmt.Sprintf(`from_port\s*=\s*%s`, sp.port)
						toPat := fmt.Sprintf(`to_port\s*=\s*%s`, sp.port)
						if hasPattern(content, fromPat) || hasPattern(content, toPat) {
							line := findPatternLine(content, fromPat)
							if line == 0 {
								line = findPatternLine(content, toPat)
							}
							findings = append(findings, withSource(fail(ctrl, path,
								fmt.Sprintf("Security group allows unrestricted ingress (0.0.0.0/0) on %s port %s",
									sp.service, sp.port),
								fmt.Sprintf("ingress on port %s from 0.0.0.0/0", sp.port),
								ctrl.Remediation), path, line))
						}
					}
				}
				// Check for ::/0 (IPv6 any)
				if hasPattern(content, `ipv6_cidr_blocks\s*=\s*\["::/0"\]`) {
					line := findPatternLine(content, `ipv6_cidr_blocks\s*=\s*\["::/0"\]`)
					findings = append(findings, withSource(warn(ctrl, path,
						"Security group allows unrestricted IPv6 ingress (::/0)",
						"ipv6_cidr_blocks = [\"::/0\"]"), path, line))
				}
				if len(findings) == 0 {
					return []types.Finding{pass(ctrl, path, "No unrestricted ingress on sensitive ports")}
				}
				return findings
			},
		},

		// ── TF-007: KMS Encryption on EBS/RDS/S3 (High) ─────────────────────
		{
			name: "KMS Encryption",
			run: func(path, content string) []types.Finding {
				ctrl := controlByID("TF-007")
				var findings []types.Finding

				// EBS volume encryption
				if strings.Contains(content, "aws_ebs_volume") {
					if hasPattern(content, `encrypted\s*=\s*false`) {
						line := findPatternLine(content, `encrypted\s*=\s*false`)
						findings = append(findings, withSource(fail(ctrl, path,
							"EBS volume has encrypted = false — data at rest is unencrypted",
							"aws_ebs_volume: encrypted = false",
							ctrl.Remediation), path, line))
					} else if !hasPattern(content, `encrypted\s*=\s*true`) {
						line := findStringLine(content, "aws_ebs_volume")
						findings = append(findings, withSource(warn(ctrl, path,
							"EBS volume does not explicitly set encrypted = true",
							"aws_ebs_volume: encrypted not set"), path, line))
					}
				}

				// S3 bucket encryption
				if strings.Contains(content, "aws_s3_bucket") &&
					!strings.Contains(content, "aws_s3_bucket_server_side_encryption_configuration") &&
					!strings.Contains(content, "server_side_encryption_configuration") {
					line := findStringLine(content, "aws_s3_bucket")
					findings = append(findings, withSource(warn(ctrl, path,
						"S3 bucket has no server-side encryption configuration",
						"aws_s3_bucket without server_side_encryption_configuration"), path, line))
				}

				if len(findings) == 0 {
					if strings.Contains(content, "aws_ebs_volume") ||
						strings.Contains(content, "aws_s3_bucket") {
						return []types.Finding{pass(ctrl, path, "Encryption properly configured")}
					}
					return []types.Finding{skipped(ctrl, path, "No EBS or S3 resources in file")}
				}
				return findings
			},
		},

		// ── TF-008: CloudTrail / Logging Enabled (Medium) ────────────────────
		{
			name: "CloudTrail Logging",
			run: func(path, content string) []types.Finding {
				ctrl := controlByID("TF-008")
				var findings []types.Finding

				// Check for CloudTrail
				if strings.Contains(content, "aws_cloudtrail") {
					if hasPattern(content, `is_multi_region_trail\s*=\s*false`) {
						line := findPatternLine(content, `is_multi_region_trail\s*=\s*false`)
						findings = append(findings, withSource(warn(ctrl, path,
							"CloudTrail is not multi-region — API calls in other regions go unrecorded",
							"is_multi_region_trail = false"), path, line))
					}
					if hasPattern(content, `enable_logging\s*=\s*false`) {
						line := findPatternLine(content, `enable_logging\s*=\s*false`)
						findings = append(findings, withSource(fail(ctrl, path,
							"CloudTrail logging is explicitly disabled",
							"enable_logging = false",
							ctrl.Remediation), path, line))
					}
				}

				// Check for S3 access logging
				if strings.Contains(content, "aws_s3_bucket") &&
					!strings.Contains(content, "aws_s3_bucket_logging") &&
					!strings.Contains(content, "logging") {
					line := findStringLine(content, "aws_s3_bucket")
					findings = append(findings, withSource(warn(ctrl, path,
						"S3 bucket has no access logging configured",
						"No aws_s3_bucket_logging or logging block"), path, line))
				}

				if len(findings) == 0 {
					if strings.Contains(content, "aws_cloudtrail") ||
						strings.Contains(content, "aws_s3_bucket") {
						return []types.Finding{pass(ctrl, path, "Logging properly configured")}
					}
					return []types.Finding{skipped(ctrl, path, "No CloudTrail or S3 resources in file")}
				}
				return findings
			},
		},
	}
}

// regexCache stores compiled regex patterns to avoid recompilation on every call.
var regexCache sync.Map // map[string]*regexp.Regexp

func hasPattern(content, pattern string) bool {
	if cached, ok := regexCache.Load(pattern); ok {
		return cached.(*regexp.Regexp).MatchString(content)
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return strings.Contains(content, pattern)
	}
	regexCache.Store(pattern, re)
	return re.MatchString(content)
}

// findPatternLine returns the 1-based line number of the first match of pattern in content.
// Returns 0 if no match is found.
func findPatternLine(content, pattern string) int {
	var re *regexp.Regexp
	if cached, ok := regexCache.Load(pattern); ok {
		re = cached.(*regexp.Regexp)
	} else {
		var err error
		re, err = regexp.Compile(pattern)
		if err != nil {
			return 0
		}
		regexCache.Store(pattern, re)
	}
	loc := re.FindStringIndex(content)
	if loc == nil {
		return 0
	}
	// Count newlines before the match to determine line number.
	return strings.Count(content[:loc[0]], "\n") + 1
}

// findStringLine returns the 1-based line number of the first occurrence of substr in content.
// Returns 0 if not found.
func findStringLine(content, substr string) int {
	idx := strings.Index(content, substr)
	if idx < 0 {
		return 0
	}
	return strings.Count(content[:idx], "\n") + 1
}

// withSource sets SourceFile and SourceLine on a finding.
func withSource(f types.Finding, file string, line int) types.Finding {
	f.SourceFile = file
	f.SourceLine = line
	return f
}
