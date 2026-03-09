# testdata/terraform/insecure.tf
# Intentionally misconfigured for testing.

# VIOLATION: SUPPLY-003 — no IMMUTABLE tag
resource "aws_ecr_repository" "insecure" {
  name = "insecure-app"
  # image_tag_mutability not set (defaults to MUTABLE)
  # scan_on_push not enabled
}

# VIOLATION: MONITOR-002 — no audit logging
resource "aws_eks_cluster" "no_audit" {
  name     = "prod-no-audit"
  role_arn = "arn:aws:iam::123456789:role/eks-role"

  vpc_config {
    subnet_ids = ["subnet-12345"]
  }
  # enabled_cluster_log_types not set
}

# VIOLATION: NETWORK-002 — IMDSv1 accessible
resource "aws_launch_template" "imds_v1" {
  name_prefix = "insecure-lt-"

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"  # IMDSv1 allowed — VIOLATION
    # hop limit not set — containers can reach IMDS
  }
}

# VIOLATION: IMAGE-002 — hardcoded password
resource "aws_db_instance" "app" {
  identifier = "app-db"
  password   = "SuperSecret123!"  # VIOLATION: hardcoded
}
