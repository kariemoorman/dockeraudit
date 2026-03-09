# Hardened database Terraform configurations — all DB-TF-001/002/003 controls satisfied
# All scanner checks should PASS against this file.

# --- KMS Keys ---
resource "aws_kms_key" "rds" {
  description             = "KMS key for RDS encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_kms_key" "elasticache" {
  description             = "KMS key for ElastiCache encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_kms_key" "docdb" {
  description             = "KMS key for DocumentDB encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

# --- RDS PostgreSQL (HARDENED — DB-TF-001) ---
resource "aws_db_instance" "hardened_postgres" {
  identifier        = "hardened-postgres"
  engine            = "postgres"
  engine_version    = "16"
  instance_class    = "db.t3.medium"
  allocated_storage = 100

  db_name  = "appdb"
  username = "appuser"

  # Password from Secrets Manager — never inline
  manage_master_user_password = true

  # PASS DB-TF-001: encrypted at rest with KMS
  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds.arn

  # PASS DB-TF-001: not publicly accessible
  publicly_accessible = false

  # PASS DB-TF-001: deletion protection enabled
  deletion_protection = true

  # PASS DB-TF-001: backup retention >= 7 days
  backup_retention_period = 14
  backup_window           = "03:00-04:00"
  maintenance_window      = "Mon:04:00-Mon:05:00"

  # PASS DB-TF-001: final snapshot on delete
  skip_final_snapshot       = false
  final_snapshot_identifier = "hardened-postgres-final-snapshot"

  # Additional hardening
  multi_az               = true
  storage_type           = "gp3"
  copy_tags_to_snapshot  = true
  auto_minor_version_upgrade = true

  # Parameter group enforcing SSL
  parameter_group_name = aws_db_parameter_group.postgres_ssl.name

  tags = {
    Environment = "production"
    Compliance  = "CIS-DB-TF-001"
  }
}

resource "aws_db_parameter_group" "postgres_ssl" {
  name   = "hardened-postgres16"
  family = "postgres16"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
}

# --- ElastiCache Redis (HARDENED — DB-TF-002) ---
resource "aws_elasticache_replication_group" "hardened_redis" {
  replication_group_id = "hardened-redis"
  description          = "Hardened Redis with encryption and auth"
  node_type            = "cache.t3.medium"
  num_cache_clusters   = 2
  engine_version       = "7.0"
  port                 = 6379

  # PASS DB-TF-002: at-rest encryption
  at_rest_encryption_enabled = true
  kms_key_id                 = aws_kms_key.elasticache.arn

  # PASS DB-TF-002: transit encryption (TLS)
  transit_encryption_enabled = true

  # PASS DB-TF-002: auth token required
  auth_token                 = data.aws_secretsmanager_secret_version.redis_auth.secret_string
  auth_token_update_strategy = "ROTATE"

  # Additional hardening
  automatic_failover_enabled = true
  multi_az_enabled           = true
  snapshot_retention_limit   = 7
  snapshot_window            = "03:00-04:00"

  tags = {
    Environment = "production"
    Compliance  = "CIS-DB-TF-002"
  }
}

data "aws_secretsmanager_secret_version" "redis_auth" {
  secret_id = "prod/redis/auth-token"
}

# --- DocumentDB (HARDENED — DB-TF-003) ---
resource "aws_docdb_cluster" "hardened_docdb" {
  cluster_identifier = "hardened-docdb"
  engine             = "docdb"
  master_username    = "docdbadmin"

  # Password from Secrets Manager
  master_password = data.aws_secretsmanager_secret_version.docdb_password.secret_string

  # PASS DB-TF-003: encrypted at rest
  storage_encrypted = true
  kms_key_id        = aws_kms_key.docdb.arn

  # PASS DB-TF-003: backup retention >= 7 days
  backup_retention_period = 14
  preferred_backup_window = "03:00-05:00"

  # Additional hardening
  deletion_protection             = true
  skip_final_snapshot             = false
  final_snapshot_identifier       = "hardened-docdb-final"
  enabled_cloudwatch_logs_exports = ["audit", "profiler"]

  tags = {
    Environment = "production"
    Compliance  = "CIS-DB-TF-003"
  }
}

data "aws_secretsmanager_secret_version" "docdb_password" {
  secret_id = "prod/docdb/master-password"
}

# --- DynamoDB (HARDENED — DB-TF-003) ---
resource "aws_dynamodb_table" "hardened_table" {
  name         = "hardened-table"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }

  # PASS DB-TF-003: server-side encryption with KMS
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.rds.arn
  }

  # PASS DB-TF-003: point-in-time recovery
  point_in_time_recovery {
    enabled = true
  }

  # Additional hardening
  deletion_protection_enabled = true

  tags = {
    Environment = "production"
    Compliance  = "CIS-DB-TF-003"
  }
}
