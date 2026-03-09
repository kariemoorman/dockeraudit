# INSECURE database Terraform configurations — for scanner FAIL case testing only
# DO NOT apply to any real environment.
# Expected scanner findings:
#   FAIL DB-TF-001: RDS not encrypted, publicly accessible, no deletion protection, short backup
#   FAIL DB-TF-002: ElastiCache no at-rest encryption, no transit encryption, no auth token
#   FAIL DB-TF-003: DocumentDB not encrypted, no backup; DynamoDB no SSE, no PITR

# --- RDS (INSECURE) ---
resource "aws_db_instance" "insecure_postgres" {
  identifier        = "insecure-postgres"
  engine            = "postgres"
  engine_version    = "16"
  instance_class    = "db.t3.micro"
  allocated_storage = 20

  db_name  = "appdb"
  username = "admin"
  password = "hardcoded_password_bad"  # Should use secrets manager

  # FAIL DB-TF-001: not encrypted
  storage_encrypted = false

  # FAIL DB-TF-001: publicly accessible
  publicly_accessible = true

  # FAIL DB-TF-001: no deletion protection
  deletion_protection = false

  # FAIL DB-TF-001: backup disabled
  backup_retention_period = 0

  # FAIL DB-TF-001: no final snapshot on delete
  skip_final_snapshot = true

  multi_az = false
}

# --- ElastiCache Redis (INSECURE) ---
resource "aws_elasticache_replication_group" "insecure_redis" {
  replication_group_id = "insecure-redis"
  description          = "Insecure Redis — test only"
  node_type            = "cache.t3.micro"
  num_cache_clusters   = 1
  engine_version       = "7.0"

  # FAIL DB-TF-002: no at-rest encryption
  at_rest_encryption_enabled = false

  # FAIL DB-TF-002: no transit encryption
  transit_encryption_enabled = false

  # FAIL DB-TF-002: no auth token (no transit encryption = auth_token not applicable,
  # but transit_encryption_enabled=false is itself a FAIL)
}

# --- DocumentDB (INSECURE) ---
resource "aws_docdb_cluster" "insecure_docdb" {
  cluster_identifier = "insecure-docdb"
  engine             = "docdb"
  master_username    = "docdbadmin"
  master_password    = "hardcoded_password_bad"

  # FAIL DB-TF-003: not encrypted
  storage_encrypted = false

  # FAIL DB-TF-003: no backup retention
  backup_retention_period = 1
}

# --- DynamoDB (INSECURE) ---
resource "aws_dynamodb_table" "insecure_table" {
  name         = "insecure-table"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }

  # FAIL DB-TF-003: no server-side encryption configuration
  # (absence of server_side_encryption block = FAIL)

  # FAIL DB-TF-003: no point-in-time recovery
  # (absence of point_in_time_recovery block = FAIL)
}
