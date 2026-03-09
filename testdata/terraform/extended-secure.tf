# Extended secure Terraform — all TF-001 through TF-008, DAEMON-002, HOST-001/003 PASS
# Controls tested (all PASS):
#   TF-001: S3 bucket with Block Public Access
#   TF-002: S3 versioning enabled
#   TF-003: ECS non-privileged
#   TF-004: ECS with user set
#   TF-005: ECS with readonlyRootFilesystem
#   TF-006: Security group with restricted ingress
#   TF-007: EBS with encryption
#   TF-008: CloudTrail properly configured
#   DAEMON-002: No port 2375 in security group
#   HOST-001: EKS node group using Bottlerocket

# --- TF-001/TF-002: S3 bucket properly configured ---
resource "aws_s3_bucket" "secure_bucket" {
  bucket = "secure-bucket"
}

resource "aws_s3_bucket_versioning" "enabled" {
  bucket = aws_s3_bucket.secure_bucket.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "secure" {
  bucket = aws_s3_bucket.secure_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  restrict_public_buckets = true
  ignore_public_acls      = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "secure" {
  bucket = aws_s3_bucket.secure_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3.arn
    }
  }
}

resource "aws_s3_bucket_logging" "secure" {
  bucket = aws_s3_bucket.secure_bucket.id

  target_bucket = aws_s3_bucket.log_bucket.id
  target_prefix = "logs/"
}

resource "aws_s3_bucket" "log_bucket" {
  bucket = "secure-access-logs"
}

resource "aws_kms_key" "s3" {
  description         = "KMS key for S3 encryption"
  enable_key_rotation = true
}

# --- TF-003/TF-004/TF-005: ECS task definition properly configured ---
resource "aws_ecs_task_definition" "hardened_task" {
  family                = "hardened-task"
  container_definitions = <<EOF
[
  {
    "name": "app",
    "image": "myapp:1.0.0",
    "essential": true,
    "user": "1001:1001",
    "readonlyRootFilesystem": true,
    "portMappings": [{"containerPort": 8080}]
  }
]
EOF
}

# --- TF-006: Security group with restricted ingress ---
resource "aws_security_group" "restricted" {
  name        = "restricted-sg"
  description = "Properly restricted SG"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

# --- TF-007: EBS volume with encryption ---
resource "aws_ebs_volume" "encrypted" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = true
  kms_key_id        = aws_kms_key.s3.arn
}

# --- TF-008: CloudTrail properly configured ---
resource "aws_cloudtrail" "enabled" {
  name                  = "enabled-trail"
  s3_bucket_name        = aws_s3_bucket.log_bucket.id
  is_multi_region_trail = true
  enable_logging        = true
}

# --- HOST-001: EKS node group using Bottlerocket ---
resource "aws_eks_node_group" "bottlerocket" {
  cluster_name    = "secure-cluster"
  node_group_name = "bottlerocket-nodes"
  node_role_arn   = "arn:aws:iam::123456789:role/node-role"
  subnet_ids      = ["subnet-12345"]
  ami_type        = "BOTTLEROCKET_x86_64"

  scaling_config {
    desired_size = 3
    max_size     = 6
    min_size     = 2
  }
}
