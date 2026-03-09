# Extended insecure Terraform — covers TF-001 through TF-008, DAEMON-002, HOST-001/003
# Controls tested (all FAIL or WARN):
#   TF-001: S3 public access
#   TF-002: S3 versioning disabled
#   TF-003: ECS privileged mode
#   TF-004: ECS non-root user missing
#   TF-005: ECS read-only rootfs missing
#   TF-006: Security group unrestricted ingress
#   TF-007: EBS/S3 encryption missing
#   TF-008: CloudTrail logging disabled
#   DAEMON-002: Security group port 2375 open
#   HOST-001: EKS node group not using Bottlerocket

# --- TF-001: S3 bucket with public ACL ---
resource "aws_s3_bucket" "public_bucket" {
  bucket = "insecure-public-bucket"
  acl    = "public-read"
}

resource "aws_s3_bucket_public_access_block" "disabled" {
  bucket = aws_s3_bucket.public_bucket.id

  block_public_acls       = false
  block_public_policy     = false
  restrict_public_buckets = false
}

# --- TF-002: S3 bucket with versioning disabled ---
resource "aws_s3_bucket" "unversioned" {
  bucket = "insecure-unversioned"

  versioning {
    enabled = false
  }
}

# --- TF-003: ECS task definition with privileged container ---
# Uses heredoc JSON so scanner regex can match "privileged": true
resource "aws_ecs_task_definition" "privileged_task" {
  family                = "insecure-task"
  container_definitions = <<EOF
[
  {
    "name": "app",
    "image": "nginx:latest",
    "essential": true,
    "privileged": true,
    "portMappings": [{"containerPort": 80, "hostPort": 80}]
  }
]
EOF
}

# --- TF-004: ECS task definition without user ---
resource "aws_ecs_task_definition" "no_user_task" {
  family                = "no-user-task"
  container_definitions = <<EOF
[
  {
    "name": "app",
    "image": "myapp:latest",
    "essential": true,
    "portMappings": [{"containerPort": 8080}]
  }
]
EOF
}

# --- TF-005: ECS task definition without readonlyRootFilesystem ---
resource "aws_ecs_task_definition" "writable_root" {
  family                = "writable-root-task"
  container_definitions = <<EOF
[
  {
    "name": "app",
    "image": "myapp:latest",
    "essential": true,
    "readonlyRootFilesystem": false
  }
]
EOF
}

# --- TF-006: Security group with unrestricted ingress ---
resource "aws_security_group" "wide_open" {
  name        = "wide-open-sg"
  description = "Insecure SG for testing"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port        = 6379
    to_port          = 6379
    protocol         = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }
}

# --- DAEMON-002: Security group exposing Docker API port ---
resource "aws_security_group" "docker_exposed" {
  name        = "docker-api-exposed"
  description = "Insecure: Docker API port open"

  ingress {
    from_port   = 2375
    to_port     = 2375
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# --- TF-007: EBS volume without encryption ---
resource "aws_ebs_volume" "unencrypted" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = false
}

# --- TF-008: CloudTrail logging disabled, S3 bucket without access logging ---
resource "aws_cloudtrail" "disabled" {
  name           = "disabled-trail"
  s3_bucket_name = aws_s3_bucket.public_bucket.id

  is_multi_region_trail = false
  enable_logging        = false
}

# --- HOST-001: EKS node group not using Bottlerocket ---
resource "aws_eks_node_group" "default_ami" {
  cluster_name    = "test-cluster"
  node_group_name = "default-nodes"
  node_role_arn   = "arn:aws:iam::123456789:role/node-role"
  subnet_ids      = ["subnet-12345"]

  scaling_config {
    desired_size = 2
    max_size     = 4
    min_size     = 1
  }

  # No ami_type specified — HOST-001 WARN
}

# --- HOST-003: EKS public endpoint without CIDR restriction ---
resource "aws_eks_cluster" "public_endpoint" {
  name     = "public-endpoint-cluster"
  role_arn = "arn:aws:iam::123456789:role/eks-role"

  vpc_config {
    subnet_ids             = ["subnet-12345"]
    endpoint_public_access = true
    # No public_access_cidrs — HOST-003 WARN
  }

  enabled_cluster_log_types = ["api", "audit"]
}
