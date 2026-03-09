# testdata/terraform/secure.tf
# All controls satisfied.

resource "aws_ecr_repository" "secure" {
  name                 = "secure-app"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
  }
}

resource "aws_eks_cluster" "with_audit" {
  name     = "prod-with-audit"
  role_arn = "arn:aws:iam::123456789:role/eks-role"

  vpc_config {
    subnet_ids              = ["subnet-12345"]
    endpoint_private_access = true
    endpoint_public_access  = false
  }

  enabled_cluster_log_types = [
    "api",
    "audit",
    "authenticator",
    "controllerManager",
    "scheduler"
  ]
}

resource "aws_launch_template" "imds_v2" {
  name_prefix = "secure-lt-"

  ami_type = "BOTTLEROCKET_x86_64"

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }
}

resource "google_container_cluster" "secure" {
  name     = "secure-gke"
  location = "us-central1"

  network_policy {
    enabled  = true
    provider = "CALICO"
  }

  database_encryption {
    state    = "ENCRYPTED"
    key_name = "projects/my-project/locations/global/keyRings/k8s/cryptoKeys/secrets"
  }

  addons_config {
    network_policy_config {
      disabled = false
    }
  }
}
