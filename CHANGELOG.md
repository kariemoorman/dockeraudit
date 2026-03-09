# Changelog

## [Unreleased]


## [0.0.1] - 2025-03-08

### Added

#### CLI & Core
- Six scan commands: `scan`, `image`, `docker`, `k8s`, `terraform`, `report controls`
- Five output formats: table (colored terminal), JSON, Markdown, SARIF 2.1.0, JUnit XML
- `--fail-on` threshold (critical/high/medium/low/any) for CI/CD exit code control
- `--exclude-check` and `--include-check` filters for selective scanning
- `--timeout` per-command scan timeout with context cancellation
- `.dockeraudit.yaml` configuration file support
- Auto-save reports to `scans/` directory with timestamped filenames
- Shell completion generation (bash, zsh, fish, powershell)
- GoReleaser cross-platform builds (linux/macOS/windows, amd64/arm64)

#### Image Scanner (16 controls)
- IMAGE-001: Digest pinning validation
- IMAGE-002: Secrets in image history layers
- IMAGE-003: CVE vulnerability scanning via Trivy and Snyk integration
- IMAGE-004: SUID/SGID/world-writable file detection (ephemeral container)
- IMAGE-005: Non-root USER directive enforcement
- IMAGE-006: ADD with remote URLs or piped installs
- IMAGE-007: Secret files in image filesystem (50+ known filenames)
- IMAGE-008: End-of-life base image detection with custom EOL list support
- IMAGE-009: Crypto miner artifact detection
- IMAGE-010: XZ-Utils backdoor (CVE-2024-3094) detection
- IMAGE-011: Debug/dev tool detection (vim, gdb, strace, tcpdump, nmap)
- IMAGE-012: Package manager GPG verification enforcement
- IMAGE-013: VOLUME directive on sensitive paths (/etc, /root, /var/run)
- IMAGE-014: COPY instead of ADD for local files
- IMAGE-015: Minimal base image / multi-stage build detection
- IMAGE-016: Recursive COPY . . warning
- Parallel multi-image scanning
- Docker daemon availability preflight check

#### Docker Scanner
- Auto-detection of Dockerfiles (Dockerfile, Dockerfile.*, *.dockerfile, Containerfile)
- Auto-detection of Compose files (docker-compose*.yml/yaml, compose.yml/yaml)
- Directory recursion and mixed file scanning
- Trivy config integration for Dockerfile misconfiguration scanning
- Snyk container test with `--file=<Dockerfile>` for Dockerfile vulnerability scanning

#### Kubernetes Scanner (3 controls + shared runtime controls)
- K8S-001: Namespace isolation (non-default namespace)
- K8S-002: Pod anti-affinity / topology spread constraints
- K8S-003: IaC vulnerability scan via Trivy config
- Pod spec extraction from all controller types (Pod, Deployment, DaemonSet, StatefulSet, Job, CronJob, ReplicaSet)
- Container security context validation (privileged, capabilities, seccomp, AppArmor/SELinux)
- Host namespace sharing detection (hostPID, hostIPC, hostNetwork)
- Resource limits, read-only filesystem, non-root enforcement
- Service account token automount verification
- Plaintext secrets in environment variable detection
- Image digest pinning validation

#### Terraform Scanner (9 controls)
- TF-001: S3 bucket public access block
- TF-002: S3 bucket versioning
- TF-003: ECS task definition privileged mode
- TF-004: ECS task non-root user
- TF-005: ECS task read-only root filesystem
- TF-006: Security group unrestricted ingress on sensitive ports
- TF-007: KMS encryption on EBS/RDS/S3
- TF-008: CloudTrail / logging enabled
- TF-009: IaC vulnerability scan via Trivy config
- ECR immutable tags and scan-on-push validation
- EKS audit logging and Bottlerocket AMI detection
- IMDSv2 enforcement (hop limit=1)
- GKE network policy validation
- Hardcoded secrets detection in HCL

#### Runtime Scanner (16 controls)
- RUNTIME-001 through RUNTIME-012: Container runtime security validation
- RUNTIME-013: AppArmor / SELinux profile configuration
- RUNTIME-014: Default service account token automount disabled
- RUNTIME-015: Container ulimits explicitly set
- RUNTIME-016: Restart policy capped (on-failure with max retries)
- Live container inspection via Docker API

#### Host Scanner (6 controls)
- HOST-001 through HOST-005: Host OS hardening validation
- HOST-006: Auditd rules for Docker paths

#### Daemon Scanner (8 controls)
- DAEMON-001 through DAEMON-005: Docker daemon configuration
- DAEMON-006: Inter-container communication disabled (icc=false)
- DAEMON-007: Userland proxy disabled
- DAEMON-008: Live restore enabled

#### Network, Secrets, Supply Chain, Monitoring
- NETWORK-001: Network policies defined
- NETWORK-002: IMDSv2 enforced
- SECRETS-001: External secrets management
- SECRETS-002: No plaintext secrets in ENV
- SECRETS-003: AI/vectorizer API key detection
- SUPPLY-001 through SUPPLY-003: Image signing, CI/CD scanning, immutable tags
- MONITOR-001, MONITOR-002: Centralized and audit logging

#### Database Scanner (12 controls)
- DB-IMAGE-001, DB-IMAGE-002: Database image hardening
- DB-K8S-001 through DB-K8S-007: Database Kubernetes deployment security
- DB-TF-001 through DB-TF-003: RDS, ElastiCache, NoSQL encryption and backup

#### Secrets Engine
- 76+ regex patterns for AWS, Azure, GCP, GitHub, private keys, and more
- Prefix-based keyword matching (password, secret, token, api_key)
- Shannon entropy-based detection for random strings
- Confidence scoring (regex: 1.0, prefix: 0.8, entropy: 0.5)
- False positive suppression (UUIDs, hash patterns, common test values)

#### Vulnerability Scanning Integration
- Trivy config for IaC scanning (Dockerfiles, Terraform, Kubernetes manifests)
- Trivy image for container image CVE scanning
- Snyk container test for image vulnerability scanning
- Snyk container test with `--file=<Dockerfile>` for Dockerfile scanning
- Automatic tool detection via PATH
- Graceful SKIP when neither tool is installed
- JSON output parsing with severity mapping

#### Compliance Mappings
- CIS Docker Benchmark v1.8
- NIST SP 800-53 Rev 5
- NIST SP 800-190
- ISO 27001:2022 Annex A
- SOC 2 Trust Services Criteria
- DISA CCI
