
<h1 align=center><b>dockeraudit</b></h1><p align=center>A CONTAINER SECURITY AUDITING TOOLKIT</p>

<p align=center>Aligned to CIS Docker Benchmark v1.8+, NIST SP 800-190, and DoDI 8510.01 RMF controls.</p>

## Badges

<p align="center">
  <a href="https://github.com/kariemoorman/dockeraudit/LICENSE">
    <img src="https://img.shields.io/badge/License-BSL-blue.svg" alt="License">
  </a>
  <a href="https://github.com/kariemoorman/dockeraudit/releases">
    <img src="https://img.shields.io/github/v/release/kariemoorman/dockeraudit?cacheSeconds=300" alt="Release">
  </a>
  <a href="https://github.com/kariemoorman/dockeraudit/actions/workflows/ci.yml/badge.svg">
    <img src="https://github.com/kariemoorman/dockeraudit/actions/workflows/ci.yml/badge.svg" alt="Tests">
  </a>
</p>


## Features

- **80 Security Controls**: 
  - Includes security controls across 11 domains with compliance mappings to CIS, NIST 800-53, NIST 800-190, ISO 27001, SOC 2, and DISA CCI.
- **Docker Scanning**: 
  - Audits Images, Dockerfiles, & Docker Compose configurations for misconfigurations, secrets, and other security vulnerabilities.
- **Kubernetes Manifest Scanning**:
  - Audits k8s manifests for misconfigurations, secrets, and other security vulnerabilities.
- **Terraform Configuration Scanning**:
  - Audits terraform files for misconfigurations, secrets, and other security vulnerabilities, including cloud resources (e.g., AWS: ECR, EKS, S3, ECS, RDS, ElastiCache, DynamoDB).
- **Secrets Detection**: 
  - 76+ regex patterns with confidence scoring and false-positive suppression.
- **Vulnerability Detection**:
  - Uses Trivy and Snyk for CVE scanning via `--scanner` flag.
- **Auto-Saved Reports**: 
  - Each scan writes a timestamped copy to `scans/` for audit trails.
  - 5 output formats - table (TXT), JSON, Markdown, SARIF (GitHub Security), JUnit (CI/CD).
- **CI/CD Ready**: 
  - Configurable exit codes with `--fail-on` threshold, SARIF upload to GitHub Security tab.

## Quick Start

```bash
# Scan a Docker image
dockeraudit image nginx:latest

# Scan Dockerfiles and Compose files in a directory
dockeraudit docker Dockerfile docker-compose.yml --scanner trivy

# Scan Kubernetes manifests
dockeraudit k8s ./manifests/

# Scan Terraform files
dockeraudit terraform ./infrastructure/

# Scan everything in one pass
dockeraudit scan \
  --images nginx:latest \
  --docker ./ \
  --k8s ./k8s/ \
  --tf ./terraform/ \
  --format markdown
```

## Installation

### From Source

Requires **Go 1.25+**.

```bash
git clone https://github.com/kariemoorman/dockeraudit.git
cd dockeraudit
make build
```

### Go Install

```bash
go install github.com/kariemoorman/dockeraudit/cmd/dockeraudit@latest
```

### From GitHub Releases

Download pre-built binaries for Linux, macOS, and Windows from the [RELEASES](https://github.com/kariemoorman/dockeraudit/releases) page:

```bash
# Linux (amd64)
curl -sSfL \
  https://github.com/kariemoorman/dockeraudit/releases/latest/download/dockeraudit_linux_amd64.tar.gz \
  | tar -xz -C /usr/local/bin dockeraudit

# macOS (Apple Silicon)
curl -sSfL \
  https://github.com/kariemoorman/dockeraudit/releases/latest/download/dockeraudit_darwin_arm64.tar.gz \
  | tar -xz -C /usr/local/bin dockeraudit

# Verify
dockeraudit --version
```


## Usage

### Commands

| Command | Description |
|---------|-------------|
| `scan` | Run all applicable scanners in a single pass |
| `image` | Scan Docker images for hardening issues |
| `docker` | Scan Dockerfiles and Docker Compose files |
| `k8s` | Scan Kubernetes manifests for security misconfigurations |
| `terraform` | Scan Terraform files for container security issues |
| `report controls` | List all hardening controls with compliance mappings |
| `completion` | Generate shell completion scripts (bash/zsh/fish/powershell) |

### Global Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--verbose` | `false` | Print scan progress to stderr |
| `--config` | `.dockeraudit.yaml` | Path to config file |
| `--version` | | Print version |

### Common Flags (all scan commands)

| Flag | Default | Description |
|------|---------|-------------|
| `-f, --format` | `table` | Output format: `table`, `json`, `markdown`, `sarif`, `junit` |
| `-o, --output` | `scans/` | Write results to filepath |
| `--fail-on` | `high` | Exit non-zero at severity threshold: `critical`, `high`, `medium`, `low`, `any` |
| `--exclude-check` | | Exclude specific control IDs (e.g., `IMAGE-001,RUNTIME-010`) |
| `--include-check` | | Include only specific control IDs |
| `-s --scanner` | `[trivy,snyk]` | Vulnerability scanners to use (trivy, snyk, none)|

### `scan` Command Flags

| Flag | Description |
|------|-------------|
| `-i, --images` | Docker image(s) to scan |
| `-d, --docker` | Dockerfile/Compose file(s) or directories |
| `-k, --k8s` | Kubernetes manifest file(s) or directories |
| `-t, --tf` | Terraform file(s) or directories |
| `--daemon` | Scan local Docker daemon configuration |
| `--runtime` | Scan all running containers |
| `--timeout` | Scan timeout in seconds (default: 300) |

### `image` Command Flags

| Flag | Description |
|------|-------------|
| `--eol-file` | Path to custom end-of-life image definitions JSON |
| `--timeout` | Timeout per image in seconds (default: 180) |

### Examples

```bash
# Scan with JSON output to file
dockeraudit image nginx:latest --format json -o results.json

# Scan multiple images in parallel
dockeraudit image nginx:latest postgres:16 redis:7

# Only fail on critical findings in CI
dockeraudit scan --k8s ./manifests/ --fail-on critical

# Exclude specific checks
dockeraudit image myapp:latest --exclude-check IMAGE-001,IMAGE-008

# Generate SARIF for GitHub Security tab
dockeraudit scan --images myapp:latest --format sarif -o results.sarif

# List all available controls
dockeraudit report controls

# List controls filtered by domain
dockeraudit report controls --domain Database
```

## Security Controls

dockeraudit evaluates **80 controls** across **11 security domains**:

| Domain | Controls | What It Covers |
|--------|----------|----------------|
| **Host** | 6 | Minimal OS, patching, firewall, SELinux/AppArmor, auditd, Bottlerocket |
| **Daemon** | 8 | Docker socket, TCP/port 2375 exposure, userns-remap, content trust, log rotation |
| **Image** | 16 | Digest pinning, secrets in layers, SUID files, non-root USER, EOL images, debug tools, package verification bypass, recursive COPY, multi-stage builds |
| **Runtime** | 16 | Privileged mode, capabilities, read-only rootfs, host namespaces, resource limits, health probes, seccomp, AppArmor/SELinux, automountSA, ulimits, restart policies |
| **Network** | 2 | Network policies, IMDSv2 enforcement |
| **Secrets** | 3 | External secrets manager, no plaintext in env, AI/API key detection |
| **Supply Chain** | 3 | Image signing, vulnerability scanning, immutable tags |
| **Monitoring** | 2 | Centralized logging, audit log forwarding |
| **Database** | 12 | Admin tools, startup flags, auth config, service types, encryption, backups, annotations |
| **Kubernetes** | 3 | Namespace isolation, pod anti-affinity/topology spread, IaC vulnerability scanning (trivy/snyk) |
| **Terraform** | 9 | S3 public access/versioning, ECS privileged/non-root/read-only rootfs, security group ingress, KMS encryption, CloudTrail logging, IaC vulnerability scanning (trivy/snyk) |

Each control maps to compliance frameworks:

- **CIS Docker Benchmark** sections
- **NIST SP 800-53** control families
- **NIST SP 800-190** sections
- **ISO 27001** Annex A controls
- **SOC 2** trust criteria
- **DISA CCI** identifiers

Run `dockeraudit report controls` for the full list.


## Configuration File

dockeraudit supports a YAML configuration file for setting default options. CLI flags always override config file values.

**Config file discovery order:**

1. Path specified by `--config` flag
2. `.dockeraudit.yaml` in the current working directory
3. `.dockeraudit.yml` in the current working directory

```yaml
# .dockeraudit.yaml
format: table
fail-on: high
verbose: false
exclude-check:
  - IMAGE-001
  - RUNTIME-010
include-check:        # when set, only these controls run
  - RUNTIME-001
  - RUNTIME-002
eol-file: custom-eol.json
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `format` | string | `table` | Output format: `table`, `json`, `markdown`, `sarif`, `junit` |
| `fail-on` | string | `high` | Exit non-zero threshold: `critical`, `high`, `medium`, `low`, `any` |
| `verbose` | bool | `false` | Print scan progress to stderr |
| `exclude-check` | list | (empty) | Control IDs to exclude from results |
| `include-check` | list | (empty) | Only include these control IDs (applied before `exclude-check`) |
| `eol-file` | string | (empty) | Path to custom end-of-life image definitions JSON |

**Example configurations:**

```yaml
# CI/CD (strict)            # Development (relaxed)       # Compliance audit
format: sarif                format: table                  format: json
fail-on: critical            fail-on: any                   fail-on: low
verbose: true                exclude-check:                 verbose: true
                               - IMAGE-001
                               - IMAGE-008
```

See [.dockeraudit.example.yaml](.dockeraudit.example.yaml) for the full reference.

## CI/CD Integration

### GitHub Actions

```yaml
- name: Install dockeraudit
  run: |
    curl -sSfL \
      https://github.com/kariemoorman/dockeraudit/releases/latest/download/dockeraudit_linux_amd64.tar.gz \
      | tar -xz -C /usr/local/bin dockeraudit

- name: Scan
  run: |
    dockeraudit scan \
      --images myapp:${{ github.sha }} \
      --k8s ./k8s/ \
      --format sarif \
      --output results.sarif \
      --fail-on critical

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: results.sarif
```


### GitLab CI

```yaml
dockeraudit:
  stage: security
  image: alpine:3.22
  before_script:
    - |
      curl -sSfL \
        https://github.com/kariemoorman/dockeraudit/releases/latest/download/dockeraudit_linux_amd64.tar.gz \
        | tar -xz -C /usr/local/bin dockeraudit
  script:
    - dockeraudit k8s ./k8s/ --format json -o report.json --fail-on high
  artifacts:
    paths: [report.json]
    when: always
  allow_failure: true
```


## Shell Completion

Generate shell completion scripts:

```bash
# Bash
dockeraudit completion bash > /etc/bash_completion.d/dockeraudit

# Zsh
dockeraudit completion zsh > "${fpath[1]}/_dockeraudit"

# Fish
dockeraudit completion fish > ~/.config/fish/completions/dockeraudit.fish

# PowerShell
dockeraudit completion powershell > dockeraudit.ps1
```


## License

This project is licensed under the BSD License. See [LICENSE](LICENSE) for details.
