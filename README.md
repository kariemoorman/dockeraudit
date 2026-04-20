
<p align='center'><img src='assets/dockeraudit.png' width='20%'></p>

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
  <a href="https://github.com/kariemoorman/dockeraudit/actions/workflows/security.yml/badge.svg">
    <img src="https://github.com/kariemoorman/dockeraudit/actions/workflows/security.yml/badge.svg" alt="Security">
  </a>
</p>

## Table of Contents 
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Examples](#examples)
- [Usage](#usage)
- [Configuration File](#configuration-file)
- [CI/CD Integration](#cicd-integration)
- [Shell Completion](#shell-completion)
- [Security Controls](#security-controls)
- [License](#license)


## Features

**80+ Security Controls**: 
  - Includes security controls across 12 domains with compliance mappings to CIS, NIST 800-53, NIST 800-190, ISO 27001, SOC 2, and DISA CCI.

**Docker Scanning**: 
  - Audits Images, Dockerfiles, & Docker Compose configurations for misconfigurations, secrets, and other security vulnerabilities.

**Kubernetes Manifest Scanning**:
  - Audits k8s manifests and helm charts for misconfigurations, secrets, and other security vulnerabilities.

**Terraform Configuration Scanning**:
  - Audits terraform files for misconfigurations, secrets, and other security vulnerabilities, including cloud resources (e.g., AWS: ECR, EKS, S3, ECS, RDS, ElastiCache, DynamoDB).

**Secrets Detection**: 
  - 76+ regex patterns with confidence scoring and false-positive suppression.

**Vulnerability Detection**:
  - Uses Trivy and Snyk for CVE scanning via `--scanner` flag.

**Auto-Saved Reports**: 
  - Each scan writes a timestamped copy to `scans/` for audit trails.
  - 5 output formats - table (TXT), JSON, Markdown, SARIF (GitHub Security), JUnit (CI/CD).

**CI/CD Ready**: 
  - Configurable exit codes with `--fail-on` threshold, SARIF upload to GitHub Security tab.


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

*Note: ensure Go binary directory is on your PATH, then reload your shell config file:*
```bash
export PATH=$PATH:$HOME/go/bin
or 
export PATH=$PATH:$(go env GOPATH)/bin

source ~/.bashrc
or 
source ~/.zshrc
```


### Verify Installation
```bash
dockeraudit --version
```

## Quick Start

```bash
# Create configuration file ($HOME/.config/dockeraudit/dockeraudit.yaml)
dockeraudit init 

# Scan a Docker image
dockeraudit image nginx:latest

# Scan Dockerfiles and Compose files
dockeraudit docker Dockerfile docker-compose.yml --scanner trivy

# Scan Kubernetes manifests
dockeraudit k8s ./manifests/

# Scan a Helm chart (rendered via `helm template` before scanning)
dockeraudit k8s ./helm_chart/

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

## Examples 

### Docker 

<p align='center'><img src='https://github.com/kariemoorman/kariemoorman.github.io/blob/master/media/images/dockeraudit/dockerfile.png' alt='dockerfile' width='80%'></p>

### Image 

<p align='center'><img src='https://github.com/kariemoorman/kariemoorman.github.io/blob/master/media/images/dockeraudit/dockerimage.png' alt='dockerfile' width='80%'></p>

### k8s 

<p align='center'>
<img src='https://github.com/kariemoorman/kariemoorman.github.io/blob/master/media/images/dockeraudit/k8s_1.png' alt='dockerfile' width='80%'>
<img src='https://github.com/kariemoorman/kariemoorman.github.io/blob/master/media/images/dockeraudit/k8s_2.png' alt='dockerfile' width='80%'>
<img src='https://github.com/kariemoorman/kariemoorman.github.io/blob/master/media/images/dockeraudit/k8s_3.png' alt='dockerfile' width='80%'>
<img src='https://github.com/kariemoorman/kariemoorman.github.io/blob/master/media/images/dockeraudit/k8s_4.png' alt='dockerfile' width='80%'></p>

### Terraform

<p align='center'><img src='https://github.com/kariemoorman/kariemoorman.github.io/blob/master/media/images/dockeraudit/terraform_1.png' alt='dockerfile' width='80%'>
<img src='https://github.com/kariemoorman/kariemoorman.github.io/blob/master/media/images/dockeraudit/terraform_2.png' alt='dockerfile' width='80%'></p>

## Usage

### Scan Modes

| Mode | Description |
|---------|-------------|
| `scan` | Run all applicable scanners in a single pass |
| `image` | Scan Docker images for hardening issues |
| `docker` | Scan Dockerfiles and Docker Compose files |
| `k8s` | Scan Kubernetes manifests for security misconfigurations |
| `terraform` | Scan Terraform files for container security issues |
| `report controls` | List all hardening controls with compliance mappings |
| `completion` | Generate shell completion scripts (bash/zsh/fish/powershell) |


### Command Flags 

<details><summary><b><code>scan</code> Mode</b></summary>

<br>

```bash
dockeraudit scan [flags]
```

<b>Examples</b>

```bash
# Only fail on critical findings in CI
dockeraudit scan --k8s ./manifests/ --fail-on critical

# Generate SARIF for GitHub Security tab
dockeraudit scan --images myapp:latest --format sarif -o results.sarif

```

<table>
  <thead>
    <tr>
      <th>Flag</th>
      <th>Type</th>
      <th>Description</th>
      <th>Default</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><code>--daemon</code></td>
      <td>bool</td>
      <td>Scan local Docker daemon configuration</td>
      <td>—</td>
    </tr>
    <tr>
      <td><code>-d</code>, <code>--docker</code></td>
      <td>strings</td>
      <td>Dockerfile(s), docker-compose file(s), or directories to scan</td>
      <td>—</td>
    </tr>
    <tr>
      <td><code>--exclude-check</code></td>
      <td>strings</td>
      <td>Exclude specific control IDs from results (e.g. <code>--exclude-check IMAGE-001,RUNTIME-010</code>)</td>
      <td>—</td>
    </tr>
    <tr>
      <td><code>--fail-on</code></td>
      <td>string</td>
      <td>Exit non-zero if failures at this severity or above: <code>critical</code>, <code>high</code>, <code>medium</code>, <code>low</code>, <code>any</code></td>
      <td><code>high</code></td>
    </tr>
    <tr>
      <td><code>-f</code>, <code>--format</code></td>
      <td>string</td>
      <td>Output format: <code>table</code>, <code>json</code>, <code>markdown</code>, <code>sarif</code>, <code>junit</code></td>
      <td><code>table</code></td>
    </tr>
    <tr>
      <td><code>-h</code>, <code>--help</code></td>
      <td>—</td>
      <td>Show help for the command</td>
      <td>—</td>
    </tr>
    <tr>
      <td><code>-i</code>, <code>--images</code></td>
      <td>strings</td>
      <td>Docker image(s) to scan (e.g. <code>--images nginx:latest,myapp:v1.0</code>)</td>
      <td>—</td>
    </tr>
    <tr>
      <td><code>--include-check</code></td>
      <td>strings</td>
      <td>Include only specific control IDs in results (e.g. <code>--include-check IMAGE-001,IMAGE-005</code>)</td>
      <td>—</td>
    </tr>
    <tr>
      <td><code>-k</code>, <code>--k8s</code></td>
      <td>strings</td>
      <td>Kubernetes manifest file(s) or directories to scan</td>
      <td>—</td>
    </tr>
    <tr>
      <td><code>-o</code>, <code>--output</code></td>
      <td>string</td>
      <td>Write results to file</td>
      <td>stdout</td>
    </tr>
    <tr>
      <td><code>--runtime</code></td>
      <td>bool</td>
      <td>Scan all running containers for runtime misconfigurations</td>
      <td>—</td>
    </tr>
    <tr>
      <td><code>-s</code>, <code>--scanner</code></td>
      <td>strings</td>
      <td>Vulnerability scanners to use: <code>trivy</code>, <code>snyk</code>, <code>none</code></td>
      <td><code>trivy,snyk</code></td>
    </tr>
    <tr>
      <td><code>-t</code>, <code>--tf</code></td>
      <td>strings</td>
      <td>Terraform file(s) or directories to scan</td>
      <td>—</td>
    </tr>
    <tr>
      <td><code>--timeout</code></td>
      <td>int</td>
      <td>Scan timeout in seconds</td>
      <td><code>300</code></td>
    </tr>
  </tbody>
</table>

<br>

</details>

<details><summary><b><code>docker</code> Mode</b></summary>

<br>

```bash
dockeraudit docker [PATH...] [flags]
```

<b>Examples</b>

```bash
# Only fail on critical findings in CI
dockeraudit docker Dockerfile --fail-on critical

# Generate Markdown file
dockeraudit docker docker-compose.yaml --format markdown
```

<table>
  <thead>
    <tr>
      <th>Flag</th>
      <th>Type</th>
      <th>Description</th>
      <th>Default</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><code>--exclude-check</code></td>
      <td>strings</td>
      <td>Exclude specific control IDs from results (e.g. <code>--exclude-check IMAGE-001,RUNTIME-010</code>)</td>
      <td>—</td>
    </tr>
    <tr>
      <td><code>--fail-on</code></td>
      <td>string</td>
      <td>Exit non-zero on: <code>critical</code>, <code>high</code>, <code>medium</code>, <code>low</code>, <code>any</code></td>
      <td><code>high</code></td>
    </tr>
    <tr>
      <td><code>-f</code>, <code>--format</code></td>
      <td>string</td>
      <td>Output format: <code>table</code>, <code>json</code>, <code>markdown</code>, <code>sarif</code>, <code>junit</code></td>
      <td><code>table</code></td>
    </tr>
    <tr>
      <td><code>-h</code>, <code>--help</code></td>
      <td>—</td>
      <td>Show help for the command</td>
      <td>—</td>
    </tr>
    <tr>
      <td><code>--include-check</code></td>
      <td>strings</td>
      <td>Include only specific control IDs in results (e.g. <code>--include-check IMAGE-001,IMAGE-005</code>)</td>
      <td>—</td>
    </tr>
    <tr>
      <td><code>-o</code>, <code>--output</code></td>
      <td>string</td>
      <td>Write results to file</td>
      <td>—</td>
    </tr>
    <tr>
      <td><code>-s</code>, <code>--scanner</code></td>
      <td>strings</td>
      <td>Vulnerability scanners to use: <code>trivy</code>, <code>snyk</code>, <code>none</code></td>
      <td><code>trivy,snyk</code></td>
    </tr>
  </tbody>
</table>

<br>

</details>


<details><summary><b><code>image</code> Mode</b></summary>

<br>

```bash
dockeraudit image [IMAGE...] [flags]
```

<b>Examples</b>

```bash
# Scan with JSON output to file
dockeraudit image nginx:latest --format json -o results.json

# Scan multiple images in parallel
dockeraudit image nginx:latest postgres:16 redis:7

# Exclude specific checks
dockeraudit image myapp:latest --exclude-check IMAGE-001,IMAGE-008
```

<table>
  <thead>
    <tr>
      <th>Flag</th>
      <th>Type</th>
      <th>Description</th>
      <th>Default</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><code>--eol-file</code></td>
      <td>string</td>
      <td>Path to JSON file with custom end-of-life image definitions (overrides built-in list)</td>
      <td>—</td>
    </tr>
    <tr>
      <td><code>--exclude-check</code></td>
      <td>strings</td>
      <td>Exclude specific control IDs from results (e.g. <code>--exclude-check IMAGE-001,RUNTIME-010</code>)</td>
      <td>—</td>
    </tr>
    <tr>
      <td><code>--fail-on</code></td>
      <td>string</td>
      <td>Exit non-zero on: <code>critical</code>, <code>high</code>, <code>medium</code>, <code>low</code>, <code>any</code></td>
      <td><code>high</code></td>
    </tr>
    <tr>
      <td><code>-f</code>, <code>--format</code></td>
      <td>string</td>
      <td>Output format: <code>table</code>, <code>json</code>, <code>markdown</code>, <code>sarif</code>, <code>junit</code></td>
      <td><code>table</code></td>
    </tr>
    <tr>
      <td><code>-h</code>, <code>--help</code></td>
      <td>—</td>
      <td>Show help for the command</td>
      <td>—</td>
    </tr>
    <tr>
      <td><code>--include-check</code></td>
      <td>strings</td>
      <td>Include only specific control IDs in results (e.g. <code>--include-check IMAGE-001,IMAGE-005</code>)</td>
      <td>—</td>
    </tr>
    <tr>
      <td><code>-o</code>, <code>--output</code></td>
      <td>string</td>
      <td>Write results to file</td>
      <td>—</td>
    </tr>
    <tr>
      <td><code>-s</code>, <code>--scanner</code></td>
      <td>strings</td>
      <td>Vulnerability scanners to use: <code>trivy</code>, <code>snyk</code>, <code>none</code></td>
      <td><code>trivy,snyk</code></td>
    </tr>
    <tr>
      <td><code>--timeout</code></td>
      <td>int</td>
      <td>Timeout in seconds per image</td>
      <td><code>180</code></td>
    </tr>
  </tbody>
</table>

<br>

</details>

<details><summary><b><code>k8s</code> Mode</b></summary>

<br>

```bash
dockeraudit k8s [PATH...] [flags]
```

<b>Examples</b>

```bash
# Scan with JSON output to file 
dockeraudit k8s ./helm_charts/ --format json -o results.json 

# Scan with Snyk 
dockeraudit k8s ./helm_charts/ --scanner snyk
```

<table>
  <thead>
    <tr>
      <th>Flag</th>
      <th>Type</th>
      <th>Description</th>
      <th>Default</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><code>--exclude-check</code></td>
      <td>strings</td>
      <td>Exclude specific control IDs from results (e.g. <code>--exclude-check K8S-001,K8S-003</code>)</td>
      <td>—</td>
    </tr>
    <tr>
      <td><code>--fail-on</code></td>
      <td>string</td>
      <td>Exit non-zero on: <code>critical</code>, <code>high</code>, <code>medium</code>, <code>low</code>, <code>any</code></td>
      <td><code>high</code></td>
    </tr>
    <tr>
      <td><code>-f</code>, <code>--format</code></td>
      <td>string</td>
      <td>Output format: <code>table</code>, <code>json</code>, <code>markdown</code>, <code>sarif</code>, <code>junit</code></td>
      <td><code>table</code></td>
    </tr>
    <tr>
      <td><code>-h</code>, <code>--help</code></td>
      <td>—</td>
      <td>Show help for the command</td>
      <td>—</td>
    </tr>
    <tr>
      <td><code>--include-check</code></td>
      <td>strings</td>
      <td>Include only specific control IDs in results (e.g. <code>--include-check K8S-001,K8S-005</code>)</td>
      <td>—</td>
    </tr>
    <tr>
      <td><code>-o</code>, <code>--output</code></td>
      <td>string</td>
      <td>Write results to file</td>
      <td>—</td>
    </tr>
    <tr>
      <td><code>-s</code>, <code>--scanner</code></td>
      <td>strings</td>
      <td>Vulnerability scanners to use: <code>trivy</code>, <code>snyk</code>, <code>none</code></td>
      <td><code>trivy,snyk</code></td>
    </tr>
  </tbody>
</table>

<br>

</details>

<details><summary><b><code>terraform</code> Mode</b></summary>

<br>

```bash
dockeraudit terraform [PATH...] [flags]
```

```bash
# Fail on medium severity findings 
dockeraudit terraform aws/ --fail-on medium
```

<table>
  <thead>
    <tr>
      <th>Flag</th>
      <th>Type</th>
      <th>Description</th>
      <th>Default</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><code>--exclude-check</code></td>
      <td>strings</td>
      <td>Exclude specific control IDs from results (e.g. <code>--exclude-check IMAGE-001,RUNTIME-010</code>)</td>
      <td>—</td>
    </tr>
    <tr>
      <td><code>--fail-on</code></td>
      <td>string</td>
      <td>Exit non-zero on: <code>critical</code>, <code>high</code>, <code>medium</code>, <code>low</code>, <code>any</code></td>
      <td><code>high</code></td>
    </tr>
    <tr>
      <td><code>-f</code>, <code>--format</code></td>
      <td>string</td>
      <td>Output format: <code>table</code>, <code>json</code>, <code>markdown</code>, <code>sarif</code>, <code>junit</code></td>
      <td><code>table</code></td>
    </tr>
    <tr>
      <td><code>-h</code>, <code>--help</code></td>
      <td>—</td>
      <td>Show help for the command</td>
      <td>—</td>
    </tr>
    <tr>
      <td><code>--include-check</code></td>
      <td>strings</td>
      <td>Include only specific control IDs in results (e.g. <code>--include-check IMAGE-001,IMAGE-005</code>)</td>
      <td>—</td>
    </tr>
    <tr>
      <td><code>-o</code>, <code>--output</code></td>
      <td>string</td>
      <td>Write results to file</td>
      <td>—</td>
    </tr>
    <tr>
      <td><code>-s</code>, <code>--scanner</code></td>
      <td>strings</td>
      <td>Vulnerability scanners to use: <code>trivy</code>, <code>snyk</code>, <code>none</code></td>
      <td><code>trivy,snyk</code></td>
    </tr>
  </tbody>
</table>

<br>

</details>



<details><summary><b> Global Flags</b></summary>

<br>

| Flag | Default | Description |
|------|---------|-------------|
| `--verbose` | `false` | Print scan progress to stderr |
| `--config` | `~/.config/dockeraudit/dockeraudit.yaml` | Path to config file |
| `--version` | | Print version |

</details>


## Configuration File

dockeraudit supports a YAML configuration file for setting default options. CLI flags always override config file values.

**Config File Discovery Order:**

1. Path specified by `--config` flag
2. `$XDG_CONFIG_HOME/dockeraudit/dockeraudit.yaml` (falls back to `~/.config/dockeraudit/dockeraudit.yaml`)

Run `dockeraudit init` to generate the global config at the XDG path with default settings.

```yaml
# ~/.config/dockeraudit/dockeraudit.yaml
format: markdown
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
| `format` | string | `markdown` | Saved file format: `table`, `json`, `markdown`, `sarif`, `junit` (terminal always renders as table) |
| `fail-on` | string | `high` | Exit non-zero threshold: `critical`, `high`, `medium`, `low`, `any` |
| `verbose` | bool | `false` | Print scan progress to stderr |
| `exclude-check` | list | (empty) | Control IDs to exclude from results |
| `include-check` | list | (empty) | Only include these control IDs (applied before `exclude-check`) |
| `eol-file` | string | (empty) | Path to custom end-of-life image definitions JSON |

**Example configurations:**

```yaml
# CI/CD (strict)            # Development (relaxed)       # Compliance audit
format: sarif                format: markdown               format: json
fail-on: critical            fail-on: any                   fail-on: low
verbose: true                exclude-check:                 verbose: true
                               - IMAGE-001
                               - IMAGE-008
```

Run `dockeraudit init` to write the annotated reference config — which documents every option — to `~/.config/dockeraudit/dockeraudit.yaml`. The same file is also viewable in the source at [internal/cmd/dockeraudit.example.yaml](internal/cmd/dockeraudit.example.yaml).

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
  image: ubuntu:24.04
  before_script:
    - apt-get update
    - apt-get install -y --no-install-recommends curl ca-certificates
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
## Per-user — add to `~/.bashrc`:
source <(dockeraudit completion bash)

# Zsh
source <(dockeraudit completion zsh)

# Fish
mkdir -p ~/.config/fish/completions
dockeraudit completion fish > ~/.config/fish/completions/dockeraudit.fish

# PowerShell
dockeraudit completion powershell >> $PROFILE

```

## Security Controls

dockeraudit evaluates **80+ controls** across **12 security domains**:


| Domain | Controls | What It Covers |
|--------|----------|----------------|
| **Host** | 6 | Minimal OS, patching, firewall, SELinux/AppArmor, auditd, Bottlerocket |
| **Daemon** | 8 | Docker socket, TCP/port 2375 exposure, userns-remap, content trust, log rotation |
| **Image** | 16 | Digest pinning, secrets in layers, SUID files, non-root USER, EOL images, debug tools, package verification bypass, recursive COPY, multi-stage builds |
| **Runtime** | 16 | Privileged mode, capabilities, read-only rootfs, host namespaces, resource limits, health probes, seccomp, AppArmor/SELinux, automountSA, ulimits, restart policies |
| **Registry** | 4 | Insecure-registries in daemon config, unauthenticated/http registry refs in Dockerfiles/Compose/k8s, ECR/GAR/ACR IAM least-privilege, lifecycle/retention policies |
| **Network** | 2 | Default-deny NetworkPolicy, cloud metadata endpoint blocked |
| **Secrets** | 3 | External secrets manager, RBAC-scoped secret access, AI/API key detection |
| **Supply Chain** | 3 | Image signing, SBOM attestation, immutable registry tags |
| **Monitoring** | 2 | Runtime threat detection (Falco), Kubernetes audit logging |
| **Database** | 12 | Admin tools, startup flags, auth config, service types, encryption, persistent storage, annotations |
| **Kubernetes** | 3 | Namespace isolation, pod anti-affinity/topology spread, IaC vulnerability scanning (Trivy/Snyk) |
| **Terraform** | 9 | S3 public access/versioning, ECS privileged/non-root/read-only rootfs, security group ingress, KMS encryption, CloudTrail logging, IaC vulnerability scanning (Trivy/Snyk) |

<br>

Run `dockeraudit report controls` for the full list.

## License

This project is licensed under the BSD License. See [LICENSE](LICENSE) for details.
