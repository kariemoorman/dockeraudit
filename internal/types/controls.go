package types

// AllControls is the canonical registry of every hardening control
var AllControls = []Control{
	// ── Domain: Host ────────────────────────────────────────────────────────── //
	{
		ID:     "HOST-001",
		Domain: "Docker",
		Title:  "Minimal Host OS",
		Description: "Host should run a container-optimized or minimal OS. " +
			"Unnecessary packages and services expand the kernel attack surface available to container escapes.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "1.1",
			NIST80053:        "CM-6, CM-7",
			NIST800190:       "§4.1, §4.5",
			ISO27001:         "A.12.6.1, A.14.2.1",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-000381",
		},
		Remediation: "Use Bottlerocket (AWS), COS (GCP), or minimal RHEL/Ubuntu. " +
			"Remove compilers, debuggers, and unnecessary services.",
	},
	{
		ID:     "HOST-002",
		Domain: "Docker",
		Title:  "OS Security Patches Applied",
		Description: "Unpatched kernel CVEs (Dirty Pipe CVE-2022-0847, runc CVE-2019-5736) " +
			"enable container escape. The host kernel must be current.",
		Severity: SeverityCritical,
		Type:     ControlCorrective,
		Compliance: ComplianceMapping{
			CISDockerSection: "1.2",
			NIST80053:        "SI-2, RA-5",
			NIST800190:       "§4.1",
			ISO27001:         "A.12.6.1",
			SOC2:             "CC7.1",
			DISACCI:          "CCI-002617",
		},
		Remediation: "Enable unattended-upgrades or dnf-automatic. " +
			"Build fresh node AMIs weekly. Rotate node groups on new AMI.",
	},
	{
		ID:     "HOST-003",
		Domain: "Docker",
		Title:  "Host Firewall Configured",
		Description: "Docker daemon port 2375 must not be network-reachable without TLS. " +
			"Kubelet port 10250 must be restricted to control plane CIDR.",
		Severity: SeverityHigh,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "N/A",
			NIST80053:        "SC-7, AC-17",
			NIST800190:       "§4.5",
			ISO27001:         "A.13.1.1, A.13.1.3",
			SOC2:             "CC6.6",
			DISACCI:          "CCI-001090",
		},
		Remediation: "Block 2375 via iptables/security group. " +
			"Restrict 10250 to control plane subnet. Use IMDSv2 (hop limit=1).",
	},
	{
		ID:     "HOST-004",
		Domain: "Docker",
		Title:  "SELinux or AppArmor in Enforcing Mode",
		Description: "Mandatory Access Controls provide kernel-level containment beyond " +
			"Linux namespace isolation. Critical defence-in-depth against container escape.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "1.6, 1.7",
			NIST80053:        "AC-3, AC-6, SI-7",
			NIST800190:       "§4.4",
			ISO27001:         "A.9.4.1, A.12.1.4",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-002235",
		},
		Remediation: "Set SELINUX=enforcing in /etc/selinux/config. " +
			"Enable and enforce AppArmor docker profile on Ubuntu.",
	},
	{
		ID:     "HOST-005",
		Domain: "Docker",
		Title:  "Auditd Rules for Docker Files",
		Description: "Without auditd rules, tampering of daemon config, docker binary, " +
			"and socket permissions goes undetected.",
		Severity: SeverityHigh,
		Type:     ControlDetective,
		Compliance: ComplianceMapping{
			CISDockerSection: "1.8–1.13",
			NIST80053:        "AU-2, AU-12",
			NIST800190:       "§4.5",
			ISO27001:         "A.12.4.1, A.12.4.3",
			SOC2:             "CC7.2",
			DISACCI:          "CCI-000172",
		},
		Remediation: "Add auditd rules for /etc/docker, /var/run/docker.sock, " +
			"/usr/bin/dockerd, and systemd unit files.",
	},

	// ── Domain: Daemon ──────────────────────────────────────────────────────── //
	{
		ID:     "DAEMON-001",
		Domain: "Docker",
		Title:  "Docker Socket Not Mounted in Containers",
		Description: "Mounting /var/run/docker.sock into any container provides unconditional " +
			"root on the host. No legitimate application workload requires it.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "2.2, 5.32",
			NIST80053:        "AC-3, AC-6",
			NIST800190:       "§4.3",
			ISO27001:         "A.9.4.1",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-002235",
		},
		Remediation: "Remove docker.sock volume mounts from all workloads. " +
			"Use OPA/Kyverno admission policy to block at admission time.",
	},
	{
		ID:     "DAEMON-002",
		Domain: "Docker",
		Title:  "No Unauthenticated TCP Daemon",
		Description: "Docker daemon listening on TCP 2375 without TLS is a remotely " +
			"exploitable root backdoor on any network-reachable host.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "2.1",
			NIST80053:        "AC-17, IA-3, SC-8",
			NIST800190:       "§4.3",
			ISO27001:         "A.13.1.1",
			SOC2:             "CC6.6",
			DISACCI:          "CCI-002418",
		},
		Remediation: "Remove -H tcp:// from daemon args. " +
			"If remote access needed, configure TLS (2376) with mutual auth only.",
	},
	{
		ID:     "DAEMON-003",
		Domain: "Docker",
		Title:  "User Namespace Remapping Enabled",
		Description: "Without userns-remap, UID 0 inside a container maps directly to " +
			"UID 0 on the host kernel. A container escape is immediately full root.",
		Severity: SeverityHigh,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "2.8",
			NIST80053:        "AC-3, AC-6",
			NIST800190:       "§4.3",
			ISO27001:         "A.9.4.1",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-002235",
		},
		Remediation: `Set "userns-remap": "default" in /etc/docker/daemon.json and restart Docker.`,
	},
	{
		ID:     "DAEMON-004",
		Domain: "Docker",
		Title:  "Docker Content Trust Enabled",
		Description: "Without content trust, images can be pulled with tampered layers " +
			"or swapped digests at the registry or via MITM without detection.",
		Severity: SeverityHigh,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "2.18, 4.5",
			NIST80053:        "SI-7, CM-14",
			NIST800190:       "§4.2",
			ISO27001:         "A.14.2.9",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-001762",
		},
		Remediation: "Set DOCKER_CONTENT_TRUST=1 in daemon environment. " +
			"For Kubernetes: use Cosign + Sigstore with Kyverno/Connaisseur admission.",
	},
	{
		ID:     "DAEMON-005",
		Domain: "Docker",
		Title:  "Daemon Log Rotation Configured",
		Description: "Unbounded log growth causes disk exhaustion. " +
			"Missing log rotation destroys forensic evidence.",
		Severity: SeverityMedium,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "2.12, 2.13",
			NIST80053:        "AU-3, AU-9, AU-12",
			NIST800190:       "§4.3",
			ISO27001:         "A.12.4.1",
			SOC2:             "CC7.2",
			DISACCI:          "CCI-000172",
		},
		Remediation: `Set log-driver, max-size, and max-file in /etc/docker/daemon.json.`,
	},

	// ── Domain: Image ───────────────────────────────────────────────────────── //
	{
		ID:     "IMAGE-001",
		Domain: "Docker",
		Title:  "Images Pinned by Digest",
		Description: "Mutable tags can be silently replaced at the registry. " +
			"Pin all images by digest (sha256:...) to guarantee immutability.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.1, 4.2",
			NIST80053:        "CM-14, SI-7",
			NIST800190:       "§4.2",
			ISO27001:         "A.14.2.1, A.14.2.9",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-001762",
		},
		Remediation: "Replace all FROM and image: fields with @sha256: digest references. " +
			"Automate digest pinning in CI with crane digest or skopeo inspect.",
	},
	{
		ID:     "IMAGE-002",
		Domain: "Docker",
		Title:  "No Secrets in Image Layers",
		Description: "Secrets baked into image layers cannot be revoked and are accessible " +
			"to anyone who can pull the image — including after a 'deletion' layer.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.10",
			NIST80053:        "IA-5, SC-28",
			NIST800190:       "§4.2",
			ISO27001:         "A.9.4.3, A.10.1.1",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-000366, CCI-002367",
		},
		Remediation: "Scan Dockerfiles and history with trivy --scanners secret and truffleHog. " +
			"Inject secrets at runtime via CSI secrets driver or Vault agent.",
	},
	{
		ID:     "IMAGE-003",
		Domain: "Docker",
		Title:  "Image Vulnerability Scan",
		Description: "Container images accumulate CVEs from OS packages and language dependencies. " +
			"Unscanned images run with known exploitable vulnerabilities.",
		Severity: SeverityCritical,
		Type:     ControlDetective,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.4",
			NIST80053:        "RA-5, SI-2",
			NIST800190:       "§4.2",
			ISO27001:         "A.12.6.1",
			SOC2:             "CC7.1",
			DISACCI:          "CCI-002617",
		},
		Remediation: "Integrate Trivy or Snyk in CI. Fail pipeline on CRITICAL or HIGH (unfixed). " +
			"Enable continuous scanning in ECR Enhanced Scanning or GCP Artifact Analysis.",
	},
	{
		ID:     "IMAGE-004",
		Domain: "Docker",
		Title:  "No SUID/SGID/World-Writable Files in Image",
		Description: "SUID/SGID binaries inside a container are exploitable for local " +
			"privilege escalation without any external capability. " +
			"World-writable files allow any process to overwrite binaries or configs, " +
			"enabling persistence after initial compromise.",
		Severity: SeverityHigh,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.8",
			NIST80053:        "AC-6, CM-7",
			NIST800190:       "§4.2",
			ISO27001:         "A.12.6.1",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-002235",
		},
		Remediation: "Remove SUID/SGID bits: RUN find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f -exec chmod a-s {} \\; " +
			"Remove world-writable: RUN find / -xdev -perm -0002 -type f -exec chmod o-w {} \\; " +
			"Verify: docker run --rm <image> find / -xdev \\( -perm -4000 -o -perm -2000 -o -perm -0002 \\) -type f",
	},
	{
		ID:     "IMAGE-005",
		Domain: "Docker",
		Title:  "Non-Root USER in Dockerfile",
		Description: "Running as UID 0 in a container provides excessive kernel access. " +
			"All application containers must define a non-root USER.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.1",
			NIST80053:        "AC-6, IA-5",
			NIST800190:       "§4.3",
			ISO27001:         "A.9.4.1",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-002235",
		},
		Remediation: "Add USER <non-root-uid> as the last non-CMD instruction in Dockerfile. " +
			"Verify with docker run --rm <image> id. UID must not be 0.",
	},
	{
		ID:     "IMAGE-006",
		Domain: "Docker",
		Title:  "ADD Not Used for Remote URLs",
		Description: "ADD with a URL fetches content at build time without checksum verification, " +
			"enabling supply chain tampering.",
		Severity: SeverityMedium,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.9",
			NIST80053:        "SI-7, CM-14",
			NIST800190:       "§4.2",
			ISO27001:         "A.14.2.1",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-001762",
		},
		Remediation: "Replace ADD <url> with RUN curl -fsSL <url> | sha256sum -c <checksum>. " +
			"Use COPY for local files.",
	},
	{
		ID:     "IMAGE-007",
		Domain: "Docker",
		Title:  "No Secret/Credential Files in Image Filesystem",
		Description: "Credential files (.env, id_rsa, .npmrc, credentials, terraform.tfvars, " +
			"wp-config.php, service-account.json, .vault-token, kubeconfig, .bash_history) " +
			"baked into image layers grant any image puller access to credentials. " +
			"Deleted files in an earlier layer are still readable by exporting the image tarball.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.10",
			NIST80053:        "IA-5, SC-28",
			NIST800190:       "§4.2",
			ISO27001:         "A.9.4.3, A.10.1.1",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-000366, CCI-002367",
		},
		Remediation: "Add all secret/key file patterns to .dockerignore. " +
			"Use multi-stage builds — secret files must never reach the final stage. " +
			"Scan with: trivy image --scanners secret <image> or trufflehog docker --image <image>.",
	},
	{
		ID:     "IMAGE-008",
		Domain: "Docker",
		Title:  "No End-of-Life Base Image",
		Description: "End-of-life OS/runtime images receive no security patches. " +
			"Commonly affected: Ubuntu 14.04–18.04, CentOS 6–8, Debian 7–9, " +
			"Node 10–16, Python 2.7/3.6–3.9, Ruby 2.5–3.1, PHP 5.x/7.x/8.0–8.1, " +
			"Go 1.16–1.21, PostgreSQL 9–13, MySQL 5.6–5.7, MongoDB 4.x–5.x, " +
			"Redis 5/6.0, Elasticsearch 6.x–7.x. " +
			"A single unpatched kernel CVE can compromise the container host.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.4",
			NIST80053:        "SI-2, RA-5",
			NIST800190:       "§4.2",
			ISO27001:         "A.12.6.1",
			SOC2:             "CC7.1",
			DISACCI:          "CCI-002617",
		},
		Remediation: "Upgrade to a currently supported base image. " +
			"Use distroless or scratch for production workloads where possible. " +
			"Track EOL dates at: https://endoflife.date/",
	},
	{
		ID:     "IMAGE-009",
		Domain: "Docker",
		Title:  "No Crypto Miner Artifacts",
		Description: "Crypto miners (xmrig, cpuminer, ethminer, cgminer, bfgminer, lolminer, " +
			"t-rex, nbminer, teamredminer, gminer, srbminer) are commonly injected into " +
			"compromised or malicious images. Mining pool URLs (stratum+tcp://, moneroocean., " +
			"nanopool.org, f2pool.com, nicehash.com) in image history or ENV are definitive indicators.",
		Severity: SeverityCritical,
		Type:     ControlDetective,
		Compliance: ComplianceMapping{
			CISDockerSection: "N/A",
			NIST80053:        "SI-3, SI-7",
			NIST800190:       "§4.2",
			ISO27001:         "A.12.2.1, A.14.2.9",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-001764",
		},
		Remediation: "Pull images only from trusted, verified registries. " +
			"Verify image signatures with Cosign before deployment. " +
			"Deploy Falco with rule detect_crypto_miners. " +
			"Scan with: trivy image --scanners vuln,misconfig <image>.",
	},
	{
		ID:     "IMAGE-010",
		Domain: "Docker",
		Title:  "No Backdoored Package Versions (xz-utils CVE-2024-3094)",
		Description: "xz-utils versions 5.6.0 and 5.6.1 contain a backdoor in liblzma " +
			"that enables remote code execution via systemd/OpenSSH on affected systems " +
			"(CVE-2024-3094, CVSS 10.0). These versions were distributed in " +
			"Debian Sid, Fedora 40 Beta, Kali 2024.1, and several rolling-release distros.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.4",
			NIST80053:        "SI-2, RA-5, SI-7",
			NIST800190:       "§4.2",
			ISO27001:         "A.12.6.1",
			SOC2:             "CC7.1",
			DISACCI:          "CCI-002617",
		},
		Remediation: "Downgrade to xz-utils <= 5.4.x (5.4.6 is confirmed safe). " +
			"Rebuild all images from known-good base layers post-March 2024. " +
			"Scan with: trivy image <image> | grep xz  or  snyk container test <image>.",
	},

	{
		ID:     "IMAGE-014",
		Domain: "Docker",
		Title:  "Use COPY Instead of ADD for Local Files",
		Description: "The ADD instruction silently auto-extracts tar archives and accepts " +
			"remote URLs, making its behaviour opaque and potentially dangerous. " +
			"COPY should be used for all local file transfers; ADD is only appropriate " +
			"when tar auto-extraction is explicitly required.",
		Severity: SeverityMedium,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.9",
			NIST80053:        "CM-7, SI-7",
			NIST800190:       "§4.2",
			ISO27001:         "A.12.5.1",
			SOC2:             "CC6.1",
		},
		Remediation: "Replace ADD with COPY for local file transfers. " +
			"Only keep ADD when tar auto-extraction is intentional and documented.",
	},

	// ── Domain: Runtime ─────────────────────────────────────────────────────── //
	{
		ID:     "RUNTIME-001",
		Domain: "Docker",
		Title:  "Containers Not Running as Root",
		Description: "Runtime UID 0 in a container (without user namespace remapping) " +
			"maps to host root. Application compromise equals host compromise.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.1, 5.22",
			NIST80053:        "AC-6, IA-5",
			NIST800190:       "§4.3",
			ISO27001:         "A.9.4.1",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-002235",
		},
		Remediation: "Set runAsNonRoot: true and runAsUser: <non-zero> in Pod securityContext. " +
			"Enforce via OPA/Kyverno admission policy.",
	},
	{
		ID:     "RUNTIME-002",
		Domain: "Docker",
		Title:  "Privileged Containers Disabled",
		Description: "Privileged mode grants nearly all kernel capabilities and disables most " +
			"security mechanisms. Equivalent to running directly on the host.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "5.5",
			NIST80053:        "AC-3, AC-6",
			NIST800190:       "§4.3",
			ISO27001:         "A.9.4.1",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-002235",
		},
		Remediation: "Set privileged: false in all container securityContexts. " +
			"Enforce via admission controller. Never use --privileged in production.",
	},
	{
		ID:     "RUNTIME-003",
		Domain: "Docker",
		Title:  "All Capabilities Dropped",
		Description: "Default Docker capabilities include NET_RAW, MKNOD, SYS_CHROOT. " +
			"These enable ARP spoofing, device creation, and filesystem escape techniques.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "5.4",
			NIST80053:        "AC-6, CM-7",
			NIST800190:       "§4.3",
			ISO27001:         "A.9.4.1",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-000381",
		},
		Remediation: "Set capabilities.drop: [ALL] in securityContext. " +
			"Add back only specific required capabilities (e.g., NET_BIND_SERVICE).",
	},
	{
		ID:     "RUNTIME-004",
		Domain: "Docker",
		Title:  "AllowPrivilegeEscalation Disabled",
		Description: "Without no-new-privileges, processes can gain capabilities via " +
			"SUID/SGID executables inside the container.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "5.26",
			NIST80053:        "AC-6",
			NIST800190:       "§4.3",
			ISO27001:         "A.9.4.1",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-002235",
		},
		Remediation: "Set allowPrivilegeEscalation: false in container securityContext.",
	},
	{
		ID:     "RUNTIME-005",
		Domain: "Docker",
		Title:  "Read-Only Root Filesystem",
		Description: "Writable root filesystem allows malware installation, binary tampering, " +
			"and persistence mechanisms inside the container.",
		Severity: SeverityHigh,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "5.13",
			NIST80053:        "SI-7, CM-5",
			NIST800190:       "§4.3",
			ISO27001:         "A.12.4.3, A.14.2.1",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-001813",
		},
		Remediation: "Set readOnlyRootFilesystem: true. " +
			"Mount emptyDir volumes for /tmp and any required write paths.",
	},
	{
		ID:     "RUNTIME-006",
		Domain: "Docker",
		Title:  "No Host PID / IPC / Network Namespace Sharing",
		Description: "Sharing host namespaces removes namespace-based isolation. " +
			"hostPID: true allows attacker to enumerate and kill host processes.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "5.10, 5.16, 5.17, 5.21",
			NIST80053:        "AC-4, AC-6",
			NIST800190:       "§4.3",
			ISO27001:         "A.13.1.3",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-001090",
		},
		Remediation: "Set hostPID: false, hostIPC: false, hostNetwork: false in pod spec.",
	},
	{
		ID:     "RUNTIME-007",
		Domain: "Docker",
		Title:  "CPU and Memory Limits Set",
		Description: "Unconstrained containers cause resource exhaustion (DoS) on the node, " +
			"affecting all co-located workloads.",
		Severity: SeverityHigh,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "5.11, 5.12",
			NIST80053:        "SC-5, AU-4",
			NIST800190:       "§4.3",
			ISO27001:         "A.12.1.3",
			SOC2:             "A1.1",
			DISACCI:          "CCI-001094, CCI-001095",
		},
		Remediation: "Set resources.requests and resources.limits for memory and CPU on all containers. " +
			"Enforce via LimitRange and ResourceQuota in each namespace.",
	},
	{
		ID:     "RUNTIME-008",
		Domain: "Docker",
		Title:  "Seccomp Profile Applied",
		Description: "Without seccomp, containers can invoke any syscall. " +
			"Kernel exploits frequently use obscure syscalls (keyctl, unshare, clone) blocked by the default profile.",
		Severity: SeverityHigh,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "5.22",
			NIST80053:        "AC-3, SI-3",
			NIST800190:       "§4.4",
			ISO27001:         "A.14.2.1",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-000381",
		},
		Remediation: "Set seccompProfile.type: RuntimeDefault in pod securityContext. " +
			"Use custom profile for workloads requiring specific syscalls.",
	},
	{
		ID:     "RUNTIME-009",
		Domain: "Docker",
		Title:  "Sensitive Host Directories Not Mounted",
		Description: "Mounting /etc, /proc, /sys, /var/run or other sensitive host paths " +
			"into containers breaks isolation and enables host manipulation.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "5.6",
			NIST80053:        "AC-3",
			NIST800190:       "§4.3",
			ISO27001:         "A.9.4.1",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-000109",
		},
		Remediation: "Audit all hostPath volume mounts. Reject via OPA/Kyverno policy. " +
			"Use PVC or emptyDir instead.",
	},

	// ── Domain: Network ─────────────────────────────────────────────────────── //
	{
		ID:     "NETWORK-001",
		Domain: "Kubernetes",
		Title:  "Default-Deny NetworkPolicy in All Namespaces",
		Description: "Without NetworkPolicy, all pods communicate cluster-wide by default. " +
			"A single compromised pod has network access to every other service.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "5.10",
			NIST80053:        "SC-7, AC-4",
			NIST800190:       "§4.3",
			ISO27001:         "A.13.1.1, A.13.1.3",
			SOC2:             "CC6.6",
			DISACCI:          "CCI-001090",
		},
		Remediation: "Apply default-deny-all NetworkPolicy to every namespace. " +
			"Add explicit allow rules for required communication paths.",
	},
	{
		ID:     "NETWORK-002",
		Domain: "Kubernetes",
		Title:  "Cloud Metadata Endpoint Blocked",
		Description: "SSRF vulnerabilities can exfiltrate IAM credentials from 169.254.169.254. " +
			"This is a critical path for cloud account takeover from a compromised container.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "5.10",
			NIST80053:        "SC-7, IA-5",
			NIST800190:       "§4.3, §4.5",
			ISO27001:         "A.13.1.1",
			SOC2:             "CC6.6",
			DISACCI:          "CCI-001090",
		},
		Remediation: "Block 169.254.169.254/32 in egress NetworkPolicy. " +
			"Set http_put_response_hop_limit: 1 and http_tokens: required (IMDSv2) on instances.",
	},

	// ── Domain: Secrets ─────────────────────────────────────────────────────── //
	{
		ID:     "SECRETS-001",
		Domain: "Secrets",
		Title:  "Secrets Managed Externally (Not in K8s Secrets Plaintext)",
		Description: "Kubernetes Secrets are base64-encoded, not encrypted by default. " +
			"etcd access or broad get-secrets RBAC exposes all credentials.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.10",
			NIST80053:        "IA-5, SC-28, AC-4",
			NIST800190:       "§4.2, §4.3",
			ISO27001:         "A.10.1.1, A.9.4.3",
			SOC2:             "CC6.1, CC6.2",
			DISACCI:          "CCI-000366, CCI-002367",
		},
		Remediation: "Use AWS Secrets Manager, GCP Secret Manager, or HashiCorp Vault. " +
			"Mount via CSI secrets driver. Enable etcd encryption at rest.",
	},
	{
		ID:     "SECRETS-002",
		Domain: "Secrets",
		Title:  "RBAC Restricts Secret Access to Named Resources",
		Description: "Wildcard secret access (resources: [\"secrets\"] without resourceNames) " +
			"allows a service account to read every secret in its namespace.",
		Severity: SeverityHigh,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "5.32",
			NIST80053:        "AC-2, AC-3, AC-6",
			NIST800190:       "§4.3",
			ISO27001:         "A.9.1.1, A.9.4.1",
			SOC2:             "CC6.2",
			DISACCI:          "CCI-002235",
		},
		Remediation: "Restrict secret access by resourceName. Audit with kubectl auth can-i. " +
			"Remove cluster-admin bindings from non-admin service accounts.",
	},

	// ── Domain: Supply Chain ────────────────────────────────────────────────── //
	{
		ID:     "SUPPLY-001",
		Domain: "Kubernetes",
		Title:  "Images Signed and Signature Verified at Admission",
		Description: "Without image signing, registry compromise or tag hijacking silently " +
			"delivers malicious images. Admission verification is the enforcement point.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.5, 4.12",
			NIST80053:        "SI-7, CM-14",
			NIST800190:       "§4.2",
			ISO27001:         "A.14.2.9, A.12.5.1",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-001762",
		},
		Remediation: "Sign images with Cosign (keyless via OIDC or KMS-backed key). " +
			"Enforce signature verification via Kyverno verifyImages or Connaisseur.",
	},
	{
		ID:     "SUPPLY-002",
		Domain: "Docker",
		Title:  "SBOM Generated and Attested per Image",
		Description: "Without SBOM, you cannot determine which deployed workloads are " +
			"affected by a newly disclosed CVE without full re-scan.",
		Severity: SeverityHigh,
		Type:     ControlDetective,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.4, 4.12",
			NIST80053:        "CM-8, RA-5",
			NIST800190:       "§4.2",
			ISO27001:         "A.8.1.1, A.12.6.1",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-002617",
		},
		Remediation: "Generate CycloneDX SBOM with Syft in CI. " +
			"Attest SBOM to image with cosign attest --type cyclonedx.",
	},
	{
		ID:     "SUPPLY-003",
		Domain: "Terraform",
		Title:  "Image Registry Tags Immutable",
		Description: "Mutable tags allow silent image replacement. Once a tagged image is " +
			"deployed, the tag must not be overwriteable.",
		Severity: SeverityHigh,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.1",
			NIST80053:        "CM-2, CM-5",
			NIST800190:       "§4.2",
			ISO27001:         "A.14.2.9",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-001762",
		},
		Remediation: "Set image_tag_mutability = IMMUTABLE in ECR. " +
			"Use Artifact Registry cleanup policies that KEEP tagged images.",
	},

	// ── Domain: Monitoring ──────────────────────────────────────────────────── //
	{
		ID:     "MONITOR-001",
		Domain: "Kubernetes",
		Title:  "Runtime Threat Detection (Falco) Deployed",
		Description: "Without runtime detection, attacker activity inside containers " +
			"(shell spawning, file writes, unexpected syscalls) generates no alerts.",
		Severity: SeverityCritical,
		Type:     ControlDetective,
		Compliance: ComplianceMapping{
			CISDockerSection: "N/A",
			NIST80053:        "AU-12, SI-4, IR-5",
			NIST800190:       "§4.4",
			ISO27001:         "A.12.4.1, A.16.1.1",
			SOC2:             "CC7.2, CC7.3",
			DISACCI:          "CCI-000172",
		},
		Remediation: "Deploy Falco DaemonSet with eBPF driver. Configure alerts for " +
			"shell-in-container, write-below-binary-dir, unexpected network connections.",
	},
	{
		ID:     "MONITOR-002",
		Domain: "Kubernetes",
		Title:  "Kubernetes API Server Audit Logging Enabled",
		Description: "Without API audit logging, all control plane activity " +
			"(secret reads, RBAC changes, exec into pods) is invisible for forensics.",
		Severity: SeverityCritical,
		Type:     ControlDetective,
		Compliance: ComplianceMapping{
			CISDockerSection: "2.12",
			NIST80053:        "AU-2, AU-3, AU-12",
			NIST800190:       "§4.3",
			ISO27001:         "A.12.4.1",
			SOC2:             "CC7.2",
			DISACCI:          "CCI-000172",
		},
		Remediation: "Configure audit policy logging secrets at Request level, " +
			"exec/attach at RequestResponse. Ship to immutable SIEM/SOAR.",
	},

	// ── Domain: Runtime (continued) ─────────────────────────────────────────── //
	{
		ID:     "RUNTIME-010",
		Domain: "Docker",
		Title:  "No SSH Daemon in Containers",
		Description: "Running sshd inside a container bypasses all audit logging, " +
			"provides an unmonitored lateral movement channel, and violates the principle " +
			"of least privilege. Use kubectl exec or ephemeral debug containers instead.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "5.7",
			NIST80053:        "AC-17, CM-7",
			NIST800190:       "§4.3",
			ISO27001:         "A.13.1.1",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-000381",
		},
		Remediation: "Remove sshd from container images and entrypoints. " +
			"Deploy Falco rule to alert on sshd execution inside containers. " +
			"Use kubectl exec or ephemeral debug containers for interactive access.",
	},
	{
		ID:     "RUNTIME-011",
		Domain: "Docker",
		Title:  "No Privileged Ports Exposed (< 1024)",
		Description: "Binding to ports below 1024 requires CAP_NET_BIND_SERVICE. " +
			"Application services must use non-privileged ports (>= 1024) and rely " +
			"on Kubernetes Services to expose them externally on standard ports.",
		Severity: SeverityHigh,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "5.8",
			NIST80053:        "AC-6, CM-7",
			NIST800190:       "§4.3",
			ISO27001:         "A.9.4.1",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-001762",
		},
		Remediation: "Move the service to port >= 1024 in application configuration. " +
			"Use a Kubernetes Service to expose the application externally on the standard port.",
	},
	{
		ID:     "RUNTIME-012",
		Domain: "Docker",
		Title:  "Liveness and Readiness Probes Configured",
		Description: "Without health probes, Docker/Kubernetes cannot detect a degraded or " +
			"hung container and continues routing traffic to it or fails to restart it. " +
			"Both probes are required for availability compliance under RMF.",
		Severity: SeverityHigh,
		Type:     ControlDetective,
		Compliance: ComplianceMapping{
			CISDockerSection: "N/A",
			NIST80053:        "CP-10, SI-17",
			NIST800190:       "§4.3, §4.4",
			ISO27001:         "A.17.1.2",
			SOC2:             "A1.2",
			DISACCI:          "CCI-002385",
		},
		Remediation: "Define livenessProbe and readinessProbe for all containers. " +
			"Use exec probe for databases (pg_isready), HTTP probe for web services. " +
			"Set appropriate initialDelaySeconds to avoid premature kills.",
	},

	// ── Domain: Database ────────────────────────────────────────────────────── //
	{
		ID:     "DB-IMAGE-001",
		Domain: "Database",
		Title:  "No Admin/Debug Tools in Database Image",
		Description: "Admin and debug tools (psql, mongosh, redis-cli, cypher-shell, " +
			"mysql, cqlsh, mongodump, arangosh) in production database images provide " +
			"an attacker who achieves any code execution a direct authenticated channel " +
			"into the database without additional exploits.",
		Severity: SeverityHigh,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.3",
			NIST80053:        "CM-7, AC-6",
			NIST800190:       "§4.2",
			ISO27001:         "A.12.6.1",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-000381",
		},
		Remediation: "Use multi-stage Dockerfile builds. Admin tools belong in a separate " +
			"debug image (-debug tag) never deployed to production. " +
			"Use kubectl debug ephemeral containers for investigations.",
	},
	{
		ID:     "DB-IMAGE-002",
		Domain: "Database",
		Title:  "No Dangerous Database Startup Flags",
		Description: "Database startup flags --skip-grant-tables (MySQL), --local-infile=1 " +
			"(MySQL), missing --auth (MongoDB), -tcpAllowOthers (H2), and -startNetworkServer " +
			"(Derby) completely bypass authentication or enable severe misconfigurations. " +
			"These are commonly introduced as quick fixes and left in production.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.1, 5.7",
			NIST80053:        "IA-2, AC-3, CM-6",
			NIST800190:       "§4.3",
			ISO27001:         "A.9.4.2, A.9.4.3",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-000366, CCI-002235",
		},
		Remediation: "Audit all database container CMD and Entrypoint values. " +
			"Remove --skip-grant-tables, --local-infile=1, --secure-file-priv= (empty). " +
			"Ensure MongoDB uses --auth. Use configmap-mounted config files instead of flags.",
	},
	{
		ID:     "DB-K8S-001",
		Domain: "Database",
		Title:  "No Auth-Disabling ENV Variables",
		Description: "Multiple databases support ENV vars that explicitly disable " +
			"authentication or enable dangerous operational modes: " +
			"POSTGRES_HOST_AUTH_METHOD=trust, NEO4J_AUTH=none, ARANGO_NO_AUTH=1, " +
			"AUTHENTICATION_ANONYMOUS_ACCESS_ENABLED=true (Weaviate), " +
			"CHROMA_ALLOW_RESET=true (deletes all data), SPRING_H2_CONSOLE_ENABLED=true (RCE).",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.10, 5.7",
			NIST80053:        "IA-2, AC-3, IA-5",
			NIST800190:       "§4.3",
			ISO27001:         "A.9.4.2, A.9.4.3",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-000366, CCI-002235",
		},
		Remediation: "Remove all auth-disabling ENV vars. Use POSTGRES_HOST_AUTH_METHOD=scram-sha-256. " +
			"Set NEO4J_AUTH to a non-default value. Set AUTHENTICATION_ANONYMOUS_ACCESS_ENABLED=false. " +
			"Never set SPRING_H2_CONSOLE_ENABLED=true in production.",
	},
	{
		ID:     "DB-K8S-002",
		Domain: "Database",
		Title:  "Database Authentication Must Be Explicitly Configured",
		Description: "Several databases default to no authentication: Qdrant, Chroma, Milvus, " +
			"Weaviate, Redis, MongoDB. In containerized environments where network-adjacent " +
			"access is the default, absent authentication configuration is a critical failure.",
		Severity: SeverityHigh,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.10",
			NIST80053:        "IA-2, IA-5, AC-3",
			NIST800190:       "§4.3",
			ISO27001:         "A.9.4.2",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-000366",
		},
		Remediation: "Qdrant: set QDRANT__SERVICE__API_KEY. Chroma: set CHROMA_SERVER_AUTH_PROVIDER. " +
			"Milvus: set MILVUS_ROOT_PASSWORD. Weaviate: set AUTHENTICATION_APIKEY_ENABLED=true. " +
			"Redis: mount redis.conf with requirepass. MongoDB: ensure --auth in CMD.",
	},
	{
		ID:     "DB-K8S-003",
		Domain: "Database",
		Title:  "Database Services Must Use ClusterIP",
		Description: "Exposing database Services as NodePort or LoadBalancer bypasses all " +
			"Kubernetes NetworkPolicy and makes the database directly reachable from the " +
			"node network or the public Internet. This is the most common real-world " +
			"database breach vector for containerized deployments.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "5.10",
			NIST80053:        "SC-7, AC-4",
			NIST800190:       "§4.5",
			ISO27001:         "A.13.1.1, A.13.1.3",
			SOC2:             "CC6.6",
			DISACCI:          "CCI-001090",
		},
		Remediation: "Set spec.type: ClusterIP on all database Services. " +
			"Use Ingress with TLS for application API access. " +
			"Never expose raw database ports via NodePort or LoadBalancer.",
	},
	{
		ID:     "DB-K8S-004",
		Domain: "Database",
		Title:  "Database Data Must Use Persistent Volume (Not emptyDir)",
		Description: "emptyDir as the primary data directory for a stateful database " +
			"causes data loss on pod restart, stores data on node-local disk accessible " +
			"via hostPath from other pods on the same node, and prevents backup/snapshot. " +
			"Only tmpfs emptyDir for runtime sockets is acceptable.",
		Severity: SeverityHigh,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "5.13",
			NIST80053:        "CP-9, SI-12",
			NIST800190:       "§4.3",
			ISO27001:         "A.12.3.1, A.17.1.2",
			SOC2:             "A1.2",
			DISACCI:          "CCI-000366",
		},
		Remediation: "Mount the database data directory from a PersistentVolumeClaim. " +
			"Use emptyDir with medium: Memory only for socket/pid directories.",
	},
	{
		ID:     "DB-K8S-005",
		Domain: "Database",
		Title:  "Database Pods Must Set fsGroup",
		Description: "Without fsGroup in the pod securityContext, volume files may be " +
			"owned by root (world-readable) or not writable by the non-root database process. " +
			"Both outcomes create security failures: data exposure or startup failure " +
			"leading to privilege escalation attempts.",
		Severity: SeverityMedium,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.1",
			NIST80053:        "AC-3, AC-6",
			NIST800190:       "§4.3",
			ISO27001:         "A.9.4.1",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-002235",
		},
		Remediation: "Set spec.securityContext.fsGroup to the database process GID " +
			"(999 for postgres/mongo, 7474 for neo4j, 1000 for most others).",
	},
	{
		ID:     "DB-K8S-006",
		Domain: "Database",
		Title:  "No Credentials in Pod Annotations or Labels",
		Description: "Connection strings, DSNs, and API keys stored in pod annotations " +
			"or labels are visible to anyone with kubectl describe pod access. " +
			"This circumvents secrets management and exposes credentials widely.",
		Severity: SeverityHigh,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.10",
			NIST80053:        "IA-5, SC-28",
			NIST800190:       "§4.2",
			ISO27001:         "A.9.4.3, A.10.1.1",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-000366, CCI-002367",
		},
		Remediation: "Remove all connection strings, passwords, and API keys from " +
			"pod annotations and labels. Reference secret names only (not values).",
	},
	{
		ID:     "DB-K8S-007",
		Domain: "Database",
		Title:  "Neo4j APOC Plugin Must Restrict URL Loading",
		Description: "The Neo4j APOC library exposes apoc.load.json() and apoc.load.url() " +
			"which can make outbound HTTP requests to arbitrary URLs including the cloud " +
			"metadata endpoint (169.254.169.254), enabling SSRF-based credential theft " +
			"from inside the graph database container.",
		Severity: SeverityHigh,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "5.10",
			NIST80053:        "SC-7, SI-10",
			NIST800190:       "§4.5",
			ISO27001:         "A.13.1.1",
			SOC2:             "CC6.6",
			DISACCI:          "CCI-001090",
		},
		Remediation: "Set NEO4J_LABS_APOC_IMPORT_FILE_ENABLED=false and " +
			"NEO4J_dbms_security_allow__csv__import__from__file__urls=false. " +
			"Enforce egress NetworkPolicy blocking 169.254.169.254/32.",
	},
	{
		ID:     "SECRETS-003",
		Domain: "Secrets",
		Title:  "AI/Vectorizer API Keys Must Not Be in ENV Vars",
		Description: "API keys for AI inference providers (OpenAI, Cohere, HuggingFace, " +
			"Anthropic, Google, Azure) stored as literal ENV vars are visible via " +
			"kubectl describe pod or docker inspect. These keys have billing and " +
			"data-access scope beyond the immediate container.",
		Severity: SeverityHigh,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.10",
			NIST80053:        "IA-5, SC-28",
			NIST800190:       "§4.2",
			ISO27001:         "A.9.4.3, A.10.1.1",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-000366, CCI-002367",
		},
		Remediation: "Store AI provider API keys in Kubernetes Secrets or external " +
			"secrets manager. Inject via valueFrom.secretKeyRef, not literal value. " +
			"Rotate keys regularly and monitor for unexpected usage.",
	},
	{
		ID:     "DB-TF-001",
		Domain: "Database",
		Title:  "RDS Instance Must Be Encrypted and Private",
		Description: "AWS RDS instances with storage_encrypted=false expose data at rest. " +
			"publicly_accessible=true exposes the database port to the Internet. " +
			"Missing deletion_protection allows accidental data destruction. " +
			"Missing backup_retention prevents point-in-time recovery after a breach.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "N/A",
			NIST80053:        "SC-28, CP-9, SI-12",
			NIST800190:       "§4.2",
			ISO27001:         "A.10.1.1, A.12.3.1",
			SOC2:             "CC6.1, A1.2",
			DISACCI:          "CCI-000366, CCI-002418",
		},
		Remediation: "Set storage_encrypted=true, publicly_accessible=false, " +
			"deletion_protection=true, backup_retention_period>=7, " +
			"iam_database_authentication_enabled=true, skip_final_snapshot=false.",
	},
	{
		ID:     "DB-TF-002",
		Domain: "Database",
		Title:  "ElastiCache Must Use Encryption and Authentication",
		Description: "ElastiCache clusters without at-rest or in-transit encryption " +
			"expose all cached data in plaintext. Missing auth_token means any " +
			"network-adjacent client has full Redis access, enabling the CONFIG SET " +
			"arbitrary file write exploit chain against a writable container rootfs.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "N/A",
			NIST80053:        "SC-8, SC-28, IA-5",
			NIST800190:       "§4.3",
			ISO27001:         "A.10.1.1, A.13.2.3",
			SOC2:             "CC6.1, CC6.7",
			DISACCI:          "CCI-000366, CCI-002418",
		},
		Remediation: "Set at_rest_encryption_enabled=true, transit_encryption_enabled=true, " +
			"and provide a strong auth_token. Enable automatic_failover_enabled=true.",
	},
	{
		ID:     "DB-TF-003",
		Domain: "Database",
		Title:  "Managed NoSQL Services Must Have Encryption and Backup",
		Description: "DocumentDB without storage encryption exposes document data at rest. " +
			"DynamoDB without server-side encryption or point-in-time recovery lacks both " +
			"data protection and recovery capability after accidental deletion or ransomware.",
		Severity: SeverityHigh,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "N/A",
			NIST80053:        "SC-28, CP-9",
			NIST800190:       "§4.2",
			ISO27001:         "A.10.1.1, A.12.3.1",
			SOC2:             "CC6.1, A1.2",
			DISACCI:          "CCI-000366",
		},
		Remediation: "DocumentDB: storage_encrypted=true, backup_retention_period>=7, " +
			"deletion_protection=true. DynamoDB: enable server_side_encryption and " +
			"point_in_time_recovery blocks.",
	},

	// ── Domain: Terraform / IaC ────────────────────────────────────────────── //
	{
		ID:     "TF-001",
		Domain: "Terraform",
		Title:  "S3 Bucket Not Publicly Accessible",
		Description: "Public S3 buckets expose sensitive data to the internet. " +
			"acl = \"public-read\" or block_public_acls = false allows unauthorized access.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "N/A",
			NIST80053:        "AC-3, AC-6",
			NIST800190:       "§4.2",
			ISO27001:         "A.9.1.2, A.13.1.3",
			SOC2:             "CC6.1, CC6.3",
			DISACCI:          "CCI-000213",
		},
		Remediation: "Set acl = \"private\", enable S3 Block Public Access: " +
			"block_public_acls = true, block_public_policy = true, " +
			"ignore_public_acls = true, restrict_public_buckets = true.",
	},
	{
		ID:     "TF-002",
		Domain: "Terraform",
		Title:  "S3 Bucket Versioning Enabled",
		Description: "Without versioning, accidental deletion or overwrite of S3 objects " +
			"is permanent. Versioning enables recovery from ransomware or operator error.",
		Severity: SeverityMedium,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "N/A",
			NIST80053:        "CP-9",
			NIST800190:       "§4.2",
			ISO27001:         "A.12.3.1",
			SOC2:             "A1.2",
			DISACCI:          "CCI-000366",
		},
		Remediation: "Add versioning { enabled = true } to aws_s3_bucket resource " +
			"or use aws_s3_bucket_versioning with versioning_configuration { status = \"Enabled\" }.",
	},
	{
		ID:     "TF-003",
		Domain: "Terraform",
		Title:  "ECS Task Definition Not Privileged",
		Description: "Privileged ECS containers have full access to host devices and kernel " +
			"capabilities, enabling container escape.",
		Severity: SeverityHigh,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "5.5",
			NIST80053:        "AC-6, CM-7",
			NIST800190:       "§4.3",
			ISO27001:         "A.9.4.4",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-000381",
		},
		Remediation: "Set \"privileged\": false in container_definitions JSON. " +
			"Use specific Linux capabilities via linuxParameters instead of privileged mode.",
	},
	{
		ID:     "TF-004",
		Domain: "Terraform",
		Title:  "ECS Task Uses Non-Root User",
		Description: "Running containers as root inside ECS tasks increases blast radius " +
			"of container compromise. Container processes should run as non-root.",
		Severity: SeverityMedium,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.1",
			NIST80053:        "AC-6",
			NIST800190:       "§4.3",
			ISO27001:         "A.9.4.4",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-000366",
		},
		Remediation: "Add \"user\": \"nonroot\" or a numeric UID to each container definition. " +
			"Build images with a non-root USER directive.",
	},
	{
		ID:     "TF-005",
		Domain: "Terraform",
		Title:  "ECS Task Has Read-Only Root Filesystem",
		Description: "Writable root filesystems allow attackers to modify binaries, " +
			"install tools, or persist malware inside the container.",
		Severity: SeverityMedium,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "5.13",
			NIST80053:        "CM-7, SI-7",
			NIST800190:       "§4.3",
			ISO27001:         "A.12.6.2",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-000366",
		},
		Remediation: "Set \"readonlyRootFilesystem\": true in container definitions. " +
			"Use tmpfs mounts or EFS for paths that need writes.",
	},
	{
		ID:     "TF-006",
		Domain: "Terraform",
		Title:  "Security Group Allows Unrestricted Ingress",
		Description: "Security groups with 0.0.0.0/0 ingress on sensitive ports " +
			"(SSH 22, RDP 3389, DB ports) expose services to brute-force and exploitation.",
		Severity: SeverityHigh,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "N/A",
			NIST80053:        "SC-7, AC-17",
			NIST800190:       "§4.5",
			ISO27001:         "A.13.1.1, A.13.1.3",
			SOC2:             "CC6.6",
			DISACCI:          "CCI-001090",
		},
		Remediation: "Restrict ingress CIDR blocks to known IP ranges. " +
			"Never use 0.0.0.0/0 or ::/0 for sensitive ports. Use VPN or bastion hosts.",
	},
	{
		ID:     "TF-007",
		Domain: "Terraform",
		Title:  "KMS Encryption on EBS/RDS/S3",
		Description: "Unencrypted EBS volumes, RDS instances, and S3 buckets expose data " +
			"at rest to physical access or snapshot theft.",
		Severity: SeverityHigh,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "N/A",
			NIST80053:        "SC-28",
			NIST800190:       "§4.2",
			ISO27001:         "A.10.1.1",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-002476",
		},
		Remediation: "EBS: set encrypted = true and kms_key_id. " +
			"S3: configure aws_s3_bucket_server_side_encryption_configuration with KMS. " +
			"RDS: set storage_encrypted = true and kms_key_id.",
	},
	{
		ID:     "TF-008",
		Domain: "Terraform",
		Title:  "CloudTrail / Logging Enabled",
		Description: "Without CloudTrail, API actions go unrecorded, preventing " +
			"incident investigation and compliance auditing.",
		Severity: SeverityMedium,
		Type:     ControlDetective,
		Compliance: ComplianceMapping{
			CISDockerSection: "N/A",
			NIST80053:        "AU-2, AU-12",
			NIST800190:       "§4.5",
			ISO27001:         "A.12.4.1",
			SOC2:             "CC7.2",
			DISACCI:          "CCI-000172",
		},
		Remediation: "Enable aws_cloudtrail with is_multi_region_trail = true. " +
			"Enable S3 access logging via aws_s3_bucket_logging.",
	},
	{
		ID:     "TF-009",
		Domain: "Terraform",
		Title:  "IaC Vulnerability Scan (Terraform)",
		Description: "Terraform files may contain insecure configurations that automated " +
			"scanners like Trivy and Snyk can detect beyond regex-based pattern checks.",
		Severity: SeverityHigh,
		Type:     ControlDetective,
		Compliance: ComplianceMapping{
			CISDockerSection: "N/A",
			NIST80053:        "RA-5, CM-6",
			NIST800190:       "§4.2",
			ISO27001:         "A.12.6.1, A.14.2.1",
			SOC2:             "CC7.1",
			DISACCI:          "CCI-002617",
		},
		Remediation: "Install trivy or snyk. Run `trivy config .` or `snyk iac test .` " +
			"on Terraform directories. Fix identified misconfigurations.",
	},

	// ── Domain: Image (continued) ──────────────────────────────────────────── //
	{
		ID:     "IMAGE-011",
		Domain: "Docker",
		Title:  "No Unnecessary Debug/Dev Tools Installed",
		Description: "Debug tools (vim, gdb, strace, tcpdump, nmap) in production images " +
			"provide attackers with ready-made reconnaissance and exploitation utilities.",
		Severity: SeverityMedium,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.3",
			NIST80053:        "CM-7, SI-7",
			NIST800190:       "§4.2",
			ISO27001:         "A.12.6.2",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-000381",
		},
		Remediation: "Remove debug and development tools from production images. " +
			"Use multi-stage builds to exclude build-time tools from the final image.",
	},
	{
		ID:     "IMAGE-012",
		Domain: "Docker",
		Title:  "Package Manager Verification Enabled",
		Description: "Disabling GPG verification (--no-check-gpg, --allow-unauthenticated, " +
			"--trusted-host) allows installation of tampered or malicious packages.",
		Severity: SeverityMedium,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.11",
			NIST80053:        "SI-7",
			NIST800190:       "§4.2",
			ISO27001:         "A.14.2.4",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-001749",
		},
		Remediation: "Never use --allow-unauthenticated, --no-check-gpg, or pip --trusted-host. " +
			"Ensure package repositories use valid GPG signatures.",
	},
	{
		ID:     "IMAGE-013",
		Domain: "Docker",
		Title:  "VOLUME Not Targeting Sensitive Paths",
		Description: "VOLUME directives on /etc, /root, /var/run, or /tmp can bypass " +
			"read-only root filesystem protections and expose sensitive host paths.",
		Severity: SeverityMedium,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "5.13",
			NIST80053:        "CM-7, AC-6",
			NIST800190:       "§4.3",
			ISO27001:         "A.9.4.1",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-000366",
		},
		Remediation: "Avoid VOLUME for sensitive paths (/etc, /root, /var/run, /tmp). " +
			"Use specific application data paths instead.",
	},
	{
		ID:     "IMAGE-015",
		Domain: "Docker",
		Title:  "Minimal Base Image / Multi-Stage Build",
		Description: "Non-minimal base images (with shell, package managers) increase " +
			"attack surface. Multi-stage builds reduce final image to runtime-only dependencies.",
		Severity: SeverityLow,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.3",
			NIST80053:        "CM-7",
			NIST800190:       "§4.2",
			ISO27001:         "A.12.6.2",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-000381",
		},
		Remediation: "Use distroless, scratch, or alpine base images for production. " +
			"Employ multi-stage builds to exclude build tooling from the final stage.",
	},
	{
		ID:     "IMAGE-016",
		Domain: "Docker",
		Title:  "COPY . . Recursive Copy Warning",
		Description: "COPY . . copies the entire build context including .env, .git, " +
			"credentials, and other sensitive files into the image layer.",
		Severity: SeverityMedium,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.9",
			NIST80053:        "CM-7",
			NIST800190:       "§4.2",
			ISO27001:         "A.9.4.1",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-000366",
		},
		Remediation: "Use specific file paths in COPY instructions instead of COPY . . " +
			"Maintain a .dockerignore to exclude sensitive files (.env, .git, *.key).",
	},

	// ── Domain: Runtime (continued) ────────────────────────────────────────── //
	{
		ID:     "RUNTIME-013",
		Domain: "Kubernetes",
		Title:  "AppArmor / SELinux Profile Configured",
		Description: "Without AppArmor or SELinux profiles, containers lack mandatory " +
			"access control enforcement, increasing container escape risk.",
		Severity: SeverityMedium,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "5.1, 5.2",
			NIST80053:        "AC-3, AC-6",
			NIST800190:       "§4.4",
			ISO27001:         "A.9.4.1",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-002235",
		},
		Remediation: "Add container.apparmor.security.beta.kubernetes.io annotation " +
			"or configure seLinuxOptions in pod/container securityContext.",
	},
	{
		ID:     "RUNTIME-014",
		Domain: "Kubernetes",
		Title:  "Default Service Account Not Automounted",
		Description: "Automounting the default service account token gives every pod " +
			"a credential that may have excessive RBAC permissions.",
		Severity: SeverityMedium,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "5.32",
			NIST80053:        "AC-2, AC-6",
			NIST800190:       "§4.3",
			ISO27001:         "A.9.4.1",
			SOC2:             "CC6.1, CC6.3",
			DISACCI:          "CCI-000366",
		},
		Remediation: "Set automountServiceAccountToken: false in pod spec. " +
			"Create dedicated service accounts with minimal RBAC for pods that need API access.",
	},
	{
		ID:     "RUNTIME-015",
		Domain: "Docker",
		Title:  "Container ulimits Explicitly Set",
		Description: "Without explicit ulimits, containers inherit host defaults for " +
			"open files and processes, enabling fork bombs and file descriptor exhaustion.",
		Severity: SeverityLow,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "5.28",
			NIST80053:        "SC-5",
			NIST800190:       "§4.3",
			ISO27001:         "A.12.1.3",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-000366",
		},
		Remediation: "Set ulimits in Docker Compose (ulimits: nofile: 65535, nproc: 4096). " +
			"In Kubernetes, use LimitRange or PodSecurityPolicy for resource constraints.",
	},
	{
		ID:     "RUNTIME-016",
		Domain: "Docker",
		Title:  "Restart Policy Capped",
		Description: "restart: always without a retry cap can cause crash-loop resource " +
			"exhaustion. Use on-failure with max_retries to prevent infinite restarts.",
		Severity: SeverityLow,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "5.14",
			NIST80053:        "SC-5",
			NIST800190:       "§4.3",
			ISO27001:         "A.12.1.3",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-000366",
		},
		Remediation: "Use restart: on-failure:5 instead of restart: always. " +
			"In Compose v3+, use deploy.restart_policy with max_attempts.",
	},

	// ── Domain: Kubernetes ─────────────────────────────────────────────────── //
	{
		ID:     "K8S-001",
		Domain: "Kubernetes",
		Title:  "Namespace Isolation (Non-Default)",
		Description: "Running workloads in the default namespace prevents effective " +
			"network policy isolation and RBAC segmentation.",
		Severity: SeverityMedium,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "N/A",
			NIST80053:        "AC-4, SC-7",
			NIST800190:       "§4.3",
			ISO27001:         "A.13.1.3",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-001090",
		},
		Remediation: "Deploy workloads to dedicated namespaces, not 'default'. " +
			"Apply NetworkPolicies per namespace to enforce pod-to-pod segmentation.",
	},
	{
		ID:     "K8S-002",
		Domain: "Kubernetes",
		Title:  "Pod Anti-Affinity / Spread Rules Set",
		Description: "Without topology spread constraints or pod anti-affinity, all replicas " +
			"may land on the same node, creating a single point of failure.",
		Severity: SeverityLow,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "N/A",
			NIST80053:        "CP-9, SC-5",
			NIST800190:       "§4.3",
			ISO27001:         "A.17.1.1",
			SOC2:             "A1.2",
			DISACCI:          "CCI-002385",
		},
		Remediation: "Add topologySpreadConstraints or podAntiAffinity rules to spread " +
			"replicas across nodes/zones for high availability.",
	},
	{
		ID:     "K8S-003",
		Domain: "Kubernetes",
		Title:  "IaC Vulnerability Scan (Kubernetes Manifests)",
		Description: "Kubernetes manifests may contain misconfigurations that automated " +
			"scanners like Trivy and Snyk can detect beyond pattern-based checks.",
		Severity: SeverityHigh,
		Type:     ControlDetective,
		Compliance: ComplianceMapping{
			CISDockerSection: "N/A",
			NIST80053:        "RA-5, CM-6",
			NIST800190:       "§4.3",
			ISO27001:         "A.12.6.1, A.14.2.1",
			SOC2:             "CC7.1",
			DISACCI:          "CCI-002617",
		},
		Remediation: "Install trivy or snyk. Run `trivy config .` or `snyk iac test .` " +
			"on manifest directories. Fix identified misconfigurations.",
	},

	// ── Domain: Daemon (continued) ─────────────────────────────────────────── //
	{
		ID:     "DAEMON-006",
		Domain: "Docker",
		Title:  "Inter-Container Communication Disabled",
		Description: "Default Docker networking allows all containers to communicate freely. " +
			"Disabling ICC (--icc=false) forces explicit --link or network declarations.",
		Severity: SeverityMedium,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "2.3",
			NIST80053:        "SC-7",
			NIST800190:       "§4.5",
			ISO27001:         "A.13.1.3",
			SOC2:             "CC6.6",
			DISACCI:          "CCI-001090",
		},
		Remediation: "Set \"icc\": false in daemon.json. " +
			"Use user-defined bridge networks for services that need to communicate.",
	},
	{
		ID:     "DAEMON-007",
		Domain: "Docker",
		Title:  "Userland Proxy Disabled",
		Description: "The Docker userland proxy (docker-proxy) is a user-space TCP forwarder " +
			"that bypasses iptables connection tracking and has higher overhead.",
		Severity: SeverityLow,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "2.11",
			NIST80053:        "SC-5",
			NIST800190:       "§4.5",
			ISO27001:         "A.13.1.1",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-000366",
		},
		Remediation: "Set \"userland-proxy\": false in daemon.json to use iptables hairpin NAT.",
	},
	{
		ID:     "DAEMON-008",
		Domain: "Docker",
		Title:  "Live Restore Enabled",
		Description: "Without live-restore, all containers stop when the Docker daemon restarts " +
			"for an upgrade, causing unnecessary downtime.",
		Severity: SeverityLow,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "2.15",
			NIST80053:        "CP-10",
			NIST800190:       "§4.3",
			ISO27001:         "A.17.1.1",
			SOC2:             "A1.2",
			DISACCI:          "CCI-002385",
		},
		Remediation: "Set \"live-restore\": true in daemon.json to keep containers running " +
			"during daemon upgrades.",
	},

	// ── Domain: Host (continued) ───────────────────────────────────────────── //
	{
		ID:     "HOST-006",
		Domain: "Docker",
		Title:  "Auditd Rules for Docker Paths",
		Description: "Without auditd watches on Docker directories and binaries, " +
			"filesystem-level tampering goes undetected.",
		Severity: SeverityMedium,
		Type:     ControlDetective,
		Compliance: ComplianceMapping{
			CISDockerSection: "1.8-1.13",
			NIST80053:        "AU-2, AU-12",
			NIST800190:       "§4.5",
			ISO27001:         "A.12.4.1",
			SOC2:             "CC7.2",
			DISACCI:          "CCI-000172",
		},
		Remediation: "Add auditd -w rules for /etc/docker, /var/lib/docker, " +
			"/usr/bin/dockerd, /var/run/docker.sock, and Docker systemd unit files.",
	},
}
