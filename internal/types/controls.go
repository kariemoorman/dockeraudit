package types

// AllControls is the canonical registry of every hardening control
var AllControls = []Control{
	// ── Domain: Host ──────────────────────────────────────────────────────────
	{
		ID:      "HOST-001",
		Domain:  "Docker",
		Title:   "Minimal Host OS",
		Summary: "Use a container-optimized OS to shrink the kernel attack surface for container escapes.",
		Description: "Host should run a container-optimized or minimal OS. " +
			"Unnecessary packages and services expand the kernel attack surface available to container escapes.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "1.1",
			NIST80053:        "CM-6, CM-7",
			NIST800190:       "§4.5.1",
			ISO27001:         "A.8.8, A.8.9",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-000381",
		},
		Remediation: "Deploy Bottlerocket (AWS), Container-Optimized OS (GCP), Flatcar, or a minimal RHEL/Ubuntu image. " +
			"Remove compilers, debuggers, package manager at runtime, X11, and unused services. " +
			"Verify package count: `rpm -qa | wc -l` (RHEL) or `dpkg -l | wc -l` (Ubuntu). " +
			"Target: <300 packages on a running container host.",
	},
	{
		ID:      "HOST-002",
		Domain:  "Docker",
		Title:   "OS Security Patches Applied",
		Summary: "Keep the host kernel current so known CVEs cannot be exploited for container escape.",
		Description: "Unpatched kernel CVEs (Dirty Pipe CVE-2022-0847, runc CVE-2019-5736) " +
			"enable container escape. The host kernel must be current.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "1.2",
			NIST80053:        "CA-7, SI-2, RA-5",
			NIST800190:       "§4.5.3",
			ISO27001:         "A.8.8, A.8.9",
			SOC2:             "CC7.1",
			DISACCI:          "N/A",
		},
		Remediation: "Enable unattended-upgrades (Ubuntu/Debian) or dnf-automatic (RHEL/Fedora) for security-only patches. " +
			"Rebuild node AMIs weekly with the latest kernel; rotate node groups on new AMI to avoid in-place reboots. " +
			"Verify: `uname -r` for current kernel; cross-check against the distro's CVE feed. " +
			"Known container-escape CVEs to rule out: CVE-2022-0847 (Dirty Pipe, <5.16.11), CVE-2019-5736 (runc).",
	},
	{
		ID:      "HOST-003",
		Domain:  "Docker",
		Title:   "Host Firewall Configured",
		Summary: "Block unauthenticated access to the Docker daemon and kubelet from untrusted networks.",
		Description: "Docker daemon port 2375 must not be network-reachable without TLS. " +
			"Kubelet port 10250 must be restricted to control plane CIDR.",
		Severity: SeverityHigh,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "N/A",
			NIST80053:        "SC-7, AC-17",
			NIST800190:       "§4.5",
			ISO27001:         "A.8.20, A.8.22",
			SOC2:             "CC6.6",
			DISACCI:          "CCI-001097",
		},
		Remediation: "Block TCP 2375 via iptables/nftables or cloud security-group rules. " +
			"Restrict TCP 10250 (kubelet) to the control-plane subnet only. " +
			"Enforce IMDSv2 with `http_put_response_hop_limit: 1` to prevent SSRF to instance metadata. " +
			"Verify from an untrusted network: `nmap -p 2375,10250 <host>` — both ports must be closed or filtered.",
	},
	{
		ID:      "HOST-004",
		Domain:  "Docker",
		Title:   "SELinux or AppArmor in Enforcing Mode",
		Summary: "Enforce mandatory access control so container escapes are contained at the kernel.",
		Description: "Mandatory Access Controls provide kernel-level containment beyond " +
			"Linux namespace isolation. Critical defence-in-depth against container escape.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "5.2, 5.3",
			NIST80053:        "AC-3, AC-6, SI-7",
			NIST800190:       "§4.4.3, §4.5",
			ISO27001:         "A.8.3, A.8.9",
			SOC2:             "CC6.1, CC6.3",
			DISACCI:          "CCI-002235",
		},
		Remediation: "RHEL/CentOS/Fedora: set `SELINUX=enforcing` in /etc/selinux/config and reboot. " +
			"Ubuntu/Debian: ensure AppArmor is active (`systemctl is-active apparmor`) and Docker's default profile is loaded (`aa-status | grep docker-default`). " +
			"In Kubernetes, set `seLinuxOptions` on pods (SELinux) or the `container.apparmor.security.beta.kubernetes.io/<container>` annotation (AppArmor). " +
			"Verify: `getenforce` returns `Enforcing` OR `aa-status` shows the profile in enforce mode.",
	},
	{
		ID:      "HOST-005",
		Domain:  "Docker",
		Title:   "Auditd Rules for Container Runtime Binaries",
		Summary: "Audit runtime binary writes (dockerd, containerd, runc, shims) to detect malicious swaps.",
		Description: "Swapped runtime binaries (dockerd, containerd, runc, shims) " +
			"give an attacker hidden root control over every container on the host. " +
			"Auditd rules must log writes to these binaries.",
		Severity: SeverityHigh,
		Type:     ControlDetective,
		Compliance: ComplianceMapping{
			CISDockerSection: "1.1.3, 1.1.14-1.1.18",
			NIST80053:        "AU-2, AU-12",
			NIST800190:       "§4.5.5",
			ISO27001:         "A.8.15, A.8.16",
			SOC2:             "CC7.2",
			DISACCI:          "CCI-000172",
		},
		Remediation: "Add the following lines to /etc/audit/rules.d/docker.rules and reload with `augenrules --load`:\n" +
			"  -w /usr/bin/dockerd                    -p wa -k docker\n" +
			"  -w /usr/bin/containerd                 -p wa -k docker\n" +
			"  -w /usr/bin/containerd-shim            -p wa -k docker\n" +
			"  -w /usr/bin/containerd-shim-runc-v1    -p wa -k docker\n" +
			"  -w /usr/bin/containerd-shim-runc-v2    -p wa -k docker\n" +
			"  -w /usr/bin/runc                       -p wa -k docker\n" +
			"Verify with `auditctl -l | grep docker` — all six paths must appear.",
	},

	{
		ID:      "HOST-006",
		Domain:  "Docker",
		Title:   "Auditd Rules for Docker Config, Sockets & Data",
		Summary: "Audit writes to Docker configs, sockets, unit files, and data dirs for posture drift.",
		Description: "An edited daemon config, unit file, or socket (daemon.json, " +
			"docker.service, docker.sock) silently weakens runtime isolation, " +
			"adding insecure-registries, disabling userns-remap, or exposing the daemon " +
			"over TCP. Auditd rules must log writes to these paths.",
		Severity: SeverityMedium,
		Type:     ControlDetective,
		Compliance: ComplianceMapping{
			CISDockerSection: "1.1.4-1.1.13",
			NIST80053:        "AU-2, AU-12",
			NIST800190:       "§4.5.5",
			ISO27001:         "A.8.15, A.8.16",
			SOC2:             "CC7.2",
			DISACCI:          "CCI-000172",
		},
		Remediation: "Add the following lines to /etc/audit/rules.d/docker.rules and reload with `augenrules --load`:\n" +
			"  -w /run/containerd                     -p wa -k docker\n" +
			"  -w /var/lib/docker                     -p wa -k docker\n" +
			"  -w /etc/docker                         -p wa -k docker\n" +
			"  -w /lib/systemd/system/docker.service  -p wa -k docker\n" +
			"  -w /run/containerd/containerd.sock     -p wa -k docker\n" +
			"  -w /var/run/docker.sock                -p wa -k docker\n" +
			"  -w /etc/default/docker                 -p wa -k docker\n" +
			"  -w /etc/docker/daemon.json             -p wa -k docker\n" +
			"  -w /etc/containerd/config.toml         -p wa -k docker\n" +
			"  -w /etc/sysconfig/docker               -p wa -k docker\n" +
			"Verify with `auditctl -l | grep docker` — all ten paths must appear.",
	},

	// ── Domain: Daemon ────────────────────────────────────────────────────────
	{
		ID:      "DAEMON-001",
		Domain:  "Docker",
		Title:   "Docker Socket Not Mounted in Containers",
		Summary: "Never mount /var/run/docker.sock into a container — it equals host root.",
		Description: "Mounting /var/run/docker.sock into any container provides unconditional " +
			"root on the host. No legitimate application workload requires it.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "5.32",
			NIST80053:        "AC-3, AC-6, CM-11",
			NIST800190:       "§3.5.5, §4.5.5",
			ISO27001:         "A.8.3, A.8.9, A.8.18",
			SOC2:             "CC6.1, CC6.3",
			DISACCI:          "CCI-002235",
		},
		Remediation: "Audit for docker.sock mounts:\n" +
			"  kubectl get pods -A -o json | jq '.items[] | select((.spec.volumes // [])[].hostPath.path? // \"\" | contains(\"docker.sock\")) | .metadata.name'\n" +
			"  docker ps -q | xargs -I{} docker inspect {} --format '{{.Name}}: {{.HostConfig.Binds}}' | grep docker.sock\n" +
			"Remove the mount from Pod specs, Compose files, and `docker run -v` invocations. " +
			"Enforce via OPA Gatekeeper or Kyverno ClusterPolicy that rejects any hostPath containing `docker.sock`. " +
			"If a workload truly needs Docker API access, use a TCP+TLS daemon endpoint or a sidecar that proxies a narrow RBAC-scoped subset.",
	},
	{
		ID:      "DAEMON-002",
		Domain:  "Docker",
		Title:   "No Unauthenticated TCP Daemon",
		Summary: "Disable unauthenticated TCP on the Docker daemon (port 2375) — require TLS mutual auth.",
		Description: "Docker daemon listening on TCP 2375 without TLS is a remotely " +
			"exploitable root backdoor on any network-reachable host.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "2.7",
			NIST80053:        "AC-17, IA-3, SC-8",
			NIST800190:       "§4.5.1",
			ISO27001:         "A.8.20, A.8.9",
			SOC2:             "CC6.6",
			DISACCI:          "CCI-002418",
		},
		Remediation: "Remove `-H tcp://...:2375` from dockerd args and the `hosts` key in /etc/docker/daemon.json; " +
			"leave only `unix:///var/run/docker.sock`. " +
			"If remote access is required, bind TLS on port 2376 with mutual auth by setting `tls: true`, `tlsverify: true`, " +
			"`tlscacert`, `tlscert`, `tlskey` in daemon.json. " +
			"Verify: `ss -tlnp | grep ':2375'` must return empty; `curl -k https://<host>:2376/version` without a client cert must fail with TLS handshake error.",
	},
	{
		ID:      "DAEMON-003",
		Domain:  "Docker",
		Title:   "User Namespace Remapping Enabled",
		Summary: "Enable userns-remap so container UID 0 does not map to host root.",
		Description: "Without userns-remap, UID 0 inside a container maps directly to " +
			"UID 0 on the host kernel. A container escape is immediately full root.",
		Severity: SeverityHigh,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "2.9",
			NIST80053:        "AC-3, AC-6",
			NIST800190:       "§4.4.3",
			ISO27001:         "A.8.3, A.8.9",
			SOC2:             "CC6.1, CC6.3",
			DISACCI:          "CCI-002235",
		},
		Remediation: "Set `\"userns-remap\": \"default\"` in /etc/docker/daemon.json and restart Docker " +
			"(`systemctl restart docker`). Docker creates `dockremap` user/group and sub-UID/GID ranges on first start. " +
			"Caveats: existing images, volumes, and bind-mounts shift to the remapped ownership — plan for image re-pulls, " +
			"chowning of persistent data, and incompatibility with `--privileged`, `--net=host`, `--pid=host`, and " +
			"external storage plugins that rely on host UIDs. " +
			"Verify: `docker info --format '{{.DockerRootDir}}'` shows path with `.<uid>.<gid>` suffix; `/etc/subuid` and `/etc/subgid` contain a `dockremap` entry.",
	},
	{
		ID:      "DAEMON-004",
		Domain:  "Docker",
		Title:   "Docker Content Trust Enabled",
		Summary: "Require signed images so the Docker daemon refuses tampered or unsigned pulls.",
		Description: "Without content trust, images can be pulled with tampered layers " +
			"or swapped digests at the registry or via MITM without detection.",
		Severity: SeverityHigh,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.5",
			NIST80053:        "SI-7, CM-14, SR-4, SR-11",
			NIST800190:       "§4.1.5",
			ISO27001:         "A.8.24, A.5.7",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-001749",
		},
		Remediation: "Export `DOCKER_CONTENT_TRUST=1` in the shell or set it in /etc/docker/daemon.json so every " +
			"`docker pull`, `push`, and `build FROM` validates Notary v1 signatures. " +
			"Docker Content Trust is daemon-side only — Kubernetes kubelet does NOT honor it. " +
			"For cluster-wide enforcement, deploy Sigstore Cosign with Kyverno `verifyImages` ClusterPolicy or Connaisseur admission controller. " +
			"Verify: `docker pull <unsigned-image>` must fail with 'No valid trust data' when DCT is set.",
	},
	{
		ID:      "DAEMON-005",
		Domain:  "Docker",
		Title:   "Daemon Log Rotation Configured",
		Summary: "Bound Docker daemon log size with log-driver rotation to prevent disk exhaustion.",
		Description: "Unbounded container log growth fills host disks and evicts other workloads. " +
			"Missing log rotation also destroys forensic evidence by forcing operators to truncate logs manually. " +
			"Bounded rotation plus central log shipping preserves both stability and audit trail.",
		Severity: SeverityMedium,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "2.3, 2.13",
			NIST80053:        "AU-3, AU-9, AU-12, AU-11",
			NIST800190:       "§4.5",
			ISO27001:         "A.8.15, A.8.16",
			SOC2:             "CC7.2",
			DISACCI:          "CCI-000172",
		},
		Remediation: "Add to /etc/docker/daemon.json and restart Docker:\n" +
			"  \"log-driver\": \"json-file\",\n" +
			"  \"log-opts\": { \"max-size\": \"10m\", \"max-file\": \"5\" }\n" +
			"Verify: `docker info --format '{{.LoggingDriver}} {{.LoggingOptions}}'` shows `json-file` with the size/file caps. " +
			"For centralized logging at scale, replace the local driver with `fluentd`, `journald`, `gelf`, or `syslog` pointing to a SIEM. " +
			"Per-container overrides are still respected via `docker run --log-opt`.",
	},

	{
		ID:      "DAEMON-006",
		Domain:  "Docker",
		Title:   "Inter-Container Communication Disabled",
		Summary: "Disable default-bridge inter-container traffic; force explicit user-defined networks.",
		Description: "Default Docker networking allows all containers to communicate freely. " +
			"Disabling ICC (--icc=false) forces explicit --link or network declarations.",
		Severity: SeverityMedium,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "2.2",
			NIST80053:        "SC-7",
			NIST800190:       "§4.4.2",
			ISO27001:         "A.8.22, A.8.9",
			SOC2:             "CC6.6",
			DISACCI:          "CCI-001090",
		},
		Remediation: "Set `\"icc\": false` in /etc/docker/daemon.json and restart Docker. " +
			"For services that must communicate, create user-defined bridge networks explicitly: " +
			"`docker network create app-net` and attach containers via `--network app-net`. " +
			"Verify: `docker network inspect bridge --format '{{index .Options \"com.docker.network.bridge.enable_icc\"}}'` returns `false`. " +
			"In Kubernetes, the analogous control is a default-deny NetworkPolicy (NETWORK-001).",
	},

	{
		ID:      "DAEMON-007",
		Domain:  "Docker",
		Title:   "Userland Proxy Disabled",
		Summary: "Disable docker-proxy; use iptables hairpin NAT for better tracing and lower overhead.",
		Description: "The Docker userland proxy (docker-proxy) is a user-space TCP forwarder " +
			"that bypasses iptables connection tracking and has higher overhead.",
		Severity: SeverityLow,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "2.16",
			NIST80053:        "SC-5",
			NIST800190:       "§4.5",
			ISO27001:         "A.8.20, A.8.9",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-000366",
		},
		Remediation: "Set `\"userland-proxy\": false` in /etc/docker/daemon.json and restart Docker. " +
			"Port publishing will now route via iptables hairpin NAT (DNAT + MASQUERADE) instead of the docker-proxy user-space forwarder. " +
			"Verify: `docker info --format '{{.UserlandProxy}}'` returns `false`; `pgrep -af docker-proxy` returns nothing while containers with published ports are running. " +
			"Requires a kernel with loopback hairpin NAT support (4.x+); legacy kernels may fall back to docker-proxy and silently ignore this setting.",
	},

	{
		ID:      "DAEMON-008",
		Domain:  "Docker",
		Title:   "Live Restore Enabled",
		Summary: "Enable live-restore so containers keep running through Docker daemon upgrades.",
		Description: "Without live-restore, all containers stop when the Docker daemon restarts " +
			"for an upgrade, causing unnecessary downtime.",
		Severity: SeverityLow,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "2.15",
			NIST80053:        "CP-10",
			NIST800190:       "§4.4.3",
			ISO27001:         "A.5.29, A.5.30",
			SOC2:             "A1.2",
			DISACCI:          "N/A",
		},
		Remediation: "Set `\"live-restore\": true` in /etc/docker/daemon.json and restart Docker once to activate. " +
			"Subsequent `systemctl restart docker` or daemon upgrades will leave running containers untouched. " +
			"Verify: `docker info --format '{{.LiveRestoreEnabled}}'` returns `true`. " +
			"Incompatible with swarm mode — live-restore is silently ignored on swarm nodes; use rolling service updates there instead.",
	},

	// ── Domain: Image ───────────────────────────────────────────────────────── //
	{
		ID:      "IMAGE-001",
		Domain:  "Docker",
		Title:   "Images Pinned by Digest",
		Summary: "Pin base images by sha256 digest to prevent silent tag-replacement supply-chain attacks.",
		Description: "Mutable tags can be silently replaced at the registry. " +
			"Pin all images by digest (sha256:...) to guarantee immutability.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.1, 4.2",
			NIST80053:        "CM-14, SI-7, SR-4",
			NIST800190:       "§4.1.5, §4.2.2",
			ISO27001:         "A.8.25, A.8.9",
			SOC2:             "CC6.1",
			DISACCI:          "N/A",
		},
		Remediation: "Replace every `FROM <image>:<tag>` and Kubernetes `image:` field with `<image>@sha256:<digest>`. " +
			"Resolve digests in CI with `crane digest <image>:<tag>` or `skopeo inspect --format {{.Digest}} docker://<image>:<tag>`. " +
			"Verify: `grep -rE 'FROM [^@]+:[^ ]+$' ` on Dockerfiles must return zero matches; " +
			"`kubectl get pods -A -o json | jq -r '.items[].spec.containers[].image' | grep -v '@sha256:'` must be empty.",
	},
	{
		ID:      "IMAGE-002",
		Domain:  "Docker",
		Title:   "No Secrets in Image Layers",
		Summary: "Never bake secrets into image layers — they're readable by every puller and unrevocable.",
		Description: "Secrets baked into image layers cannot be revoked and are accessible " +
			"to anyone who can pull the image — including after a 'deletion' layer.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.10",
			NIST80053:        "IA-5, SC-28",
			NIST800190:       "§4.1.4",
			ISO27001:         "A.5.17, A.8.12, A.8.24",
			SOC2:             "CC6.1, CC6.7",
			DISACCI:          "CCI-000366, CCI-002367",
		},
		Remediation: "Scan built images and Dockerfile history before push:\n" +
			"  trivy image --scanners secret <image>\n" +
			"  trufflehog docker --image <image>\n" +
			"  dive <image>    # manual layer inspection\n" +
			"Inject secrets at runtime only — via Kubernetes CSI secrets driver, HashiCorp Vault agent, " +
			"AWS Secrets Manager SDK, or `--env-file` (outside VCS). " +
			"For build-time secrets, use BuildKit `--mount=type=secret` which never writes to layers.",
	},
	{
		ID:      "IMAGE-003",
		Domain:  "Docker",
		Title:   "Image Vulnerability Scan",
		Summary: "Scan images for CVEs in CI and block pipelines on fixable CRITICAL or HIGH findings.",
		Description: "Container images accumulate CVEs from OS packages and language dependencies. " +
			"Unscanned images run with known exploitable vulnerabilities.",
		Severity: SeverityCritical,
		Type:     ControlDetective,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.4",
			NIST80053:        "CA-7, RA-5, SR-10, SI-2",
			NIST800190:       "§3.1.1, §4.1.1",
			ISO27001:         "A.8.8, A.8.26, A.5.7",
			SOC2:             "CC7.1",
			DISACCI:          "CCI-001067",
		},
		Remediation: "Integrate a scanner into CI — run on every build and block on fixable Critical/High:\n" +
			"  trivy image --severity CRITICAL,HIGH --ignore-unfixed --exit-code 1 <image>\n" +
			"  snyk container test <image> --severity-threshold=high\n" +
			"  grype <image> --fail-on high\n" +
			"Also enable continuous re-scanning of stored images: ECR Enhanced Scanning (Inspector v2), " +
			"GCP Artifact Registry + Container Analysis, GitHub advanced security, or Harbor/Quay native scanners. " +
			"Re-scan on vulnerability-DB refresh — new CVEs apply to already-built images.",
	},
	{
		ID:      "IMAGE-004",
		Domain:  "Docker",
		Title:   "No SUID/SGID/World-Writable Files in Image",
		Summary: "Strip SUID/SGID and world-writable bits from images to block local privilege escalation.",
		Description: "SUID/SGID binaries inside a container are exploitable for local " +
			"privilege escalation without any external capability. " +
			"World-writable files allow any process to overwrite binaries or configs, " +
			"enabling persistence after initial compromise.",
		Severity: SeverityHigh,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.8",
			NIST80053:        "AC-6, CM-7",
			NIST800190:       "§4.1.2",
			ISO27001:         "A.8.8, A.8.9",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-002235",
		},
		Remediation: "In the Dockerfile (near the end, before USER):\n" +
			"  RUN find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f -exec chmod a-s {} \\;\n" +
			"  RUN find / -xdev -perm -0002 -type f -exec chmod o-w {} \\;\n" +
			"Verify no SUID/SGID/world-writable remain in the built image:\n" +
			"  docker run --rm <image> find / -xdev \\( -perm -4000 -o -perm -2000 -o -perm -0002 \\) -type f\n" +
			"Note: some packages (e.g. ping, mount, sudo) legitimately need SUID — allow-list these rather than blanket-stripping if required.",
	},
	{
		ID:      "IMAGE-005",
		Domain:  "Docker",
		Title:   "Non-Root USER in Dockerfile",
		Summary: "Declare a non-root USER in every Dockerfile so runtime UID is not 0 by default.",
		Description: "Running as UID 0 in a container provides excessive kernel access. " +
			"All application containers must define a non-root USER.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.1",
			NIST80053:        "AC-6, IA-5",
			NIST800190:       "§4.1.2, §4.4.3",
			ISO27001:         "A.8.3, A.8.9",
			SOC2:             "CC6.1, CC6.3",
			DISACCI:          "CCI-002235",
		},
		Remediation: "Create and switch to a dedicated non-root user near the end of the Dockerfile:\n" +
			"  RUN groupadd -r app && useradd -r -g app -u 10001 app\n" +
			"  USER 10001    # numeric UID — Kubernetes runAsNonRoot only trusts numeric form\n" +
			"Ensure directories the process writes to are chowned to this UID before USER. " +
			"Verify: `docker run --rm <image> id` returns `uid=10001` (not 0); " +
			"pair with Pod `securityContext.runAsNonRoot: true` for defense-in-depth.",
	},
	{
		ID:      "IMAGE-006",
		Domain:  "Docker",
		Title:   "ADD Not Used for Remote URLs",
		Summary: "Never use ADD <URL>; it fetches remote content without checksum verification.",
		Description: "ADD with a URL fetches content at build time without checksum verification, " +
			"enabling supply chain tampering.",
		Severity: SeverityMedium,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.9",
			NIST80053:        "SI-7, CM-14",
			NIST800190:       "§4.1.5",
			ISO27001:         "A.8.25, A.8.28",
			SOC2:             "CC6.1, CC6.8",
			DISACCI:          "CCI-001762",
		},
		Remediation: "Replace every `ADD <url>` with an explicit download + checksum verification step:\n" +
			"  RUN curl -fsSL -o /tmp/app.tgz https://example.com/app.tgz \\\n" +
			"      && echo \"<expected-sha256>  /tmp/app.tgz\" | sha256sum -c - \\\n" +
			"      && tar -xzf /tmp/app.tgz -C /opt/app \\\n" +
			"      && rm /tmp/app.tgz\n" +
			"Use `COPY` (never `ADD`) for local files — see IMAGE-014. " +
			"Verify: `grep -nE '^ADD[[:space:]]+(https?|ftp):' Dockerfile` returns no matches.",
	},
	{
		ID:      "IMAGE-007",
		Domain:  "Docker",
		Title:   "No Secret/Credential Files in Image Filesystem",
		Summary: "Exclude credential files (.env, id_rsa, kubeconfig, tokens) from images via .dockerignore.",
		Description: "Credential files (.env, id_rsa, .npmrc, credentials, terraform.tfvars, " +
			"wp-config.php, service-account.json, .vault-token, kubeconfig, .bash_history) " +
			"baked into image layers grant any image puller access to credentials. " +
			"Deleted files in an earlier layer are still readable by exporting the image tarball.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.10",
			NIST80053:        "IA-5, SC-28",
			NIST800190:       "§4.1.4",
			ISO27001:         "A.5.17, A.8.12, A.8.24",
			SOC2:             "CC6.1, CC6.7",
			DISACCI:          "CCI-000366, CCI-002367",
		},
		Remediation: "Add a broad .dockerignore at the repo root:\n" +
			"  .env*\n" +
			"  **/id_rsa*\n" +
			"  **/.npmrc\n" +
			"  **/credentials\n" +
			"  **/*.tfvars\n" +
			"  **/kubeconfig*\n" +
			"  **/.vault-token\n" +
			"  **/.aws/credentials\n" +
			"  **/.ssh/\n" +
			"Use multi-stage builds so build-time secrets never reach the final stage. " +
			"Deleted files in earlier layers are still readable — never `COPY` a secret then `RUN rm`. " +
			"Verify: `trivy image --scanners secret <image>` and `trufflehog docker --image <image>` both clean.",
	},
	{
		ID:      "IMAGE-008",
		Domain:  "Docker",
		Title:   "No End-of-Life Base Image",
		Summary: "Upgrade base images before they reach EOL — no upstream patches means unfixable CVEs.",
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
			NIST80053:        "SA-22, SI-2, RA-5",
			NIST800190:       "§4.1.1",
			ISO27001:         "A.8.8, A.5.7",
			SOC2:             "CC7.1",
			DISACCI:          "CCI-002617",
		},
		Remediation: "Identify EOL bases and upgrade to a currently supported version. " +
			"Reference EOL tracker: https://endoflife.date (programmatic API: https://endoflife.date/api/<product>.json). " +
			"For production workloads, prefer `gcr.io/distroless/*`, `cgr.dev/chainguard/*`, or `scratch` — minimal images have the smallest CVE surface. " +
			"Automate detection in CI with Trivy's `--detection-priority comprehensive` mode and custom EOL rules. " +
			"Verify: `docker run --rm <image> cat /etc/os-release` — cross-check VERSION_ID against the tracker.",
	},
	{
		ID:      "IMAGE-009",
		Domain:  "Docker",
		Title:   "No Crypto Miner Artifacts",
		Summary: "Detect crypto miners (xmrig, ethminer, stratum URLs) in images before deployment.",
		Description: "Crypto miners (xmrig, cpuminer, ethminer, cgminer, bfgminer, lolminer, " +
			"t-rex, nbminer, teamredminer, gminer, srbminer) are commonly injected into " +
			"compromised or malicious images. Mining pool URLs (stratum+tcp://, moneroocean., " +
			"nanopool.org, f2pool.com, nicehash.com) in image history or ENV are definitive indicators.",
		Severity: SeverityCritical,
		Type:     ControlDetective,
		Compliance: ComplianceMapping{
			CISDockerSection: "N/A",
			NIST80053:        "SI-3, SI-7, SR-11(3)",
			NIST800190:       "§3.1.3, §4.1.3",
			ISO27001:         "A.8.7, A.5.7",
			SOC2:             "CC6.1, CC6.8",
			DISACCI:          "CCI-001764",
		},
		Remediation: "Scan images for known miner signatures and indicators:\n" +
			"  trivy image --scanners vuln,misconfig <image>\n" +
			"  docker history --no-trunc <image> | grep -iE 'xmrig|ethminer|cpuminer|stratum\\+tcp'\n" +
			"  docker inspect <image> --format '{{.Config.Env}}' | grep -iE 'pool|wallet|stratum'\n" +
			"Pull only from trusted registries; verify signatures with `cosign verify` before `kubectl apply`. " +
			"At runtime deploy Falco with the built-in `Detect crypto miners using the Stratum protocol` rule " +
			"plus egress NetworkPolicy blocking known mining pool domains.",
	},
	{
		ID:      "IMAGE-010",
		Domain:  "Docker",
		Title:   "No Backdoored Package Versions (xz-utils CVE-2024-3094)",
		Summary: "Block known-backdoored package versions (xz-utils 5.6.0–5.6.1, CVE-2024-3094).",
		Description: "xz-utils versions 5.6.0 and 5.6.1 contain a backdoor in liblzma " +
			"that enables remote code execution via systemd/OpenSSH on affected systems " +
			"(CVE-2024-3094, CVSS 10.0). These versions were distributed in " +
			"Debian Sid, Fedora 40 Beta, Kali 2024.1, and several rolling-release distros.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.4",
			NIST80053:        "SI-2, RA-5, SI-7, SR-4, SR-11",
			NIST800190:       "§3.1.3, §3.1.1, §4.1.3, §4.1.1",
			ISO27001:         "A.8.8, A.8.7, A.5.7",
			SOC2:             "CC7.1, CC6.8",
			DISACCI:          "CCI-001241",
		},
		Remediation: "Confirm xz-utils version inside the image and rebuild if compromised:\n" +
			"  docker run --rm <image> xz --version   # must report ≤ 5.4.x (5.4.6 is confirmed safe)\n" +
			"  trivy image --severity CRITICAL <image> | grep -i CVE-2024-3094\n" +
			"  snyk container test <image>\n" +
			"If backdoored: rebuild from a known-good base layer pulled after 2024-03-29 with pinned xz-utils 5.4.6 " +
			"(or distribution-specific backport). Rotate any SSH keys, host credentials, or secrets that might have been exposed on affected hosts.",
	},

	{
		ID:      "IMAGE-011",
		Domain:  "Docker",
		Title:   "No Unnecessary Debug/Dev Tools Installed",
		Summary: "Remove debug/dev tools (vim, gdb, strace, tcpdump, nmap) from production images.",
		Description: "Debug tools (vim, gdb, strace, tcpdump, nmap) in production images " +
			"provide attackers with ready-made reconnaissance and exploitation utilities.",
		Severity: SeverityMedium,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.3",
			NIST80053:        "CM-7, SI-7",
			NIST800190:       "§4.1.2",
			ISO27001:         "A.8.19, A.8.9",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-000381",
		},
		Remediation: "Use multi-stage builds: install build-time tools only in a `builder` stage, " +
			"then `COPY --from=builder` artefacts into a minimal runtime stage (distroless or scratch). " +
			"Or explicitly purge before the final image:\n" +
			"  RUN apt-get remove -y --purge vim* gdb strace tcpdump nmap netcat* curl wget perl \\\n" +
			"      && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*\n" +
			"Verify with `trivy image --scanners misconfig` or manually: `docker run --rm <image> which vim gdb strace` returns nothing.",
	},

	{
		ID:      "IMAGE-012",
		Domain:  "Docker",
		Title:   "Package Manager Verification Enabled",
		Summary: "Keep GPG signature verification on; never use --no-check-gpg or --trusted-host.",
		Description: "Disabling GPG verification (--no-check-gpg, --allow-unauthenticated, " +
			"--trusted-host) allows installation of tampered or malicious packages.",
		Severity: SeverityMedium,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.11",
			NIST80053:        "SI-7",
			NIST800190:       "§4.1.5",
			ISO27001:         "A.8.19, A.8.24",
			SOC2:             "CC6.1, CC6.8",
			DISACCI:          "CCI-001749",
		},
		Remediation: "Never disable package signature verification anywhere in the Dockerfile. " +
			"Forbidden flags across package managers:\n" +
			"  apt:   --allow-unauthenticated, APT::Get::AllowUnauthenticated \"true\"\n" +
			"  dnf:   --nogpgcheck, gpgcheck=0\n" +
			"  apk:   --allow-untrusted\n" +
			"  pip:   --trusted-host, --index-url http:// (non-HTTPS)\n" +
			"  npm:   --strict-ssl=false, registry http://\n" +
			"  gem:   --no-check-hash\n" +
			"Verify: `grep -nE 'allow-unauthenticated|nogpgcheck|allow-untrusted|trusted-host|strict-ssl=false' Dockerfile` returns no matches.",
	},

	{
		ID:      "IMAGE-013",
		Domain:  "Docker",
		Title:   "VOLUME Not Targeting Sensitive Paths",
		Summary: "Do not declare VOLUME on /etc, /root, /var/run, or /tmp — it bypasses read-only rootfs.",
		Description: "VOLUME directives on /etc, /root, /var/run, or /tmp can bypass " +
			"read-only root filesystem protections and expose sensitive host paths.",
		Severity: SeverityMedium,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "N/A",
			NIST80053:        "CM-7, AC-6",
			NIST800190:       "§4.1.2, §4.4.3",
			ISO27001:         "A.8.3, A.8.9",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-000366",
		},
		Remediation: "Restrict VOLUME directives to application-specific data paths (e.g. `/var/lib/<app>`, `/data`). " +
			"Never declare VOLUME on: /, /etc, /root, /var/run, /run, /tmp, /proc, /sys, /dev, /boot. " +
			"For ephemeral write space, use `tmpfs` at runtime (`--tmpfs /tmp` or emptyDir+medium:Memory) instead of VOLUME. " +
			"Verify: `grep -nE '^VOLUME.*(\\s|\\[|\")(/|/etc|/root|/var/run|/run|/tmp|/proc|/sys|/dev|/boot)(/|\"|\\])' Dockerfile` returns no matches.",
	},

	{
		ID:      "IMAGE-014",
		Domain:  "Docker",
		Title:   "Use COPY Instead of ADD for Local Files",
		Summary: "Use COPY for local files; reserve ADD for intentional tar auto-extraction only.",
		Description: "The ADD instruction silently auto-extracts tar archives and accepts " +
			"remote URLs, making its behaviour opaque and potentially dangerous. " +
			"COPY should be used for all local file transfers; ADD is only appropriate " +
			"when tar auto-extraction is explicitly required.",
		Severity: SeverityMedium,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.9",
			NIST80053:        "CM-7, SI-7",
			NIST800190:       "§4.1.2",
			ISO27001:         "A.8.19, A.8.28",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-000381",
		},
		Remediation: "Replace every `ADD <local-path>` with `COPY <local-path>`. " +
			"Reserve `ADD` only for cases where implicit tar auto-extraction is the point " +
			"(e.g. `ADD rootfs.tar.gz /`) — and document why in a Dockerfile comment. " +
			"For remote URLs, use an explicit curl + checksum + extract sequence instead (see IMAGE-006). " +
			"Verify: `grep -nE '^ADD[[:space:]]+[^h]' Dockerfile` — every remaining `ADD` should either be a tar file or have an explanatory comment.",
	},

	{
		ID:      "IMAGE-015",
		Domain:  "Docker",
		Title:   "Minimal Base Image / Multi-Stage Build",
		Summary: "Use distroless or alpine bases with multi-stage builds to minimize attack surface.",
		Description: "Non-minimal base images (with shell, package managers) increase " +
			"attack surface. Multi-stage builds reduce final image to runtime-only dependencies.",
		Severity: SeverityLow,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.3",
			NIST80053:        "CM-7",
			NIST800190:       "§4.1.2, §4.5.1",
			ISO27001:         "A.8.19, A.8.9",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-000381",
		},
		Remediation: "Adopt multi-stage builds: heavy tooling stays in the `builder` stage; final stage is minimal.\n" +
			"  FROM golang:1.22 AS builder\n" +
			"  WORKDIR /src\n" +
			"  COPY . .\n" +
			"  RUN CGO_ENABLED=0 go build -o /out/app ./cmd/app\n" +
			"\n" +
			"  FROM gcr.io/distroless/static-debian12:nonroot\n" +
			"  COPY --from=builder /out/app /app\n" +
			"  USER nonroot\n" +
			"  ENTRYPOINT [\"/app\"]\n" +
			"Preferred bases: `gcr.io/distroless/*`, `cgr.dev/chainguard/*`, or `scratch`. " +
			"Verify: final image size < 50 MB for typical Go/Rust services; `docker run --rm <image> sh` should fail (no shell present).",
	},
	
	{
		ID:      "IMAGE-016",
		Domain:  "Docker",
		Title:   "COPY . . Recursive Copy Warning",
		Summary: "Avoid COPY . . — it pulls the full context including .env, .git, into the image layer.",
		Description: "COPY . . copies the entire build context including .env, .git, " +
			"credentials, and other sensitive files into the image layer.",
		Severity: SeverityMedium,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.9",
			NIST80053:        "CM-7",
			NIST800190:       "§4.1.2, §4.1.4",
			ISO27001:         "A.8.3, A.8.28",
			SOC2:             "CC6.1, CC6.7",
			DISACCI:          "CCI-000366",
		},
		Remediation: "Replace blanket `COPY . .` with explicit path lists:\n" +
			"  COPY go.mod go.sum ./\n" +
			"  COPY cmd/ cmd/\n" +
			"  COPY internal/ internal/\n" +
			"Maintain a strict .dockerignore in the repo root to exclude VCS + secrets + local build state:\n" +
			"  .git/\n" +
			"  .env*\n" +
			"  **/*.key\n" +
			"  **/*.pem\n" +
			"  node_modules/\n" +
			"  .vscode/\n" +
			"  .idea/\n" +
			"Verify: `grep -nE '^COPY[[:space:]]+\\.[[:space:]]+\\.' Dockerfile` returns no matches, " +
			"and audit the image with `dive <image>` for unexpected files in the final layers.",
	},

	// ── Domain: Runtime ─────────────────────────────────────────────────────── //
	{
		ID:      "RUNTIME-001",
		Domain:  "Docker",
		Title:   "Containers Not Running as Root",
		Summary: "Run containers as a non-zero UID so a compromised process cannot act as host root.",
		Description: "Runtime UID 0 in a container (without user namespace remapping) " +
			"maps to host root. Application compromise equals host compromise.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.1",
			NIST80053:        "AC-6, IA-5",
			NIST800190:       "§4.4.3",
			ISO27001:         "A.8.2, A.8.3, A.8.9",
			SOC2:             "CC6.1, CC6.3",
			DISACCI:          "CCI-002235",
		},
		Remediation: "Set in Pod spec (at pod level, inherited by all containers):\n" +
			"  spec.securityContext.runAsNonRoot: true\n" +
			"  spec.securityContext.runAsUser: 10001       # any non-zero UID\n" +
			"  spec.securityContext.runAsGroup: 10001\n" +
			"Docker run equivalent: `--user 10001:10001`. Docker Compose: `user: \"10001:10001\"`. " +
			"Enforce cluster-wide via Kyverno or OPA Gatekeeper rejecting any container with `runAsUser: 0` or omitted. " +
			"Verify: `kubectl get pod <name> -o jsonpath='{.spec.containers[*].securityContext.runAsUser}'` returns non-zero; `docker exec <id> id -u` returns non-zero.",
	},

	{
		ID:      "RUNTIME-002",
		Domain:  "Docker",
		Title:   "Privileged Containers Disabled",
		Summary: "Never run privileged containers — they bypass namespaces, capabilities, and seccomp.",
		Description: "Privileged mode grants nearly all kernel capabilities and disables most " +
			"security mechanisms. Equivalent to running directly on the host.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "5.5",
			NIST80053:        "AC-3, AC-6",
			NIST800190:       "§3.4.3, §4.4.3",
			ISO27001:         "A.8.2, A.8.3, A.8.9",
			SOC2:             "CC6.1, CC6.3",
			DISACCI:          "CCI-002235",
		},
		Remediation: "Set `spec.containers[].securityContext.privileged: false` (or omit — it defaults to false). " +
			"Never pass `docker run --privileged` in production. " +
			"For legitimate use cases (host device access, kernel modules), grant narrow capabilities instead: " +
			"`capabilities.add: [NET_ADMIN]` or specific `volumeDevices`. " +
			"Enforce cluster-wide via Kyverno `disallow-privileged-containers` or Pod Security Admission `baseline`/`restricted`. " +
			"Verify: `kubectl get pod <name> -o jsonpath='{.spec.containers[*].securityContext.privileged}'` returns `false` or empty.",
	},

	{
		ID:      "RUNTIME-003",
		Domain:  "Docker",
		Title:   "All Capabilities Dropped",
		Summary: "Drop ALL Linux capabilities by default; add back only those strictly needed.",
		Description: "Default Docker capabilities include NET_RAW, MKNOD, SYS_CHROOT. " +
			"These enable ARP spoofing, device creation, and filesystem escape techniques.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "5.4",
			NIST80053:        "AC-6, CM-7",
			NIST800190:       "§4.4.3",
			ISO27001:         "A.8.2, A.8.3, A.8.9",
			SOC2:             "CC6.1, CC6.3",
			DISACCI:          "CCI-000381",
		},
		Remediation: "Set in each container's securityContext:\n" +
			"  capabilities:\n" +
			"    drop: [\"ALL\"]\n" +
			"    add: [\"NET_BIND_SERVICE\"]     # only if binding ports < 1024; otherwise omit\n" +
			"Docker run equivalent: `--cap-drop=ALL --cap-add=NET_BIND_SERVICE`. " +
			"Common legitimate additions: NET_BIND_SERVICE (privileged ports), CHOWN (uid/gid changes in init). " +
			"Never add SYS_ADMIN, SYS_PTRACE, NET_RAW, or DAC_READ_SEARCH in production. " +
			"Verify: `kubectl get pod <name> -o jsonpath='{.spec.containers[*].securityContext.capabilities}'` shows `{\"drop\":[\"ALL\"]...}`.",
	},

	{
		ID:      "RUNTIME-004",
		Domain:  "Docker",
		Title:   "AllowPrivilegeEscalation Disabled",
		Summary: "Block SUID/SGID-based privilege gains with no-new-privileges at container exec.",
		Description: "Without no-new-privileges, processes can gain capabilities via " +
			"SUID/SGID executables inside the container.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "5.26",
			NIST80053:        "AC-6",
			NIST800190:       "§4.4.3",
			ISO27001:         "A.8.2, A.8.3, A.8.9",
			SOC2:             "CC6.1, CC6.3",
			DISACCI:          "CCI-002235",
		},
		Remediation: "Set in each container's securityContext:\n" +
			"  allowPrivilegeEscalation: false\n" +
			"Docker run equivalent: `--security-opt=no-new-privileges:true`. " +
			"Pair with `capabilities.drop: [ALL]` (RUNTIME-003) and `runAsNonRoot: true` (RUNTIME-001) for defense in depth — " +
			"no-new-privileges alone does not prevent a container running as root from escalating. " +
			"Verify: `kubectl get pod <name> -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}'` returns `false`.",
	},

	{
		ID:      "RUNTIME-005",
		Domain:  "Docker",
		Title:   "Read-Only Root Filesystem",
		Summary: "Mount the container root filesystem read-only; writes allowed only on mounted volumes.",
		Description: "Writable root filesystem allows malware installation, binary tampering, " +
			"and persistence mechanisms inside the container.",
		Severity: SeverityHigh,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "5.13",
			NIST80053:        "SI-7, CM-5",
			NIST800190:       "§4.4.3, §4.4.4",
			ISO27001:         "A.8.3, A.8.9",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-001813",
		},
		Remediation: "In each container's securityContext: `readOnlyRootFilesystem: true`. " +
			"Docker run equivalent: `--read-only`. " +
			"Mount `emptyDir` (or `tmpfs`) volumes for paths the app must write to:\n" +
			"  volumeMounts:\n" +
			"    - { name: tmp,     mountPath: /tmp }\n" +
			"    - { name: run,     mountPath: /var/run }\n" +
			"    - { name: varlog,  mountPath: /var/log }\n" +
			"  volumes:\n" +
			"    - { name: tmp,    emptyDir: { medium: Memory } }\n" +
			"    - { name: run,    emptyDir: { medium: Memory } }\n" +
			"    - { name: varlog, emptyDir: {} }\n" +
			"Verify: `kubectl exec <pod> -- touch /somefile` must fail with 'read-only file system'.",
	},

	{
		ID:      "RUNTIME-006",
		Domain:  "Docker",
		Title:   "No Host PID / IPC / Network Namespace Sharing",
		Summary: "Never share host PID, IPC, or network namespaces — it dissolves container isolation.",
		Description: "Sharing host namespaces removes namespace-based isolation. " +
			"hostPID: true allows attacker to enumerate and kill host processes.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "5.10, 5.16, 5.17, 5.21",
			NIST80053:        "AC-4, AC-6",
			NIST800190:       "§4.4.3, §4.5.5",
			ISO27001:         "A.8.22, A.8.9",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-001090",
		},
		Remediation: "Omit or explicitly set false in Pod spec (all default to false if omitted):\n" +
			"  spec.hostPID: false\n" +
			"  spec.hostIPC: false\n" +
			"  spec.hostNetwork: false\n" +
			"Docker run equivalents to forbid: `--pid=host`, `--ipc=host`, `--net=host`. " +
			"Legitimate exceptions (debugging tools, node-local daemons) must run in a dedicated namespace with tight RBAC and an admission exception. " +
			"Enforce via Kyverno `disallow-host-namespaces` or Pod Security Admission `baseline`. " +
			"Verify: `kubectl get pod <name> -o jsonpath='{.spec.hostPID}{.spec.hostIPC}{.spec.hostNetwork}'` returns `falsefalsefalse` or empty.",
	},

	{
		ID:      "RUNTIME-007",
		Domain:  "Docker",
		Title:   "CPU and Memory Limits Set",
		Summary: "Set CPU and memory requests + limits on every container to prevent node-wide DoS.",
		Description: "Unconstrained containers cause resource exhaustion (DoS) on the node, " +
			"affecting all co-located workloads.",
		Severity: SeverityHigh,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "5.11, 5.12",
			NIST80053:        "SC-5, AU-4",
			NIST800190:       "§4.4.3",
			ISO27001:         "A.8.6, A.8.9",
			SOC2:             "A1.1",
			DISACCI:          "CCI-001094, CCI-001095",
		},
		Remediation: "Set per-container resources in Pod spec:\n" +
			"  resources:\n" +
			"    requests: { cpu: \"100m\", memory: \"128Mi\" }\n" +
			"    limits:   { cpu: \"500m\", memory: \"512Mi\" }\n" +
			"Docker run: `--cpus=0.5 --memory=512m`. Compose v3+: `deploy.resources.limits`. " +
			"Enforce namespace-wide defaults with LimitRange + caps with ResourceQuota. " +
			"Verify: `kubectl get pod <name> -o jsonpath='{.spec.containers[*].resources}'` shows both requests and limits populated. " +
			"Tune limits using `kubectl top pod` historical usage; avoid memory limits < actual working set to prevent OOMKill loops.",
	},

	{
		ID:      "RUNTIME-008",
		Domain:  "Docker",
		Title:   "Seccomp Profile Applied",
		Summary: "Apply seccomp (RuntimeDefault) to block obscure syscalls used in container escapes.",
		Description: "Without seccomp, containers can invoke any syscall. " +
			"Kernel exploits frequently use obscure syscalls (keyctl, unshare, clone) blocked by the default profile.",
		Severity: SeverityHigh,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "5.22",
			NIST80053:        "AC-3, SI-3",
			NIST800190:       "§4.4.3",
			ISO27001:         "A.8.3, A.8.9",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-000381",
		},
		Remediation: "Set in Pod or container securityContext (Kubernetes 1.19+):\n" +
			"  securityContext.seccompProfile.type: RuntimeDefault\n" +
			"Docker run equivalent: the default profile is already applied; `--security-opt seccomp=unconfined` disables it (never do this). " +
			"For workloads needing specific syscalls (e.g. FUSE, ptrace debuggers), generate a narrow profile with `docker run --security-opt seccomp=profile.json` " +
			"using `syscall2seccomp` or `falco-seccomp` based on observed behaviour. " +
			"Verify: `kubectl get pod <name> -o jsonpath='{.spec.securityContext.seccompProfile.type}'` returns `RuntimeDefault`.",
	},

	{
		ID:      "RUNTIME-009",
		Domain:  "Docker",
		Title:   "Sensitive Host Directories Not Mounted",
		Summary: "Never mount host /etc, /proc, /sys, /var/run into containers — it breaks isolation.",
		Description: "Mounting /etc, /proc, /sys, /var/run or other sensitive host paths " +
			"into containers breaks isolation and enables host manipulation.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "5.6",
			NIST80053:        "AC-3",
			NIST800190:       "§3.5.5, §4.5.5",
			ISO27001:         "A.8.3, A.8.9",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-000213",
		},
		Remediation: "Audit every hostPath volume in Pod specs and Docker bind mounts:\n" +
			"  kubectl get pods -A -o json | jq '.items[] | select((.spec.volumes // [])[].hostPath.path? // \"\" | test(\"^/(etc|proc|sys|var/run|root|boot|dev)\")) | .metadata.name'\n" +
			"  docker ps -q | xargs -I{} docker inspect {} --format '{{.Name}}: {{.HostConfig.Binds}}' | grep -E '/(etc|proc|sys|var/run|root|boot|dev)'\n" +
			"Replace with PVC (durable data), emptyDir (scratch), or ConfigMap (read-only config). " +
			"Forbidden host paths: /, /etc, /proc, /sys, /var/run, /run, /root, /boot, /dev, /var/lib/docker. " +
			"Enforce via Kyverno `disallow-host-path` ClusterPolicy or Pod Security Admission `baseline`.",
	},

	{
		ID:      "RUNTIME-010",
		Domain:  "Docker",
		Title:   "No SSH Daemon in Containers",
		Summary: "Never run sshd inside containers; use kubectl exec or ephemeral debug containers instead.",
		Description: "Running sshd inside a container bypasses all audit logging, " +
			"provides an unmonitored lateral movement channel, and violates the principle " +
			"of least privilege. Use kubectl exec or ephemeral debug containers instead.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "5.7",
			NIST80053:        "AC-17, CM-7",
			NIST800190:       "§4.1.2",
			ISO27001:         "A.8.20, A.8.9",
			SOC2:             "CC6.1, CC6.6",
			DISACCI:          "CCI-000381",
		},
		Remediation: "Remove sshd from base images — in Dockerfile: `RUN apt-get remove -y --purge openssh-server`. " +
			"Strip any `ENTRYPOINT`/`CMD` referencing `/usr/sbin/sshd`. " +
			"For interactive access use `kubectl exec -it <pod> -- /bin/sh` (or `kubectl debug`); for headless systems use `docker exec`. " +
			"Runtime detection: deploy Falco with the built-in `Launch Ingress Remote File Copy Tools in Container` + `sshd launched inside a container` rules. " +
			"Verify: `docker run --rm <image> which sshd` returns nothing; `ss -tlnp | grep :22` on running containers is empty.",
	},

	{
		ID:      "RUNTIME-011",
		Domain:  "Docker",
		Title:   "No Privileged Ports Exposed (< 1024)",
		Summary: "Use ports ≥ 1024 in containers; expose on privileged ports via a Kubernetes Service.",
		Description: "Binding to ports below 1024 requires CAP_NET_BIND_SERVICE. " +
			"Application services must use non-privileged ports (>= 1024) and rely " +
			"on Kubernetes Services to expose them externally on standard ports.",
		Severity: SeverityHigh,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "5.8",
			NIST80053:        "AC-6, CM-7",
			NIST800190:       "§4.4.3",
			ISO27001:         "A.8.3, A.8.9",
			SOC2:             "CC6.1, CC6.3",
			DISACCI:          "CCI-001762",
		},
		Remediation: "Reconfigure the app to listen on a non-privileged port (e.g. 8080 for HTTP, 8443 for HTTPS). " +
			"Expose the standard port externally via a Kubernetes Service: `service.spec.ports[0].port: 443, targetPort: 8443`. " +
			"If the app truly must bind <1024, grant only CAP_NET_BIND_SERVICE (do not use --privileged) and pair with RUNTIME-003. " +
			"Verify: `kubectl get pod <name> -o jsonpath='{.spec.containers[*].ports[*].containerPort}'` shows only ports ≥ 1024.",
	},

	{
		ID:      "RUNTIME-012",
		Domain:  "Docker",
		Title:   "Liveness and Readiness Probes Configured",
		Summary: "Define liveness and readiness probes so orchestrators detect and restart hung containers.",
		Description: "Without health probes, Docker/Kubernetes cannot detect a degraded or " +
			"hung container and continues routing traffic to it or fails to restart it. " +
			"Both probes are required for availability compliance under RMF.",
		Severity: SeverityHigh,
		Type:     ControlDetective,
		Compliance: ComplianceMapping{
			CISDockerSection: "N/A",
			NIST80053:        "CP-10, SI-17",
			NIST800190:       "§4.4.4",
			ISO27001:         "A.5.30, A.8.16",
			SOC2:             "A1.2",
			DISACCI:          "N/A",
		},
		Remediation: "Define both probes on every container. Patterns by workload:\n" +
			"  HTTP service:    httpGet { path: /healthz, port: 8080 }\n" +
			"  gRPC service:    grpc    { port: 9090 }      # K8s 1.24+\n" +
			"  TCP service:     tcpSocket { port: 5432 }\n" +
			"  Database:        exec { command: [pg_isready, -U, postgres] }\n" +
			"Distinct endpoints: readiness may fail during warm-up (pulled from Service endpoints); liveness failure restarts the container. " +
			"Tune `initialDelaySeconds` > startup time to avoid premature kills; `failureThreshold` × `periodSeconds` > transient hiccup duration. " +
			"For slow-start apps, use `startupProbe` (K8s 1.16+) to guard the early window.",
	},
	
	{
		ID:      "RUNTIME-013",
		Domain:  "Kubernetes",
		Title:   "AppArmor / SELinux Profile Configured",
		Summary: "Apply AppArmor or SELinux profiles to pods so MAC restrictions limit container escape.",
		Description: "Without AppArmor or SELinux profiles, containers lack mandatory " +
			"access control enforcement, increasing container escape risk.",
		Severity: SeverityMedium,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "5.2, 5.3",
			NIST80053:        "AC-3, AC-6",
			NIST800190:       "§4.4.3",
			ISO27001:         "A.8.3, A.8.9",
			SOC2:             "CC6.1, CC6.3",
			DISACCI:          "CCI-002235",
		},
		Remediation: "AppArmor (Ubuntu/Debian): Kubernetes 1.30+ uses `securityContext.appArmorProfile.type: RuntimeDefault`. " +
			"Older clusters: `metadata.annotations: { container.apparmor.security.beta.kubernetes.io/<container-name>: runtime/default }`. " +
			"SELinux (RHEL/CentOS/Fedora): `securityContext.seLinuxOptions: { type: container_t, level: \"s0:c123,c456\" }`. " +
			"Pair with HOST-004 (host-level enforcement). " +
			"Verify: `kubectl get pod <name> -o yaml | grep -E 'apparmor|seLinux'` shows a profile; on host, `aa-status` or `getenforce` confirms MAC is loaded and enforcing.",
	},

	{
		ID:      "RUNTIME-014",
		Domain:  "Kubernetes",
		Title:   "Default Service Account Not Automounted",
		Summary: "Disable automountServiceAccountToken on pods that don't need Kubernetes API access.",
		Description: "Automounting the default service account token gives every pod " +
			"a credential that may have excessive RBAC permissions.",
		Severity: SeverityMedium,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "N/A",
			NIST80053:        "AC-2, AC-6",
			NIST800190:       "§4.3.1",
			ISO27001:         "A.8.3, A.8.9",
			SOC2:             "CC6.1, CC6.3",
			DISACCI:          "CCI-000366",
		},
		Remediation: "Set on every Pod spec: `automountServiceAccountToken: false`. " +
			"Also disable on the default ServiceAccount itself: " +
			"`kubectl patch serviceaccount default -n <ns> -p '{\"automountServiceAccountToken\": false}'`. " +
			"For pods that legitimately need the Kubernetes API, create a dedicated ServiceAccount with a minimal Role, and set `serviceAccountName` + `automountServiceAccountToken: true` explicitly. " +
			"Verify: `kubectl exec <pod> -- ls /var/run/secrets/kubernetes.io/serviceaccount/ 2>/dev/null` must return nothing.",
	},

	{
		ID:      "RUNTIME-015",
		Domain:  "Docker",
		Title:   "Container ulimits Explicitly Set",
		Summary: "Set container ulimits (nofile, nproc) explicitly to prevent fork bombs and FD exhaustion.",
		Description: "Without explicit ulimits, containers inherit host defaults for " +
			"open files and processes, enabling fork bombs and file descriptor exhaustion.",
		Severity: SeverityLow,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "5.19",
			NIST80053:        "SC-5",
			NIST800190:       "§4.4.3",
			ISO27001:         "A.8.6, A.8.9",
			SOC2:             "A1.1",
			DISACCI:          "CCI-000366",
		},
		Remediation: "Docker Compose:\n" +
			"  ulimits:\n" +
			"    nofile: { soft: 65535, hard: 65535 }\n" +
			"    nproc:  { soft: 4096,  hard: 4096  }\n" +
			"Docker run: `--ulimit nofile=65535:65535 --ulimit nproc=4096:4096`. " +
			"Kubernetes does not expose per-container ulimits directly; use a LimitRange for namespace-level defaults " +
			"and rely on `resources.limits.memory` + `pids.max` cgroup (see RUNTIME-007). " +
			"For daemon-wide defaults: `default-ulimits` in /etc/docker/daemon.json. " +
			"Verify: `docker exec <id> sh -c 'ulimit -n && ulimit -u'` reports the expected values.",
	},

	{
		ID:      "RUNTIME-016",
		Domain:  "Docker",
		Title:   "Restart Policy Capped",
		Summary: "Cap container restart policy (on-failure:5) to prevent crash-loop resource exhaustion.",
		Description: "restart: always without a retry cap can cause crash-loop resource " +
			"exhaustion. Use on-failure with max_retries to prevent infinite restarts.",
		Severity: SeverityLow,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "5.15",
			NIST80053:        "SC-5",
			NIST800190:       "§4.4.3",
			ISO27001:         "A.8.6, A.5.30",
			SOC2:             "A1.1, A1.2",
			DISACCI:          "CCI-000366",
		},
		Remediation: "Docker run: `--restart=on-failure:5` (stops retrying after 5 consecutive failures). " +
			"Docker Compose v3+:\n" +
			"  deploy:\n" +
			"    restart_policy:\n" +
			"      condition: on-failure\n" +
			"      max_attempts: 5\n" +
			"      delay: 10s\n" +
			"In Kubernetes this is handled by kubelet's exponential back-off (capped at 5 min); combine with a PodDisruptionBudget and alerting on `CrashLoopBackOff` events. " +
			"Verify: `docker inspect <id> --format '{{.HostConfig.RestartPolicy}}'` shows a bounded policy.",
	},

	// ── Domain: Network ─────────────────────────────────────────────────────── //
	{
		ID:      "NETWORK-001",
		Domain:  "Kubernetes",
		Title:   "Default-Deny NetworkPolicy in All Namespaces",
		Summary: "Apply a default-deny NetworkPolicy per namespace so a compromised pod can't reach others.",
		Description: "Without NetworkPolicy, all pods communicate cluster-wide by default. " +
			"A single compromised pod has network access to every other service.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "N/A",
			NIST80053:        "SC-7, AC-4",
			NIST800190:       "§3.3.3, §3.4.2, §4.3.3, §4.4.2",
			ISO27001:         "A.8.20, A.8.22",
			SOC2:             "CC6.6",
			DISACCI:          "CCI-001090",
		},
		Remediation: "Apply a default-deny NetworkPolicy in every namespace:\n" +
			"  apiVersion: networking.k8s.io/v1\n" +
			"  kind: NetworkPolicy\n" +
			"  metadata: { name: default-deny-all, namespace: <ns> }\n" +
			"  spec:\n" +
			"    podSelector: {}\n" +
			"    policyTypes: [Ingress, Egress]\n" +
			"Then add explicit allow rules for required flows (DNS, app-to-DB, ingress-to-app). " +
			"Requires a CNI that supports NetworkPolicy (Calico, Cilium, Weave — not vanilla Flannel). " +
			"Verify: `kubectl exec -n <ns> <pod-a> -- curl -m 3 <pod-b>:<port>` must time out before allow rules are added.",
	},

	{
		ID:      "NETWORK-002",
		Domain:  "Kubernetes",
		Title:   "Cloud Metadata Endpoint Blocked",
		Summary: "Block 169.254.169.254 egress from pods to prevent SSRF-based IAM credential theft.",
		Description: "SSRF vulnerabilities can exfiltrate IAM credentials from 169.254.169.254. " +
			"This is a critical path for cloud account takeover from a compromised container.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "N/A",
			NIST80053:        "SC-7, IA-5",
			NIST800190:       "§4.4.2",
			ISO27001:         "A.8.20, A.8.23",
			SOC2:             "CC6.6",
			DISACCI:          "CCI-001097",
		},
		Remediation: "Block 169.254.169.254/32 in an egress NetworkPolicy applied cluster-wide:\n" +
			"  egress:\n" +
			"    - to:\n" +
			"        - ipBlock: { cidr: 0.0.0.0/0, except: [169.254.169.254/32] }\n" +
			"On AWS, enforce IMDSv2 (token-required) on every instance via Terraform:\n" +
			"  metadata_options: { http_tokens: \"required\", http_put_response_hop_limit: 1 }\n" +
			"Hop limit 1 prevents tokens from reaching the pod network namespace. " +
			"Verify: `kubectl exec <pod> -- curl -m 3 http://169.254.169.254/latest/meta-data/` must fail.",
	},

	// ── Domain: Secrets ─────────────────────────────────────────────────────── //
	{
		ID:      "SECRETS-001",
		Domain:  "Secrets",
		Title:   "Secrets Managed Externally (Not in K8s Secrets Plaintext)",
		Summary: "Store secrets in an external KMS (Vault/ASM/GSM), not base64 in etcd.",
		Description: "Kubernetes Secrets are base64-encoded, not encrypted by default. " +
			"etcd access or broad get-secrets RBAC exposes all credentials.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.10",
			NIST80053:        "IA-5, SC-28, AC-4",
			NIST800190:       "§4.1.4, §4.3",
			ISO27001:         "A.8.24, A.5.17",
			SOC2:             "CC6.1, CC6.7",
			DISACCI:          "CCI-000366, CCI-002367",
		},
		Remediation: "Store secrets in AWS Secrets Manager, GCP Secret Manager, or HashiCorp Vault. " +
			"Project them into pods via the Secrets Store CSI Driver: " +
			"`secrets-store.csi.x-k8s.io/*` provider + `SecretProviderClass` referencing the external KMS entry. " +
			"Enable etcd encryption-at-rest as a last line of defence: `--encryption-provider-config` on kube-apiserver with aescbc or KMS provider. " +
			"Audit RBAC: `kubectl auth can-i get secrets --as <subject> -n <ns>` should be denied for non-admin principals. " +
			"Verify: `kubectl get secrets -n <ns> -o json | jq '.items[].data | keys'` should not show plaintext-equivalent credentials.",
	},

	{
		ID:      "SECRETS-002",
		Domain:  "Secrets",
		Title:   "RBAC Restricts Secret Access to Named Resources",
		Summary: "Scope RBAC secret access to named resources; never grant cluster-wide get/list secrets.",
		Description: "Wildcard secret access (resources: [\"secrets\"] without resourceNames) " +
			"allows a service account to read every secret in its namespace.",
		Severity: SeverityHigh,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "N/A",
			NIST80053:        "AC-2, AC-3, AC-6",
			NIST800190:       "§4.3.1",
			ISO27001:         "A.5.15, A.8.3",
			SOC2:             "CC6.3",
			DISACCI:          "CCI-002235",
		},
		Remediation: "Use Role/RoleBinding with `resourceNames` to scope access to specific secrets:\n" +
			"  rules:\n" +
			"    - apiGroups: [\"\"]\n" +
			"      resources: [\"secrets\"]\n" +
			"      resourceNames: [\"app-db-credentials\", \"app-jwt-key\"]\n" +
			"      verbs: [\"get\"]\n" +
			"Remove any ClusterRoleBinding of `cluster-admin` to non-admin service accounts. " +
			"Audit who can read secrets in a namespace: `kubectl auth can-i get secrets -n <ns> --as system:serviceaccount:<ns>:<sa>`. " +
			"Enumerate risky bindings: `kubectl get clusterrolebindings -o json | jq '.items[] | select(.roleRef.name==\"cluster-admin\") | .subjects'`.",
	},

	{
		ID:      "SECRETS-003",
		Domain:  "Secrets",
		Title:   "AI/Vectorizer API Keys Must Not Be in ENV Vars",
		Summary: "Never set AI/vectorizer API keys (OpenAI, Anthropic, Cohere) as literal env values.",
		Description: "API keys for AI inference providers (OpenAI, Cohere, HuggingFace, " +
			"Anthropic, Google, Azure) stored as literal ENV vars are visible via " +
			"kubectl describe pod or docker inspect. These keys have billing and " +
			"data-access scope beyond the immediate container.",
		Severity: SeverityHigh,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.10",
			NIST80053:        "IA-5, SC-28",
			NIST800190:       "§3.1.4, §4.1.4",
			ISO27001:         "A.5.17, A.8.12, A.8.24",
			SOC2:             "CC6.1, CC6.7",
			DISACCI:          "CCI-000366, CCI-002367",
		},
		Remediation: "Inject via secretKeyRef, never as literal values:\n" +
			"  env:\n" +
			"    - name: OPENAI_API_KEY\n" +
			"      valueFrom: { secretKeyRef: { name: ai-keys, key: openai } }\n" +
			"Preferred: project from external KMS via Secrets Store CSI Driver so the value never lands in etcd. " +
			"Rotate on a schedule (every 90 days) and on any suspected exposure; monitor provider dashboards for anomalous billing/usage. " +
			"Audit for regressions: `kubectl get pod <name> -o json | jq '.spec.containers[].env[] | select(.value != null and (.name | test(\"(?i)api.?key|token|secret\")))'` must be empty.",
	},

	// ── Domain: Supply Chain ────────────────────────────────────────────────── //
	{
		ID:      "SUPPLY-001",
		Domain:  "Kubernetes",
		Title:   "Images Signed and Signature Verified at Admission",
		Summary: "Sign images with Cosign and verify at admission so unsigned images are rejected.",
		Description: "Without image signing, registry compromise or tag hijacking silently " +
			"delivers malicious images. Admission verification is the enforcement point.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.5, 4.12",
			NIST80053:        "SI-7, CM-14, SR-4(3)",
			NIST800190:       "§4.1.5, §4.2.3",
			ISO27001:         "A.8.24, A.8.19",
			SOC2:             "CC6.1, CC6.8",
			DISACCI:          "CCI-001749",
		},
		Remediation: "Sign every image in CI after build (keyless via Sigstore/OIDC is simplest for GitHub Actions):\n" +
			"  cosign sign --yes <registry>/<image>@sha256:<digest>\n" +
			"Enforce signature verification at admission with Kyverno `verifyImages` or Connaisseur:\n" +
			"  apiVersion: kyverno.io/v1\n" +
			"  kind: ClusterPolicy\n" +
			"  spec:\n" +
			"    validationFailureAction: Enforce\n" +
			"    rules:\n" +
			"      - name: verify-signature\n" +
			"        match: { any: [ { resources: { kinds: [Pod] } } ] }\n" +
			"        verifyImages:\n" +
			"          - imageReferences: [\"<registry>/*\"]\n" +
			"            attestors: [ { entries: [ { keyless: { subject: \"...\", issuer: \"https://token.actions.githubusercontent.com\" } } ] } ]\n" +
			"Verify: `cosign verify <image>` must succeed before deploy; Kyverno PolicyReport must show `pass` for the pod.",
	},

	{
		ID:      "SUPPLY-002",
		Domain:  "Docker",
		Title:   "SBOM Generated and Attested per Image",
		Summary: "Generate and attest an SBOM per image so new CVEs can be mapped to deployed workloads.",
		Description: "Without SBOM, you cannot determine which deployed workloads are " +
			"affected by a newly disclosed CVE without full re-scan.",
		Severity: SeverityHigh,
		Type:     ControlDetective,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.4, 4.12",
			NIST80053:        "CM-8, RA-5, SR-3, SR-4(4)",
			NIST800190:       "§4.1.1",
			ISO27001:         "A.5.9, A.8.8, A.5.7",
			SOC2:             "CC6.1, CC7.1",
			DISACCI:          "N/A",
		},
		Remediation: "In CI, after image build:\n" +
			"  syft <image> -o cyclonedx-json > sbom.cdx.json\n" +
			"  cosign attest --yes --type cyclonedx --predicate sbom.cdx.json <image>@sha256:<digest>\n" +
			"Also supported: SPDX (`syft -o spdx-json`), and BuildKit `docker buildx build --sbom=true`. " +
			"Store SBOMs as OCI attestations alongside the image; downstream scanners (`grype sbom:sbom.cdx.json`, `trivy sbom`) re-evaluate against updated CVE databases without needing the original image. " +
			"Verify: `cosign download attestation <image> | jq -r .payload | base64 -d | jq '.predicate.Data | fromjson'` returns a valid CycloneDX document.",
	},

	{
		ID:      "SUPPLY-003",
		Domain:  "Terraform",
		Title:   "Image Registry Tags Immutable",
		Summary: "Make registry tags immutable so an already-deployed tag cannot be silently replaced.",
		Description: "Mutable tags allow silent image replacement. Once a tagged image is " +
			"deployed, the tag must not be overwriteable.",
		Severity: SeverityHigh,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "N/A",
			NIST80053:        "CM-2, CM-5, SR-4",
			NIST800190:       "§4.2.2",
			ISO27001:         "A.8.32, A.8.9",
			SOC2:             "CC6.1, CC6.8",
			DISACCI:          "CCI-001762",
		},
		Remediation: "AWS ECR (Terraform):\n" +
			"  resource \"aws_ecr_repository\" \"app\" {\n" +
			"    name                 = \"app\"\n" +
			"    image_tag_mutability = \"IMMUTABLE\"\n" +
			"  }\n" +
			"GCP Artifact Registry: enable `immutable_tags = true` on the repository. " +
			"Azure Container Registry: use image lock (`az acr repository update --write-enabled false`) or tag-level locks. " +
			"Harbor: enable project-level tag immutability rules. " +
			"Pair with IMAGE-001 (digest pinning) — immutability backs up pinning, it doesn't replace it. " +
			"Verify: `aws ecr describe-repositories --repository-names app --query 'repositories[0].imageTagMutability'` returns `IMMUTABLE`.",
	},

	// ── Domain: Monitoring ──────────────────────────────────────────────────── //
	{
		ID:      "MONITOR-001",
		Domain:  "Kubernetes",
		Title:   "Runtime Threat Detection (Falco) Deployed",
		Summary: "Deploy Falco (or equivalent) to alert on suspicious container behaviour in real time.",
		Description: "Without runtime detection, attacker activity inside containers " +
			"(shell spawning, file writes, unexpected syscalls) generates no alerts.",
		Severity: SeverityCritical,
		Type:     ControlDetective,
		Compliance: ComplianceMapping{
			CISDockerSection: "N/A",
			NIST80053:        "AU-12, SI-4, IR-5, IR-4, CA-7",
			NIST800190:       "§3.4.4, §4.4.4, §4.4.5",
			ISO27001:         "A.8.15, A.5.24, A.5.7, A.8.16",
			SOC2:             "CC7.2, CC7.3",
			DISACCI:          "CCI-000172",
		},
		Remediation: "Install Falco via Helm with the eBPF driver (kernel ≥ 4.14):\n" +
			"  helm install falco falcosecurity/falco -n falco --create-namespace \\\n" +
			"    --set driver.kind=ebpf --set falcosidekick.enabled=true\n" +
			"Enable the default ruleset + `k8s_audit`, `application` (shells/crypto miners), and add custom rules for your workloads. " +
			"Ship alerts to SIEM via Falcosidekick (Slack/PagerDuty for severity≥ERROR; all to S3/OpenSearch). " +
			"Alternatives: Tracee, Tetragon (Cilium), or managed runtime protection (Sysdig Secure, Aqua, Prisma). " +
			"Verify: `kubectl get pods -n falco` shows a DaemonSet ready on every node; trigger a test: `kubectl run busy --rm -it --image=busybox -- sh` — Falco should log `Terminal shell in container`.",
	},

	{
		ID:      "MONITOR-002",
		Domain:  "Kubernetes",
		Title:   "Kubernetes API Server Audit Logging Enabled",
		Summary: "Enable kube-apiserver audit logging and ship to an immutable SIEM for forensics.",
		Description: "Without API audit logging, all control plane activity " +
			"(secret reads, RBAC changes, exec into pods) is invisible for forensics.",
		Severity: SeverityCritical,
		Type:     ControlDetective,
		Compliance: ComplianceMapping{
			CISDockerSection: "N/A",
			NIST80053:        "AU-2, AU-3, AU-12, AU-6, CA-7",
			NIST800190:       "§4.3.2",
			ISO27001:         "A.8.15, A.8.16",
			SOC2:             "CC7.2",
			DISACCI:          "CCI-000172",
		},
		Remediation: "Pass on kube-apiserver (or configure via managed-control-plane audit settings):\n" +
			"  --audit-log-path=/var/log/kubernetes/audit.log\n" +
			"  --audit-log-maxage=30 --audit-log-maxbackup=10 --audit-log-maxsize=100\n" +
			"  --audit-policy-file=/etc/kubernetes/audit-policy.yaml\n" +
			"Recommended policy: secrets `get`/`list` at `Request`; `exec`/`attach`/`portforward` at `RequestResponse`; RBAC changes at `RequestResponse`. " +
			"EKS/GKE/AKS: enable control-plane audit logs via provider console and route to CloudWatch/Stackdriver/Log Analytics. " +
			"Ship to an immutable SIEM (S3 + Object Lock, GCS bucket lock, immutable blob storage) to preserve evidence against admin compromise. " +
			"Verify: trigger a test — `kubectl get secret <name>` — and confirm a matching audit event reaches the SIEM within SLA.",
	},

	// ── Domain: Database ────────────────────────────────────────────────────── //
	{
		ID:      "DB-IMAGE-001",
		Domain:  "Database",
		Title:   "No Admin/Debug Tools in Database Image",
		Summary: "Strip admin/debug tools (psql, mongosh, redis-cli) from production database images.",
		Description: "Admin and debug tools (psql, mongosh, redis-cli, cypher-shell, " +
			"mysql, cqlsh, mongodump, arangosh) in production database images provide " +
			"an attacker who achieves any code execution a direct authenticated channel " +
			"into the database without additional exploits.",
		Severity: SeverityHigh,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.3",
			NIST80053:        "CM-7, AC-6",
			NIST800190:       "§4.1.2",
			ISO27001:         "A.8.8, A.8.9",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-000381",
		},
		Remediation: "Build prod and debug images as separate targets in a multi-stage Dockerfile. " +
			"The `prod` final stage copies only the server binary; admin clients stay in a `-debug`/`-admin` tagged image that is never deployed. " +
			"For ad-hoc investigation: `kubectl debug -it <pod> --image=<debug-image>` (K8s 1.25+) attaches an ephemeral container with the needed CLIs without mutating the production pod. " +
			"Verify: `docker run --rm <prod-image> which psql mongosh redis-cli cypher-shell mysql cqlsh mongodump arangosh` returns nothing.",
	},

	{
		ID:      "DB-IMAGE-002",
		Domain:  "Database",
		Title:   "No Dangerous Database Startup Flags",
		Summary: "Reject auth-bypass DB startup flags (--skip-grant-tables, missing --auth, etc.).",
		Description: "Database startup flags --skip-grant-tables (MySQL), --local-infile=1 " +
			"(MySQL), missing --auth (MongoDB), -tcpAllowOthers (H2), and -startNetworkServer " +
			"(Derby) completely bypass authentication or enable severe misconfigurations. " +
			"These are commonly introduced as quick fixes and left in production.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "N/A",
			NIST80053:        "IA-2, AC-3, CM-6",
			NIST800190:       "§4.1.2",
			ISO27001:         "A.8.5, A.5.17",
			SOC2:             "CC6.1, CC6.3",
			DISACCI:          "CCI-000366, CCI-002235",
		},
		Remediation: "Audit every database container's CMD/ENTRYPOINT and Pod `args` for forbidden flags:\n" +
			"  MySQL/MariaDB: --skip-grant-tables, --local-infile=1, --secure-file-priv= (empty)\n" +
			"  MongoDB:       absence of --auth in CMD\n" +
			"  H2:            -tcpAllowOthers, -webAllowOthers\n" +
			"  Derby:         -startNetworkServer -h 0.0.0.0 without auth\n" +
			"  Cassandra:     authenticator: AllowAllAuthenticator in cassandra.yaml\n" +
			"Replace ad-hoc flags with a ConfigMap-mounted config file + explicit auth. " +
			"Verify: `kubectl get pod <db> -o jsonpath='{.spec.containers[*].args}'` contains no forbidden flags; `grep` the image's actual CMD with `docker inspect <image> --format '{{.Config.Cmd}}'`.",
	},

	{
		ID:      "DB-K8S-001",
		Domain:  "Database",
		Title:   "No Auth-Disabling ENV Variables",
		Summary: "Never set auth-disabling DB env vars (POSTGRES_HOST_AUTH_METHOD=trust, NEO4J_AUTH=none).",
		Description: "Multiple databases support ENV vars that explicitly disable " +
			"authentication or enable dangerous operational modes: " +
			"POSTGRES_HOST_AUTH_METHOD=trust, NEO4J_AUTH=none, ARANGO_NO_AUTH=1, " +
			"AUTHENTICATION_ANONYMOUS_ACCESS_ENABLED=true (Weaviate), " +
			"CHROMA_ALLOW_RESET=true (deletes all data), SPRING_H2_CONSOLE_ENABLED=true (RCE).",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.10",
			NIST80053:        "IA-2, AC-3, IA-5",
			NIST800190:       "§4.1.2, §4.1.4",
			ISO27001:         "A.8.5, A.5.17",
			SOC2:             "CC6.1, CC6.2",
			DISACCI:          "CCI-000366, CCI-002235",
		},
		Remediation: "Forbidden env values to scan for in Pod specs:\n" +
			"  POSTGRES_HOST_AUTH_METHOD=trust     → use scram-sha-256\n" +
			"  NEO4J_AUTH=none                     → set to a strong username/password or point at secretKeyRef\n" +
			"  ARANGO_NO_AUTH=1                    → remove; set ARANGO_ROOT_PASSWORD\n" +
			"  AUTHENTICATION_ANONYMOUS_ACCESS_ENABLED=true  (Weaviate) → set to false\n" +
			"  CHROMA_ALLOW_RESET=true             → never in prod (allows DB wipe)\n" +
			"  SPRING_H2_CONSOLE_ENABLED=true      → never in prod (RCE risk)\n" +
			"Inject the required credentials via `valueFrom.secretKeyRef`. " +
			"Verify: `kubectl get pod <db> -o jsonpath='{.spec.containers[*].env[?(@.value)]}'` — scan for any of the above literal values.",
	},

	{
		ID:      "DB-K8S-002",
		Domain:  "Database",
		Title:   "Database Authentication Must Be Explicitly Configured",
		Summary: "Explicitly configure DB auth for Qdrant/Chroma/Milvus/Weaviate/Redis — defaults are open.",
		Description: "Several databases default to no authentication: Qdrant, Chroma, Milvus, " +
			"Weaviate, Redis, MongoDB. In containerized environments where network-adjacent " +
			"access is the default, absent authentication configuration is a critical failure.",
		Severity: SeverityHigh,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.10",
			NIST80053:        "IA-2, IA-5, AC-3",
			NIST800190:       "§4.1.2, §4.1.4",
			ISO27001:         "A.8.5, A.8.9",
			SOC2:             "CC6.1, CC6.2",
			DISACCI:          "CCI-000366",
		},
		Remediation: "Required auth settings by database (all injected via secretKeyRef):\n" +
			"  Qdrant:    QDRANT__SERVICE__API_KEY\n" +
			"  Chroma:    CHROMA_SERVER_AUTH_PROVIDER=<basic|token>, CHROMA_SERVER_AUTH_CREDENTIALS_FILE\n" +
			"  Milvus:    MILVUS_ROOT_PASSWORD (+ common.security.authorizationEnabled: true in milvus.yaml)\n" +
			"  Weaviate:  AUTHENTICATION_APIKEY_ENABLED=true + AUTHENTICATION_APIKEY_ALLOWED_KEYS\n" +
			"  Redis:     mount redis.conf with `requirepass <value>` (or use `--requirepass` via args)\n" +
			"  MongoDB:   include `--auth` in CMD; create root user via MONGO_INITDB_ROOT_* env on first start\n" +
			"  PostgreSQL: POSTGRES_PASSWORD set and POSTGRES_HOST_AUTH_METHOD != trust\n" +
			"Verify by probing from another pod: connecting without credentials must fail.",
	},

	{
		ID:      "DB-K8S-003",
		Domain:  "Database",
		Title:   "Database Services Must Use ClusterIP",
		Summary: "Use ClusterIP for DB Services; never NodePort/LoadBalancer — they bypass NetworkPolicy.",
		Description: "Exposing database Services as NodePort or LoadBalancer bypasses all " +
			"Kubernetes NetworkPolicy and makes the database directly reachable from the " +
			"node network or the public Internet. This is the most common real-world " +
			"database breach vector for containerized deployments.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "N/A",
			NIST80053:        "SC-7, AC-4",
			NIST800190:       "§4.3.3, §4.4.2",
			ISO27001:         "A.8.20, A.8.22",
			SOC2:             "CC6.6",
			DISACCI:          "CCI-001090",
		},
		Remediation: "Set `spec.type: ClusterIP` (or omit — it's the default) on every database Service. " +
			"If an external client needs DB access, front it with an Ingress + TLS + authentication proxy, never expose the raw DB port. " +
			"Enforce via Kyverno: reject `Service` resources where `spec.type in (NodePort, LoadBalancer)` and a label selector matches DB pods. " +
			"Audit existing services: `kubectl get svc -A -o json | jq '.items[] | select(.spec.type != \"ClusterIP\" and .spec.type != \"ExternalName\") | {ns: .metadata.namespace, name: .metadata.name, type: .spec.type, ports: .spec.ports[].port}'`.",
	},

	{
		ID:      "DB-K8S-004",
		Domain:  "Database",
		Title:   "Database Data Must Use Persistent Volume (Not emptyDir)",
		Summary: "Mount DB data on a PersistentVolume; emptyDir is lost on restart and not backup-able.",
		Description: "emptyDir as the primary data directory for a stateful database " +
			"causes data loss on pod restart, stores data on node-local disk accessible " +
			"via hostPath from other pods on the same node, and prevents backup/snapshot. " +
			"Only tmpfs emptyDir for runtime sockets is acceptable.",
		Severity: SeverityHigh,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "N/A",
			NIST80053:        "CP-9, SI-12",
			NIST800190:       "§4.3",
			ISO27001:         "A.8.13, A.5.30",
			SOC2:             "A1.2",
			DISACCI:          "CCI-000366",
		},
		Remediation: "Use a StatefulSet with volumeClaimTemplates, not a Deployment:\n" +
			"  kind: StatefulSet\n" +
			"  spec:\n" +
			"    volumeClaimTemplates:\n" +
			"      - metadata: { name: data }\n" +
			"        spec:\n" +
			"          accessModes: [\"ReadWriteOnce\"]\n" +
			"          storageClassName: <gp3|ssd|premium>\n" +
			"          resources: { requests: { storage: 50Gi } }\n" +
			"Mount `data` at the DB's data path (`/var/lib/postgresql/data`, `/data/db`, `/bitnami/mongodb`, etc.). " +
			"Reserve `emptyDir { medium: Memory }` only for sockets/PID files that don't need persistence. " +
			"Verify: `kubectl get pod <db> -o jsonpath='{.spec.volumes[*]}'` shows a `persistentVolumeClaim`, not `emptyDir`, for the data path.",
	},

	{
		ID:      "DB-K8S-005",
		Domain:  "Database",
		Title:   "Database Pods Must Set fsGroup",
		Summary: "Set pod fsGroup to the DB process GID so mounted volumes are owned and writable.",
		Description: "Without fsGroup in the pod securityContext, volume files may be " +
			"owned by root (world-readable) or not writable by the non-root database process. " +
			"Both outcomes create security failures: data exposure or startup failure " +
			"leading to privilege escalation attempts.",
		Severity: SeverityMedium,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "N/A",
			NIST80053:        "AC-3, AC-6",
			NIST800190:       "§4.1.2, §4.1.4",
			ISO27001:         "A.8.3, A.8.9",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-002235",
		},
		Remediation: "Set at pod level so all volumes are chowned to this GID before mount:\n" +
			"  spec:\n" +
			"    securityContext:\n" +
			"      runAsUser:  999\n" +
			"      runAsGroup: 999\n" +
			"      fsGroup:    999\n" +
			"      fsGroupChangePolicy: OnRootMismatch    # avoids slow recursive chown on large volumes\n" +
			"Common DB GIDs: postgres/mongo=999, mysql=999, neo4j=7474, cassandra=999, redis=999, elasticsearch=1000. " +
			"Check the image default with `docker run --rm <image> id -g`. " +
			"Verify on a running pod: `kubectl exec <db> -- stat -c '%u:%g' /var/lib/postgresql/data` (or equivalent path) returns the expected UID:GID.",
	},

	{
		ID:      "DB-K8S-006",
		Domain:  "Database",
		Title:   "No Credentials in Pod Annotations or Labels",
		Summary: "Never store connection strings or API keys in pod annotations/labels.",
		Description: "Connection strings, DSNs, and API keys stored in pod annotations " +
			"or labels are visible to anyone with kubectl describe pod access. " +
			"This circumvents secrets management and exposes credentials widely.",
		Severity: SeverityHigh,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.10",
			NIST80053:        "IA-5, SC-28",
			NIST800190:       "§4.1.4",
			ISO27001:         "A.5.17, A.8.12, A.8.24",
			SOC2:             "CC6.1, CC6.7",
			DISACCI:          "CCI-000366, CCI-002367",
		},
		Remediation: "Remove any connection-string/password/API-key text from `metadata.annotations` and `metadata.labels`. " +
			"References are fine (`secretName: app-db-creds`); literal values are not. " +
			"Scan existing pods for regressions:\n" +
			"  kubectl get pods -A -o json | jq '.items[] | {ns: .metadata.namespace, name: .metadata.name, " +
			"sus_annotations: (.metadata.annotations // {} | to_entries[] | select(.value | test(\"(?i)password|secret|api.?key|token|://.+:.+@\")))}' \n" +
			"Enforce via Kyverno ClusterPolicy that rejects label/annotation values matching the above pattern.",
	},

	{
		ID:      "DB-K8S-007",
		Domain:  "Database",
		Title:   "Neo4j APOC Plugin Must Restrict URL Loading",
		Summary: "Disable Neo4j APOC URL loading to block SSRF from the graph database container.",
		Description: "The Neo4j APOC library exposes apoc.load.json() and apoc.load.url() " +
			"which can make outbound HTTP requests to arbitrary URLs including the cloud " +
			"metadata endpoint (169.254.169.254), enabling SSRF-based credential theft " +
			"from inside the graph database container.",
		Severity: SeverityHigh,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "N/A",
			NIST80053:        "SC-7, SI-10",
			NIST800190:       "§4.4.2",
			ISO27001:         "A.8.20, A.8.23",
			SOC2:             "CC6.6",
			DISACCI:          "CCI-001090",
		},
		Remediation: "Set in Neo4j Pod env:\n" +
			"  NEO4J_LABS_APOC_IMPORT_FILE_ENABLED=false\n" +
			"  NEO4J_dbms_security_allow__csv__import__from__file__urls=false\n" +
			"  NEO4J_apoc_import_file_enabled=false\n" +
			"  NEO4J_apoc_import_file_use__neo4j__config=true\n" +
			"Combine with an egress NetworkPolicy that denies 169.254.169.254/32 (see NETWORK-002) and any outbound that isn't to the application layer. " +
			"Verify: connect to Neo4j and run `CALL apoc.load.json('http://169.254.169.254/latest/meta-data/')` — it must fail.",
	},

	{
		ID:      "DB-TF-001",
		Domain:  "Database",
		Title:   "RDS Instance Must Be Encrypted and Private",
		Summary: "Encrypt RDS at rest, keep it private, and retain ≥7 days of backups.",
		Description: "AWS RDS instances with storage_encrypted=false expose data at rest. " +
			"publicly_accessible=true exposes the database port to the Internet. " +
			"Missing deletion_protection allows accidental data destruction. " +
			"Missing backup_retention prevents point-in-time recovery after a breach.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "N/A",
			NIST80053:        "SC-28, CP-9, SI-12",
			NIST800190:       "§4.1.4, §4.4.2",
			ISO27001:         "A.8.24, A.8.13, A.5.23",
			SOC2:             "CC6.1, A1.2",
			DISACCI:          "CCI-000366, CCI-002418, CCI-002476",
		},
		Remediation: "Required properties on `aws_db_instance`:\n" +
			"  storage_encrypted                    = true\n" +
			"  kms_key_id                           = aws_kms_key.rds.arn     # customer-managed, not aws/rds default\n" +
			"  publicly_accessible                  = false\n" +
			"  deletion_protection                  = true\n" +
			"  backup_retention_period              = 7                         # 30+ for regulated data\n" +
			"  iam_database_authentication_enabled  = true\n" +
			"  skip_final_snapshot                  = false\n" +
			"  performance_insights_enabled         = true\n" +
			"  performance_insights_kms_key_id      = aws_kms_key.rds.arn\n" +
			"Place the instance in private subnets (vpc_security_group_ids restricts ingress to app SG only). " +
			"Verify: `aws rds describe-db-instances --db-instance-identifier <id> --query 'DBInstances[0].[StorageEncrypted,PubliclyAccessible,DeletionProtection,BackupRetentionPeriod]'`.",
	},

	{
		ID:      "DB-TF-002",
		Domain:  "Database",
		Title:   "ElastiCache Must Use Encryption and Authentication",
		Summary: "Enable at-rest + in-transit encryption and auth_token on ElastiCache; no plaintext Redis.",
		Description: "ElastiCache clusters without at-rest or in-transit encryption " +
			"expose all cached data in plaintext. Missing auth_token means any " +
			"network-adjacent client has full Redis access, enabling the CONFIG SET " +
			"arbitrary file write exploit chain against a writable container rootfs.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "N/A",
			NIST80053:        "SC-8, SC-28, IA-5",
			NIST800190:       "§4.1.4, §4.4.2",
			ISO27001:         "A.8.24, A.5.14, A.5.23",
			SOC2:             "CC6.1, CC6.7",
			DISACCI:          "CCI-000366, CCI-002418",
		},
		Remediation: "Required on `aws_elasticache_replication_group`:\n" +
			"  at_rest_encryption_enabled   = true\n" +
			"  kms_key_id                   = aws_kms_key.cache.arn\n" +
			"  transit_encryption_enabled   = true\n" +
			"  auth_token                   = random_password.redis.result   # ≥16 chars, high entropy\n" +
			"  automatic_failover_enabled   = true\n" +
			"  multi_az_enabled             = true\n" +
			"  subnet_group_name            = aws_elasticache_subnet_group.private.name\n" +
			"Rotate `auth_token` via `AuthToken` rotation strategy; update client applications accordingly. " +
			"Clients must connect with `rediss://` (TLS) and the token. " +
			"Verify: `aws elasticache describe-replication-groups --replication-group-id <id> --query 'ReplicationGroups[0].[AtRestEncryptionEnabled,TransitEncryptionEnabled,AuthTokenEnabled]'` returns `[true, true, true]`.",
	},

	{
		ID:      "DB-TF-003",
		Domain:  "Database",
		Title:   "Managed NoSQL Services Must Have Encryption and Backup",
		Summary: "Encrypt DocumentDB/DynamoDB at rest and enable backups + point-in-time recovery.",
		Description: "DocumentDB without storage encryption exposes document data at rest. " +
			"DynamoDB without server-side encryption or point-in-time recovery lacks both " +
			"data protection and recovery capability after accidental deletion or ransomware.",
		Severity: SeverityHigh,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "N/A",
			NIST80053:        "SC-28, CP-9",
			NIST800190:       "§4.1.4",
			ISO27001:         "A.8.24, A.8.13, A.5.23",
			SOC2:             "CC6.1, A1.2",
			DISACCI:          "CCI-000366",
		},
		Remediation: "DocumentDB (`aws_docdb_cluster`):\n" +
			"  storage_encrypted         = true\n" +
			"  kms_key_id                = aws_kms_key.docdb.arn\n" +
			"  backup_retention_period   = 7\n" +
			"  deletion_protection       = true\n" +
			"  skip_final_snapshot       = false\n" +
			"\n" +
			"DynamoDB (`aws_dynamodb_table`):\n" +
			"  server_side_encryption { enabled = true, kms_key_arn = aws_kms_key.ddb.arn }\n" +
			"  point_in_time_recovery  { enabled = true }\n" +
			"  deletion_protection_enabled = true\n" +
			"Verify: `aws dynamodb describe-table --table-name <name> --query 'Table.[SSEDescription.Status,ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus]'` returns `[ENABLED, ENABLED]`.",
	},

	// ── Domain: Terraform / IaC ────────────────────────────────────────────── //
	{
		ID:      "TF-001",
		Domain:  "Terraform",
		Title:   "S3 Bucket Not Publicly Accessible",
		Summary: "Block all four S3 public-access levers on every bucket; never use acl=public-read.",
		Description: "Public S3 buckets expose sensitive data to the internet. " +
			"acl = \"public-read\" or block_public_acls = false allows unauthorized access.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "N/A",
			NIST80053:        "AC-3, AC-6",
			NIST800190:       "§4.4.2",
			ISO27001:         "A.5.15, A.8.3, A.8.22, A.5.23",
			SOC2:             "CC6.1, CC6.3",
			DISACCI:          "CCI-000213",
		},
		Remediation: "On every bucket, attach `aws_s3_bucket_public_access_block`:\n" +
			"  resource \"aws_s3_bucket_public_access_block\" \"this\" {\n" +
			"    bucket                  = aws_s3_bucket.this.id\n" +
			"    block_public_acls       = true\n" +
			"    block_public_policy     = true\n" +
			"    ignore_public_acls      = true\n" +
			"    restrict_public_buckets = true\n" +
			"  }\n" +
			"Never set `acl = \"public-read\"` or `\"public-read-write\"`. Enable account-level block public access (AWS: `aws_s3_account_public_access_block`). " +
			"Verify: `aws s3api get-public-access-block --bucket <name>` returns all four booleans `true`.",
	},

	{
		ID:      "TF-002",
		Domain:  "Terraform",
		Title:   "S3 Bucket Versioning Enabled",
		Summary: "Enable S3 versioning so accidental deletes or ransomware overwrites are recoverable.",
		Description: "Without versioning, accidental deletion or overwrite of S3 objects " +
			"is permanent. Versioning enables recovery from ransomware or operator error.",
		Severity: SeverityMedium,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "N/A",
			NIST80053:        "CP-9",
			NIST800190:       "§4.2, §4.5",
			ISO27001:         "A.8.13, A.5.23",
			SOC2:             "A1.2",
			DISACCI:          "CCI-000366",
		},
		Remediation: "Use the dedicated `aws_s3_bucket_versioning` resource:\n" +
			"  resource \"aws_s3_bucket_versioning\" \"this\" {\n" +
			"    bucket = aws_s3_bucket.this.id\n" +
			"    versioning_configuration { status = \"Enabled\" }\n" +
			"  }\n" +
			"For immutable/compliance workloads, add Object Lock + default retention: `aws_s3_bucket_object_lock_configuration` in governance or compliance mode. " +
			"Pair with a lifecycle rule to expire old versions and clean up incomplete multipart uploads so storage cost stays bounded. " +
			"Verify: `aws s3api get-bucket-versioning --bucket <name>` returns `Status: Enabled`.",
	},

	{
		ID:      "TF-003",
		Domain:  "Terraform",
		Title:   "ECS Task Definition Not Privileged",
		Summary: "Never set privileged=true on ECS container definitions — it grants host-root access.",
		Description: "Privileged ECS containers have full access to host devices and kernel " +
			"capabilities, enabling container escape.",
		Severity: SeverityHigh,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "5.5",
			NIST80053:        "AC-6, CM-7",
			NIST800190:       "§4.4.3",
			ISO27001:         "A.8.18, A.5.23, A.8.9",
			SOC2:             "CC6.1, CC6.3",
			DISACCI:          "CCI-000381",
		},
		Remediation: "In `aws_ecs_task_definition` container_definitions JSON, set `\"privileged\": false` (or omit — defaults to false on EC2; Fargate forbids it entirely). " +
			"For workloads that need narrow capabilities, use `linuxParameters.capabilities.add`:\n" +
			"  \"linuxParameters\": { \"capabilities\": { \"add\": [\"NET_BIND_SERVICE\"], \"drop\": [\"ALL\"] } }\n" +
			"Launch on Fargate where possible — the `privileged` parameter is unsupported and blocks this class of regression by design. " +
			"Verify: `aws ecs describe-task-definition --task-definition <name> --query 'taskDefinition.containerDefinitions[*].privileged'` returns `[false]` or `[null]`.",
	},

	{
		ID:      "TF-004",
		Domain:  "Terraform",
		Title:   "ECS Task Uses Non-Root User",
		Summary: "Set user to a non-root UID in every ECS container definition.",
		Description: "Running containers as root inside ECS tasks increases blast radius " +
			"of container compromise. Container processes should run as non-root.",
		Severity: SeverityMedium,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.1",
			NIST80053:        "AC-6",
			NIST800190:       "§4.4.3, §4.1.2",
			ISO27001:         "A.8.18, A.5.23, A.8.9",
			SOC2:             "CC6.1, CC6.3",
			DISACCI:          "CCI-000366",
		},
		Remediation: "In each entry under `container_definitions`, set a non-root `user`:\n" +
			"  \"user\": \"10001:10001\"     # numeric UID:GID preferred\n" +
			"  # or \"user\": \"nonroot\"    # resolved from image's /etc/passwd\n" +
			"Pair with a Dockerfile `USER 10001` so the image default is already non-root. " +
			"Chown any data volumes / bind mounts to the same UID during image build. " +
			"Verify: `aws ecs describe-task-definition --task-definition <name> --query 'taskDefinition.containerDefinitions[*].user'` returns non-empty, non-root values.",
	},

	{
		ID:      "TF-005",
		Domain:  "Terraform",
		Title:   "ECS Task Has Read-Only Root Filesystem",
		Summary: "Set readonlyRootFilesystem=true on ECS container definitions; writes go to tmpfs or EFS.",
		Description: "Writable root filesystems allow attackers to modify binaries, " +
			"install tools, or persist malware inside the container.",
		Severity: SeverityMedium,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "5.13",
			NIST80053:        "CM-7, SI-7",
			NIST800190:       "§4.4.3",
			ISO27001:         "A.8.19, A.5.23, A.8.9",
			SOC2:             "CC6.1",
			DISACCI:          "CCI-000366",
		},
		Remediation: "In each `container_definitions` entry, set `\"readonlyRootFilesystem\": true`. " +
			"For paths the app writes to, attach tmpfs mounts or EFS volumes:\n" +
			"  \"linuxParameters\": { \"tmpfs\": [ { \"containerPath\": \"/tmp\", \"size\": 64 } ] }\n" +
			"  \"mountPoints\":     [ { \"sourceVolume\": \"data\", \"containerPath\": \"/data\" } ]\n" +
			"Verify: `aws ecs describe-task-definition --task-definition <name> --query 'taskDefinition.containerDefinitions[*].readonlyRootFilesystem'` returns `[true]`.",
	},

	{
		ID:      "TF-006",
		Domain:  "Terraform",
		Title:   "Security Group Allows Unrestricted Ingress",
		Summary: "Never allow 0.0.0.0/0 ingress on SSH/RDP/DB ports; use VPN or bastion instead.",
		Description: "Security groups with 0.0.0.0/0 ingress on sensitive ports " +
			"(SSH 22, RDP 3389, DB ports) expose services to brute-force and exploitation.",
		Severity: SeverityHigh,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "N/A",
			NIST80053:        "SC-7, AC-17",
			NIST800190:       "§4.4.2, §4.5",
			ISO27001:         "A.8.20, A.8.22, A.5.23",
			SOC2:             "CC6.6",
			DISACCI:          "CCI-001097",
		},
		Remediation: "Forbidden patterns in `aws_security_group`/`aws_security_group_rule`:\n" +
			"  cidr_blocks = [\"0.0.0.0/0\"] with from_port/to_port in (22, 3389, 3306, 5432, 6379, 27017, 9200, 11211, 1433)\n" +
			"  ipv6_cidr_blocks = [\"::/0\"] same ports\n" +
			"Use explicit CIDR allow-lists for office/VPN ranges, or front admin access with SSM Session Manager (SSH) / AWS Client VPN / a bastion host in a dedicated admin subnet. " +
			"For HTTP/HTTPS (80/443), 0.0.0.0/0 is acceptable only on ALBs/NLBs that front auth middleware. " +
			"Verify: `aws ec2 describe-security-groups --query 'SecurityGroups[].IpPermissions[?IpRanges[?CidrIp==\\`0.0.0.0/0\\`]]'` returns no sensitive-port rules.",
	},

	{
		ID:      "TF-007",
		Domain:  "Terraform",
		Title:   "KMS Encryption on EBS/RDS/S3",
		Summary: "Encrypt EBS, RDS, and S3 with a customer-managed KMS key (not the default aws/* alias).",
		Description: "Unencrypted EBS volumes, RDS instances, and S3 buckets expose data " +
			"at rest to physical access or snapshot theft.",
		Severity: SeverityHigh,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "N/A",
			NIST80053:        "SC-28",
			NIST800190:       "§4.1.4",
			ISO27001:         "A.8.24, A.5.23",
			SOC2:             "CC6.1, CC6.7",
			DISACCI:          "CCI-002476",
		},
		Remediation: "Create a customer-managed KMS key (CMK) with automatic rotation; reference it everywhere:\n" +
			"  EBS  (aws_ebs_volume / launch template): encrypted = true, kms_key_id = aws_kms_key.data.arn\n" +
			"  RDS  (aws_db_instance):                   storage_encrypted = true, kms_key_id = aws_kms_key.data.arn\n" +
			"  S3   (aws_s3_bucket_server_side_encryption_configuration):\n" +
			"         rule { apply_server_side_encryption_by_default { sse_algorithm = \"aws:kms\", kms_master_key_id = aws_kms_key.data.arn } }\n" +
			"Enable account-level default EBS encryption: `aws_ebs_encryption_by_default`. " +
			"Verify: `aws ec2 get-ebs-encryption-by-default`, `aws rds describe-db-instances --query 'DBInstances[*].StorageEncrypted'`, and `aws s3api get-bucket-encryption --bucket <name>` all confirm KMS-backed encryption.",
	},

	{
		ID:      "TF-008",
		Domain:  "Terraform",
		Title:   "CloudTrail / Logging Enabled",
		Summary: "Enable a multi-region CloudTrail with log-file validation and ship to an immutable bucket.",
		Description: "Without CloudTrail, API actions go unrecorded, preventing " +
			"incident investigation and compliance auditing.",
		Severity: SeverityMedium,
		Type:     ControlDetective,
		Compliance: ComplianceMapping{
			CISDockerSection: "N/A",
			NIST80053:        "AU-2, AU-12",
			NIST800190:       "§4.3.2, §4.5",
			ISO27001:         "A.8.15, A.5.23, A.8.16",
			SOC2:             "CC7.2",
			DISACCI:          "CCI-000172",
		},
		Remediation: "Required on `aws_cloudtrail`:\n" +
			"  is_multi_region_trail         = true\n" +
			"  include_global_service_events = true\n" +
			"  enable_log_file_validation    = true\n" +
			"  kms_key_id                    = aws_kms_key.trail.arn\n" +
			"  event_selector { read_write_type = \"All\", include_management_events = true }\n" +
			"Ship logs to a dedicated log-archive account S3 bucket with Object Lock (compliance mode) — prevents tampering by admin compromise. " +
			"Enable S3 access logging on every bucket via `aws_s3_bucket_logging` to capture data-plane events not covered by CloudTrail. " +
			"Verify: `aws cloudtrail describe-trails --query 'trailList[*].[IsMultiRegionTrail,LogFileValidationEnabled]'` returns `[[true, true]]`.",
	},

	{
		ID:      "TF-009",
		Domain:  "Terraform",
		Title:   "IaC Vulnerability Scan (Terraform)",
		Summary: "Scan Terraform in CI for insecure AWS/GCP/Azure configurations beyond pattern checks.",
		Description: "Terraform files may contain insecure configurations that automated " +
			"scanners like Trivy and Snyk can detect beyond regex-based pattern checks.",
		Severity: SeverityHigh,
		Type:     ControlDetective,
		Compliance: ComplianceMapping{
			CISDockerSection: "N/A",
			NIST80053:        "RA-5, SA-11, CM-6",
			NIST800190:       "§4.1.2",
			ISO27001:         "A.8.8, A.8.26, A.8.25, A.5.23",
			SOC2:             "CC7.1",
			DISACCI:          "CCI-001067",
		},
		Remediation: "Run at least one of these in CI on every Terraform PR and fail on high-severity findings:\n" +
			"  trivy config --severity HIGH,CRITICAL --exit-code 1 ./terraform\n" +
			"  snyk iac test ./terraform --severity-threshold=high\n" +
			"  checkov -d ./terraform\n" +
			"  tfsec ./terraform --minimum-severity HIGH\n" +
			"Also layer policy enforcement: OPA/Conftest against the Terraform plan JSON (`terraform show -json plan.out | conftest test --policy policies/ -`). " +
			"Run `terraform plan` in a non-prod account (or as a read-only dry run) so findings reflect actual intent, not template defaults. " +
			"Verify: scanner exits 0 with no open waivers before apply.",
	},

	// ── Domain: Kubernetes ─────────────────────────────────────────────────── //
	{
		ID:      "K8S-001",
		Domain:  "Kubernetes",
		Title:   "Namespace Isolation (Non-Default)",
		Summary: "Deploy workloads to dedicated namespaces (never 'default') so RBAC and NetworkPolicy bind.",
		Description: "Running workloads in the default namespace prevents effective " +
			"network policy isolation and RBAC segmentation.",
		Severity: SeverityMedium,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "N/A",
			NIST80053:        "AC-4, SC-7",
			NIST800190:       "§4.3.3",
			ISO27001:         "A.8.22",
			SOC2:             "CC6.1, CC6.3",
			DISACCI:          "CCI-001090",
		},
		Remediation: "Create and deploy to a dedicated namespace:\n" +
			"  kubectl create namespace <app>\n" +
			"  kubectl label namespace <app> pod-security.kubernetes.io/enforce=restricted\n" +
			"Apply a default-deny NetworkPolicy (see NETWORK-001) and namespace-scoped Role/RoleBindings. " +
			"Prevent future deploys to `default` via Kyverno ClusterPolicy that rejects workloads with `.metadata.namespace == \"default\"`. " +
			"Verify: `kubectl get all -n default` returns only the built-in `kubernetes` service.",
	},

	{
		ID:      "K8S-002",
		Domain:  "Kubernetes",
		Title:   "Pod Anti-Affinity / Spread Rules Set",
		Summary: "Spread pod replicas across nodes/zones so a single node failure won't take down the app.",
		Description: "Without topology spread constraints or pod anti-affinity, all replicas " +
			"may land on the same node, creating a single point of failure.",
		Severity: SeverityLow,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "N/A",
			NIST80053:        "CP-9, SC-5",
			NIST800190:       "§4.3.4",
			ISO27001:         "A.5.29, A.5.30, A.8.14",
			SOC2:             "A1.2",
			DISACCI:          "N/A",
		},
		Remediation: "Prefer `topologySpreadConstraints` (K8s 1.19+) over `podAntiAffinity`:\n" +
			"  topologySpreadConstraints:\n" +
			"    - maxSkew: 1\n" +
			"      topologyKey: topology.kubernetes.io/zone\n" +
			"      whenUnsatisfiable: DoNotSchedule\n" +
			"      labelSelector: { matchLabels: { app: <app> } }\n" +
			"    - maxSkew: 1\n" +
			"      topologyKey: kubernetes.io/hostname\n" +
			"      whenUnsatisfiable: ScheduleAnyway\n" +
			"      labelSelector: { matchLabels: { app: <app> } }\n" +
			"Pair with a PodDisruptionBudget (`minAvailable: N-1`) so voluntary disruptions respect the spread. " +
			"Verify: `kubectl get pods -l app=<app> -o wide` shows distribution across distinct nodes and zones.",
	},

	{
		ID:      "K8S-003",
		Domain:  "Kubernetes",
		Title:   "IaC Vulnerability Scan (Kubernetes Manifests)",
		Summary: "Scan Kubernetes manifests in CI for misconfigurations beyond what regex checks catch.",
		Description: "Kubernetes manifests may contain misconfigurations that automated " +
			"scanners like Trivy and Snyk can detect beyond pattern-based checks.",
		Severity: SeverityHigh,
		Type:     ControlDetective,
		Compliance: ComplianceMapping{
			CISDockerSection: "N/A",
			NIST80053:        "RA-5, SA-11, CM-6",
			NIST800190:       "§4.1.2",
			ISO27001:         "A.8.8, A.8.26, A.8.25",
			SOC2:             "CC7.1",
			DISACCI:          "CCI-001067",
		},
		Remediation: "Run at least one of these in CI and fail the pipeline on high-severity findings:\n" +
			"  trivy config --severity HIGH,CRITICAL --exit-code 1 ./manifests\n" +
			"  snyk iac test ./manifests --severity-threshold=high\n" +
			"  kube-linter lint ./manifests\n" +
			"  checkov -d ./manifests --framework kubernetes\n" +
			"Also run policy engines against rendered manifests:\n" +
			"  conftest test --policy policies/ ./manifests\n" +
			"  kyverno test ./policies\n" +
			"Fix identified misconfigs (e.g. missing resource limits, runAsRoot, host namespace sharing). " +
			"Verify: the scanner exits 0 in CI with no pending waivers.",
	},

		// ── Domain: Registry ───────────────────────────────────────────────────── //
	{
		ID:      "REGISTRY-001",
		Domain:  "Docker",
		Title:   "No Insecure Registries Configured",
		Summary: "Never list a registry in insecure-registries — it disables TLS cert verification.",
		Description: "Listing a registry in insecure-registries (or passing --insecure-registry to " +
			"dockerd) disables TLS certificate verification for that registry. Image pulls can then " +
			"be silently MITM'd: an attacker on the network path serves a malicious image layer and " +
			"the daemon accepts it without verification. Also applies to registries referenced over " +
			"plain http:// URLs.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "2.5",
			NIST80053:        "SC-8, SC-13, IA-3, SR-3",
			NIST800190:       "§3.2.1, §4.2.1",
			ISO27001:         "A.8.20, A.5.14, A.8.23",
			SOC2:             "CC6.6, CC6.7",
			DISACCI:          "CCI-002418, CCI-002421",
		},
		Remediation: "Empty the `insecure-registries` array in /etc/docker/daemon.json and remove any `--insecure-registry` flag from the dockerd unit:\n" +
			"  { \"insecure-registries\": [] }\n" +
			"Configure every registry — including internal ones — to serve TLS with a trusted certificate. " +
			"For registries signed by an internal CA, install the CA bundle on the host (`/etc/docker/certs.d/<registry>/ca.crt`) rather than disabling verification. " +
			"After change: `systemctl restart docker` and pull a test image to confirm TLS works. " +
			"Verify: `docker info --format '{{.RegistryConfig.InsecureRegistryCIDRs}} {{.RegistryConfig.IndexConfigs}}'` shows no user-added insecure entries.",
	},
	{
		ID:      "REGISTRY-002",
		Domain:  "Docker",
		Title:   "No Image References to Unauthenticated Registries",
		Summary: "Pull images only from authenticated TLS registries; never http:// or anonymous mirrors.",
		Description: "FROM directives, compose image fields, and k8s pod image references pointing " +
			"at http:// registries or known public anonymous mirrors expose image pulls to MITM and " +
			"allow any network-adjacent attacker to substitute images. This control pairs with " +
			"REGISTRY-001, which enforces the daemon-side posture.",
		Severity: SeverityHigh,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "4.5",
			NIST80053:        "IA-3, SC-8, SI-7, SR-3, SR-4",
			NIST800190:       "§3.2.3, §4.2.3",
			ISO27001:         "A.8.3, A.5.14, A.8.5",
			SOC2:             "CC6.1, CC6.6, CC6.8",
			DISACCI:          "CCI-000778, CCI-002418",
		},
		Remediation: "Audit for insecure/anonymous references across the repo:\n" +
			"  grep -rnE 'FROM[[:space:]]+http://' .\n" +
			"  grep -rnE 'image:[[:space:]]*http://' .\n" +
			"  kubectl get pods -A -o json | jq -r '.items[].spec.containers[].image' | grep -E '^http://|^[^./]+/[^@]+$'\n" +
			"Pull only from authenticated registries (ECR, GAR, ACR, Harbor, private Docker Hub). Configure imagePullSecrets in Kubernetes and provide a credential helper in CI. " +
			"Combine with REGISTRY-001 (daemon-side) and SUPPLY-001 (signature verification). " +
			"Verify: every `image:` field resolves through an authenticated registry; anonymous pull attempts via `curl -I <registry>/v2/<repo>/manifests/<tag>` return `401` without a token.",
	},
	{
		ID:      "REGISTRY-003",
		Domain:  "Terraform",
		Title:   "Cloud Registry Enforces Authentication and IAM Least-Privilege",
		Summary: "Never allow anonymous/wildcard IAM on ECR/GAR/ACR repositories.",
		Description: "ECR, Google Artifact Registry, and Azure Container Registry can be configured " +
			"to allow anonymous pulls or permissive repository policies (Principal: \"*\", " +
			"allUsers / allAuthenticatedUsers, anonymous_pull_enabled = true). Any such configuration " +
			"effectively exposes proprietary images and makes stale vulnerable images reachable from " +
			"the public Internet.",
		Severity: SeverityCritical,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "N/A",
			NIST80053:        "AC-3, AC-6, IA-2, SR-3",
			NIST800190:       "§3.2.3, §4.2.3",
			ISO27001:         "A.5.15, A.8.3, A.5.23",
			SOC2:             "CC6.1, CC6.3",
			DISACCI:          "CCI-000213, CCI-002235",
		},
		Remediation: "Forbidden IAM patterns across cloud registries:\n" +
			"  ECR:  aws_ecr_repository_policy with `Principal = \"*\"` in the policy document\n" +
			"  GAR:  google_artifact_registry_repository_iam_* with `member = \"allUsers\"` or `\"allAuthenticatedUsers\"`\n" +
			"  ACR:  azurerm_container_registry with `anonymous_pull_enabled = true`\n" +
			"Scope every policy to specific principal ARNs / service-account emails / AD groups that actually need pull/push. " +
			"Separate push (CI) and pull (runtime) identities; grant each only the narrow verbs (`ecr:BatchGetImage`, `ecr:GetDownloadUrlForLayer` for pull). " +
			"Verify: `aws ecr get-repository-policy --repository-name <name>` Principal list contains only expected ARNs; `gcloud artifacts repositories get-iam-policy ...` has no allUsers/allAuthenticatedUsers bindings; `az acr show --name <name> --query anonymousPullEnabled` returns `false`.",
	},
	{
		ID:      "REGISTRY-004",
		Domain:  "Terraform",
		Title:   "Cloud Registry Has Lifecycle / Retention Policy",
		Summary: "Expire untagged images and cap retained tags so stale, vulnerable images are pruned.",
		Description: "Registries without a lifecycle or retention policy accumulate stale, vulnerable " +
			"images indefinitely. Each stale tag is a candidate for accidental deployment — a developer " +
			"pulls \"latest\" or an older pinned tag and resurrects a known-exploitable image. A lifecycle " +
			"policy that ages out untagged images and caps the number of retained tags bounds this risk.",
		Severity: SeverityMedium,
		Type:     ControlPreventive,
		Compliance: ComplianceMapping{
			CISDockerSection: "N/A",
			NIST80053:        "SI-2, RA-5, CM-2, SR-3, SR-12",
			NIST800190:       "§3.2.2, §4.2.2",
			ISO27001:         "A.8.10, A.8.8, A.8.25, A.5.23",
			SOC2:             "CC7.1, A1.2",
			DISACCI:          "CCI-002617",
		},
		Remediation: "ECR example (expire untagged after 14 days, keep 10 most recent tagged):\n" +
			"  resource \"aws_ecr_lifecycle_policy\" \"app\" {\n" +
			"    repository = aws_ecr_repository.app.name\n" +
			"    policy = jsonencode({ rules = [\n" +
			"      { rulePriority = 1, selection = { tagStatus = \"untagged\", countType = \"sinceImagePushed\", countUnit = \"days\", countNumber = 14 }, action = { type = \"expire\" } },\n" +
			"      { rulePriority = 2, selection = { tagStatus = \"tagged\", tagPrefixList = [\"v\"], countType = \"imageCountMoreThan\", countNumber = 10 }, action = { type = \"expire\" } }\n" +
			"    ] })\n" +
			"  }\n" +
			"GAR: set `cleanup_policies` blocks on the repository with KEEP (recent) and DELETE (older than) rules. " +
			"ACR: enable `retention_policy { enabled = true, days = 7 }` and `trust_policy { enabled = true }`. " +
			"Verify: `aws ecr get-lifecycle-policy --repository-name <name>` returns the expected JSON; untagged images age out after the configured window.",
	},
}
