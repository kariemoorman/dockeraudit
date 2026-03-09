package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"strconv"

	"github.com/kariemoorman/dockeraudit/internal/types"
)

// containerInspect holds fields from docker inspect for a running container.
type containerInspect struct {
	Name       string `json:"Name"`
	HostConfig struct {
		Privileged      bool     `json:"Privileged"`
		CapDrop         []string `json:"CapDrop"`
		CapAdd          []string `json:"CapAdd"`
		SecurityOpt     []string `json:"SecurityOpt"`
		Memory          int64    `json:"Memory"`
		NanoCpus        int64    `json:"NanoCpus"`
		ReadonlyRootfs  bool     `json:"ReadonlyRootfs"`
		UsernsMode      string   `json:"UsernsMode"`
		Binds           []string `json:"Binds"`
		NetworkMode     string   `json:"NetworkMode"`
		PidMode         string   `json:"PidMode"`
		IpcMode         string   `json:"IpcMode"`
		UTSMode         string   `json:"UTSMode"`
	} `json:"HostConfig"`
	Mounts []struct {
		Type   string `json:"Type"`
		Source string `json:"Source"`
	} `json:"Mounts"`
}

// ScanRunningContainers inspects all running containers for runtime misconfigurations.
func ScanRunningContainers(ctx context.Context) (*types.ScanResult, error) {
	result := &types.ScanResult{
		Target:  "running-containers",
		Scanner: "runtime",
	}

	// Get all running container IDs
	listCmd := exec.CommandContext(ctx, "docker", "ps", "-q")
	out, err := listCmd.Output()
	if err != nil {
		return nil, fmt.Errorf("docker ps failed: %w", err)
	}

	ids := strings.Fields(strings.TrimSpace(string(out)))
	if len(ids) == 0 {
		return result, nil
	}

	args := append([]string{"inspect"}, ids...)
	inspectCmd := exec.CommandContext(ctx, "docker", args...) // #nosec G204 -- fixed executable; ids are hex container IDs from docker ps output
	inspectOut, err := inspectCmd.Output()
	if err != nil {
		return nil, fmt.Errorf("docker inspect containers failed: %w", err)
	}

	var containers []containerInspect
	if err := json.Unmarshal(inspectOut, &containers); err != nil {
		return nil, fmt.Errorf("parse container inspect: %w", err)
	}

	for _, c := range containers {
		result.Findings = append(result.Findings, checkContainerPrivileged(c)...)
		result.Findings = append(result.Findings, checkContainerCapabilities(c)...)
		result.Findings = append(result.Findings, checkContainerReadonly(c)...)
		result.Findings = append(result.Findings, checkContainerResourceLimits(c)...)
		result.Findings = append(result.Findings, checkContainerSecurityOpts(c)...)
		result.Findings = append(result.Findings, checkContainerNamespaces(c)...)
		result.Findings = append(result.Findings, checkDockerSocketMount(c)...)
	}

	result.Tally()
	return result, nil
}

func checkContainerPrivileged(c containerInspect) []types.Finding {
	ctrl := controlByID("RUNTIME-002")
	if c.HostConfig.Privileged {
		return []types.Finding{fail(ctrl, c.Name,
			"Container is running in privileged mode",
			"HostConfig.Privileged == true",
			ctrl.Remediation)}
	}
	return []types.Finding{pass(ctrl, c.Name, "Container is not privileged")}
}

func checkContainerCapabilities(c containerInspect) []types.Finding {
	ctrl := controlByID("RUNTIME-003")
	capDrop := strings.Join(c.HostConfig.CapDrop, ",")
	if !strings.Contains(strings.ToUpper(capDrop), "ALL") {
		return []types.Finding{fail(ctrl, c.Name,
			"Container does not drop ALL capabilities",
			fmt.Sprintf("CapDrop: %v", c.HostConfig.CapDrop),
			ctrl.Remediation)}
	}
	return []types.Finding{pass(ctrl, c.Name, fmt.Sprintf("CapDrop: %v", c.HostConfig.CapDrop))}
}

func checkContainerReadonly(c containerInspect) []types.Finding {
	ctrl := controlByID("RUNTIME-005")
	if !c.HostConfig.ReadonlyRootfs {
		return []types.Finding{warn(ctrl, c.Name,
			"Container root filesystem is writable",
			"HostConfig.ReadonlyRootfs == false")}
	}
	return []types.Finding{pass(ctrl, c.Name, "Root filesystem is read-only")}
}

func checkContainerResourceLimits(c containerInspect) []types.Finding {
	ctrl := controlByID("RUNTIME-007")
	if c.HostConfig.Memory == 0 {
		return []types.Finding{fail(ctrl, c.Name,
			"No memory limit set on container",
			"HostConfig.Memory == 0",
			ctrl.Remediation)}
	}
	return []types.Finding{pass(ctrl, c.Name,
		fmt.Sprintf("Memory limit: %d bytes", c.HostConfig.Memory))}
}

func checkContainerSecurityOpts(c containerInspect) []types.Finding {
	var findings []types.Finding

	// Check no-new-privileges
	ctrl1 := controlByID("RUNTIME-004")
	hasNoNewPriv := false
	hasSeccomp := false
	for _, opt := range c.HostConfig.SecurityOpt {
		if strings.Contains(opt, "no-new-privileges:true") || opt == "no-new-privileges" {
			hasNoNewPriv = true
		}
		if strings.HasPrefix(opt, "seccomp") {
			hasSeccomp = true
		}
	}

	if !hasNoNewPriv {
		findings = append(findings, fail(ctrl1, c.Name,
			"no-new-privileges not set",
			fmt.Sprintf("SecurityOpts: %v", c.HostConfig.SecurityOpt),
			ctrl1.Remediation))
	} else {
		findings = append(findings, pass(ctrl1, c.Name, "no-new-privileges is set"))
	}

	ctrl2 := controlByID("RUNTIME-008")
	if !hasSeccomp {
		findings = append(findings, warn(ctrl2, c.Name,
			"No seccomp profile explicitly configured",
			fmt.Sprintf("SecurityOpts: %v", c.HostConfig.SecurityOpt)))
	} else {
		findings = append(findings, pass(ctrl2, c.Name, "seccomp profile is configured"))
	}

	return findings
}

func checkContainerNamespaces(c containerInspect) []types.Finding {
	ctrl := controlByID("RUNTIME-006")
	var issues []string

	if c.HostConfig.PidMode == "host" {
		issues = append(issues, "hostPID: true")
	}
	if c.HostConfig.IpcMode == "host" {
		issues = append(issues, "hostIPC: true")
	}
	if c.HostConfig.NetworkMode == "host" {
		issues = append(issues, "hostNetwork: true")
	}
	if c.HostConfig.UTSMode == "host" {
		issues = append(issues, "hostUTS: true")
	}

	if len(issues) > 0 {
		return []types.Finding{fail(ctrl, c.Name,
			"Container shares host namespaces: "+strings.Join(issues, ", "),
			strings.Join(issues, ", "),
			ctrl.Remediation)}
	}
	return []types.Finding{pass(ctrl, c.Name, "No host namespace sharing")}
}

func checkDockerSocketMount(c containerInspect) []types.Finding {
	ctrl := controlByID("DAEMON-001")
	for _, mount := range c.Mounts {
		if mount.Source == "/var/run/docker.sock" {
			return []types.Finding{fail(ctrl, c.Name,
				"Docker socket mounted into container",
				"Mounts[].Source == /var/run/docker.sock",
				ctrl.Remediation)}
		}
	}
	// Also check Binds
	for _, bind := range c.HostConfig.Binds {
		if strings.HasPrefix(bind, "/var/run/docker.sock") {
			return []types.Finding{fail(ctrl, c.Name,
				"Docker socket mounted via bind",
				bind,
				ctrl.Remediation)}
		}
	}
	return []types.Finding{pass(ctrl, c.Name, "Docker socket not mounted")}
}

// ScanDaemon inspects docker daemon configuration.
func ScanDaemon(ctx context.Context) (*types.ScanResult, error) {
	result := &types.ScanResult{
		Target:  "docker-daemon",
		Scanner: "daemon",
	}

	infoCmd := exec.CommandContext(ctx, "docker", "info", "--format", "{{json .}}")
	out, err := infoCmd.Output()
	if err != nil {
		return nil, fmt.Errorf("docker info failed: %w", err)
	}

	var info struct {
		SecurityOptions []string `json:"SecurityOptions"`
		LoggingDriver   string   `json:"LoggingDriver"`
		KernelVersion   string   `json:"KernelVersion"`
		OperatingSystem string   `json:"OperatingSystem"`
	}
	if err := json.Unmarshal(out, &info); err != nil {
		return nil, fmt.Errorf("parse docker info: %w", err)
	}

	// Check usernamespace
	ctrl := controlByID("DAEMON-003")
	hasUserns := false
	hasAppArmor := false
	hasSeccomp := false
	hasSelinux := false

	for _, opt := range info.SecurityOptions {
		lower := strings.ToLower(opt)
		if strings.Contains(lower, "userns") {
			hasUserns = true
		}
		if strings.Contains(lower, "apparmor") {
			hasAppArmor = true
		}
		if strings.Contains(lower, "seccomp") {
			hasSeccomp = true
		}
		if strings.Contains(lower, "selinux") {
			hasSelinux = true
		}
	}

	if !hasUserns {
		result.Findings = append(result.Findings, fail(ctrl, "docker-daemon",
			"User namespace remapping is not enabled",
			fmt.Sprintf("SecurityOptions: %v", info.SecurityOptions),
			ctrl.Remediation))
	} else {
		result.Findings = append(result.Findings, pass(ctrl, "docker-daemon", "User namespace remapping is enabled"))
	}

	// Check TCP port 2375
	ctrl2 := controlByID("DAEMON-002")
	ssCmd := exec.CommandContext(ctx, "ss", "-lntp") // #nosec G204 -- fixed executable and args, no user input
	ssOut, _ := ssCmd.Output()
	if strings.Contains(string(ssOut), "2375") {
		result.Findings = append(result.Findings, fail(ctrl2, "docker-daemon",
			"Docker daemon is listening on unauthenticated TCP port 2375",
			string(ssOut),
			ctrl2.Remediation))
	} else {
		result.Findings = append(result.Findings, pass(ctrl2, "docker-daemon", "Port 2375 is not listening"))
	}

	// MAC
	ctrl3 := controlByID("HOST-004")
	if hasAppArmor || hasSelinux {
		result.Findings = append(result.Findings, pass(ctrl3, "docker-daemon",
			fmt.Sprintf("MAC active: AppArmor=%v SELinux=%v", hasAppArmor, hasSelinux)))
	} else {
		result.Findings = append(result.Findings, fail(ctrl3, "docker-daemon",
			"Neither AppArmor nor SELinux detected in Docker security options",
			fmt.Sprintf("SecurityOptions: %v", info.SecurityOptions),
			ctrl3.Remediation))
	}

	// Seccomp
	ctrl4 := controlByID("RUNTIME-008")
	if hasSeccomp {
		result.Findings = append(result.Findings, pass(ctrl4, "docker-daemon", "Default seccomp profile active"))
	} else {
		result.Findings = append(result.Findings, warn(ctrl4, "docker-daemon", "seccomp not listed in security options",
			fmt.Sprintf("SecurityOptions: %v", info.SecurityOptions)))
	}

	// Logging driver
	ctrl5 := controlByID("DAEMON-005")
	if info.LoggingDriver == "" || info.LoggingDriver == "none" {
		result.Findings = append(result.Findings, fail(ctrl5, "docker-daemon",
			"Logging driver is none or not configured",
			fmt.Sprintf("LoggingDriver: %q", info.LoggingDriver),
			ctrl5.Remediation))
	} else {
		result.Findings = append(result.Findings, pass(ctrl5, "docker-daemon",
			fmt.Sprintf("Logging driver: %s", info.LoggingDriver)))
	}

	// Check daemon.json for additional settings
	result.Findings = append(result.Findings, checkDaemonJSON()...)

	// HOST-002: Check kernel version for known container-escape CVEs
	result.Findings = append(result.Findings, checkKernelVersion(info.KernelVersion)...)

	// Auditd rules: read once, check both HOST-005 and HOST-006
	auditRules := getAuditdRules(ctx)
	result.Findings = append(result.Findings, checkAuditdDockerFiles(ctx, auditRules)...)
	result.Findings = append(result.Findings, checkAuditdDockerPaths(auditRules)...)

	result.Tally()
	return result, nil
}

// checkDaemonJSON reads /etc/docker/daemon.json and checks for
// DAEMON-004 (content trust), DAEMON-006 (ICC), DAEMON-007 (userland-proxy), DAEMON-008 (live-restore).
func checkDaemonJSON() []types.Finding {
	var findings []types.Finding

	data, err := os.ReadFile("/etc/docker/daemon.json")
	if err != nil {
		// File not found is not an error — daemon may use defaults
		if os.IsNotExist(err) {
			ctrl6 := controlByID("DAEMON-006")
			findings = append(findings, warn(ctrl6, "docker-daemon",
				"No daemon.json found — cannot verify ICC, userland-proxy, or live-restore settings",
				"/etc/docker/daemon.json not found"))
			// DAEMON-004: Check env var fallback when no daemon.json
			findings = append(findings, checkContentTrustEnv()...)
			return findings
		}
		return []types.Finding{errFinding(controlByID("DAEMON-006"), "docker-daemon",
			fmt.Sprintf("Failed to read daemon.json: %v", err))}
	}

	var daemon map[string]interface{}
	if err := json.Unmarshal(data, &daemon); err != nil {
		return []types.Finding{errFinding(controlByID("DAEMON-006"), "docker-daemon",
			fmt.Sprintf("Failed to parse daemon.json: %v", err))}
	}

	// DAEMON-004: Docker Content Trust
	ctrl4ct := controlByID("DAEMON-004")
	if ct, ok := daemon["content-trust"]; ok {
		// daemon.json may have "content-trust": {"mode": "enforced"} or similar
		if ctMap, ok := ct.(map[string]interface{}); ok {
			if mode, ok := ctMap["mode"].(string); ok && strings.EqualFold(mode, "enforced") {
				findings = append(findings, pass(ctrl4ct, "docker-daemon", "Docker content trust enforced via daemon.json"))
			} else {
				findings = append(findings, fail(ctrl4ct, "docker-daemon",
					"Docker content trust is configured but not set to enforced mode",
					fmt.Sprintf("daemon.json: content-trust = %v", ct),
					ctrl4ct.Remediation))
			}
		} else {
			findings = append(findings, warn(ctrl4ct, "docker-daemon",
				"Docker content trust key present in daemon.json but has unexpected format",
				fmt.Sprintf("content-trust = %v", ct)))
		}
	} else {
		// No content-trust key in daemon.json — check DOCKER_CONTENT_TRUST env var
		findings = append(findings, checkContentTrustEnv()...)
	}

	// DAEMON-006: Inter-Container Communication
	ctrl6 := controlByID("DAEMON-006")
	if icc, ok := daemon["icc"]; ok {
		if iccBool, ok := icc.(bool); ok && !iccBool {
			findings = append(findings, pass(ctrl6, "docker-daemon", "ICC disabled (icc: false)"))
		} else {
			findings = append(findings, fail(ctrl6, "docker-daemon",
				"Inter-container communication is enabled (icc: true)",
				"daemon.json: icc = true",
				ctrl6.Remediation))
		}
	} else {
		findings = append(findings, warn(ctrl6, "docker-daemon",
			"ICC not configured in daemon.json — defaults to true (all containers can communicate)",
			"icc key not present in daemon.json"))
	}

	// DAEMON-007: Userland Proxy
	ctrl7 := controlByID("DAEMON-007")
	if up, ok := daemon["userland-proxy"]; ok {
		if upBool, ok := up.(bool); ok && !upBool {
			findings = append(findings, pass(ctrl7, "docker-daemon", "Userland proxy disabled"))
		} else {
			findings = append(findings, warn(ctrl7, "docker-daemon",
				"Userland proxy enabled — uses user-space TCP forwarder instead of iptables hairpin NAT",
				"daemon.json: userland-proxy = true"))
		}
	} else {
		findings = append(findings, warn(ctrl7, "docker-daemon",
			"userland-proxy not set in daemon.json — defaults to true",
			"userland-proxy key not present in daemon.json"))
	}

	// DAEMON-008: Live Restore
	ctrl8 := controlByID("DAEMON-008")
	if lr, ok := daemon["live-restore"]; ok {
		if lrBool, ok := lr.(bool); ok && lrBool {
			findings = append(findings, pass(ctrl8, "docker-daemon", "Live restore enabled"))
		} else {
			findings = append(findings, warn(ctrl8, "docker-daemon",
				"live-restore is false — containers will stop on daemon restart",
				"daemon.json: live-restore = false"))
		}
	} else {
		findings = append(findings, warn(ctrl8, "docker-daemon",
			"live-restore not set in daemon.json — defaults to false",
			"live-restore key not present in daemon.json"))
	}

	// DAEMON-005: Log rotation settings (max-size/max-file)
	ctrl5 := controlByID("DAEMON-005")
	if logOpts, ok := daemon["log-opts"]; ok {
		if optsMap, ok := logOpts.(map[string]interface{}); ok {
			hasMaxSize := false
			hasMaxFile := false
			var maxSizeVal, maxFileVal string
			if ms, ok := optsMap["max-size"]; ok {
				hasMaxSize = true
				maxSizeVal = fmt.Sprintf("%v", ms)
			}
			if mf, ok := optsMap["max-file"]; ok {
				hasMaxFile = true
				maxFileVal = fmt.Sprintf("%v", mf)
			}
			if hasMaxSize && hasMaxFile {
				findings = append(findings, pass(ctrl5, "docker-daemon",
					fmt.Sprintf("Log rotation configured (max-size: %s, max-file: %s)", maxSizeVal, maxFileVal)))
			} else if hasMaxSize {
				findings = append(findings, warn(ctrl5, "docker-daemon",
					fmt.Sprintf("Log rotation partially configured — max-size: %s but max-file not set", maxSizeVal),
					"daemon.json: log-opts has max-size but missing max-file"))
			} else if hasMaxFile {
				findings = append(findings, warn(ctrl5, "docker-daemon",
					fmt.Sprintf("Log rotation partially configured — max-file: %s but max-size not set", maxFileVal),
					"daemon.json: log-opts has max-file but missing max-size"))
			} else {
				findings = append(findings, warn(ctrl5, "docker-daemon",
					"log-opts present in daemon.json but no max-size or max-file configured — unbounded log growth possible",
					"daemon.json: log-opts missing max-size and max-file"))
			}
		}
	} else {
		findings = append(findings, warn(ctrl5, "docker-daemon",
			"No log-opts in daemon.json — log rotation not configured, unbounded log growth possible",
			"log-opts key not present in daemon.json"))
	}

	return findings
}

// checkKernelVersion checks for known container-escape kernel CVEs (HOST-002).
// This is best-effort: a static CVE list will go stale. Use external vulnerability
// scanners for comprehensive host auditing.
func checkKernelVersion(kernelVersion string) []types.Finding {
	ctrl := controlByID("HOST-002")

	if kernelVersion == "" {
		return []types.Finding{warn(ctrl, "docker-daemon",
			"Kernel version not available from docker info — cannot verify OS patches",
			"KernelVersion field is empty")}
	}

	// Known container-escape CVEs by kernel version range.
	// These are major Linux kernel CVEs that enable container breakout.
	type vulnKernel struct {
		cve         string
		description string
		vulnerable  func(major, minor, patch int) bool
	}

	vulns := []vulnKernel{
		{
			cve:         "CVE-2022-0847",
			description: "Dirty Pipe — arbitrary file overwrite via splice, enables container escape",
			vulnerable: func(major, minor, patch int) bool {
				// Affected: 5.8 <= kernel < 5.10.102, 5.15.x < 5.15.25, 5.16.x < 5.16.11
				if major < 5 || (major == 5 && minor < 8) {
					return false // not affected
				}
				if major == 5 && minor == 10 && patch < 102 {
					return true
				}
				if major == 5 && minor == 15 && patch < 25 {
					return true
				}
				if major == 5 && minor == 16 && patch < 11 {
					return true
				}
				if major == 5 && minor >= 8 && minor < 10 {
					return true
				}
				return false
			},
		},
		{
			cve:         "CVE-2022-0185",
			description: "Heap overflow in legacy_parse_param — container escape via unshare",
			vulnerable: func(major, minor, patch int) bool {
				// Affected: 5.1 <= kernel, fixed in 5.4.173, 5.10.93, 5.15.14, 5.16.1
				if major != 5 {
					return false
				}
				if minor < 1 {
					return false
				}
				// Per-minor patch cutoffs for stable branches
				if minor == 4 {
					return patch < 173
				}
				if minor == 10 {
					return patch < 93
				}
				if minor == 15 {
					return patch < 14
				}
				if minor == 16 {
					return patch < 1
				}
				// Other 5.x minors between 1 and 15 without backported fix
				if minor >= 1 && minor < 4 {
					return true
				}
				if minor > 4 && minor < 10 {
					return true
				}
				if minor > 10 && minor < 15 {
					return true
				}
				return false
			},
		},
	}

	// Parse kernel version — format: "5.15.49-linuxkit" or "6.1.0-22-generic"
	major, minor, patch := parseKernelVersion(kernelVersion)
	if major == 0 && minor == 0 && patch == 0 {
		return []types.Finding{warn(ctrl, "docker-daemon",
			fmt.Sprintf("Cannot parse kernel version %q — manual review needed", kernelVersion),
			fmt.Sprintf("KernelVersion: %s", kernelVersion))}
	}

	var issues []string
	for _, v := range vulns {
		if v.vulnerable(major, minor, patch) {
			issues = append(issues, fmt.Sprintf("%s: %s", v.cve, v.description))
		}
	}

	if len(issues) > 0 {
		return []types.Finding{fail(ctrl, "docker-daemon",
			fmt.Sprintf("Kernel %s is vulnerable to container escape CVEs: %s",
				kernelVersion, strings.Join(issues, "; ")),
			fmt.Sprintf("KernelVersion: %s", kernelVersion),
			ctrl.Remediation)}
	}

	return []types.Finding{pass(ctrl, "docker-daemon",
		fmt.Sprintf("Kernel %s: no known container-escape CVEs matched (note: this is a best-effort check)", kernelVersion))}
}

// parseKernelVersion extracts major.minor.patch from a kernel version string.
func parseKernelVersion(version string) (major, minor, patch int) {
	parts := strings.SplitN(version, ".", 4)
	if len(parts) < 2 {
		return 0, 0, 0
	}
	major, _ = strconv.Atoi(strings.TrimSpace(parts[0]))
	minor, _ = strconv.Atoi(strings.TrimSpace(parts[1]))
	if len(parts) >= 3 {
		// Strip suffix like "49-linuxkit"
		patchStr := strings.SplitN(parts[2], "-", 2)[0]
		patch, _ = strconv.Atoi(patchStr)
	}
	return major, minor, patch
}

// checkContentTrustEnv checks the DOCKER_CONTENT_TRUST environment variable (DAEMON-004).
func checkContentTrustEnv() []types.Finding {
	ctrl := controlByID("DAEMON-004")
	if os.Getenv("DOCKER_CONTENT_TRUST") == "1" {
		return []types.Finding{pass(ctrl, "docker-daemon",
			"Docker content trust enabled via DOCKER_CONTENT_TRUST=1")}
	}
	return []types.Finding{fail(ctrl, "docker-daemon",
		"Docker content trust is not enabled — images can be pulled with tampered layers",
		"DOCKER_CONTENT_TRUST is not set to 1 and daemon.json has no content-trust configuration",
		ctrl.Remediation)}
}

// checkAuditdDockerFiles verifies that auditd watches Docker binary and config files (HOST-005).
func checkAuditdDockerFiles(ctx context.Context, auditRules string) []types.Finding {
	ctrl := controlByID("HOST-005")

	if auditRules == "" {
		return []types.Finding{warn(ctrl, "docker-daemon",
			"Cannot verify auditd rules for Docker files (auditctl not available)",
			"auditctl output was empty or unavailable")}
	}

	requiredPaths := []string{
		"/usr/bin/docker",
		"/usr/bin/containerd",
		"/usr/sbin/runc",
		"/etc/docker/daemon.json",
		"/etc/default/docker",
	}

	var missing []string
	for _, p := range requiredPaths {
		if !strings.Contains(auditRules, p) {
			missing = append(missing, p)
		}
	}

	if len(missing) > 0 {
		return []types.Finding{fail(ctrl, "docker-daemon",
			fmt.Sprintf("Missing auditd watches for Docker files: %s", strings.Join(missing, ", ")),
			fmt.Sprintf("auditctl -l output does not contain: %s", strings.Join(missing, ", ")),
			ctrl.Remediation)}
	}
	return []types.Finding{pass(ctrl, "docker-daemon", "Auditd rules configured for Docker files")}
}

// getAuditdRules runs auditctl -l and returns the output. Empty string on error.
func getAuditdRules(ctx context.Context) string {
	auditCmd := exec.CommandContext(ctx, "auditctl", "-l") // #nosec G204 -- fixed executable, no user input
	out, err := auditCmd.Output()
	if err != nil {
		return ""
	}
	return string(out)
}

// checkAuditdDockerPaths verifies that auditd watches Docker data directories (HOST-006).
func checkAuditdDockerPaths(auditRules string) []types.Finding {
	ctrl := controlByID("HOST-006")

	if auditRules == "" {
		return []types.Finding{warn(ctrl, "docker-daemon",
			"Cannot read auditd rules (auditctl not available or insufficient permissions)",
			"auditctl -l failed or returned empty output")}
	}

	requiredPaths := []string{
		"/etc/docker",
		"/var/lib/docker",
		"/usr/bin/dockerd",
	}

	var missing []string
	for _, p := range requiredPaths {
		if !strings.Contains(auditRules, p) {
			missing = append(missing, p)
		}
	}

	if len(missing) > 0 {
		return []types.Finding{fail(ctrl, "docker-daemon",
			fmt.Sprintf("Missing auditd watches for Docker paths: %s", strings.Join(missing, ", ")),
			fmt.Sprintf("auditctl -l output does not contain: %s", strings.Join(missing, ", ")),
			ctrl.Remediation)}
	}
	return []types.Finding{pass(ctrl, "docker-daemon", "Auditd rules configured for Docker paths")}
}
