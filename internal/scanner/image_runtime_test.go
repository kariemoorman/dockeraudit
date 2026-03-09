package scanner

import (
	"strings"
	"context"
	"testing"

	"https://github.com/kariemoorman/dockeraudit/internal/types"
)

// ══════════════════════════════════════════════════════════════════════════════
// Unit tests for checkContainer* functions in image_runtime.go
// ══════════════════════════════════════════════════════════════════════════════

// ── checkContainerPrivileged ─────────────────────────────────────────────────

func TestCheckContainerPrivileged_True(t *testing.T) {
	c := containerInspect{Name: "/test"}
	c.HostConfig.Privileged = true
	findings := checkContainerPrivileged(c)
	assertFail(t, findings, "RUNTIME-002")
}

func TestCheckContainerPrivileged_False(t *testing.T) {
	c := containerInspect{Name: "/test"}
	c.HostConfig.Privileged = false
	findings := checkContainerPrivileged(c)
	assertPass(t, findings, "RUNTIME-002")
}

// ── checkContainerCapabilities ───────────────────────────────────────────────

func TestCheckContainerCapabilities_NoDropAll(t *testing.T) {
	c := containerInspect{Name: "/test"}
	c.HostConfig.CapDrop = []string{"NET_RAW"}
	findings := checkContainerCapabilities(c)
	assertFail(t, findings, "RUNTIME-003")
}

func TestCheckContainerCapabilities_DropAll(t *testing.T) {
	c := containerInspect{Name: "/test"}
	c.HostConfig.CapDrop = []string{"ALL"}
	findings := checkContainerCapabilities(c)
	assertPass(t, findings, "RUNTIME-003")
}

// ── checkContainerReadonly ───────────────────────────────────────────────────

func TestCheckContainerReadonly_False(t *testing.T) {
	c := containerInspect{Name: "/test"}
	c.HostConfig.ReadonlyRootfs = false
	findings := checkContainerReadonly(c)
	if len(findings) == 0 {
		t.Fatal("expected findings for writable rootfs")
	}
	if findings[0].Status != types.StatusWarn {
		t.Errorf("expected WARN for writable rootfs, got %s", findings[0].Status)
	}
}

func TestCheckContainerReadonly_True(t *testing.T) {
	c := containerInspect{Name: "/test"}
	c.HostConfig.ReadonlyRootfs = true
	findings := checkContainerReadonly(c)
	assertPass(t, findings, "RUNTIME-005")
}

// ── checkContainerResourceLimits ─────────────────────────────────────────────

func TestCheckContainerResourceLimits_NoLimits(t *testing.T) {
	c := containerInspect{Name: "/test"}
	c.HostConfig.Memory = 0
	findings := checkContainerResourceLimits(c)
	assertFail(t, findings, "RUNTIME-007")
}

func TestCheckContainerResourceLimits_WithLimits(t *testing.T) {
	c := containerInspect{Name: "/test"}
	c.HostConfig.Memory = 536870912 // 512 MB
	findings := checkContainerResourceLimits(c)
	assertPass(t, findings, "RUNTIME-007")
}

// ── checkContainerSecurityOpts ───────────────────────────────────────────────

func TestCheckContainerSecurityOpts_NoNewPrivileges(t *testing.T) {
	c := containerInspect{Name: "/test"}
	c.HostConfig.SecurityOpt = []string{"no-new-privileges:true", "seccomp=default"}
	findings := checkContainerSecurityOpts(c)
	assertPass(t, findings, "RUNTIME-004")
	assertPass(t, findings, "RUNTIME-008")
}

func TestCheckContainerSecurityOpts_Missing(t *testing.T) {
	c := containerInspect{Name: "/test"}
	c.HostConfig.SecurityOpt = []string{}
	findings := checkContainerSecurityOpts(c)
	assertFail(t, findings, "RUNTIME-004")
	// RUNTIME-008 should be WARN when seccomp is missing
	f := findFinding(findings, "RUNTIME-008")
	if f == nil {
		t.Errorf("expected finding for RUNTIME-008 but none found")
	} else if f.Status != types.StatusWarn {
		t.Errorf("RUNTIME-008: expected WARN, got %s", f.Status)
	}
}

// ── checkContainerNamespaces ─────────────────────────────────────────────────

func TestCheckContainerNamespaces_HostPID(t *testing.T) {
	c := containerInspect{Name: "/test"}
	c.HostConfig.PidMode = "host"
	findings := checkContainerNamespaces(c)
	assertFail(t, findings, "RUNTIME-006")
}

func TestCheckContainerNamespaces_Safe(t *testing.T) {
	c := containerInspect{Name: "/test"}
	// All namespace modes default to empty (not "host")
	findings := checkContainerNamespaces(c)
	assertPass(t, findings, "RUNTIME-006")
}

// ── checkDockerSocketMount ───────────────────────────────────────────────────

func TestCheckDockerSocketMount_Mounted(t *testing.T) {
	c := containerInspect{Name: "/test"}
	c.Mounts = []struct {
		Type   string `json:"Type"`
		Source string `json:"Source"`
	}{
		{Type: "bind", Source: "/var/run/docker.sock"},
	}
	findings := checkDockerSocketMount(c)
	assertFail(t, findings, "DAEMON-001")
}

func TestCheckDockerSocketMount_NotMounted(t *testing.T) {
	c := containerInspect{Name: "/test"}
	c.Mounts = []struct {
		Type   string `json:"Type"`
		Source string `json:"Source"`
	}{
		{Type: "bind", Source: "/data"},
	}
	findings := checkDockerSocketMount(c)
	assertPass(t, findings, "DAEMON-001")
}

func TestCheckDockerSocketMount_ViaBinds(t *testing.T) {
	c := containerInspect{Name: "/test"}
	c.HostConfig.Binds = []string{"/var/run/docker.sock:/var/run/docker.sock"}
	findings := checkDockerSocketMount(c)
	assertFail(t, findings, "DAEMON-001")
}

// ── Edge cases ─────────────────────────────────────────────────────────────

func TestCheckContainerNamespaces_MultipleHostModes(t *testing.T) {
	c := containerInspect{Name: "/test"}
	c.HostConfig.PidMode = "host"
	c.HostConfig.NetworkMode = "host"
	c.HostConfig.IpcMode = "host"
	findings := checkContainerNamespaces(c)
	assertFail(t, findings, "RUNTIME-006")
	// Should mention all three in the detail
	if len(findings) == 0 {
		t.Fatal("expected findings for multiple host modes")
	}
	for _, f := range findings {
		if f.Control.ID == "RUNTIME-006" && f.Status == types.StatusFail {
			if !strings.Contains(f.Detail, "hostPID") {
				t.Error("expected detail to mention hostPID")
			}
			if !strings.Contains(f.Detail, "hostNetwork") {
				t.Error("expected detail to mention hostNetwork")
			}
			if !strings.Contains(f.Detail, "hostIPC") {
				t.Error("expected detail to mention hostIPC")
			}
		}
	}
}

func TestCheckContainerResourceLimits_WithCPUOnly(t *testing.T) {
	c := containerInspect{Name: "/test"}
	c.HostConfig.Memory = 0
	c.HostConfig.NanoCpus = 500000000 // 0.5 CPU
	findings := checkContainerResourceLimits(c)
	// Memory=0 means no memory limit, so should still FAIL
	assertFail(t, findings, "RUNTIME-007")
}

func TestCheckContainerCapabilities_DropAllWithAdd(t *testing.T) {
	c := containerInspect{Name: "/test"}
	c.HostConfig.CapDrop = []string{"ALL"}
	c.HostConfig.CapAdd = []string{"NET_BIND_SERVICE"}
	findings := checkContainerCapabilities(c)
	// Still passes because cap_drop: ALL is present
	assertPass(t, findings, "RUNTIME-003")
}

// ── checkKernelVersion (HOST-002) ───────────────────────────────────────────

func TestCheckKernelVersion_Vulnerable_DirtyPipe(t *testing.T) {
	findings := checkKernelVersion("5.10.90-linuxkit")
	assertFail(t, findings, "HOST-002")
	f := findFinding(findings, "HOST-002")
	if f != nil && !strings.Contains(f.Detail, "CVE-2022-0847") {
		t.Errorf("expected detail to mention CVE-2022-0847, got: %s", f.Detail)
	}
}

func TestCheckKernelVersion_Safe(t *testing.T) {
	findings := checkKernelVersion("6.1.0-22-generic")
	assertPass(t, findings, "HOST-002")
}

func TestCheckKernelVersion_Empty(t *testing.T) {
	findings := checkKernelVersion("")
	f := findFinding(findings, "HOST-002")
	if f == nil {
		t.Fatal("expected finding for HOST-002")
	}
	if f.Status != types.StatusWarn {
		t.Errorf("expected WARN for empty kernel version, got %s", f.Status)
	}
}

func TestCheckKernelVersion_DirtyPipe_Patched(t *testing.T) {
	findings := checkKernelVersion("5.10.102-linuxkit")
	assertPass(t, findings, "HOST-002")
}

func TestParseKernelVersion(t *testing.T) {
	tests := []struct {
		input               string
		major, minor, patch int
	}{
		{"5.10.102-linuxkit", 5, 10, 102},
		{"6.1.0-22-generic", 6, 1, 0},
		{"5.15.49", 5, 15, 49},
		{"4.19", 4, 19, 0},
	}
	for _, tt := range tests {
		major, minor, patch := parseKernelVersion(tt.input)
		if major != tt.major || minor != tt.minor || patch != tt.patch {
			t.Errorf("parseKernelVersion(%q) = (%d, %d, %d), want (%d, %d, %d)",
				tt.input, major, minor, patch, tt.major, tt.minor, tt.patch)
		}
	}
}

// ── checkContentTrustEnv (DAEMON-004) ──────────────────────────────────────

func TestCheckContentTrustEnv_Enabled(t *testing.T) {
	t.Setenv("DOCKER_CONTENT_TRUST", "1")
	findings := checkContentTrustEnv()
	assertPass(t, findings, "DAEMON-004")
}

func TestCheckContentTrustEnv_NotSet(t *testing.T) {
	t.Setenv("DOCKER_CONTENT_TRUST", "")
	findings := checkContentTrustEnv()
	assertFail(t, findings, "DAEMON-004")
}

func TestCheckContentTrustEnv_Zero(t *testing.T) {
	t.Setenv("DOCKER_CONTENT_TRUST", "0")
	findings := checkContentTrustEnv()
	assertFail(t, findings, "DAEMON-004")
}

// ── checkAuditdDockerFiles (HOST-005) ──────────────────────────────────────

func TestCheckAuditdDockerFiles_AllPresent(t *testing.T) {
	rules := `-w /usr/bin/docker -p rwxa -k docker
-w /usr/bin/containerd -p rwxa -k docker
-w /usr/sbin/runc -p rwxa -k docker
-w /etc/docker/daemon.json -p rwxa -k docker
-w /etc/default/docker -p rwxa -k docker`
	findings := checkAuditdDockerFiles(context.Background(), rules)
	assertPass(t, findings, "HOST-005")
}

func TestCheckAuditdDockerFiles_MissingPaths(t *testing.T) {
	rules := `-w /usr/bin/docker -p rwxa -k docker`
	findings := checkAuditdDockerFiles(context.Background(), rules)
	assertFail(t, findings, "HOST-005")
}

func TestCheckAuditdDockerFiles_EmptyRules(t *testing.T) {
	findings := checkAuditdDockerFiles(context.Background(), "")
	f := findFinding(findings, "HOST-005")
	if f == nil {
		t.Fatal("expected finding for HOST-005")
	}
	if f.Status != types.StatusWarn {
		t.Errorf("expected WARN for empty auditctl output, got %s", f.Status)
	}
}

// ── checkAuditdDockerPaths (HOST-006 refactored) ───────────────────────────

func TestCheckAuditdDockerPaths_AllPresent(t *testing.T) {
	rules := `-w /etc/docker -p rwxa -k docker
-w /var/lib/docker -p rwxa -k docker
-w /usr/bin/dockerd -p rwxa -k docker`
	findings := checkAuditdDockerPaths(rules)
	assertPass(t, findings, "HOST-006")
}

func TestCheckAuditdDockerPaths_MissingPaths(t *testing.T) {
	rules := `-w /etc/docker -p rwxa -k docker`
	findings := checkAuditdDockerPaths(rules)
	assertFail(t, findings, "HOST-006")
}

func TestCheckAuditdDockerPaths_EmptyRules(t *testing.T) {
	findings := checkAuditdDockerPaths("")
	f := findFinding(findings, "HOST-006")
	if f == nil {
		t.Fatal("expected finding for HOST-006")
	}
	if f.Status != types.StatusWarn {
		t.Errorf("expected WARN for empty auditctl output, got %s", f.Status)
	}
}
