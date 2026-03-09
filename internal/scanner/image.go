package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/kariemoorman/dockeraudit/internal/types"
)

// validImageRef is a lightweight regex that matches valid Docker image references.
// Format: [registry/][name][:tag][@digest]
// Rejects shell metacharacters, whitespace, and other injection-prone characters.
var validImageRef = regexp.MustCompile(
	`^[a-zA-Z0-9][a-zA-Z0-9._/:@\-]*$`,
)

// ImageScanner evaluates a Docker image against hardening controls.
type ImageScanner struct {
	Image           string
	Timeout         time.Duration
	CustomEOLImages []EOLEntry // if set, overrides DefaultEOLImages for IMAGE-008 check
}

func NewImageScanner(image string) *ImageScanner {
	return &ImageScanner{
		Image:   image,
		Timeout: 5 * time.Minute,
	}
}

// imageInspect holds the fields we parse from docker inspect output.
type imageInspect struct {
	Config struct {
		User         string                 `json:"User"`
		Env          []string               `json:"Env"`
		Cmd          []string               `json:"Cmd"`
		Entrypoint   []string               `json:"Entrypoint"`
		ExposedPorts map[string]interface{} `json:"ExposedPorts"`
		Labels       map[string]string      `json:"Labels"`
		Healthcheck  *struct {
			Test []string `json:"Test"` // e.g. ["CMD", "wget", "-q", ...] or ["NONE"]
		} `json:"Healthcheck"`
	} `json:"Config"`
	RootFS struct {
		Layers []string `json:"Layers"`
	} `json:"RootFS"`
	RepoDigests []string `json:"RepoDigests"`
	RepoTags    []string `json:"RepoTags"`
}

// dockerAvailable returns an error if the Docker daemon is not reachable.
// This provides a clear diagnostic instead of a cryptic "docker inspect" failure.
func dockerAvailable(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "docker", "info", "--format", "{{.ServerVersion}}") // #nosec G204 -- fixed args, no user input
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker daemon is not reachable (is Docker running?): %w", err)
	}
	return nil
}

func (s *ImageScanner) Scan(ctx context.Context) (*types.ScanResult, error) {
	// Validate image reference: reject empty, dash-prefixed, and references with shell metacharacters.
	if s.Image == "" {
		return nil, fmt.Errorf("empty image reference")
	}
	if strings.HasPrefix(s.Image, "-") {
		return nil, fmt.Errorf("invalid image reference %q: must not start with '-'", s.Image)
	}
	if !validImageRef.MatchString(s.Image) {
		return nil, fmt.Errorf("invalid image reference %q: contains disallowed characters", s.Image)
	}

	// Preflight: ensure Docker daemon is reachable before attempting any scans.
	if err := dockerAvailable(ctx); err != nil {
		return nil, err
	}

	result := &types.ScanResult{
		Target:  s.Image,
		Scanner: "image",
	}

	inspect, history, err := s.fetchImageData(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect image %s: %w", s.Image, err)
	}

	result.Findings = append(result.Findings, s.checkDigestPinning(inspect))
	result.Findings = append(result.Findings, s.checkNonRootUser(inspect))
	result.Findings = append(result.Findings, s.checkSecretsInHistory(history))
	result.Findings = append(result.Findings, s.checkADDInstruction(history)...)
	// Combine three docker-run checks (SUID, secrets, xz-utils) into a single container
	// to reduce overhead from spinning up separate containers.
	result.Findings = append(result.Findings, s.runContainerChecks(ctx)...)
	result.Findings = append(result.Findings, s.checkEOLBaseImage(inspect))                // IMAGE-008: end-of-life base image
	result.Findings = append(result.Findings, s.checkEOLFromHistory(history)...)           // IMAGE-008: EOL via history (TASK-9.27)
	result.Findings = append(result.Findings, s.checkCryptoMinerInImage(inspect, history)) // IMAGE-009: crypto miner
	result.Findings = append(result.Findings, s.checkSSHDaemon(inspect))                   // RUNTIME-010
	result.Findings = append(result.Findings, s.checkPrivilegedPorts(inspect))             // RUNTIME-011
	result.Findings = append(result.Findings, s.checkHealthcheck(inspect))                 // RUNTIME-012
	result.Findings = append(result.Findings, s.checkAdminToolsInImage(history))           // DB-IMAGE-001
	result.Findings = append(result.Findings, s.checkDangerousDBFlags(inspect))            // DB-IMAGE-002
	result.Findings = append(result.Findings, s.checkVulnerabilities(ctx)...)              // IMAGE-003
	result.Findings = append(result.Findings, s.checkSBOMAttestation(ctx, inspect))        // SUPPLY-002

	// RUNTIME-001 through RUNTIME-009 are container-launch configuration, not image properties.
	// They cannot be determined from a static image scan; emit SKIP so they appear in the report
	// and remind users to verify these controls at deploy time via orchestrator policy.
	runtimeDeployControls := []struct {
		id  string
		msg string
	}{
		{"RUNTIME-001", "Non-root user at runtime depends on orchestrator/docker run config — image USER checked under IMAGE-005"},
		{"RUNTIME-002", "Privileged mode is set at container launch via --privileged or securityContext.privileged"},
		{"RUNTIME-003", "Linux capabilities are set at container launch via --cap-drop/--cap-add or securityContext.capabilities"},
		{"RUNTIME-004", "no-new-privileges is set at container launch via --security-opt no-new-privileges or securityContext"},
		{"RUNTIME-005", "Read-only root filesystem is set at container launch via --read-only or securityContext.readOnlyRootFilesystem"},
		{"RUNTIME-006", "Host namespace sharing (PID/IPC/network) is set at container launch; not an image property"},
		{"RUNTIME-007", "CPU/memory limits are set at container launch via --memory/--cpus or resources.limits"},
		{"RUNTIME-008", "Seccomp profile is set at container launch via --security-opt seccomp= or securityContext.seccompProfile"},
		{"RUNTIME-009", "Host path mounts are configured at container launch via -v or volumes; not an image property"},
	}
	for _, rc := range runtimeDeployControls {
		result.Findings = append(result.Findings,
			skipped(controlByID(rc.id), s.Image, rc.msg+" — verify at deploy time via orchestrator policy"))
	}

	result.Tally()
	return result, nil
}

func (s *ImageScanner) fetchImageData(ctx context.Context) (*imageInspect, string, error) {
	// docker inspect — '--' prevents a leading-dash image name from being parsed as a flag.
	inspectCmd := exec.CommandContext(ctx, "docker", "inspect", "--type", "image", "--", s.Image) // #nosec G204 -- fixed executable; image validated in Scan()
	out, err := inspectCmd.Output()
	if err != nil {
		return nil, "", fmt.Errorf("docker inspect: %w", err)
	}

	var inspects []imageInspect
	if err := json.Unmarshal(out, &inspects); err != nil {
		return nil, "", fmt.Errorf("parse inspect: %w", err)
	}
	if len(inspects) == 0 {
		return nil, "", fmt.Errorf("no inspect data returned for %s", s.Image)
	}

	// docker history — '--' prevents a leading-dash image name from being parsed as a flag.
	histCmd := exec.CommandContext(ctx, "docker", "history", "--no-trunc", "--", s.Image) // #nosec G204 -- fixed executable; image validated in Scan()
	histOut, err := histCmd.Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: docker history for %s failed: %v (history-based checks may miss issues)\n", s.Image, err)
	}

	return &inspects[0], string(histOut), nil
}

// ── Static image checks ──────────────────────────────────────────────────────

func (s *ImageScanner) checkDigestPinning(inspect *imageInspect) types.Finding {
	ctrl := controlByID("IMAGE-001")
	// If the image reference contains @sha256: it is pinned
	if strings.Contains(s.Image, "@sha256:") {
		return pass(ctrl, s.Image, "Image reference includes @sha256: digest")
	}
	// Check RepoDigests — if populated, image was pulled by digest even if referenced by tag
	if len(inspect.RepoDigests) > 0 {
		return warn(ctrl, s.Image,
			"Image has a RepoDigest but is not referenced by digest in manifests",
			inspect.RepoDigests[0])
	}
	return fail(ctrl, s.Image,
		"Image is referenced by mutable tag with no digest pinning",
		fmt.Sprintf("Tags: %v", inspect.RepoTags),
		ctrl.Remediation)
}

func (s *ImageScanner) checkNonRootUser(inspect *imageInspect) types.Finding {
	ctrl := controlByID("IMAGE-005")
	user := inspect.Config.User
	if user == "" || user == "0" || user == "root" {
		return fail(ctrl, s.Image,
			fmt.Sprintf("Image runs as user %q (root)", user),
			"docker inspect .Config.User",
			ctrl.Remediation)
	}
	return pass(ctrl, s.Image, fmt.Sprintf("Image USER is %q", user))
}

func (s *ImageScanner) checkSecretsInHistory(history string) types.Finding {
	ctrl := controlByID("IMAGE-002")
	secretsScanner := NewSecretScanner(s.Image, ctrl)
	return secretsScanner.CheckSecrets(history)
}

func (s *ImageScanner) checkADDInstruction(history string) []types.Finding {
	ctrl006 := controlByID("IMAGE-006")
	ctrl014 := controlByID("IMAGE-014")
	sc := bufio.NewScanner(bytes.NewBufferString(history))
	var findings []types.Finding
	hasRemoteADD := false
	hasLocalADD := false
	for sc.Scan() {
		line := sc.Text()
		cb := strings.TrimSpace(extractCreatedBy(line))
		// Docker history shows ADD as "ADD …" (BuildKit) or "/bin/sh -c #(nop)  ADD …" (classic).
		lower := strings.ToLower(cb)
		isADD := false
		if strings.HasPrefix(lower, "add ") {
			isADD = true
		} else if i := strings.Index(lower, "#(nop)"); i >= 0 {
			rest := strings.TrimSpace(lower[i+len("#(nop)"):])
			if strings.HasPrefix(rest, "add ") {
				isADD = true
			}
		}
		if !isADD {
			continue
		}
		// IMAGE-006: ADD with a remote URL
		if strings.Contains(lower, "add http") || strings.Contains(lower, "add ftp") {
			findings = append(findings, fail(ctrl006, s.Image,
				"Dockerfile uses ADD with a remote URL",
				line, ctrl006.Remediation))
			hasRemoteADD = true
			continue
		}
		// IMAGE-014: ADD used for local file (no URL, no tar archive) — prefer COPY
		if !strings.Contains(lower, ".tar") && !strings.Contains(lower, ".tgz") {
			findings = append(findings, warn(ctrl014, s.Image,
				"Dockerfile uses ADD for a local file — use COPY instead (ADD silently extracts archives and accepts URLs)",
				line))
			hasLocalADD = true
		}
	}
	if err := sc.Err(); err != nil {
		return []types.Finding{errFinding(ctrl006, s.Image,
			fmt.Sprintf("scanner error reading image history: %v", err))}
	}
	// Emit PASS for each control that had no violations.
	if !hasRemoteADD {
		findings = append(findings, pass(ctrl006, s.Image, "No remote ADD instructions detected in history"))
	}
	if !hasLocalADD {
		findings = append(findings, pass(ctrl014, s.Image, "No local-file ADD instructions detected in history"))
	}
	return findings
}

func extractCreatedBy(line string) string {
	// docker history --no-trunc format: <ID>\t<created>\t<created by>\t<size>
	parts := strings.SplitN(line, "\t", 4)
	if len(parts) >= 3 {
		return parts[2] // third column is "created by"
	}
	return line
}

// checkSSHDaemon detects sshd in the image entrypoint, cmd, or layer history (CIS 5.7 / RUNTIME-010).
func (s *ImageScanner) checkSSHDaemon(inspect *imageInspect) types.Finding {
	ctrl := controlByID("RUNTIME-010")
	all := make([]string, 0, len(inspect.Config.Entrypoint)+len(inspect.Config.Cmd))
	all = append(all, inspect.Config.Entrypoint...)
	all = append(all, inspect.Config.Cmd...)
	for _, part := range all {
		if strings.Contains(strings.ToLower(part), "sshd") {
			return fail(ctrl, s.Image,
				"SSH daemon (sshd) detected in container Entrypoint or Cmd",
				fmt.Sprintf("Entrypoint: %v, Cmd: %v", inspect.Config.Entrypoint, inspect.Config.Cmd),
				ctrl.Remediation)
		}
	}
	return pass(ctrl, s.Image, "No sshd in Entrypoint or Cmd")
}

// checkHealthcheck detects whether the image defines a HEALTHCHECK (RUNTIME-012).
func (s *ImageScanner) checkHealthcheck(inspect *imageInspect) types.Finding {
	ctrl := controlByID("RUNTIME-012")
	hc := inspect.Config.Healthcheck
	if hc == nil || len(hc.Test) == 0 ||
		(len(hc.Test) > 0 && strings.EqualFold(hc.Test[0], "NONE")) {
		return warn(ctrl, s.Image,
			"No HEALTHCHECK defined in image — container health cannot be monitored",
			"Config.Healthcheck is nil or NONE")
	}
	return pass(ctrl, s.Image,
		fmt.Sprintf("HEALTHCHECK defined: %s", strings.Join(hc.Test, " ")))
}

// checkPrivilegedPorts flags exposed ports below 1024 (CIS 5.8 / RUNTIME-011).
func (s *ImageScanner) checkPrivilegedPorts(inspect *imageInspect) types.Finding {
	ctrl := controlByID("RUNTIME-011")
	var priv []string
	for portProto := range inspect.Config.ExposedPorts {
		// format is "80/tcp" or "443/tcp"
		parts := strings.SplitN(portProto, "/", 2)
		if len(parts) == 0 {
			continue
		}
		var port int
		if _, err := fmt.Sscanf(parts[0], "%d", &port); err == nil && port < 1024 {
			priv = append(priv, portProto)
		}
	}
	if len(priv) > 0 {
		return fail(ctrl, s.Image,
			fmt.Sprintf("Image exposes privileged port(s): %s", strings.Join(priv, ", ")),
			fmt.Sprintf("ExposedPorts: %v", priv),
			ctrl.Remediation)
	}
	return pass(ctrl, s.Image, "No privileged ports (< 1024) exposed")
}

// checkAdminToolsInImage warns when database admin/debug binaries are present (DB-IMAGE-001).
func (s *ImageScanner) checkAdminToolsInImage(history string) types.Finding {
	ctrl := controlByID("DB-IMAGE-001")
	adminTools := []struct {
		name string
		db   string
	}{
		{"psql", "PostgreSQL"}, {"pg_dump", "PostgreSQL"}, {"pg_restore", "PostgreSQL"},
		{"mysql", "MySQL"}, {"mysqladmin", "MySQL"}, {"mysqldump", "MySQL"},
		{"mongosh", "MongoDB"}, {"mongodump", "MongoDB"}, {"mongorestore", "MongoDB"},
		{"redis-cli", "Redis"}, {"redis-benchmark", "Redis"},
		{"cypher-shell", "Neo4j"}, {"neo4j-admin", "Neo4j"},
		{"cqlsh", "Cassandra"}, {"nodetool", "Cassandra"},
		{"arangosh", "ArangoDB"}, {"arangodump", "ArangoDB"},
		{"sqlite3", "SQLite"},
	}
	lower := strings.ToLower(history)
	for _, t := range adminTools {
		// Match install or binary presence in history layers
		if strings.Contains(lower, t.name) {
			return warn(ctrl, s.Image,
				fmt.Sprintf("Admin/debug tool %q (%s) detected in image layers", t.name, t.db),
				fmt.Sprintf("Found %q in docker history", t.name))
		}
	}
	return pass(ctrl, s.Image, "No database admin/debug tools detected in image layers")
}

// checkDangerousDBFlags detects unsafe startup flags in image Entrypoint/Cmd (DB-IMAGE-002).
func (s *ImageScanner) checkDangerousDBFlags(inspect *imageInspect) types.Finding {
	ctrl := controlByID("DB-IMAGE-002")
	all := make([]string, 0, len(inspect.Config.Entrypoint)+len(inspect.Config.Cmd))
	all = append(all, inspect.Config.Entrypoint...)
	all = append(all, inspect.Config.Cmd...)
	combined := strings.ToLower(strings.Join(all, " "))

	type dangerousFlag struct {
		flag string
		msg  string
	}
	flags := []dangerousFlag{
		{"--skip-grant-tables", "MySQL --skip-grant-tables bypasses all authentication"},
		{"--local-infile=1", "MySQL --local-infile=1 enables client-side file reads"},
		{"--secure-file-priv=", "MySQL --secure-file-priv= (empty) removes file write restrictions"},
		{"-tcpallowothers", "H2 -tcpAllowOthers exposes unauthenticated TCP server"},
		{"-weballowothers", "H2 -webAllowOthers exposes unauthenticated web console (RCE risk)"},
		{"-startnetworkserver", "Derby -startNetworkServer exposes unauthenticated network DB"},
	}

	for _, f := range flags {
		if strings.Contains(combined, f.flag) {
			return fail(ctrl, s.Image, f.msg,
				fmt.Sprintf("Found %q in: %v", f.flag, all),
				ctrl.Remediation)
		}
	}

	// MongoDB: warn if image is mongo and --auth is not in CMD/Entrypoint
	imageL := strings.ToLower(s.Image)
	if strings.Contains(imageL, "mongo") && !strings.Contains(combined, "--auth") && len(all) > 0 {
		return fail(ctrl, s.Image,
			"MongoDB container CMD/Entrypoint does not include --auth — unauthenticated access enabled",
			fmt.Sprintf("Cmd/Entrypoint: %v", all),
			ctrl.Remediation)
	}

	// Redis: warn if image is redis and --requirepass / requirepass is not in CMD/Entrypoint
	if strings.Contains(imageL, "redis") && !strings.Contains(combined, "requirepass") && len(all) > 0 {
		return warn(ctrl, s.Image,
			"Redis CMD/Entrypoint does not set --requirepass — verify auth is configured via redis.conf mount",
			fmt.Sprintf("Cmd/Entrypoint: %v", all))
	}

	return pass(ctrl, s.Image, "No dangerous database startup flags detected")
}

// checkSBOMAttestation checks if the image has SBOM attestation (SUPPLY-002).
// It checks image labels first, then tries cosign if available.
func (s *ImageScanner) checkSBOMAttestation(ctx context.Context, inspect *imageInspect) types.Finding {
	ctrl := controlByID("SUPPLY-002")

	// Check image labels for SBOM indicators
	sbomLabelPrefixes := []string{
		"io.buildkit.sbom",
		"org.opencontainers.image.sbom",
		"sbom",
	}
	for key := range inspect.Config.Labels {
		keyLower := strings.ToLower(key)
		for _, prefix := range sbomLabelPrefixes {
			if strings.HasPrefix(keyLower, prefix) || strings.Contains(keyLower, "sbom") {
				return pass(ctrl, s.Image,
					fmt.Sprintf("SBOM label found: %s", key))
			}
		}
	}

	// Try cosign tree to check for SBOM attestation
	if cosignPath, err := exec.LookPath("cosign"); err == nil && cosignPath != "" {
		ref := s.Image
		if len(inspect.RepoDigests) > 0 {
			ref = inspect.RepoDigests[0]
		}
		cosignCmd := exec.CommandContext(ctx, "cosign", "tree", ref) // #nosec G204 -- fixed executable; ref validated in Scan()
		cosignOut, err := cosignCmd.CombinedOutput()
		if err == nil {
			outStr := string(cosignOut)
			if strings.Contains(outStr, "sbom") || strings.Contains(outStr, "SBOM") ||
				strings.Contains(outStr, "spdx") || strings.Contains(outStr, "cyclonedx") {
				return pass(ctrl, s.Image, "SBOM attestation found via cosign tree")
			}
		}
	}

	return warn(ctrl, s.Image,
		"No SBOM attestation found — generate with 'docker buildx build --sbom=true' or 'syft' and attach with 'cosign attest'",
		"No SBOM labels or cosign attestation detected")
}

// Additional check methods are defined in:
// - image_container.go: runContainerChecks, checkVulnerabilities, checkCryptoMinerInImage
// - image_eol.go: checkEOLBaseImage, DefaultEOLImages, LoadEOLFile
// - image_runtime.go: ScanRunningContainers, ScanDaemon, checkContainer*
