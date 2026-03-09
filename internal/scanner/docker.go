package scanner

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"https://github.com/kariemoorman/dockeraudit/internal/types"

	"gopkg.in/yaml.v3"
)

// ── File type detection ─────────────────────────────────────────────────────

type dockerFileType int

const (
	fileTypeDockerfile dockerFileType = iota
	fileTypeCompose
	fileTypeUnknown
)

// detectDockerFileType classifies a file path as Dockerfile, Compose, or unknown.
func detectDockerFileType(path string) dockerFileType {
	base := strings.ToLower(filepath.Base(path))

	// Dockerfile patterns: dockerfile, dockerfile.*, *.dockerfile, containerfile
	if base == "dockerfile" || strings.HasPrefix(base, "dockerfile.") ||
		strings.HasSuffix(base, ".dockerfile") || base == "containerfile" {
		return fileTypeDockerfile
	}

	// Compose patterns: docker-compose*.yml/yaml, compose.yml/yaml, *-compose.yml/yaml, *compose*.yml/yaml
	ext := filepath.Ext(base)
	if ext == ".yml" || ext == ".yaml" {
		nameNoExt := strings.TrimSuffix(base, ext)
		if strings.HasPrefix(nameNoExt, "docker-compose") || nameNoExt == "compose" ||
			strings.Contains(nameNoExt, "compose") {
			return fileTypeCompose
		}
	}

	return fileTypeUnknown
}

// collectDockerFiles walks root and returns all Dockerfile and Compose file paths.
// If root is a single file, it returns that file directly.
func collectDockerFiles(root string) ([]string, error) {
	if root == "" {
		return nil, nil
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []string{root}, nil
	}

	var files []string
	err = filepath.Walk(root, func(path string, fi os.FileInfo, walkErr error) error {
		if walkErr != nil || fi.IsDir() {
			return walkErr
		}
		if detectDockerFileType(path) != fileTypeUnknown {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

// ── DockerScanner ───────────────────────────────────────────────────────────

// DockerScanner performs static analysis on Dockerfiles and Docker Compose files
// to detect security misconfigurations, embedded secrets, and best-practice violations.
type DockerScanner struct {
	Path    string
	Timeout time.Duration
}

// NewDockerScanner creates a scanner for Dockerfiles and/or Compose files at the given path.
func NewDockerScanner(path string) *DockerScanner {
	return &DockerScanner{
		Path:    path,
		Timeout: 5 * time.Minute,
	}
}

// NewDockerfileScanner is a backward-compatible alias for NewDockerScanner.
func NewDockerfileScanner(path string) *DockerScanner {
	return NewDockerScanner(path)
}

// Scan implements the Scanner interface. It auto-detects Dockerfiles and
// Compose files at s.Path and runs the appropriate checks for each.
func (s *DockerScanner) Scan(ctx context.Context) (*types.ScanResult, error) {
	result := &types.ScanResult{
		Target:  s.Path,
		Scanner: "docker",
	}

	files, err := collectDockerFiles(s.Path)
	if err != nil {
		return nil, err
	}

	for _, f := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ft := detectDockerFileType(f)
		// When a single file is passed directly with an unknown type,
		// infer from extension: .yml/.yaml → compose, otherwise Dockerfile.
		if ft == fileTypeUnknown && len(files) == 1 {
			ext := strings.ToLower(filepath.Ext(f))
			if ext == ".yml" || ext == ".yaml" {
				ft = fileTypeCompose
			} else {
				ft = fileTypeDockerfile
			}
		}
		switch ft {
		case fileTypeDockerfile:
			result.Findings = append(result.Findings, s.scanSingleDockerfile(f)...)
		case fileTypeCompose:
			result.Findings = append(result.Findings, s.scanComposeFile(f)...)
		}
	}

	// IMAGE-003: vulnerability scan on Dockerfiles using trivy config.
	// Snyk container test requires a built image — use `dockeraudit image` instead.
	// Neither trivy nor snyk support docker-compose.yml scanning directly.
	ctrl := controlByID("IMAGE-003")
	avail := detectVulnTools()
	if avail.HasTrivy || avail.HasSnyk {
		for _, f := range files {
			relF := relPath(s.Path, f)
			if detectDockerFileType(f) != fileTypeDockerfile {
				result.Findings = append(result.Findings, skipped(ctrl, relF,
					"Vulnerability scanning not supported for docker-compose files — "+
						"build the image and scan with: dockeraudit image <name>:<tag>"))
				continue
			}
			if avail.HasTrivy {
				findings := runTrivyConfig(ctx, f, ctrl)
				for i := range findings {
					findings[i].Target = relF
					if findings[i].SourceFile != "" {
						findings[i].SourceFile = relF
					}
				}
				result.Findings = append(result.Findings, findings...)
			}
			if avail.HasSnyk {
				findings := runSnykDockerfile(ctx, f, ctrl)
				for i := range findings {
					findings[i].Target = relF
					if findings[i].SourceFile != "" {
						findings[i].SourceFile = relF
					}
				}
				result.Findings = append(result.Findings, findings...)
			}
		}
	} else {
		result.Findings = append(result.Findings, skipped(ctrl, s.Path,
			"Neither trivy nor snyk found on PATH — install one to enable Dockerfile vulnerability scanning"))
	}

	result.Tally()
	return result, nil
}

// ScanPerFile is like Scan but returns one ScanResult per discovered file
// instead of merging everything into a single result. This provides per-file
// summary counts and a distinct Target for each file, which is essential when
// scanning a directory that contains multiple Dockerfiles or Compose files.
func (s *DockerScanner) ScanPerFile(ctx context.Context) ([]*types.ScanResult, error) {
	files, err := collectDockerFiles(s.Path)
	if err != nil {
		return nil, err
	}

	var results []*types.ScanResult
	for _, f := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ft := detectDockerFileType(f)
		if ft == fileTypeUnknown && len(files) == 1 {
			ext := strings.ToLower(filepath.Ext(f))
			if ext == ".yml" || ext == ".yaml" {
				ft = fileTypeCompose
			} else {
				ft = fileTypeDockerfile
			}
		}

		var findings []types.Finding
		switch ft {
		case fileTypeDockerfile:
			findings = s.scanSingleDockerfile(f)
		case fileTypeCompose:
			findings = s.scanComposeFile(f)
		default:
			continue
		}

		r := &types.ScanResult{
			Target:   relPath(s.Path, f),
			Scanner:  "docker",
			Findings: findings,
		}
		r.Tally()
		results = append(results, r)
	}
	return results, nil
}

// ── Dockerfile scanning (existing) ──────────────────────────────────────────

// scanSingleDockerfile runs all checks against one Dockerfile and returns findings
// with SourceFile and SourceLine set for precise location tracking.
func (s *DockerScanner) scanSingleDockerfile(dockerfilePath string) []types.Finding {
	content, err := os.ReadFile(dockerfilePath) // #nosec G304 -- user-supplied Dockerfile path
	relP := relPath(s.Path, dockerfilePath)
	if err != nil {
		ctrl := controlByID("IMAGE-002")
		return []types.Finding{
			withSource(fail(ctrl, relP,
				fmt.Sprintf("Failed to read Dockerfile: %v", err), "", ctrl.Remediation),
				relP, 0),
		}
	}

	var findings []types.Finding

	// Line-by-line checks — use relative path for targets and source references
	lineFindings := s.checkLines(relP, content)
	findings = append(findings, lineFindings...)

	// Whole-file secret scan using the regex-based SecretScanner
	secretFinding := s.checkSecretsInHistory(relP, content)
	findings = append(findings, secretFinding)

	return findings
}

// checkLines scans each line for Dockerfile-specific security issues.
func (s *DockerScanner) checkLines(dockerfilePath string, content []byte) []types.Finding {
	var findings []types.Finding
	scanner := bufio.NewScanner(bytes.NewReader(content))
	lineNum := 0

	hasUserDirective    := false
	userIsRoot          := false
	hasFromDigest       := true  // assume true; set false if any FROM lacks @sha256:
	hasHealthcheck      := false
	hasLocalADD         := false  // IMAGE-014: set true when a local-ADD WARN is emitted
	hasRemoteADDIssue   := false  // IMAGE-006: set true when a remote-ADD/pipe-shell finding is emitted
	hasChmodIssue       := false  // IMAGE-004: set true when SUID/world-writable FAIL is emitted
	hasPackageInstall   := false  // IMAGE-003: set true when any package-install WARN is emitted
	hasPrivilegedExpose := false  // RUNTIME-011: set true when a privileged-port WARN is emitted
	hasFromLine         := false  // IMAGE-008: set true when any FROM line is processed
	eolIssueFound       := false  // IMAGE-008: set true when checkEOLInLine returns a finding
	hasDebugTool        := false  // IMAGE-011: set true when debug/dev tool install detected
	hasPkgVerifyBypass  := false  // IMAGE-012: set true when package verification bypass detected
	hasSensitiveVolume  := false  // IMAGE-013: set true when VOLUME targets sensitive path
	hasRecursiveCopy    := false  // IMAGE-016: set true when COPY . . detected
	fromCount           := 0      // IMAGE-015: count FROM instructions for multi-stage check
	lastFromImage       := ""     // HOST-001: track final FROM image for minimality check
	var cmdEntrypoint   []string  // RUNTIME-010 / DB-IMAGE-002: accumulate CMD/ENTRYPOINT values

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)

		// Skip comments and empty lines
		if strings.HasPrefix(trimmed, "#") || trimmed == "" {
			continue
		}

		// IMAGE-001: FROM not pinned by digest
		if strings.HasPrefix(lower, "from ") {
			hasFromLine = true
			if !strings.Contains(line, "@sha256:") {
				// Skip "FROM scratch" which doesn't need pinning
				parts := strings.Fields(lower)
				if len(parts) >= 2 && parts[1] != "scratch" {
					hasFromDigest = false
					ctrl := controlByID("IMAGE-001")
					findings = append(findings, withSource(fail(ctrl, dockerfilePath,
						fmt.Sprintf("FROM not pinned by digest at line %d: %s", lineNum, strings.TrimSpace(line)),
						line, ctrl.Remediation), dockerfilePath, lineNum))
				}
			}

			// IMAGE-008: EOL base image
			eolFinding := s.checkEOLInLine(dockerfilePath, line, lineNum)
			if eolFinding != nil {
				eolIssueFound = true
				findings = append(findings, *eolFinding)
			}

			// HOST-001: Minimal base image check (only on the final FROM stage)
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				lastFromImage = parts[1] // track last FROM image for multi-stage final check
			}
		}

		// IMAGE-005: USER directive
		if strings.HasPrefix(lower, "user ") {
			hasUserDirective = true
			userVal := strings.TrimSpace(strings.TrimPrefix(lower, "user "))
			if userVal == "root" || userVal == "0" {
				userIsRoot = true
				ctrl := controlByID("IMAGE-005")
				findings = append(findings, withSource(fail(ctrl, dockerfilePath,
					fmt.Sprintf("Explicit root USER directive at line %d", lineNum),
					line, ctrl.Remediation), dockerfilePath, lineNum))
			}
		}

		// IMAGE-006 / IMAGE-014: ADD with remote URL, pipe-to-shell, or local-file ADD
		addFindings := checkADDInstruction(dockerfilePath, line, lineNum)
		for _, af := range addFindings {
			if af.Control.ID == "IMAGE-014" {
				hasLocalADD = true
			}
			if af.Control.ID == "IMAGE-006" && (af.Status == types.StatusFail || af.Status == types.StatusWarn) {
				hasRemoteADDIssue = true
			}
		}
		findings = append(findings, addFindings...)

		// IMAGE-004: SUID/SGID/world-writable
		if strings.Contains(line, "chmod") {
			if strings.Contains(line, "+s") || strings.Contains(line, "4755") ||
				strings.Contains(line, "2755") || strings.Contains(line, "u+s") ||
				strings.Contains(line, "g+s") || strings.Contains(line, "a+s") {
				hasChmodIssue = true
				ctrl := controlByID("IMAGE-004")
				findings = append(findings, withSource(fail(ctrl, dockerfilePath,
					fmt.Sprintf("SUID/SGID bit set at line %d", lineNum),
					line, ctrl.Remediation), dockerfilePath, lineNum))
			}
			if strings.Contains(line, "777") || strings.Contains(line, "o+w") ||
				strings.Contains(line, "a+w") {
				hasChmodIssue = true
				ctrl := controlByID("IMAGE-004")
				findings = append(findings, withSource(fail(ctrl, dockerfilePath,
					fmt.Sprintf("World-writable permission set at line %d", lineNum),
					line, ctrl.Remediation), dockerfilePath, lineNum))
			}
		}

		// IMAGE-002: ENV with secret-like names
		if strings.HasPrefix(lower, "env ") {
			envLine := strings.TrimPrefix(lower, "env ")
			for _, p := range credentialKeywords {
				if strings.Contains(envLine, p) {
					ctrl := controlByID("IMAGE-002")
					findings = append(findings, withSource(fail(ctrl, dockerfilePath,
						fmt.Sprintf("Potential secret in ENV at line %d (matches %q pattern)", lineNum, p),
						line, ctrl.Remediation), dockerfilePath, lineNum))
					break
				}
			}
		}

		// IMAGE-003: Package installation without version pinning
		if strings.Contains(lower, "apt-get install") || strings.Contains(lower, "apk add") ||
			strings.Contains(lower, "pip install") || strings.Contains(lower, "npm install") ||
			strings.Contains(lower, "yum install") || strings.Contains(lower, "dnf install") {
			hasPackageInstall = true
			ctrl := controlByID("IMAGE-003")
			findings = append(findings, withSource(warn(ctrl, dockerfilePath,
				fmt.Sprintf("Package installation at line %d — pin versions and run vulnerability scans", lineNum),
				line), dockerfilePath, lineNum))
		}

		// RUNTIME-011: EXPOSE privileged ports
		if strings.HasPrefix(lower, "expose ") {
			exposeParts := strings.Fields(trimmed)
			for _, ep := range exposeParts[1:] {
				// Strip protocol suffix (e.g., 80/tcp → 80)
				portStr := strings.Split(ep, "/")[0]
				if port, err := strconv.Atoi(portStr); err == nil && port > 0 && port < 1024 {
					hasPrivilegedExpose = true
					ctrl := controlByID("RUNTIME-011")
					findings = append(findings, withSource(warn(ctrl, dockerfilePath,
						fmt.Sprintf("Privileged port %d exposed at line %d", port, lineNum),
						line), dockerfilePath, lineNum))
				}
			}
		}

		// Check for --no-cache-dir missing in pip install (best practice)
		if strings.Contains(lower, "pip install") && !strings.Contains(lower, "--no-cache-dir") {
			ctrl := controlByID("IMAGE-004")
			findings = append(findings, withSource(warn(ctrl, dockerfilePath,
				fmt.Sprintf("pip install without --no-cache-dir at line %d — increases image size", lineNum),
				line), dockerfilePath, lineNum))
		}

		// IMAGE-011: Debug/dev tools in package install commands
		if strings.Contains(lower, "apt-get install") || strings.Contains(lower, "apk add") ||
			strings.Contains(lower, "yum install") || strings.Contains(lower, "dnf install") {
			debugTools := []string{
				"vim", "nano", "curl", "wget", "gcc", "gdb", "strace",
				"tcpdump", "nmap", "net-tools", "telnet", "netcat", "nc",
				"socat", "htop", "ltrace", "procps",
			}
			for _, tool := range debugTools {
				// Match tool as a whole word in the install line
				if strings.Contains(lower, " "+tool+" ") || strings.HasSuffix(lower, " "+tool) ||
					strings.Contains(lower, " "+tool+"\t") || strings.Contains(lower, " "+tool+"\\") {
					hasDebugTool = true
					ctrl := controlByID("IMAGE-011")
					findings = append(findings, withSource(warn(ctrl, dockerfilePath,
						fmt.Sprintf("Debug/dev tool %q installed at line %d — remove from production images", tool, lineNum),
						line), dockerfilePath, lineNum))
					break // one finding per line
				}
			}
		}

		// IMAGE-012: Package manager verification bypass
		pkgVerifyBypass := []struct{ pattern, msg string }{
			{"--allow-unauthenticated", "apt --allow-unauthenticated bypasses GPG verification"},
			{"--no-check-gpg", "apk --no-check-gpg disables package signature verification"},
			{"--force-bad-verify", "rpm --force-bad-verify ignores signature failures"},
			{"--nogpgcheck", "yum/dnf --nogpgcheck disables GPG verification"},
			{"--trusted-host", "pip --trusted-host disables TLS certificate verification"},
			{"--no-check-certificate", "wget --no-check-certificate skips TLS verification"},
			{"-k ", "curl -k skips TLS certificate verification"},
			{"--insecure", "curl --insecure skips TLS certificate verification"},
		}
		for _, p := range pkgVerifyBypass {
			if strings.Contains(lower, p.pattern) {
				hasPkgVerifyBypass = true
				ctrl := controlByID("IMAGE-012")
				findings = append(findings, withSource(fail(ctrl, dockerfilePath,
					fmt.Sprintf("%s at line %d", p.msg, lineNum),
					line, ctrl.Remediation), dockerfilePath, lineNum))
				break
			}
		}

		// IMAGE-013: VOLUME targeting sensitive paths
		if strings.HasPrefix(lower, "volume ") {
			sensitiveDirs := []string{"/etc", "/root", "/tmp", "/var/run", "/proc", "/sys", "/dev"}
			volArgs := strings.TrimPrefix(lower, "volume ")
			// Handle both JSON array and space-separated forms
			volArgs = strings.NewReplacer("[", " ", "]", " ", "\"", " ", ",", " ").Replace(volArgs)
			for _, vol := range strings.Fields(volArgs) {
				vol = strings.TrimSpace(vol)
				for _, sd := range sensitiveDirs {
					if vol == sd || strings.HasPrefix(vol, sd+"/") {
						hasSensitiveVolume = true
						ctrl := controlByID("IMAGE-013")
						findings = append(findings, withSource(fail(ctrl, dockerfilePath,
							fmt.Sprintf("VOLUME targets sensitive path %q at line %d", vol, lineNum),
							line, ctrl.Remediation), dockerfilePath, lineNum))
						break
					}
				}
			}
		}

		// IMAGE-016: COPY . . recursive copy warning
		if strings.HasPrefix(lower, "copy ") {
			copyArgs := strings.TrimPrefix(trimmed, strings.Fields(trimmed)[0]+" ")
			// Check for "COPY . ." or "COPY . /" patterns
			// Strip leading --flags (e.g., --chown=1000:1000, --from=builder)
			copyFields := strings.Fields(copyArgs)
			for len(copyFields) > 0 && strings.HasPrefix(copyFields[0], "--") {
				copyFields = copyFields[1:]
			}
			if len(copyFields) >= 2 && copyFields[0] == "." {
				hasRecursiveCopy = true
				ctrl := controlByID("IMAGE-016")
				findings = append(findings, withSource(warn(ctrl, dockerfilePath,
					fmt.Sprintf("COPY . copies entire build context at line %d — may include secrets (.env, .git)",
						lineNum),
					line), dockerfilePath, lineNum))
			}
		}

		// IMAGE-015: Count FROM instructions for multi-stage build check
		if strings.HasPrefix(lower, "from ") {
			fromCount++
		}

		// RUNTIME-012: HEALTHCHECK instruction
		if strings.HasPrefix(lower, "healthcheck ") {
			hasHealthcheck = true
		}

		// RUNTIME-010 / DB-IMAGE-002: collect CMD and ENTRYPOINT values for post-scan checks
		if strings.HasPrefix(lower, "cmd ") || strings.HasPrefix(lower, "entrypoint ") {
			cmdEntrypoint = append(cmdEntrypoint, trimmed)
		}
	}

	if err := scanner.Err(); err != nil {
		findings = append(findings, errFinding(controlByID("IMAGE-002"), dockerfilePath,
			fmt.Sprintf("scanner error reading Dockerfile: %v", err)))
	}

	// ── Post-scan findings ───────────────────────────────────────────────────

	// IMAGE-001: PASS when all FROMs were digest-pinned
	if hasFromDigest {
		findings = append(findings, pass(controlByID("IMAGE-001"), dockerfilePath,
			"All FROM instructions are pinned by digest"))
	}

	// IMAGE-003: PASS when no package installs were detected
	if !hasPackageInstall {
		findings = append(findings, pass(controlByID("IMAGE-003"), dockerfilePath,
			"No unversioned package installs detected"))
	}

	// IMAGE-004: PASS when no SUID/world-writable chmod was detected
	if !hasChmodIssue {
		findings = append(findings, pass(controlByID("IMAGE-004"), dockerfilePath,
			"No SUID/SGID or world-writable chmod instructions detected"))
	}

	// IMAGE-005: WARN when no USER or root USER; PASS when non-root USER found
	if !hasUserDirective {
		findings = append(findings, withSource(warn(controlByID("IMAGE-005"), dockerfilePath,
			"No USER directive found — container will run as root by default",
			"Dockerfile missing USER instruction"), dockerfilePath, 0))
	} else if !userIsRoot {
		findings = append(findings, pass(controlByID("IMAGE-005"), dockerfilePath,
			"Non-root USER directive found"))
	}

	// IMAGE-006: PASS when no remote ADD / pipe-to-shell detected
	if !hasRemoteADDIssue {
		findings = append(findings, pass(controlByID("IMAGE-006"), dockerfilePath,
			"No remote fetch or pipe-to-shell patterns found"))
	}

	// IMAGE-008: PASS when FROM seen but no EOL image found; SKIP when no FROM
	if hasFromLine {
		if !eolIssueFound {
			findings = append(findings, pass(controlByID("IMAGE-008"), dockerfilePath,
				"No known end-of-life base image detected"))
		}
	} else {
		findings = append(findings, skipped(controlByID("IMAGE-008"), dockerfilePath,
			"No FROM instruction found — cannot determine base image"))
	}

	// IMAGE-014: PASS when no local-file ADD instructions found
	if !hasLocalADD {
		findings = append(findings, pass(controlByID("IMAGE-014"), dockerfilePath,
			"No local-file ADD instructions found — COPY is used correctly"))
	}

	// RUNTIME-010: check CMD/ENTRYPOINT for sshd; SKIP when neither is present
	if len(cmdEntrypoint) == 0 {
		findings = append(findings, skipped(controlByID("RUNTIME-010"), dockerfilePath,
			"No CMD or ENTRYPOINT found — cannot determine runtime command"))
	} else {
		hasSshd := false
		for _, v := range cmdEntrypoint {
			if strings.Contains(strings.ToLower(v), "sshd") {
				hasSshd = true
				ctrl := controlByID("RUNTIME-010")
				findings = append(findings, fail(ctrl, dockerfilePath,
					"SSH daemon (sshd) found in CMD/ENTRYPOINT",
					v, ctrl.Remediation))
				break
			}
		}
		if !hasSshd {
			findings = append(findings, pass(controlByID("RUNTIME-010"), dockerfilePath,
				"No sshd in CMD or ENTRYPOINT"))
		}
	}

	// RUNTIME-011: PASS when no privileged ports exposed
	if !hasPrivilegedExpose {
		findings = append(findings, pass(controlByID("RUNTIME-011"), dockerfilePath,
			"No privileged ports (< 1024) in EXPOSE instructions"))
	}

	// RUNTIME-012: WARN when no HEALTHCHECK; PASS when present
	if !hasHealthcheck {
		findings = append(findings, warn(controlByID("RUNTIME-012"), dockerfilePath,
			"No HEALTHCHECK instruction — container health cannot be monitored",
			"Dockerfile missing HEALTHCHECK instruction"))
	} else {
		findings = append(findings, pass(controlByID("RUNTIME-012"), dockerfilePath,
			"HEALTHCHECK instruction found"))
	}

	// IMAGE-011: PASS when no debug/dev tools detected
	if !hasDebugTool {
		findings = append(findings, pass(controlByID("IMAGE-011"), dockerfilePath,
			"No debug or development tools detected in package installs"))
	}

	// IMAGE-012: PASS when no package verification bypass detected
	if !hasPkgVerifyBypass {
		findings = append(findings, pass(controlByID("IMAGE-012"), dockerfilePath,
			"No package manager verification bypass flags detected"))
	}

	// IMAGE-013: PASS when no VOLUME targeting sensitive paths
	if !hasSensitiveVolume {
		findings = append(findings, pass(controlByID("IMAGE-013"), dockerfilePath,
			"No VOLUME directives targeting sensitive paths"))
	}

	// IMAGE-015: WARN when single FROM (no multi-stage build)
	if fromCount == 1 {
		findings = append(findings, warn(controlByID("IMAGE-015"), dockerfilePath,
			"Single-stage build — consider multi-stage builds to reduce final image size and attack surface",
			fmt.Sprintf("FROM count: %d", fromCount)))
	} else if fromCount > 1 {
		findings = append(findings, pass(controlByID("IMAGE-015"), dockerfilePath,
			fmt.Sprintf("Multi-stage build detected (%d stages)", fromCount)))
	}

	// IMAGE-016: PASS when no recursive COPY . . detected
	if !hasRecursiveCopy {
		findings = append(findings, pass(controlByID("IMAGE-016"), dockerfilePath,
			"No recursive COPY . . instructions detected"))
	}

	// HOST-001: Minimal base image check (on the final FROM stage for shipped image)
	if lastFromImage != "" {
		findings = append(findings, checkImageMinimality(lastFromImage, dockerfilePath)...)
	}

	// DB-IMAGE-001: SKIP for static Dockerfile analysis (requires running the image)
	findings = append(findings, skipped(controlByID("DB-IMAGE-001"), dockerfilePath,
		"Admin tool detection requires running the image — scan with dockeraudit image"))

	// DB-IMAGE-002: check CMD/ENTRYPOINT for dangerous DB startup flags
	if len(cmdEntrypoint) == 0 {
		findings = append(findings, skipped(controlByID("DB-IMAGE-002"), dockerfilePath,
			"No CMD or ENTRYPOINT found — cannot check for dangerous DB startup flags"))
	} else {
		combined := strings.ToLower(strings.Join(cmdEntrypoint, " "))
		dangerFlags := []struct{ flag, msg string }{
			{"--skip-grant-tables", "MySQL --skip-grant-tables bypasses all authentication"},
			{"--local-infile=1", "MySQL --local-infile=1 enables client-side file reads"},
			{"--secure-file-priv=,", "MySQL --secure-file-priv= (empty) removes file write restrictions"},
			{"-tcpallowothers", "H2 -tcpAllowOthers exposes unauthenticated TCP server"},
			{"-weballowothers", "H2 -webAllowOthers exposes unauthenticated web console"},
			{"-startnetworkserver", "Derby -startNetworkServer exposes unauthenticated network DB"},
		}
		hasDangerFlag := false
		for _, df := range dangerFlags {
			if strings.Contains(combined, df.flag) {
				hasDangerFlag = true
				ctrl := controlByID("DB-IMAGE-002")
				findings = append(findings, fail(ctrl, dockerfilePath, df.msg,
					strings.Join(cmdEntrypoint, " "), ctrl.Remediation))
				break
			}
		}
		if !hasDangerFlag {
			findings = append(findings, pass(controlByID("DB-IMAGE-002"), dockerfilePath,
				"No dangerous database startup flags in CMD/ENTRYPOINT"))
		}
	}

	return findings
}

// checkEOLInLine checks a FROM line against known end-of-life base images.
func (s *DockerScanner) checkEOLInLine(dockerfilePath, line string, lineNum int) *types.Finding {
	ctrl := controlByID("IMAGE-008")

	// Parse the FROM instruction to get the image reference
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return nil
	}
	imageRef := fields[1] // e.g. "debian:9-slim", "ubuntu:18.04 AS builder"

	name, tag := imageNameTag(imageRef)
	if tag == "latest" || tag == "" {
		return nil // can't determine EOL for untagged/latest
	}

	for _, eol := range DefaultEOLImages {
		if name == eol.Name && eolTagMatches(tag, eol.Tag) {
			f := withSource(fail(ctrl, dockerfilePath,
				fmt.Sprintf("EOL base image at line %d: %s", lineNum, eol.Reason),
				line, ctrl.Remediation), dockerfilePath, lineNum)
			return &f
		}
	}
	return nil
}

// checkSecretsInHistory uses the regex-based SecretScanner to detect secrets
// in the entire Dockerfile content.
func (s *DockerScanner) checkSecretsInHistory(dockerfilePath string, content []byte) types.Finding {
	ctrl := controlByID("IMAGE-002")
	dockerfileName := filepath.Base(dockerfilePath)
	secretsScanner := NewSecretScanner(dockerfileName, ctrl)
	return secretsScanner.CheckSecrets(string(content))
}

// ── Docker Compose scanning ─────────────────────────────────────────────────

// Compose YAML structs — only security-relevant fields.

type composeFile struct {
	Services map[string]composeService `yaml:"services"`
	Secrets  map[string]composeSecret  `yaml:"secrets"`
	Networks map[string]composeNetwork `yaml:"networks"`
}

type composeService struct {
	Image       string             `yaml:"image"`
	Command     interface{}        `yaml:"command"`
	Entrypoint  interface{}        `yaml:"entrypoint"`
	User        string             `yaml:"user"`
	Privileged  *bool              `yaml:"privileged"`
	ReadOnly    *bool              `yaml:"read_only"`
	CapDrop     []string           `yaml:"cap_drop"`
	CapAdd      []string           `yaml:"cap_add"`
	SecurityOpt []string           `yaml:"security_opt"`
	NetworkMode string             `yaml:"network_mode"`
	PidMode     string             `yaml:"pid"`
	IpcMode     string             `yaml:"ipc"`
	Ports       []interface{}      `yaml:"ports"`
	Environment composeEnv         `yaml:"environment"`
	Secrets     []interface{}      `yaml:"secrets"`
	Healthcheck *composeHealthcheck `yaml:"healthcheck"`
	Deploy      *composeDeploy     `yaml:"deploy"`
	Volumes     []interface{}      `yaml:"volumes"`
	Restart     string             `yaml:"restart"`
	Ulimits     interface{}        `yaml:"ulimits"`
}

// composeEnv handles both map and list forms of Docker Compose environment.
type composeEnv struct {
	Vars map[string]string
}

func (e *composeEnv) UnmarshalYAML(value *yaml.Node) error {
	e.Vars = make(map[string]string)
	switch value.Kind {
	case yaml.MappingNode:
		// environment:
		//   FOO: bar
		var m map[string]string
		if err := value.Decode(&m); err != nil {
			return err
		}
		e.Vars = m
	case yaml.SequenceNode:
		// environment:
		//   - FOO=bar
		var list []string
		if err := value.Decode(&list); err != nil {
			return err
		}
		for _, item := range list {
			parts := strings.SplitN(item, "=", 2)
			if len(parts) == 2 {
				e.Vars[parts[0]] = parts[1]
			} else {
				e.Vars[parts[0]] = ""
			}
		}
	}
	return nil
}

// composeCommandArgs converts a compose command or entrypoint value (string or list) to a
// single space-joined string suitable for pattern matching against dangerous flags.
func composeCommandArgs(v interface{}) string {
	if v == nil {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	case []interface{}:
		parts := make([]string, 0, len(val))
		for _, p := range val {
			parts = append(parts, fmt.Sprintf("%v", p))
		}
		return strings.Join(parts, " ")
	default:
		return fmt.Sprintf("%v", val)
	}
}

type composeHealthcheck struct {
	Test     interface{} `yaml:"test"`
	Interval string      `yaml:"interval"`
	Timeout  string      `yaml:"timeout"`
	Retries  int         `yaml:"retries"`
	Disable  bool        `yaml:"disable"`
}

type composeDeploy struct {
	Resources *composeResources `yaml:"resources"`
}

type composeResources struct {
	Limits       *composeResourceSpec `yaml:"limits"`
	Reservations *composeResourceSpec `yaml:"reservations"`
}

type composeResourceSpec struct {
	CPUs   string `yaml:"cpus"`
	Memory string `yaml:"memory"`
}

type composeSecret struct {
	File     string `yaml:"file"`
	External bool   `yaml:"external"`
}

type composeNetwork struct {
	Driver   string `yaml:"driver"`
	Internal bool   `yaml:"internal"`
}

// scanComposeFile parses a Docker Compose file and runs all security checks.
func (s *DockerScanner) scanComposeFile(path string) []types.Finding {
	relP := relPath(s.Path, path)
	data, err := os.ReadFile(path) // #nosec G304 -- user-supplied compose path
	if err != nil {
		ctrl := controlByID("RUNTIME-002")
		return []types.Finding{fail(ctrl, relP,
			fmt.Sprintf("Failed to read compose file: %v", err), "", ctrl.Remediation)}
	}

	var compose composeFile
	if err := yaml.Unmarshal(data, &compose); err != nil {
		ctrl := controlByID("RUNTIME-002")
		return []types.Finding{fail(ctrl, relP,
			fmt.Sprintf("Failed to parse compose YAML: %v", err), "", ctrl.Remediation)}
	}

	var findings []types.Finding
	for name, svc := range compose.Services {
		target := fmt.Sprintf("%s[%s]", relP, name)
		var svcFindings []types.Finding
		svcFindings = append(svcFindings, checkComposeUser(svc, target)...)
		svcFindings = append(svcFindings, checkComposePrivileged(svc, target)...)
		svcFindings = append(svcFindings, checkComposeCapabilities(svc, target)...)
		svcFindings = append(svcFindings, checkComposeNoNewPrivileges(svc, target)...)
		svcFindings = append(svcFindings, checkComposeSeccomp(svc, target)...)
		svcFindings = append(svcFindings, checkComposeReadOnly(svc, target)...)
		svcFindings = append(svcFindings, checkComposeHostNamespaces(svc, target)...)
		svcFindings = append(svcFindings, checkComposeResources(svc, target)...)
		svcFindings = append(svcFindings, checkComposeImageDigest(svc, target)...)
		svcFindings = append(svcFindings, checkComposeEOLImage(svc, target)...)
		if svc.Image != "" {
			svcFindings = append(svcFindings, checkImageMinimality(svc.Image, target)...)
		}
		svcFindings = append(svcFindings, checkComposeSecrets(svc, target)...)
		svcFindings = append(svcFindings, checkComposeADDInstruction(svc, target)...)
		svcFindings = append(svcFindings, checkComposeHealthcheck(svc, target)...)
		svcFindings = append(svcFindings, checkComposePorts(svc, target)...)
		svcFindings = append(svcFindings, checkComposeVolumes(svc, target)...)
		svcFindings = append(svcFindings, checkComposeContentTrust(svc, target)...)
		svcFindings = append(svcFindings, checkComposeDangerousDBFlags(svc, target)...)
		svcFindings = append(svcFindings, checkComposeUlimits(svc, target)...)
		svcFindings = append(svcFindings, checkComposeRestartPolicy(svc, target)...)

		// Set SourceFile on all compose findings
		for i := range svcFindings {
			if svcFindings[i].SourceFile == "" {
				svcFindings[i].SourceFile = relP
			}
		}
		findings = append(findings, svcFindings...)
	}
	return findings
}

// ── Compose check functions ─────────────────────────────────────────────────

// checkComposeUser checks that a non-root user is specified (RUNTIME-001).
func checkComposeUser(svc composeService, target string) []types.Finding {
	ctrl := controlByID("RUNTIME-001")
	if svc.User == "" {
		return []types.Finding{warn(ctrl, target,
			"No user directive — container will run as root by default",
			"user: not set")}
	}
	uid := strings.Split(svc.User, ":")[0]
	if uid == "0" || strings.EqualFold(uid, "root") {
		return []types.Finding{fail(ctrl, target,
			fmt.Sprintf("Container runs as root (user: %s)", svc.User),
			fmt.Sprintf("user: %s", svc.User), ctrl.Remediation)}
	}
	return []types.Finding{pass(ctrl, target,
		fmt.Sprintf("Non-root user: %s", svc.User))}
}

// checkComposePrivileged checks that privileged mode is not enabled (RUNTIME-002).
func checkComposePrivileged(svc composeService, target string) []types.Finding {
	ctrl := controlByID("RUNTIME-002")
	if svc.Privileged != nil && *svc.Privileged {
		return []types.Finding{fail(ctrl, target,
			"Container runs in privileged mode",
			"privileged: true", ctrl.Remediation)}
	}
	return []types.Finding{pass(ctrl, target, "Not running in privileged mode")}
}

// checkComposeCapabilities checks that all capabilities are dropped (RUNTIME-003).
func checkComposeCapabilities(svc composeService, target string) []types.Finding {
	ctrl := controlByID("RUNTIME-003")
	for _, c := range svc.CapDrop {
		if strings.EqualFold(c, "ALL") {
			return []types.Finding{pass(ctrl, target, "Cap_drop includes ALL")}
		}
	}
	return []types.Finding{fail(ctrl, target,
		"Capabilities not dropped — add cap_drop: [ALL]",
		"Cap_drop does not include ALL", ctrl.Remediation)}
}

// checkComposeNoNewPrivileges checks for no-new-privileges in security_opt (RUNTIME-004).
func checkComposeNoNewPrivileges(svc composeService, target string) []types.Finding {
	ctrl := controlByID("RUNTIME-004")
	for _, opt := range svc.SecurityOpt {
		lower := strings.TrimSpace(strings.ToLower(opt))
		if lower == "no-new-privileges:true" || lower == "no-new-privileges" {
			return []types.Finding{pass(ctrl, target, "Security_opt: no-new-privileges:true")}
		}
	}
	return []types.Finding{fail(ctrl, target,
		"No-new-privileges not set in security_opt",
		"security_opt missing no-new-privileges:true", ctrl.Remediation)}
}

// checkComposeSeccomp checks that a seccomp profile is configured in security_opt (RUNTIME-008).
// Mirrors checkComposeNoNewPrivileges: both inspect the same security_opt list.
// seccomp=unconfined → FAIL (explicitly disabled); missing entry → WARN (relying on runtime default).
func checkComposeSeccomp(svc composeService, target string) []types.Finding {
	ctrl := controlByID("RUNTIME-008")
	for _, opt := range svc.SecurityOpt {
		lower := strings.TrimSpace(strings.ToLower(opt))
		if strings.HasPrefix(lower, "seccomp=") {
			profile := strings.TrimPrefix(lower, "seccomp=")
			if profile == "unconfined" {
				return []types.Finding{fail(ctrl, target,
					"seccomp explicitly set to unconfined — all syscalls permitted",
					fmt.Sprintf("security_opt: %s", opt), ctrl.Remediation)}
			}
			return []types.Finding{pass(ctrl, target,
				fmt.Sprintf("seccomp profile configured: %s", strings.TrimPrefix(opt, "seccomp=")))}
		}
	}
	return []types.Finding{warn(ctrl, target,
		"No seccomp profile in security_opt — relying on runtime default",
		"security_opt missing seccomp= entry")}
}

// checkComposeReadOnly checks that the root filesystem is read-only (RUNTIME-005).
func checkComposeReadOnly(svc composeService, target string) []types.Finding {
	ctrl := controlByID("RUNTIME-005")
	if svc.ReadOnly != nil && *svc.ReadOnly {
		return []types.Finding{pass(ctrl, target, "Read_only: true")}
	}
	return []types.Finding{warn(ctrl, target,
		"Root filesystem is writable — set read_only: true",
		"read_only not set or false")}
}

// checkComposeHostNamespaces checks for host namespace sharing (RUNTIME-006).
func checkComposeHostNamespaces(svc composeService, target string) []types.Finding {
	ctrl := controlByID("RUNTIME-006")
	var violations []string
	if strings.EqualFold(svc.NetworkMode, "host") {
		violations = append(violations, "network_mode: host")
	}
	if strings.EqualFold(svc.PidMode, "host") {
		violations = append(violations, "pid: host")
	}
	if strings.EqualFold(svc.IpcMode, "host") {
		violations = append(violations, "ipc: host")
	}
	if len(violations) > 0 {
		return []types.Finding{fail(ctrl, target,
			fmt.Sprintf("Host namespace sharing: %s", strings.Join(violations, ", ")),
			strings.Join(violations, "; "), ctrl.Remediation)}
	}
	return []types.Finding{pass(ctrl, target, "No host namespace sharing")}
}

// checkComposeResources checks that resource limits are configured (RUNTIME-007).
func checkComposeResources(svc composeService, target string) []types.Finding {
	ctrl := controlByID("RUNTIME-007")
	if svc.Deploy == nil || svc.Deploy.Resources == nil || svc.Deploy.Resources.Limits == nil {
		return []types.Finding{fail(ctrl, target,
			"No resource limits configured — set deploy.resources.limits",
			"deploy.resources.limits missing", ctrl.Remediation)}
	}
	limits := svc.Deploy.Resources.Limits
	var missing []string
	if limits.Memory == "" {
		missing = append(missing, "memory")
	}
	if limits.CPUs == "" {
		missing = append(missing, "cpus")
	}
	if len(missing) > 0 {
		return []types.Finding{fail(ctrl, target,
			fmt.Sprintf("Missing resource limits: %s", strings.Join(missing, ", ")),
			fmt.Sprintf("deploy.resources.limits missing: %s", strings.Join(missing, ", ")),
			ctrl.Remediation)}
	}
	return []types.Finding{pass(ctrl, target,
		fmt.Sprintf("Resource limits: memory=%s, cpus=%s", limits.Memory, limits.CPUs))}
}

// checkComposeImageDigest checks that the image reference is pinned by digest (IMAGE-001).
func checkComposeImageDigest(svc composeService, target string) []types.Finding {
	ctrl := controlByID("IMAGE-001")
	if svc.Image == "" {
		return []types.Finding{warn(ctrl, target,
			"No image specified (may use build context)",
			"image: not set")}
	}
	if strings.Contains(svc.Image, "@sha256:") {
		return []types.Finding{pass(ctrl, target,
			fmt.Sprintf("Image pinned by digest: %s", shortImage(svc.Image)))}
	}
	return []types.Finding{fail(ctrl, target,
		fmt.Sprintf("Image not pinned by digest: %s", shortImage(svc.Image)),
		fmt.Sprintf("image: %s", shortImage(svc.Image)), ctrl.Remediation)}
}

// checkComposeSecrets checks for plaintext secrets in environment variables (IMAGE-002).
func checkComposeSecrets(svc composeService, target string) []types.Finding {
	ctrl := controlByID("IMAGE-002")
	secretScanner := NewSecretScanner(target, ctrl)
	var findings []types.Finding

	// Sort keys for deterministic iteration order (TASK-8.10)
	envNames := make([]string, 0, len(svc.Environment.Vars))
	for name := range svc.Environment.Vars {
		envNames = append(envNames, name)
	}
	sort.Strings(envNames)

	for _, name := range envNames {
		value := svc.Environment.Vars[name]
		if value == "" {
			continue
		}
		nameL := strings.ToLower(name)
		// Skip _FILE convention (proper Docker secrets usage)
		if strings.HasSuffix(nameL, "_file") {
			continue
		}
		// Skip file path values (e.g., /run/secrets/...)
		if strings.HasPrefix(value, "/") {
			continue
		}

		matched := false

		// AI/vectorizer key patterns (more specific SECRETS-003 control)
		for _, p := range aiKeyPatterns {
			if strings.Contains(nameL, p) {
				aiCtrl := controlByID("SECRETS-003")
				findings = append(findings, fail(aiCtrl, target,
					fmt.Sprintf("AI/vectorizer API key in env var %q — use Docker secrets", name),
					fmt.Sprintf("environment.%s has a literal value", name),
					aiCtrl.Remediation))
				matched = true
				break
			}
		}
		if matched {
			continue
		}

		// Generic *_apikey or *_api_key suffix
		if (strings.HasSuffix(nameL, "_apikey") || strings.HasSuffix(nameL, "_api_key")) && value != "" {
			aiCtrl := controlByID("SECRETS-003")
			findings = append(findings, fail(aiCtrl, target,
				fmt.Sprintf("API key in env var %q — use Docker secrets", name),
				fmt.Sprintf("environment.%s matches *_api_key pattern", name),
				aiCtrl.Remediation))
			continue
		}

		// Name-based check
		for _, p := range credentialKeywords {
			if strings.Contains(nameL, p) {
				findings = append(findings, fail(ctrl, target,
					fmt.Sprintf("Potential secret in env var %q — use Docker secrets instead", name),
					fmt.Sprintf("environment.%s has a literal value", name),
					ctrl.Remediation))
				matched = true
				break
			}
		}
		if matched {
			continue
		}

		// Value-based regex check
		matches := secretScanner.CheckLine(value)
		if len(matches) > 0 {
			findings = append(findings, fail(ctrl, target,
				fmt.Sprintf("Regex-detected %s in env var %q value", matches[0].PatternName, name),
				fmt.Sprintf("environment.%s matches %s pattern", name, matches[0].PatternName),
				ctrl.Remediation))
		}
	}
	if len(findings) == 0 {
		return []types.Finding{pass(ctrl, target, "No plaintext secrets in environment")}
	}
	return findings
}

// checkComposeHealthcheck checks that a healthcheck is configured (RUNTIME-012).
func checkComposeHealthcheck(svc composeService, target string) []types.Finding {
	ctrl := controlByID("RUNTIME-012")
	if svc.Healthcheck == nil {
		return []types.Finding{fail(ctrl, target,
			"No healthcheck configured",
			"healthcheck: not set", ctrl.Remediation)}
	}
	if svc.Healthcheck.Disable {
		return []types.Finding{fail(ctrl, target,
			"Healthcheck explicitly disabled",
			"healthcheck.disable: true", ctrl.Remediation)}
	}
	return []types.Finding{pass(ctrl, target, "Healthcheck configured")}
}

// checkComposePorts checks for privileged host ports < 1024 (RUNTIME-011).
func checkComposePorts(svc composeService, target string) []types.Finding {
	ctrl := controlByID("RUNTIME-011")
	var privPorts []string
	for _, p := range svc.Ports {
		portStr := fmt.Sprintf("%v", p)
		parts := strings.Split(portStr, ":")
		var hostPart string
		switch len(parts) {
		case 3:
			// IP:hostPort:containerPort (e.g., "127.0.0.1:80:8080")
			hostPart = parts[1]
		case 2:
			// hostPort:containerPort (e.g., "80:8080")
			hostPart = parts[0]
		default:
			continue
		}
		hostPart = strings.Split(hostPart, "/")[0] // strip protocol if present
		if port, err := strconv.Atoi(strings.TrimSpace(hostPart)); err == nil && port > 0 && port < 1024 {
			privPorts = append(privPorts, strconv.Itoa(port))
		}
	}
	if len(privPorts) > 0 {
		return []types.Finding{warn(ctrl, target,
			fmt.Sprintf("Privileged host port(s) exposed: %s", strings.Join(privPorts, ", ")),
			fmt.Sprintf("ports: %s", strings.Join(privPorts, ", ")))}
	}
	return []types.Finding{pass(ctrl, target, "No privileged ports (< 1024) on host")}
}

// checkComposeContentTrust checks for DOCKER_CONTENT_TRUST env var in Compose services (DAEMON-004).
func checkComposeContentTrust(svc composeService, target string) []types.Finding {
	ctrl := controlByID("DAEMON-004")
	for name, value := range svc.Environment.Vars {
		if strings.EqualFold(name, "DOCKER_CONTENT_TRUST") {
			if value == "1" {
				return []types.Finding{pass(ctrl, target, "DOCKER_CONTENT_TRUST=1 set in Compose environment")}
			}
			return []types.Finding{warn(ctrl, target,
				fmt.Sprintf("DOCKER_CONTENT_TRUST=%s in Compose environment (should be 1)", value),
				fmt.Sprintf("environment.%s=%s", name, value))}
		}
	}
	return nil // Don't emit for every service — absence is normal, daemon-level check handles it
}

// checkComposeVolumes checks for sensitive host path mounts (RUNTIME-009).
// Handles both short-syntax strings ("host:container") and long-syntax maps
// ({type: bind, source: /host, target: /container}).
// Reuses sensitivePaths defined in k8s.go (same package).
func checkComposeVolumes(svc composeService, target string) []types.Finding {
	ctrl := controlByID("RUNTIME-009")
	var findings []types.Finding
	ctrlDaemon := controlByID("DAEMON-001")
	for _, v := range svc.Volumes {
		var hostPath string
		switch vol := v.(type) {
		case string:
			// Short syntax: "hostPath:containerPath[:options]"
			parts := strings.Split(vol, ":")
			if len(parts) >= 2 {
				hostPath = parts[0]
			}
		case map[string]interface{}:
			// Long syntax (yaml.v3 decodes string keys)
			if src, ok := vol["source"]; ok {
				hostPath = fmt.Sprintf("%v", src)
			}
		case map[interface{}]interface{}:
			// Long syntax fallback
			if src, ok := vol["source"]; ok {
				hostPath = fmt.Sprintf("%v", src)
			}
		}
		if hostPath == "" {
			continue
		}
		// DAEMON-001: Docker socket mount — defense-in-depth dual finding
		if strings.Contains(hostPath, "docker.sock") {
			findings = append(findings, fail(ctrlDaemon, target,
				"Docker socket mounted in Compose service",
				fmt.Sprintf("volumes: %v", v), ctrlDaemon.Remediation))
		}
		for _, sp := range sensitivePaths {
			if hostPath == sp || strings.HasPrefix(hostPath, sp+"/") {
				findings = append(findings, fail(ctrl, target,
					fmt.Sprintf("Sensitive host path %q mounted", hostPath),
					fmt.Sprintf("volumes: %v", v), ctrl.Remediation))
				break // one finding per volume — stop at first matching sensitive path
			}
		}
	}
	if len(findings) == 0 {
		return []types.Finding{pass(ctrl, target, "No sensitive host path mounts")}
	}
	return findings
}

// checkADDInstruction checks a single Dockerfile line for IMAGE-006 violations:
// ADD with a remote URL, and curl/wget piped to a shell interpreter.
// Called per-line from checkLines so each finding carries an accurate source line number.
func checkADDInstruction(path, line string, lineNum int) []types.Finding {
	var findings []types.Finding
	ctrl := controlByID("IMAGE-006")
    ctrl014 := controlByID("IMAGE-014")
	trimmed := strings.TrimSpace(line)
	lower := strings.ToLower(trimmed)

	// ADD with remote URL
	if strings.HasPrefix(lower, "add ") && (strings.Contains(lower, "http://") || strings.Contains(lower, "https://")) {
		findings = append(findings, withSource(fail(ctrl, path,
			fmt.Sprintf("ADD used with remote URL at line %d — use COPY + curl/wget with checksum verification", lineNum),
			line, ctrl.Remediation), path, lineNum))
	}

	// IMAGE-014: ADD used for local files (no URL, no tar/archive glob) — prefer COPY
	if strings.HasPrefix(lower, "add ") &&
		!strings.Contains(lower, "http://") && !strings.Contains(lower, "https://") &&
		!strings.Contains(lower, ".tar") && !strings.Contains(lower, ".tgz") &&
		!strings.Contains(lower, ".tar.gz") && !strings.Contains(lower, ".tar.bz2") {
		findings = append(findings, withSource(warn(ctrl014, path,
			fmt.Sprintf("ADD used for local file at line %d — use COPY instead", lineNum),
			line), path, lineNum))
	}

	// curl/wget pipe to shell (skip package-manager invocations)
	hasCurlWget := strings.Contains(lower, "curl") || strings.Contains(lower, "wget")
	isPackageInstall := strings.Contains(lower, "apt-get") || strings.Contains(lower, "apk add") ||
		strings.Contains(lower, "yum install") || strings.Contains(lower, "dnf install")
	if hasCurlWget && !isPackageInstall {
		if strings.Contains(line, "| sh") || strings.Contains(line, "| bash") ||
			strings.Contains(line, "|sh") || strings.Contains(line, "|bash") {
			findings = append(findings, withSource(fail(ctrl, path,
				fmt.Sprintf("Piping remote content to shell at line %d — verify checksums before executing", lineNum),
				line, ctrl.Remediation), path, lineNum))
		} else {
			findings = append(findings, withSource(warn(ctrl, path,
				fmt.Sprintf("Remote fetch via curl/wget at line %d — ensure integrity verification", lineNum),
				line), path, lineNum))
		}
	}
	return findings
}

// checkComposeADDInstruction checks compose service command/entrypoint for:
//   - IMAGE-006: curl/wget piped to a shell interpreter
//   - IMAGE-014: ADD used for local files instead of COPY
func checkComposeADDInstruction(svc composeService, target string) []types.Finding {
	ctrl006 := controlByID("IMAGE-006")
	ctrl014 := controlByID("IMAGE-014")

	combined := composeCommandArgs(svc.Command) + " " + composeCommandArgs(svc.Entrypoint)
	trimmed := strings.TrimSpace(combined)
	lower := strings.ToLower(trimmed)

	var findings []types.Finding

	// IMAGE-006: detect curl/wget pipe-to-shell in runtime command/entrypoint
	if trimmed == "" {
		findings = append(findings, skipped(ctrl006, target, "No command or entrypoint to inspect"))
	} else {
		hasCurlWget := strings.Contains(lower, "curl") || strings.Contains(lower, "wget")
		isPackageInstall := strings.Contains(lower, "apt-get") || strings.Contains(lower, "apk add") ||
			strings.Contains(lower, "yum install") || strings.Contains(lower, "dnf install")
		if hasCurlWget && !isPackageInstall {
			if strings.Contains(trimmed, "| sh") || strings.Contains(trimmed, "| bash") ||
				strings.Contains(trimmed, "|sh") || strings.Contains(trimmed, "|bash") {
				findings = append(findings, fail(ctrl006, target,
					"Command/entrypoint pipes remote content to a shell interpreter",
					fmt.Sprintf("command: %q", trimmed), ctrl006.Remediation))
			} else {
				findings = append(findings, warn(ctrl006, target,
					"Command/entrypoint contains remote fetch — ensure integrity verification",
					fmt.Sprintf("command: %q", trimmed)))
			}
		} else {
			findings = append(findings, pass(ctrl006, target, "No remote fetch or pipe-to-shell in command/entrypoint"))
		}
	}

	// IMAGE-014: ADD used for local files (no URL, no archive extension) — prefer COPY
	if strings.HasPrefix(lower, "add ") &&
		!strings.Contains(lower, "http://") && !strings.Contains(lower, "https://") &&
		!strings.Contains(lower, ".tar") && !strings.Contains(lower, ".tgz") &&
		!strings.Contains(lower, ".tar.gz") && !strings.Contains(lower, ".tar.bz2") {
		findings = append(findings, warn(ctrl014, target,
			"Command uses ADD for local file — use COPY instead",
			fmt.Sprintf("command: %q", trimmed)))
	} else {
		findings = append(findings, pass(ctrl014, target, "No local-file ADD instructions detected"))
	}

	return findings
}

// checkComposeUlimits checks that ulimits are configured (RUNTIME-015).
func checkComposeUlimits(svc composeService, target string) []types.Finding {
	ctrl := controlByID("RUNTIME-015")
	if svc.Ulimits == nil {
		return []types.Finding{warn(ctrl, target,
			"No ulimits configured — container inherits host defaults (fork bomb risk)",
			"ulimits: not set")}
	}
	return []types.Finding{pass(ctrl, target, "ulimits configured")}
}

// checkComposeRestartPolicy checks restart policy is capped (RUNTIME-016).
func checkComposeRestartPolicy(svc composeService, target string) []types.Finding {
	ctrl := controlByID("RUNTIME-016")
	if svc.Restart == "" {
		return []types.Finding{pass(ctrl, target, "No restart policy (default: no)")}
	}
	lower := strings.ToLower(svc.Restart)
	if lower == "always" || lower == "unless-stopped" {
		return []types.Finding{warn(ctrl, target,
			fmt.Sprintf("Restart policy %q has no retry cap — use on-failure:5 to prevent crash-loop resource exhaustion",
				svc.Restart),
			fmt.Sprintf("restart: %s", svc.Restart))}
	}
	if strings.HasPrefix(lower, "on-failure") {
		// Check if max retry is specified
		if !strings.Contains(lower, ":") {
			return []types.Finding{warn(ctrl, target,
				"restart: on-failure without max retries — add a cap (e.g., on-failure:5)",
				fmt.Sprintf("restart: %s", svc.Restart))}
		}
	}
	return []types.Finding{pass(ctrl, target,
		fmt.Sprintf("Restart policy: %s", svc.Restart))}
}

// checkComposeEOLImage checks the service image tag against known end-of-life images (IMAGE-008).
// Mirrors checkK8sEOLImage from k8s.go for Docker Compose services.
func checkComposeEOLImage(svc composeService, target string) []types.Finding {
	ctrl := controlByID("IMAGE-008")
	if svc.Image == "" {
		return []types.Finding{skipped(ctrl, target, "Build-context service — no image tag to inspect")}
	}
	name, tag := imageNameTag(svc.Image)
	if tag == "latest" || tag == "" {
		return []types.Finding{skipped(ctrl, target, "Cannot determine EOL for :latest or untagged images")}
	}
	for _, eol := range DefaultEOLImages {
		if name == eol.Name && eolTagMatches(tag, eol.Tag) {
			return []types.Finding{fail(ctrl, target,
				fmt.Sprintf("EOL base image: %s", eol.Reason),
				fmt.Sprintf("image: %s", shortImage(svc.Image)), ctrl.Remediation)}
		}
	}
	return []types.Finding{pass(ctrl, target,
		fmt.Sprintf("Image %s is not a known end-of-life image", shortImage(svc.Image)))}
}

// composeDangerousDBFlags is the unified set of database startup flags that bypass
// authentication or enable severe misconfigurations. Combines the k8s (dbDangerousFlags)
// and image-layer flag sets into one list for compose command/entrypoint analysis.
var composeDangerousDBFlags = []struct{ flag, msg string }{
	{"--noauth",            "MongoDB --noauth disables authentication entirely"},
	{"--skip-grant-tables", "MySQL --skip-grant-tables bypasses all authentication"},
	{"--skip-networking",   "MySQL --skip-networking (often paired with --skip-grant-tables)"},
	{"--local-infile=1",    "MySQL --local-infile=1 enables client-side file reads"},
	{"--secure-file-priv=", "MySQL --secure-file-priv= (empty) removes file write restrictions"},
	{"--auth=trust",        "PostgreSQL --auth=trust allows passwordless connections from any host"},
	{"--protected-mode no", "Redis --protected-mode no removes bind/auth safeguards"},
	{"--protected-mode=no", "Redis --protected-mode=no removes bind/auth safeguards"},
	{"-tcpallowothers",     "H2 -tcpAllowOthers exposes unauthenticated TCP server"},
	{"-weballowothers",     "H2 -webAllowOthers exposes unauthenticated web console (RCE risk)"},
	{"-startnetworkserver", "Derby -startNetworkServer exposes unauthenticated network DB"},
}

// checkComposeDangerousDBFlags detects unsafe database startup flags in compose
// command/entrypoint fields (DB-IMAGE-002). Mirrors image.go::checkDangerousDBFlags
// for static compose analysis.
func checkComposeDangerousDBFlags(svc composeService, target string) []types.Finding {
	ctrl := controlByID("DB-IMAGE-002")
	combined := strings.TrimSpace(composeCommandArgs(svc.Command) + " " + composeCommandArgs(svc.Entrypoint))
	if combined == "" {
		return []types.Finding{skipped(ctrl, target, "No command or entrypoint to inspect statically")}
	}
	lower := strings.ToLower(combined)
	for _, f := range composeDangerousDBFlags {
		if strings.Contains(lower, strings.ToLower(f.flag)) {
			return []types.Finding{fail(ctrl, target, f.msg,
				fmt.Sprintf("Command/entrypoint contains %q", f.flag), ctrl.Remediation)}
		}
	}
	// MongoDB: if the image is mongo and --auth is absent from the command/entrypoint
	if svc.Image != "" && strings.Contains(strings.ToLower(svc.Image), "mongo") &&
		!strings.Contains(lower, "--auth") {
		return []types.Finding{fail(ctrl, target,
			"MongoDB command/entrypoint does not include --auth — unauthenticated access enabled",
			fmt.Sprintf("command: %q entrypoint: %q",
				composeCommandArgs(svc.Command), composeCommandArgs(svc.Entrypoint)),
			ctrl.Remediation)}
	}
	return []types.Finding{pass(ctrl, target, "No dangerous database startup flags in command/entrypoint")}
}
