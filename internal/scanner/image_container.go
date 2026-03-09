package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"https://github.com/kariemoorman/dockeraudit/internal/types"
)

// ── IMAGE-007: Secret files in filesystem ─────────────────────────────────────

// knownSecretFileNames is the set of filenames that, if present anywhere in the
// image filesystem, indicate credentials were baked into the image.
var knownSecretFileNames = []string{
	// Generic env / dotfiles
	".env", ".env.local", ".env.prod", ".env.production",
	".env.development", ".env.staging", ".env.test", ".env.backup",
	// Cloud provider credentials
	"credentials", "credentials.json", "credentials.csv",
	// Package manager / tool auth
	".npmrc", ".pypirc", ".netrc", ".gitconfig", ".git-credentials",
	".dockerconfigjson", ".docker-credentials",
	// SSH / TLS private keys
	"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
	"id_rsa.pub", "id_dsa.pub",
	// Web application configs
	"wp-config.php", "config.php", "local_settings.py",
	// Database / app config
	"database.yml", "database.yaml", "secrets.yml", "secrets.yaml",
	"application.properties", "application-prod.properties",
	// Web server auth
	".htpasswd", "htpasswd",
	// Infrastructure-as-Code secrets
	"terraform.tfvars", "terraform.tfvars.json",
	// Vault / K8s
	".vault-token", "kubeconfig",
	// Service accounts
	"service-account.json", "oauth.json", "token",
	// Shell history (may contain credentials passed as CLI args)
	".bash_history", ".zsh_history", ".sh_history",
	// Misc
	"private.pem", "private.key", "server.key",
}

// runContainerChecks launches a single ephemeral container to check for
// SUID/SGID/world-writable files (IMAGE-004), secret/credential files (IMAGE-007),
// and the xz-utils backdoor (IMAGE-010).
func (s *ImageScanner) runContainerChecks(ctx context.Context) []types.Finding {
	suidCtrl := controlByID("IMAGE-004")
	secretCtrl := controlByID("IMAGE-007")
	xzCtrl := controlByID("IMAGE-010")

	// Build the find expression for secret file names.
	var secretNameArgs []string
	for i, name := range knownSecretFileNames {
		if i > 0 {
			secretNameArgs = append(secretNameArgs, "-o")
		}
		secretNameArgs = append(secretNameArgs, "-name", name)
	}

	// Combined shell script with delimited output sections.
	// Each section is bracketed by ===SECTION=== markers for reliable parsing.
	script := strings.Join([]string{
		`echo "===SUID==="`,
		`find / -xdev \( -perm -4000 -o -perm -2000 -o -perm -0002 \) -type f 2>/dev/null`,
		`echo "===SECRETS==="`,
		`find / -xdev -type f \( ` + strings.Join(secretNameArgs, " ") + ` \) 2>/dev/null`,
		`echo "===XZ==="`,
		`dpkg-query -W -f '${Package}\t${Version}\n' xz-utils liblzma5 2>/dev/null`,
		`rpm -q --qf '%{NAME}\t%{VERSION}\n' xz xz-libs 2>/dev/null`,
		`apk info -v xz 2>/dev/null`,
		`echo "===END==="`,
	}, "; ")

	// '--' prevents a crafted image name starting with '-' from being parsed as a docker flag.
	cmd := exec.CommandContext(ctx, // #nosec G204 -- fixed executable "docker"; image validated in Scan()
		"docker", "run", "--rm", "--entrypoint", "sh",
		"--", s.Image, "-c", script)

	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		// If sh is unavailable, fall back to skipped for all checks.
		return []types.Finding{
			skipped(suidCtrl, s.Image, "container check skipped (sh not available in image)"),
			skipped(secretCtrl, s.Image, "secret file scan skipped (sh not available in image)"),
			skipped(xzCtrl, s.Image, "xz-utils check skipped (sh not available in image)"),
		}
	}

	output := string(out)

	// Parse sections from delimited output.
	suidSection := extractSection(output, "===SUID===", "===SECRETS===")
	secretSection := extractSection(output, "===SECRETS===", "===XZ===")
	xzSection := extractSection(output, "===XZ===", "===END===")

	var findings []types.Finding

	// IMAGE-004: SUID/SGID/world-writable files
	if suidSection == "" {
		findings = append(findings, pass(suidCtrl, s.Image, "No SUID/SGID/world-writable files found in image"))
	} else {
		lines := strings.Split(suidSection, "\n")
		findings = append(findings, fail(suidCtrl, s.Image,
			fmt.Sprintf("%d SUID/SGID/world-writable file(s) found in image", len(lines)),
			suidSection,
			suidCtrl.Remediation))
	}

	// IMAGE-007: Secret files
	findings = append(findings, s.parseSecretFileResults(secretCtrl, secretSection))

	// IMAGE-010: xz-utils backdoor
	findings = append(findings, s.parseXZResults(xzCtrl, xzSection))

	return findings
}

// extractSection extracts text between start and end markers, trimming whitespace.
func extractSection(output, startMarker, endMarker string) string {
	startIdx := strings.Index(output, startMarker)
	if startIdx < 0 {
		return ""
	}
	startIdx += len(startMarker)
	endIdx := strings.Index(output[startIdx:], endMarker)
	if endIdx < 0 {
		return strings.TrimSpace(output[startIdx:])
	}
	return strings.TrimSpace(output[startIdx : startIdx+endIdx])
}

// parseSecretFileResults processes the secret file scan output into a Finding.
func (s *ImageScanner) parseSecretFileResults(ctrl types.Control, section string) types.Finding {
	if section == "" {
		return pass(ctrl, s.Image,
			fmt.Sprintf("No known secret/credential files found (checked %d filename patterns)", len(knownSecretFileNames)))
	}

	// Filter out known false positives: files under package manager internal directories
	var realFindings []string
	for _, line := range strings.Split(section, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(line, "/node_modules/") ||
			strings.Contains(line, "/site-packages/") ||
			strings.Contains(line, "/dist-packages/") {
			continue
		}
		realFindings = append(realFindings, line)
	}

	if len(realFindings) == 0 {
		return pass(ctrl, s.Image,
			"No user-placed secret/credential files found (filtered package manager internals)")
	}
	return fail(ctrl, s.Image,
		fmt.Sprintf("%d credential file(s) found baked into image filesystem", len(realFindings)),
		strings.Join(realFindings, "\n"),
		ctrl.Remediation)
}

// parseXZResults processes the xz-utils check output into a Finding.
func (s *ImageScanner) parseXZResults(ctrl types.Control, section string) types.Finding {
	if section == "" {
		return skipped(ctrl, s.Image, "xz-utils not found in image (no package manager output)")
	}

	for _, version := range []string{"5.6.0", "5.6.1"} {
		if strings.Contains(section, version) {
			return fail(ctrl, s.Image,
				fmt.Sprintf("BACKDOORED xz-utils %s detected (CVE-2024-3094 — CVSS 10.0 RCE)", version),
				fmt.Sprintf("Package query output:\n%s", section),
				ctrl.Remediation)
		}
	}

	return pass(ctrl, s.Image,
		fmt.Sprintf("xz-utils backdoor versions (5.6.0/5.6.1) not present\n%s", section))
}

// checkVulnerabilities runs image vulnerability scans using trivy and/or snyk (IMAGE-003).
func (s *ImageScanner) checkVulnerabilities(ctx context.Context) []types.Finding {
	ctrl := controlByID("IMAGE-003")
	avail := detectVulnTools()

	if !avail.HasTrivy && !avail.HasSnyk {
		return []types.Finding{skipped(ctrl, s.Image,
			"Neither trivy nor snyk found in PATH — install one to enable CVE scanning")}
	}

	var findings []types.Finding
	if avail.HasTrivy {
		findings = append(findings, s.runTrivyImage(ctx, ctrl)...)
	}
	if avail.HasSnyk {
		findings = append(findings, runSnykContainer(ctx, s.Image, ctrl)...)
	}
	return findings
}

// runTrivyImage runs `trivy image` and returns findings.
func (s *ImageScanner) runTrivyImage(ctx context.Context, ctrl types.Control) []types.Finding {
	cmd := exec.CommandContext(ctx, // #nosec G204 -- fixed executable "trivy"; image validated in Scan()
		"trivy", "image",
		"--exit-code", "0",
		"--severity", "CRITICAL,HIGH",
		"--ignore-unfixed",
		"--format", "json",
		"--quiet",
		s.Image)

	out, err := cmd.Output()
	if err != nil {
		return []types.Finding{errFinding(ctrl, s.Image,
			fmt.Sprintf("[trivy] image scan failed: %v", err))}
	}

	var report struct {
		Results []struct {
			Vulnerabilities []struct {
				VulnerabilityID string `json:"VulnerabilityID"`
				Severity        string `json:"Severity"`
				PkgName         string `json:"PkgName"`
				Title           string `json:"Title"`
			} `json:"Vulnerabilities"`
		} `json:"Results"`
	}

	if err := json.Unmarshal(out, &report); err != nil {
		return []types.Finding{errFinding(ctrl, s.Image,
			fmt.Sprintf("[trivy] failed to parse output: %v", err))}
	}

	var critical, high int
	var details []string
	for _, r := range report.Results {
		for _, v := range r.Vulnerabilities {
			switch v.Severity {
			case "CRITICAL":
				critical++
				details = append(details,
					fmt.Sprintf("CRITICAL %s (%s): %s", v.VulnerabilityID, v.PkgName, v.Title))
			case "HIGH":
				high++
				details = append(details,
					fmt.Sprintf("HIGH %s (%s): %s", v.VulnerabilityID, v.PkgName, v.Title))
			}
		}
	}

	if critical > 0 || high > 0 {
		summary := fmt.Sprintf("[trivy] %d CRITICAL, %d HIGH unfixed vulnerabilities", critical, high)
		return []types.Finding{fail(ctrl, s.Image, summary,
			strings.Join(details, "\n"), ctrl.Remediation)}
	}
	return []types.Finding{pass(ctrl, s.Image, "[trivy] No unfixed CRITICAL or HIGH CVEs found")}
}

// ── IMAGE-009: Crypto miner detection ─────────────────────────────────────────

var minerBinaryNames = []string{
	"xmrig", "xmrig-cuda", "xmrig-amd",
	"cpuminer", "cpuminer-multi", "minerd",
	"ethminer", "eth-proxy",
	"cgminer", "bfgminer",
	"lolminer", "t-rex", "nbminer", "teamredminer",
	"gminer", "phoenixminer", "claymore",
	"srbminer", "wildrig", "nanominer", "kawpow",
}

var minerPoolPatterns = []string{
	"stratum+tcp://", "stratum+ssl://", "stratum2+tcp://",
	"pool.minexmr.com", "xmrpool.", "moneroocean.",
	"nanopool.org", "f2pool.com", "antpool.com",
	"nicehash.com", "2miners.com",
	"pool.hashvault.pro", "supportxmr.com",
	"mining.hashcryptos.com", "gulf.moneroocean.stream",
}

// checkCryptoMinerInImage detects crypto miner artifacts in image history,
// ENV vars, and Entrypoint/Cmd (IMAGE-009).
func (s *ImageScanner) checkCryptoMinerInImage(inspect *imageInspect, history string) types.Finding {
	ctrl := controlByID("IMAGE-009")

	lowerHistory := strings.ToLower(history)

	// 1. Scan history for miner binary names (catches RUN apt-get install xmrig etc.)
	for _, bin := range minerBinaryNames {
		if strings.Contains(lowerHistory, bin) {
			return fail(ctrl, s.Image,
				fmt.Sprintf("Crypto miner binary %q detected in image build history", bin),
				fmt.Sprintf("docker history --no-trunc output contains: %q", bin),
				ctrl.Remediation)
		}
	}

	// 2. Scan history and ENV for mining pool connection strings
	envStr := strings.ToLower(strings.Join(inspect.Config.Env, " "))
	combined := lowerHistory + " " + envStr
	for _, pool := range minerPoolPatterns {
		if strings.Contains(combined, pool) {
			return fail(ctrl, s.Image,
				fmt.Sprintf("Mining pool connection pattern %q detected in image history/ENV", pool),
				"Pattern found in docker history or container ENV configuration",
				ctrl.Remediation)
		}
	}

	// 3. Scan Entrypoint and Cmd for direct miner invocations
	allCmds := make([]string, 0, len(inspect.Config.Entrypoint)+len(inspect.Config.Cmd))
	allCmds = append(allCmds, inspect.Config.Entrypoint...)
	allCmds = append(allCmds, inspect.Config.Cmd...)
	cmdStr := strings.ToLower(strings.Join(allCmds, " "))
	for _, bin := range minerBinaryNames {
		if strings.Contains(cmdStr, bin) {
			return fail(ctrl, s.Image,
				fmt.Sprintf("Crypto miner %q detected in container Entrypoint/Cmd", bin),
				fmt.Sprintf("Entrypoint: %v  Cmd: %v", inspect.Config.Entrypoint, inspect.Config.Cmd),
				ctrl.Remediation)
		}
	}

	return pass(ctrl, s.Image, "No crypto miner artifacts detected in image configuration")
}
