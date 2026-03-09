package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"https://github.com/kariemoorman/dockeraudit/internal/types"
)

// ── tool detection ───────────────────────────────────────────────────────────

// VulnScannerPref controls which vulnerability scanners are used.
// Accepted values: "trivy", "snyk", "none".
// Default (nil) enables both trivy and snyk.
var VulnScannerPref []string

type toolAvailability struct {
	HasTrivy bool
	HasSnyk  bool
}

func detectVulnTools() toolAvailability {
	// "none" disables all scanners.
	for _, v := range VulnScannerPref {
		if v == "none" {
			return toolAvailability{}
		}
	}

	wantTrivy := true
	wantSnyk := true
	if len(VulnScannerPref) > 0 {
		wantTrivy = false
		wantSnyk = false
		for _, v := range VulnScannerPref {
			switch v {
			case "trivy":
				wantTrivy = true
			case "snyk":
				wantSnyk = true
			}
		}
	}

	avail := toolAvailability{}
	if wantTrivy {
		if _, err := exec.LookPath("trivy"); err == nil {
			avail.HasTrivy = true
		}
	}
	if wantSnyk {
		if _, err := exec.LookPath("snyk"); err == nil {
			avail.HasSnyk = true
		}
	}
	return avail
}

// ── trivy config JSON structures ─────────────────────────────────────────────

type trivyConfigReport struct {
	Results []trivyConfigResult `json:"Results"`
}

type trivyConfigResult struct {
	Target            string                  `json:"Target"`
	Misconfigurations []trivyMisconfiguration `json:"Misconfigurations"`
}

type trivyMisconfiguration struct {
	ID         string `json:"ID"`
	Title      string `json:"Title"`
	Message    string `json:"Message"`
	Severity   string `json:"Severity"`
	Resolution string `json:"Resolution"`
	CauseMeta  struct {
		StartLine int `json:"StartLine"`
	} `json:"CauseMetadata"`
}

// ── snyk container JSON structures ───────────────────────────────────────────

type snykContainerReport struct {
	OK              bool               `json:"ok"`
	Vulnerabilities []snykContainerVuln `json:"vulnerabilities"`
}

type snykContainerVuln struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	PkgName  string `json:"packageName"`
	Version  string `json:"version"`
}

// ── runner functions ─────────────────────────────────────────────────────────

// runTrivyConfig runs `trivy config --format json` on a directory and returns
// parsed findings under the given control.
func runTrivyConfig(ctx context.Context, dir string, ctrl types.Control) []types.Finding {
	cmd := exec.CommandContext(ctx, // #nosec G204 -- fixed executable "trivy"
		"trivy", "config",
		"--format", "json",
		"--exit-code", "0",
		"--severity", "CRITICAL,HIGH,MEDIUM",
		"--quiet",
		dir)

	out, err := cmd.Output()
	if err != nil {
		return []types.Finding{errFinding(ctrl, dir,
			fmt.Sprintf("[trivy] config scan failed: %v", err))}
	}

	var report trivyConfigReport
	if err := json.Unmarshal(out, &report); err != nil {
		return []types.Finding{errFinding(ctrl, dir,
			fmt.Sprintf("[trivy] failed to parse config output: %v", err))}
	}

	findings := trivyConfigToFindings(report, ctrl)
	if len(findings) == 0 {
		return []types.Finding{pass(ctrl, dir, "[trivy] No misconfigurations found")}
	}
	return findings
}

// trivyConfigToFindings converts a trivy config report into Finding objects.
func trivyConfigToFindings(report trivyConfigReport, ctrl types.Control) []types.Finding {
	var findings []types.Finding
	for _, r := range report.Results {
		for _, m := range r.Misconfigurations {
			f := types.Finding{
				Control:     ctrl,
				Status:      types.StatusFail,
				Target:      r.Target,
				Detail:      fmt.Sprintf("[trivy] %s: %s (%s)", m.ID, m.Title, strings.ToUpper(m.Severity)),
				Evidence:    m.Message,
				Remediation: m.Resolution,
				SourceFile:  r.Target,
				SourceLine:  m.CauseMeta.StartLine,
			}
			findings = append(findings, f)
		}
	}
	return findings
}

// runSnykContainer runs `snyk container test --json` on an image and returns
// parsed findings under the given control.
func runSnykContainer(ctx context.Context, image string, ctrl types.Control) []types.Finding {
	cmd := exec.CommandContext(ctx, // #nosec G204 -- fixed executable "snyk"
		"snyk", "container", "test",
		"--json",
		"--severity-threshold=high",
		image)

	out, err := cmd.CombinedOutput() // snyk exits non-zero when vulns found
	if len(out) == 0 {
		if err != nil {
			return []types.Finding{errFinding(ctrl, image,
				fmt.Sprintf("[snyk] container test failed: %v", err))}
		}
		return []types.Finding{errFinding(ctrl, image, "[snyk] container test returned no output")}
	}

	var report snykContainerReport
	if err := json.Unmarshal(out, &report); err != nil {
		msg := string(out)
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return []types.Finding{errFinding(ctrl, image,
			fmt.Sprintf("[snyk] container test returned non-JSON output: %s", strings.TrimSpace(msg)))}
	}

	return snykContainerToFindings(report, ctrl, image)
}

// runSnykDockerfile runs `snyk container test <base-image> --file=<Dockerfile> --json`
// on a Dockerfile. It extracts the base image from the last FROM instruction and
// uses it as the image argument. Returns SKIP if no FROM instruction is found.
func runSnykDockerfile(ctx context.Context, dockerfilePath string, ctrl types.Control) []types.Finding {
	baseImage := lastFROMImage(dockerfilePath)
	if baseImage == "" {
		return []types.Finding{skipped(ctrl, dockerfilePath,
			"[snyk] No FROM instruction found — cannot determine base image for snyk container test")}
	}

	cmd := exec.CommandContext(ctx, // #nosec G204 -- fixed executable "snyk"
		"snyk", "container", "test",
		"--json",
		"--severity-threshold=high",
		"--file="+dockerfilePath,
		baseImage)

	out, err := cmd.CombinedOutput() // snyk exits non-zero when vulns found
	if len(out) == 0 {
		if err != nil {
			return []types.Finding{errFinding(ctrl, dockerfilePath,
				fmt.Sprintf("[snyk] container test failed: %v", err))}
		}
		return []types.Finding{errFinding(ctrl, dockerfilePath, "[snyk] container test returned no output")}
	}

	var report snykContainerReport
	if err := json.Unmarshal(out, &report); err != nil {
		msg := string(out)
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return []types.Finding{errFinding(ctrl, dockerfilePath,
			fmt.Sprintf("[snyk] container test returned non-JSON output: %s", strings.TrimSpace(msg)))}
	}

	return snykContainerToFindings(report, ctrl, dockerfilePath)
}

// lastFROMImage parses a Dockerfile and returns the image reference from the
// last FROM instruction (the final build stage). Returns "" if no FROM found.
func lastFROMImage(dockerfilePath string) string {
	data, err := os.ReadFile(dockerfilePath) // #nosec G304 -- user-supplied path
	if err != nil {
		return ""
	}
	var last string
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "from ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				last = fields[1]
			}
		}
	}
	return last
}

// snykContainerToFindings converts a snyk container report into Finding objects.
func snykContainerToFindings(report snykContainerReport, ctrl types.Control, image string) []types.Finding {
	if report.OK {
		return []types.Finding{pass(ctrl, image, "[snyk] No critical or high vulnerabilities found")}
	}

	var critical, high int
	var details []string
	for _, v := range report.Vulnerabilities {
		switch strings.ToUpper(v.Severity) {
		case "CRITICAL":
			critical++
			details = append(details,
				fmt.Sprintf("CRITICAL %s (%s %s): %s", v.ID, v.PkgName, v.Version, v.Title))
		case "HIGH":
			high++
			details = append(details,
				fmt.Sprintf("HIGH %s (%s %s): %s", v.ID, v.PkgName, v.Version, v.Title))
		}
	}

	if critical == 0 && high == 0 {
		return []types.Finding{pass(ctrl, image, "[snyk] No critical or high vulnerabilities found")}
	}
	summary := fmt.Sprintf("[snyk] %d CRITICAL, %d HIGH vulnerabilities", critical, high)
	return []types.Finding{fail(ctrl, image, summary,
		strings.Join(details, "\n"), ctrl.Remediation)}
}

// ── orchestrator ─────────────────────────────────────────────────────────────

// runIaCVulnScan runs trivy config on directories,
// returning SKIP if trivy is not installed.
func runIaCVulnScan(ctx context.Context, dirs []string, ctrl types.Control) []types.Finding {
	avail := detectVulnTools()
	if !avail.HasTrivy {
		return []types.Finding{skipped(ctrl, strings.Join(dirs, ", "),
			"Trivy not found on PATH — install trivy to enable IaC vulnerability scanning")}
	}

	var findings []types.Finding
	for _, dir := range dirs {
		findings = append(findings, runTrivyConfig(ctx, dir, ctrl)...)
	}

	return findings
}
