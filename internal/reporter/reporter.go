package reporter

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/kariemoorman/dockeraudit/internal/types"
)

// Column widths in visible (printable) characters.
const (
	colStatus   = 6  // "STATUS"=6; display labels: FAIL=4, WARN=4, PASS=4, SKIP=4, ERROR=5 (StatusSkipped stored as "SKIPPED", displayed as "SKIP")
	colSeverity = 8  // "SEVERITY"=8; values: CRITICAL=8, HIGH=4, MEDIUM=6, LOW=3
	colID       = 12 // "CONTROL ID"=10; longest IDs ~11 chars (e.g. "RUNTIME-011")
	colType     = 13 // "TYPE"=4; values: Preventive=10, Detective=9, Corrective=10
	colTarget   = 40 // "TARGET"
	colDetail   = 60 // "DETAIL"
)

// Format determines the output format
type Format string

const (
	FormatTable    Format = "table"
	FormatJSON     Format = "json"
	FormatMarkdown Format = "markdown"
	FormatSARIF    Format = "sarif"
	FormatJUnit    Format = "junit"

	sarifVersion = "2.1.0"
	sarifSchema  = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)

// Reporter renders scan results.
type Reporter struct {
	Format  Format
	Output  io.Writer
	Color   bool
	Version string // build version injected from main; used in SARIF output
}

func New(format Format) *Reporter {
	return &Reporter{
		Format: format,
		Output: os.Stdout,
		Color:  true,
	}
}

// Render writes results to the configured output.
func (r *Reporter) Render(results []*types.ScanResult) error {
	switch r.Format {
	case FormatJSON:
		return r.renderJSON(results)
	case FormatMarkdown:
		return r.renderMarkdown(results)
	case FormatSARIF:
		return r.renderSARIF(results)
	case FormatJUnit:
		return r.renderJUnit(results)
	default:
		return r.renderTable(results)
	}
}

// ── Table ─────────────────────────────────────────────────────────────────────
//nolint:errcheck // writing to output stream; broken pipe not recoverable in reporter context
func (r *Reporter) renderTable(results []*types.ScanResult) error {
	out := r.Output

	// Pre-compute reusable structural chrome (all blue when color is enabled).
	divider    := r.blue(strings.Repeat("─", 150))
	doubleLine := r.blue(strings.Repeat("═", 150))

	// Header: each column title is blue+underlined and padded with padRight so that
	// ANSI bytes do not inflate the visible width (same technique as data rows).
	hStatus   := padRight(r.boldBlue("STATUS"),     len("STATUS"),     colStatus)
	hSeverity := padRight(r.boldBlue("SEVERITY"),   len("SEVERITY"),   colSeverity)
	hID       := padRight(r.boldBlue("CONTROL ID"), len("CONTROL ID"), colID)
	hType     := padRight(r.boldBlue("TYPE"),       len("TYPE"),       colType)
	hTarget   := padRight(r.boldBlue("TARGET"),     len("TARGET"),     colTarget)
	hDetail   := r.boldBlue("DETAIL")
	header    := strings.Join([]string{hStatus, hSeverity, hID, hType, hTarget, hDetail}, "  ")

	// Separator: pure ASCII content so wrapping the whole string in blue is safe —
	// no per-column width correction needed.
	sep := r.blue(strings.Join([]string{
		strings.Repeat("-", colStatus),
		strings.Repeat("-", colSeverity),
		strings.Repeat("-", colID),
		strings.Repeat("-", colType),
		strings.Repeat("-", colTarget),
		strings.Repeat("-", colDetail),
	}, "  "))

	fmt.Fprintln(out)
	fmt.Fprintln(out, r.blue("dockerAudit Results"))
	fmt.Fprintf(out, "%s%s\n", r.blue("Generated: "), time.Now().Format(time.RFC1123))
	fmt.Fprintln(out, divider)

	for _, result := range results {
		fmt.Fprintf(out, "\n%s%s  %s%s\n",
			r.blue("Scanner: "), result.Scanner,
			r.blue("Target: "), result.Target)
		fmt.Fprintln(out, divider)
		fmt.Fprintln(out)
		fmt.Fprintln(out, header)
		fmt.Fprintln(out, sep)

		for _, f := range result.Findings {
			statusStr   := r.colorStatus(f.Status)
			severityStr := r.colorSeverity(f.Control.Severity)

			// padRight appends spaces outside ANSI codes so terminal width is correct.
			// Use statusText() for visible length: "SKIPPED" is stored internally but
			// displayed as "SKIP" so the STATUS column stays at colStatus width.
			statusVis   := len(statusText(f.Status))
			severityVis := len(string(f.Control.Severity))

			id     := truncate(f.Control.ID, colID)
			typ    := truncate(string(f.Control.Type), colType)
			target := truncate(f.Target, colTarget)
			detail := truncate(f.Detail, colDetail)

			// Non-colored columns (id, typ, target) are pure ASCII so %-*s is correct.
			fmt.Fprintf(out, "%s  %s  %-*s  %-*s  %-*s  %s\n",
				padRight(statusStr, statusVis, colStatus),
				padRight(severityStr, severityVis, colSeverity),
				colID, id,
				colType, typ,
				colTarget, target,
				detail,
			)
		}

		fmt.Fprintln(out)
		fmt.Fprintln(out, divider)

		// Summary line: each count colored by its meaning.
		summary := strings.Join([]string{
			r.blue("Summary:"),
			r.colorCount("PASS",  result.Pass,     "\033[32m"),
			r.colorCount("FAIL",  result.Fail,     "\033[31m"),
			r.colorCount("WARN",  result.Warn,     "\033[33m"),
			r.colorCount("SKIP",  result.Skipped,  "\033[90m"),
			r.colorCount("ERROR", result.Error,    "\033[35m"),
			r.blue("|"),
			r.colorCount("CRITICAL", result.Critical, "\033[31;1m"),
			r.colorCount("HIGH",     result.High,     "\033[31m"),
			r.colorCount("MEDIUM",   result.Medium,   "\033[38;5;208m"),
			r.colorCount("LOW",      result.Low,      "\033[36m"),
		}, "  ")
		fmt.Fprintln(out, summary)
	}

	fmt.Fprintln(out)

	// Print failures and remediations only when at least one FAIL exists.
	totalFail := 0
	totalWarn := 0
	for _, result := range results {
		totalFail += result.Fail
		totalWarn += result.Warn
	}
	if totalFail > 0 {
		fmt.Fprintln(out, doubleLine)
		fmt.Fprintln(out, r.boldBlue("FAILED CONTROLS — REMEDIATION"))
		fmt.Fprintln(out, doubleLine)

		for _, result := range results {
			for _, f := range result.Findings {
				if f.Status != types.StatusFail {
					continue
				}
				r.writeFindingDetail(out, f)
			}
		}
		fmt.Fprintln(out)
	}

	// Print warnings with the same detail block so advisory findings are
	// actionable in the same report.
	if totalWarn > 0 {
		fmt.Fprintln(out, doubleLine)
		fmt.Fprintln(out, r.boldBlue("WARNINGS — REMEDIATION"))
		fmt.Fprintln(out, doubleLine)

		for _, result := range results {
			for _, f := range result.Findings {
				if f.Status != types.StatusWarn {
					continue
				}
				r.writeFindingDetail(out, f)
			}
		}
		fmt.Fprintln(out)
	}

	return nil
}

// writeFindingDetail prints the indented detail block (title line + Detail /
// Evidence / Remediation / Compliance) shared by the FAILED CONTROLS and
// WARNINGS sections of the table renderer.
func (r *Reporter) writeFindingDetail(out io.Writer, f types.Finding) {
	fmt.Fprintln(out)
	fmt.Fprintln(out, r.blue(fmt.Sprintf("[%s] %s — %s", f.Control.ID, f.Control.Title, f.Target)))
	fmt.Fprintf(out, "%s%s\n", r.blue("  Detail:      "), f.Detail)
	if f.Evidence != "" {
		fmt.Fprintf(out, "%s%s\n", r.blue("  Evidence:    "), truncate(f.Evidence, 200))
	}
	rem := f.Remediation
	if rem == "" {
		rem = f.Control.Remediation
	}
	if rem != "" {
		fmt.Fprintf(out, "%s%s\n", r.blue("  Remediation: "), rem)
	}
	compliance := fmt.Sprintf("CIS %s | NIST 800-53: %s | ISO 27001: %s | DISA: %s",
		f.Control.Compliance.CISDockerSection,
		f.Control.Compliance.NIST80053,
		f.Control.Compliance.ISO27001,
		f.Control.Compliance.DISACCI)
	fmt.Fprintf(out, "%s%s\n", r.blue("  Compliance:  "), compliance)
}

// ── JSON ──────────────────────────────────────────────────────────────────────

type jsonOutput struct {
	GeneratedAt string               `json:"generated_at"`
	Results     []*types.ScanResult  `json:"results"`
	TotalFail   int                  `json:"total_fail"`
	TotalPass   int                  `json:"total_pass"`
	TotalCritical int                `json:"total_critical"`
	TotalHigh     int                `json:"total_high"`
}

func (r *Reporter) renderJSON(results []*types.ScanResult) error {
	out := jsonOutput{
		GeneratedAt: time.Now().Format(time.RFC3339),
		Results:     results,
	}
	for _, res := range results {
		out.TotalFail += res.Fail
		out.TotalPass += res.Pass
		out.TotalCritical += res.Critical
		out.TotalHigh += res.High
	}
	enc := json.NewEncoder(r.Output)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// ── Markdown ──────────────────────────────────────────────────────────────────
//nolint:errcheck // writing to output stream; broken pipe not recoverable in reporter context
func (r *Reporter) renderMarkdown(results []*types.ScanResult) error {
	fmt.Fprintf(r.Output, "# dockerAudit Report\n\n")
	fmt.Fprintf(r.Output, "Generated: %s\n\n", time.Now().Format(time.RFC1123))

	for _, result := range results {
		fmt.Fprintf(r.Output, "## Scanner: `%s` — Target: `%s`\n\n", result.Scanner, result.Target)
		fmt.Fprintf(r.Output, "| Status | Severity | Control ID | Type | Target | Title | Detail |\n")
		fmt.Fprintf(r.Output, "|--------|----------|------------|------|--------|-------|--------|\n")

		for _, f := range result.Findings {
			fmt.Fprintf(r.Output, "| %s | %s | %s | %s | %s | %s | %s |\n",
				statusText(f.Status), f.Control.Severity, f.Control.ID,
				f.Control.Type, mdEscape(f.Target),
				f.Control.Title, mdEscape(truncate(f.Detail, 80)))
		}
		fmt.Fprintf(r.Output, "\n**Summary:** PASS=%d FAIL=%d WARN=%d SKIP=%d | Critical=%d High=%d Medium=%d Low=%d\n\n",
			result.Pass, result.Fail, result.Warn, result.Skipped, result.Critical, result.High, result.Medium, result.Low)
	}

	// Failed controls
	if r.hasStatus(results, types.StatusFail) {
		fmt.Fprintf(r.Output, "## Failed Controls\n\n")
		r.writeMarkdownFindings(results, types.StatusFail)
	}

	// Warnings — same detail block as failures so advisory findings are
	// actionable in the same report.
	if r.hasStatus(results, types.StatusWarn) {
		fmt.Fprintf(r.Output, "## Warnings\n\n")
		r.writeMarkdownFindings(results, types.StatusWarn)
	}
	return nil
}

// hasStatus reports whether any finding in results has the given status.
func (r *Reporter) hasStatus(results []*types.ScanResult, status types.Status) bool {
	for _, result := range results {
		for _, f := range result.Findings {
			if f.Status == status {
				return true
			}
		}
	}
	return false
}

// writeMarkdownFindings emits a markdown detail block for every finding in
// results that matches the given status.
func (r *Reporter) writeMarkdownFindings(results []*types.ScanResult, status types.Status) {
	for _, result := range results {
		for _, f := range result.Findings {
			if f.Status != status {
				continue
			}
			fmt.Fprintf(r.Output, "### %s — %s\n\n", f.Control.ID, f.Control.Title)
			fmt.Fprintf(r.Output, "- **Target:** `%s`\n", f.Target)
			fmt.Fprintf(r.Output, "- **Severity:** %s\n", f.Control.Severity)
			fmt.Fprintf(r.Output, "- **Detail:** %s\n", f.Detail)
			if f.Evidence != "" {
				fmt.Fprintf(r.Output, "- **Evidence:** %s\n", f.Evidence)
			}
			rem := f.Remediation
			if rem == "" {
				rem = f.Control.Remediation
			}
			if rem != "" {
				fmt.Fprintf(r.Output, "- **Remediation:** %s\n", rem)
			}
			fmt.Fprintf(r.Output, "- **CIS:** %s | **NIST 800-53:** %s | **ISO 27001:** %s | **DISA CCI:** %s\n\n",
				f.Control.Compliance.CISDockerSection,
				f.Control.Compliance.NIST80053,
				f.Control.Compliance.ISO27001,
				f.Control.Compliance.DISACCI)
		}
	}
}

// ── SARIF ─────────────────────────────────────────────────────────────────────

// renderSARIF produces a minimal SARIF 2.1.0 output compatible with GitHub Code Scanning.
func (r *Reporter) renderSARIF(results []*types.ScanResult) error {
	type sarifMessage struct {
		Text string `json:"text"`
	}
	type sarifRule struct {
		ID               string       `json:"id"`
		Name             string       `json:"name"`
		ShortDescription sarifMessage `json:"shortDescription"`
		FullDescription  sarifMessage `json:"fullDescription"`
	}
	type sarifRegion struct {
		StartLine int `json:"startLine"`
	}
	type sarifPhysicalLocation struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
		Region *sarifRegion `json:"region,omitempty"`
	}
	type sarifLocation struct {
		PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
	}
	type sarifResult struct {
		RuleID    string          `json:"ruleId"`
		Level     string          `json:"level"`
		Message   sarifMessage    `json:"message"`
		Locations []sarifLocation `json:"locations"`
	}
	type sarifRun struct {
		Tool struct {
			Driver struct {
				Name    string      `json:"name"`
				Version string      `json:"version"`
				Rules   []sarifRule `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []sarifResult `json:"results"`
	}
	type sarif struct {
		Version string     `json:"version"`
		Schema  string     `json:"$schema"`
		Runs    []sarifRun `json:"runs"`
	}

	run := sarifRun{}
	run.Tool.Driver.Name = "dockeraudit"
	run.Tool.Driver.Version = r.Version
	if run.Tool.Driver.Version == "" {
		run.Tool.Driver.Version = "dev"
	}

	rulesSeen := map[string]bool{}

	for _, result := range results {
		for _, f := range result.Findings {
			if f.Status == types.StatusPass || f.Status == types.StatusSkipped {
				continue
			}
			if !rulesSeen[f.Control.ID] {
				run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, sarifRule{
					ID:               f.Control.ID,
					Name:             f.Control.Title,
					ShortDescription: sarifMessage{Text: f.Control.Description},
					FullDescription:  sarifMessage{Text: f.Control.Remediation},
				})
				rulesSeen[f.Control.ID] = true
			}

			level := "warning"
			switch f.Control.Severity {
			case types.SeverityCritical, types.SeverityHigh:
				level = "error"
			case types.SeverityLow, types.SeverityInformation:
				level = "note"
			}

			var loc sarifLocation
			uri := f.Target
			if f.SourceFile != "" {
				uri = f.SourceFile
			}
			loc.PhysicalLocation.ArtifactLocation.URI = uri
			if f.SourceLine > 0 {
				loc.PhysicalLocation.Region = &sarifRegion{StartLine: f.SourceLine}
			}
			locs := []sarifLocation{loc}

			run.Results = append(run.Results, sarifResult{
				RuleID:    f.Control.ID,
				Level:     level,
				Message:   sarifMessage{Text: f.Detail},
				Locations: locs,
			})
		}
	}

	output := sarif{
		Version: sarifVersion,
		Schema:  sarifSchema,
		Runs:    []sarifRun{run},
	}

	enc := json.NewEncoder(r.Output)
	enc.SetIndent("", "  ")
	return enc.Encode(output)
}

// ── JUnit XML ─────────────────────────────────────────────────────────────────

// renderJUnit produces a JUnit XML output compatible with CI/CD systems.
func (r *Reporter) renderJUnit(results []*types.ScanResult) error {
	type junitFailure struct {
		XMLName xml.Name `xml:"failure"`
		Message string   `xml:"message,attr"`
		Type    string   `xml:"type,attr"`
		Content string   `xml:",chardata"`
	}
	type junitTestCase struct {
		XMLName   xml.Name      `xml:"testcase"`
		Name      string        `xml:"name,attr"`
		ClassName string        `xml:"classname,attr"`
		Time      string        `xml:"time,attr"`
		Failure   *junitFailure `xml:"failure,omitempty"`
		Skipped   *struct{}     `xml:"skipped,omitempty"`
	}
	type junitTestSuite struct {
		XMLName  xml.Name        `xml:"testsuite"`
		Name     string          `xml:"name,attr"`
		Tests    int             `xml:"tests,attr"`
		Failures int             `xml:"failures,attr"`
		Errors   int             `xml:"errors,attr"`
		Skipped  int             `xml:"skipped,attr"`
		Time     string          `xml:"time,attr"`
		Cases    []junitTestCase `xml:"testcase"`
	}
	type junitTestSuites struct {
		XMLName xml.Name         `xml:"testsuites"`
		Name    string           `xml:"name,attr"`
		Suites  []junitTestSuite `xml:"testsuite"`
	}

	var suites []junitTestSuite

	for _, result := range results {
		suite := junitTestSuite{
			Name:     fmt.Sprintf("dockeraudit-%s-%s", result.Scanner, result.Target),
			Tests:    len(result.Findings),
			Failures: result.Fail,
			Errors:   result.Error,
			Skipped:  result.Skipped,
			Time:     "0",
		}

		for _, f := range result.Findings {
			tc := junitTestCase{
				Name:      fmt.Sprintf("[%s] %s", f.Control.ID, f.Control.Title),
				ClassName: fmt.Sprintf("dockeraudit.%s.%s", result.Scanner, f.Target),
				Time:      "0",
			}

			switch f.Status {
			case types.StatusFail:
				tc.Failure = &junitFailure{
					Message: f.Detail,
					Type:    string(f.Control.Severity),
					Content: f.Evidence,
				}
			case types.StatusWarn:
				tc.Failure = &junitFailure{
					Message: f.Detail,
					Type:    "WARNING",
					Content: f.Evidence,
				}
			case types.StatusError:
				tc.Failure = &junitFailure{
					Message: f.Detail,
					Type:    "ERROR",
					Content: f.Evidence,
				}
			case types.StatusSkipped:
				tc.Skipped = &struct{}{}
			}

			suite.Cases = append(suite.Cases, tc)
		}

		suites = append(suites, suite)
	}

	output := junitTestSuites{
		Name:   "dockeraudit",
		Suites: suites,
	}

	if _, err := fmt.Fprint(r.Output, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(r.Output)
	enc.Indent("", "  ")
	if err := enc.Encode(output); err != nil {
		return err
	}
	_, err := fmt.Fprintln(r.Output)
	return err
}

// ── helpers ───────────────────────────────────────────────────────────────────

// ansiWrap wraps text with ANSI color codes.
func ansiWrap(code, text, reset string) string {
	return code + text + reset
}

// padRight pads a (possibly ANSI-colored) string to a given visible column width.
// visibleLen is the number of printable characters in s (excluding ANSI escape bytes).
// width is the desired column width in printable characters.
// Trailing spaces are appended OUTSIDE any ANSI escape codes so the terminal
// renders the correct width and the next column starts at the right offset.
func padRight(s string, visibleLen, width int) string {
	if visibleLen >= width {
		return s
	}
	return s + strings.Repeat(" ", width-visibleLen)
}

// statusText returns the fixed-width label shown in the table for each status.
// "SKIPPED" is the canonical JSON field value but renders as "SKIP" in the table
// so the STATUS column stays at colStatus width.
func statusText(s types.Status) string {
	if s == types.StatusSkipped {
		return "SKIP"
	}
	return string(s)
}

func (r *Reporter) colorStatus(s types.Status) string {
	text := statusText(s)
	if !r.Color {
		return text
	}
	switch s {
	case types.StatusPass:
		return ansiWrap("\033[32m", text, "\033[0m")
	case types.StatusFail:
		return ansiWrap("\033[31m", text, "\033[0m")
	case types.StatusWarn:
		return ansiWrap("\033[33m", text, "\033[0m")
	case types.StatusSkipped:
		return ansiWrap("\033[90m", text, "\033[0m")
	case types.StatusError:
		return ansiWrap("\033[35m", text, "\033[0m")
	}
	return text
}

func (r *Reporter) colorSeverity(sev types.Severity) string {
	if !r.Color {
		return string(sev)
	}
	switch sev {
	case types.SeverityCritical:
		return ansiWrap("\033[31;1m", "CRITICAL", "\033[0m")
	case types.SeverityHigh:
		return ansiWrap("\033[31m", "HIGH", "\033[0m")
	case types.SeverityMedium:
		return ansiWrap("\033[1;38;5;208m", "MEDIUM", "\033[0m")
	case types.SeverityLow:
		return ansiWrap("\033[36m", "LOW", "\033[0m")
	case types.SeverityInformation:
		return ansiWrap("\033[90m", "INFO", "\033[0m")
	}
	return string(sev)
}

// blue renders s in blue, or returns s unchanged when color is disabled.
func (r *Reporter) blue(s string) string {
	if !r.Color {
		return s
	}
	return ansiWrap("\033[34m", s, "\033[0m")
}

// boldBlue renders s in bold blue (used for section headings).
func (r *Reporter) boldBlue(s string) string {
	if !r.Color {
		return s
	}
	return ansiWrap("\033[34;1m", s, "\033[0m")
}

// blueUnderline renders s in blue with an underline (used for column headers).
// func (r *Reporter) blueUnderline(s string) string {
// 	if !r.Color {
// 		return s
// 	}
// 	return ansiWrap("\033[34;4m", s, "\033[0m")
// }

// colorCount formats "Label=N" and applies the given ANSI color code to the
// whole string. When color is disabled it returns the plain label=value string.
func (r *Reporter) colorCount(label string, n int, code string) string {
	s := fmt.Sprintf("%s=%d", label, n)
	if !r.Color {
		return s
	}
	return ansiWrap(code, s, "\033[0m")
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

// mdEscape escapes characters that break Markdown table cells.
func mdEscape(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "|", `\|`)
	return s
}

// ExitCode returns a non-zero exit code if any critical or high failures exist.
func ExitCode(results []*types.ScanResult) int {
	for _, r := range results {
		if r.Critical > 0 || r.High > 0 {
			return 1
		}
	}
	return 0
}
