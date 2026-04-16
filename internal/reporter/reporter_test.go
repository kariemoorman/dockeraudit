package reporter

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/kariemoorman/dockeraudit/internal/types"
)

// mkResults returns a test ScanResult with a mix of PASS, FAIL, and WARN findings.
func mkResults() []*types.ScanResult {
	r := &types.ScanResult{
		Target:  "test-image:latest",
		Scanner: "image",
		Findings: []types.Finding{
			{
				Control: types.Control{
					ID:       "IMAGE-001",
					Title:    "Digest Pinning",
					Domain:   "Image",
					Severity: types.SeverityHigh,
					Type:     types.ControlPreventive,
					Compliance: types.ComplianceMapping{
						CISDockerSection: "4.7",
						NIST80053:        "CM-6",
						ISO27001:         "A.12.6.1",
						DISACCI:          "CCI-000366",
					},
					Remediation: "Pin images by digest",
				},
				Status: types.StatusFail,
				Target: "test-image:latest",
				Detail: "Image not pinned by digest",
			},
			{
				Control: types.Control{
					ID:       "IMAGE-005",
					Title:    "Non-Root User",
					Severity: types.SeverityMedium,
					Type:     types.ControlPreventive,
				},
				Status: types.StatusPass,
				Target: "test-image:latest",
				Detail: "Image USER is appuser",
			},
			{
				Control: types.Control{
					ID:       "RUNTIME-010",
					Title:    "SSH Daemon",
					Severity: types.SeverityLow,
					Type:     types.ControlDetective,
				},
				Status: types.StatusWarn,
				Target: "test-image:latest",
				Detail: "SSH daemon might be present",
			},
		},
	}
	r.Tally()
	return []*types.ScanResult{r}
}

func TestRenderTable(t *testing.T) {
	var buf bytes.Buffer
	rep := New(FormatTable)
	rep.Output = &buf
	rep.Color = false

	results := mkResults()
	if err := rep.Render(results); err != nil {
		t.Fatalf("renderTable error: %v", err)
	}

	out := buf.String()

	// Must contain header text
	if !strings.Contains(out, "dockerAudit Results") {
		t.Error("table output missing header")
	}
	// Must contain control IDs
	if !strings.Contains(out, "IMAGE-001") {
		t.Error("table output missing IMAGE-001")
	}
	if !strings.Contains(out, "IMAGE-005") {
		t.Error("table output missing IMAGE-005")
	}
	// Must contain summary line
	if !strings.Contains(out, "PASS=1") || !strings.Contains(out, "FAIL=1") {
		t.Error("table output missing summary counts")
	}
	// Must contain remediation section
	if !strings.Contains(out, "FAILED CONTROLS") {
		t.Error("table output missing failed controls section")
	}
}

func TestRenderJSON(t *testing.T) {
	var buf bytes.Buffer
	rep := New(FormatJSON)
	rep.Output = &buf

	results := mkResults()
	if err := rep.Render(results); err != nil {
		t.Fatalf("renderJSON error: %v", err)
	}

	// Must be valid JSON
	var parsed jsonOutput
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("JSON output is not valid JSON: %v", err)
	}

	// Verify structure
	if parsed.GeneratedAt == "" {
		t.Error("JSON output missing generated_at")
	}
	if len(parsed.Results) != 1 {
		t.Errorf("JSON output: expected 1 result, got %d", len(parsed.Results))
	}
	if parsed.TotalFail != 1 {
		t.Errorf("JSON output: total_fail = %d, want 1", parsed.TotalFail)
	}
	if parsed.TotalPass != 1 {
		t.Errorf("JSON output: total_pass = %d, want 1", parsed.TotalPass)
	}
}

func TestRenderMarkdown(t *testing.T) {
	var buf bytes.Buffer
	rep := New(FormatMarkdown)
	rep.Output = &buf

	results := mkResults()
	if err := rep.Render(results); err != nil {
		t.Fatalf("renderMarkdown error: %v", err)
	}

	out := buf.String()

	// Must contain markdown header
	if !strings.Contains(out, "# dockerAudit Report") {
		t.Error("markdown output missing main header")
	}
	// Must contain table headers
	if !strings.Contains(out, "| Status |") {
		t.Error("markdown output missing table header")
	}
	// Must contain control IDs
	if !strings.Contains(out, "IMAGE-001") {
		t.Error("markdown output missing IMAGE-001")
	}
	// Must contain summary
	if !strings.Contains(out, "PASS=1") {
		t.Error("markdown output missing summary")
	}
	// Must contain failed controls section
	if !strings.Contains(out, "## Failed Controls") {
		t.Error("markdown output missing failed controls section")
	}
}

func TestRenderSARIF(t *testing.T) {
	var buf bytes.Buffer
	rep := New(FormatSARIF)
	rep.Output = &buf

	results := mkResults()
	if err := rep.Render(results); err != nil {
		t.Fatalf("renderSARIF error: %v", err)
	}

	// Must be valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v", err)
	}

	// Check SARIF version
	if v, ok := parsed["version"]; !ok || v != "2.1.0" {
		t.Errorf("SARIF version = %v, want 2.1.0", v)
	}

	// Check schema
	if _, ok := parsed["$schema"]; !ok {
		t.Error("SARIF output missing $schema")
	}

	// Check runs
	runs, ok := parsed["runs"].([]interface{})
	if !ok || len(runs) != 1 {
		t.Fatal("SARIF output should have exactly 1 run")
	}

	run := runs[0].(map[string]interface{})
	tool := run["tool"].(map[string]interface{})
	driver := tool["driver"].(map[string]interface{})
	if driver["name"] != "dockeraudit" {
		t.Errorf("SARIF tool name = %v, want dockeraudit", driver["name"])
	}

	// Must have results (FAIL and WARN findings, but not PASS)
	sarifResults := run["results"].([]interface{})
	if len(sarifResults) != 2 { // FAIL + WARN = 2 (PASS is excluded)
		t.Errorf("SARIF results count = %d, want 2 (FAIL + WARN)", len(sarifResults))
	}
}

func TestRenderSARIF_WithLineNumbers(t *testing.T) {
	var buf bytes.Buffer
	rep := New(FormatSARIF)
	rep.Output = &buf

	r := &types.ScanResult{
		Target:  "main.tf",
		Scanner: "terraform",
		Findings: []types.Finding{
			{
				Control: types.Control{
					ID:       "DB-TF-001",
					Title:    "RDS Encryption",
					Severity: types.SeverityHigh,
				},
				Status:     types.StatusFail,
				Target:     "main.tf",
				Detail:     "RDS storage_encrypted = false",
				SourceFile: "infra/main.tf",
				SourceLine: 42,
			},
			{
				Control: types.Control{
					ID:       "IMAGE-001",
					Title:    "Digest Pinning",
					Severity: types.SeverityHigh,
				},
				Status: types.StatusFail,
				Target: "nginx:latest",
				Detail: "Not pinned by digest",
				// No SourceFile/SourceLine — image scanner doesn't have file context
			},
		},
	}
	r.Tally()

	if err := rep.Render([]*types.ScanResult{r}); err != nil {
		t.Fatalf("renderSARIF error: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v", err)
	}

	runs := parsed["runs"].([]interface{})
	run := runs[0].(map[string]interface{})
	sarifResults := run["results"].([]interface{})
	if len(sarifResults) != 2 {
		t.Fatalf("expected 2 SARIF results, got %d", len(sarifResults))
	}

	// First result should have a region with startLine
	r0 := sarifResults[0].(map[string]interface{})
	locs0 := r0["locations"].([]interface{})
	loc0 := locs0[0].(map[string]interface{})
	phys0 := loc0["physicalLocation"].(map[string]interface{})
	art0 := phys0["artifactLocation"].(map[string]interface{})
	if art0["uri"] != "infra/main.tf" {
		t.Errorf("first result URI = %v, want infra/main.tf", art0["uri"])
	}
	region0, ok := phys0["region"].(map[string]interface{})
	if !ok {
		t.Fatal("first result should have a region with startLine")
	}
	if region0["startLine"] != float64(42) {
		t.Errorf("first result startLine = %v, want 42", region0["startLine"])
	}

	// Second result should NOT have a region (no source line)
	r1 := sarifResults[1].(map[string]interface{})
	locs1 := r1["locations"].([]interface{})
	loc1 := locs1[0].(map[string]interface{})
	phys1 := loc1["physicalLocation"].(map[string]interface{})
	if _, hasRegion := phys1["region"]; hasRegion {
		t.Error("second result should NOT have a region (no source line)")
	}
}

func TestRenderJUnit(t *testing.T) {
	var buf bytes.Buffer
	rep := New(FormatJUnit)
	rep.Output = &buf

	results := mkResults()
	if err := rep.Render(results); err != nil {
		t.Fatalf("renderJUnit error: %v", err)
	}

	out := buf.String()

	// Must be valid XML
	if !strings.Contains(out, "<?xml") {
		t.Error("JUnit output missing XML header")
	}
	if !strings.Contains(out, "<testsuites") {
		t.Error("JUnit output missing testsuites element")
	}
	if !strings.Contains(out, "<testsuite") {
		t.Error("JUnit output missing testsuite element")
	}
	if !strings.Contains(out, "<testcase") {
		t.Error("JUnit output missing testcase element")
	}
	// FAIL finding should have a failure element
	if !strings.Contains(out, "<failure") {
		t.Error("JUnit output missing failure element for failed check")
	}
	// Must contain control IDs
	if !strings.Contains(out, "IMAGE-001") {
		t.Error("JUnit output missing IMAGE-001")
	}
	if !strings.Contains(out, "IMAGE-005") {
		t.Error("JUnit output missing IMAGE-005")
	}

	// Verify it's valid XML by parsing
	type testsuites struct {
		Name   string `xml:"name,attr"`
		Suites []struct {
			Name  string `xml:"name,attr"`
			Tests int    `xml:"tests,attr"`
			Cases []struct {
				Name string `xml:"name,attr"`
			} `xml:"testcase"`
		} `xml:"testsuite"`
	}
	var parsed testsuites
	if err := xml.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("JUnit output is not valid XML: %v", err)
	}
	if len(parsed.Suites) != 1 {
		t.Errorf("expected 1 test suite, got %d", len(parsed.Suites))
	}
	if parsed.Suites[0].Tests != 3 {
		t.Errorf("expected 3 test cases, got %d", parsed.Suites[0].Tests)
	}
}

func TestRenderTable_EmptyResults(t *testing.T) {
	var buf bytes.Buffer
	rep := New(FormatTable)
	rep.Output = &buf
	rep.Color = false

	if err := rep.Render(nil); err != nil {
		t.Fatalf("renderTable error with nil results: %v", err)
	}

	if !strings.Contains(buf.String(), "dockerAudit Results") {
		t.Error("table output missing header with nil results")
	}
}

func TestRenderJSON_EmptyResults(t *testing.T) {
	var buf bytes.Buffer
	rep := New(FormatJSON)
	rep.Output = &buf

	if err := rep.Render(nil); err != nil {
		t.Fatalf("renderJSON error with nil results: %v", err)
	}

	var parsed jsonOutput
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("JSON output is not valid JSON: %v", err)
	}
}

// TestRenderTable_ColumnAlignment verifies that STATUS, SEVERITY, and CONTROL ID
// columns start at exactly the same byte offset in every data row as they do in
// the header, regardless of which status/severity value is present in that row.
func TestRenderTable_RemediationSectionHiddenWhenNoFails(t *testing.T) {
	// Result with a WARN finding but no failures: the FAILED CONTROLS
	// section must not appear, but the WARNINGS section should, so that
	// advisory findings still carry their detail block.
	r := &types.ScanResult{
		Target:  "clean-image",
		Scanner: "image",
		Findings: []types.Finding{
			{Control: types.Control{ID: "IMAGE-005", Severity: types.SeverityMedium}, Status: types.StatusPass, Detail: "all good"},
			{Control: types.Control{ID: "RUNTIME-010", Severity: types.SeverityLow}, Status: types.StatusWarn, Detail: "minor warning"},
		},
	}
	r.Tally()

	var buf bytes.Buffer
	rep := New(FormatTable)
	rep.Output = &buf
	rep.Color = false

	if err := rep.Render([]*types.ScanResult{r}); err != nil {
		t.Fatalf("renderTable error: %v", err)
	}

	out := buf.String()
	if strings.Contains(out, "FAILED CONTROLS") {
		t.Error("FAILED CONTROLS section should not appear when FAIL=0")
	}
	if !strings.Contains(out, "WARNINGS — REMEDIATION") {
		t.Error("WARNINGS — REMEDIATION section should appear when WARN>0")
	}
	// Summary must still appear
	if !strings.Contains(out, "FAIL=0") {
		t.Error("summary line missing")
	}
}

// TestRenderTable_NoRemediationSectionsWhenAllPass verifies that a scan with
// only PASS findings emits neither the FAILED CONTROLS nor the WARNINGS
// detail block.
func TestRenderTable_NoRemediationSectionsWhenAllPass(t *testing.T) {
	r := &types.ScanResult{
		Target:  "clean-image",
		Scanner: "image",
		Findings: []types.Finding{
			{Control: types.Control{ID: "IMAGE-005", Severity: types.SeverityMedium}, Status: types.StatusPass, Detail: "all good"},
		},
	}
	r.Tally()

	var buf bytes.Buffer
	rep := New(FormatTable)
	rep.Output = &buf
	rep.Color = false

	if err := rep.Render([]*types.ScanResult{r}); err != nil {
		t.Fatalf("renderTable error: %v", err)
	}

	out := buf.String()
	if strings.Contains(out, "FAILED CONTROLS") {
		t.Error("FAILED CONTROLS section should not appear when FAIL=0")
	}
	if strings.Contains(out, "WARNINGS") {
		t.Error("WARNINGS section should not appear when WARN=0")
	}
}

func TestRenderTable_RemediationSectionPresentWhenFailsExist(t *testing.T) {
	results := mkResults() // contains one FAIL finding
	var buf bytes.Buffer
	rep := New(FormatTable)
	rep.Output = &buf
	rep.Color = false

	if err := rep.Render(results); err != nil {
		t.Fatalf("renderTable error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "FAILED CONTROLS") {
		t.Error("FAILED CONTROLS section should appear when FAIL > 0")
	}
}

func TestRenderTable_ColumnAlignment(t *testing.T) {
	// Findings covering all status lengths (FAIL=4, WARN=4, PASS=4, ERROR=5)
	// and all severity lengths (CRITICAL=8, HIGH=4, MEDIUM=6, LOW=3).
	r := &types.ScanResult{
		Target:  "align-test",
		Scanner: "test",
		Findings: []types.Finding{
			{Control: types.Control{ID: "IMAGE-001", Severity: types.SeverityCritical, Type: types.ControlPreventive}, Status: types.StatusFail, Target: "img:latest", Detail: "fail critical"},
			{Control: types.Control{ID: "RUNTIME-010", Severity: types.SeverityHigh, Type: types.ControlDetective}, Status: types.StatusWarn, Target: "ctr", Detail: "warn high"},
			{Control: types.Control{ID: "K8S-001", Severity: types.SeverityMedium, Type: types.ControlPreventive}, Status: types.StatusPass, Target: "pod", Detail: "pass medium"},
			{Control: types.Control{ID: "IMAGE-005", Severity: types.SeverityLow, Type: types.ControlPreventive}, Status: types.StatusPass, Target: "img", Detail: "pass low"},
		},
	}
	r.Tally()

	var buf bytes.Buffer
	rep := New(FormatTable)
	rep.Output = &buf
	rep.Color = false // no ANSI bytes — byte offsets == visual offsets

	if err := rep.Render([]*types.ScanResult{r}); err != nil {
		t.Fatalf("renderTable error: %v", err)
	}

	lines := strings.Split(buf.String(), "\n")

	// Locate the header line ("STATUS  SEVERITY  ...").
	headerIdx := -1
	for i, line := range lines {
		if strings.HasPrefix(line, "STATUS") {
			headerIdx = i
			break
		}
	}
	if headerIdx < 0 {
		t.Fatal("could not find header line in table output")
	}
	headerLine := lines[headerIdx]

	// Derive expected column offsets from the header itself.
	sevOffset  := strings.Index(headerLine, "SEVERITY")
	idOffset   := strings.Index(headerLine, "CONTROL ID")
	typeOffset := strings.Index(headerLine, "TYPE")
	if sevOffset < 0 || idOffset < 0 || typeOffset < 0 {
		t.Fatalf("could not locate all column headers in: %q", headerLine)
	}

	// Collect data lines: they follow the separator line (headerIdx+1) until a
	// blank line or a summary/divider line.
	var dataLines []string
	for _, line := range lines[headerIdx+2:] {
		if line == "" || strings.HasPrefix(line, "─") || strings.HasPrefix(line, "Summary") {
			break
		}
		dataLines = append(dataLines, line)
	}
	if len(dataLines) == 0 {
		t.Fatal("no data lines found after header")
	}

	for _, line := range dataLines {
		// Every data line must be long enough to reach SEVERITY and CONTROL ID.
		if len(line) <= sevOffset {
			t.Errorf("data line too short to reach SEVERITY column (len=%d): %q", len(line), line)
			continue
		}
		if line[sevOffset] == ' ' {
			t.Errorf("SEVERITY column misaligned (expected non-space at offset %d): %q", sevOffset, line)
		}
		if len(line) <= idOffset {
			t.Errorf("data line too short to reach CONTROL ID column (len=%d): %q", len(line), line)
			continue
		}
		if line[idOffset] == ' ' {
			t.Errorf("CONTROL ID column misaligned (expected non-space at offset %d): %q", idOffset, line)
		}
		if len(line) <= typeOffset {
			t.Errorf("data line too short to reach TYPE column (len=%d): %q", len(line), line)
			continue
		}
		if line[typeOffset] == ' ' {
			t.Errorf("TYPE column misaligned (expected non-space at offset %d): %q", typeOffset, line)
		}
	}
}

func TestPadRight(t *testing.T) {
	tests := []struct {
		s          string
		visibleLen int
		width      int
		wantSuffix string
		wantLen    int
	}{
		{"FAIL", 4, 6, "  ", 6},
		{"CRITICAL", 8, 8, "", 8},
		{"HIGH", 4, 8, "    ", 8},
		{"PASS", 4, 6, "  ", 6},
		// visibleLen >= width: no padding added
		{"TOOLONG", 7, 5, "", 7},
	}
	for _, tc := range tests {
		got := padRight(tc.s, tc.visibleLen, tc.width)
		if !strings.HasSuffix(got, tc.wantSuffix) || len(got) != tc.wantLen {
			t.Errorf("padRight(%q, %d, %d) = %q (len %d), want suffix %q and len %d",
				tc.s, tc.visibleLen, tc.width, got, len(got), tc.wantSuffix, tc.wantLen)
		}
	}
}

func TestColorStatus(t *testing.T) {
	rep := &Reporter{Color: true}
	noColor := &Reporter{Color: false}

	// Color enabled: must contain ANSI escape codes
	colored := rep.colorStatus(types.StatusFail)
	if !strings.Contains(colored, "\033[") {
		t.Error("colorStatus(FAIL) with Color=true should contain ANSI codes")
	}

	// Color disabled: must be plain text
	plain := noColor.colorStatus(types.StatusFail)
	if plain != "FAIL" {
		t.Errorf("colorStatus(FAIL) with Color=false = %q, want %q", plain, "FAIL")
	}
}
