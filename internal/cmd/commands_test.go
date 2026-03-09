package cmd

import (
	"testing"

	"github.com/kariemoorman/dockeraudit/internal/types"
)

func TestComputeExitCode(t *testing.T) {
	mkResult := func(critical, high, medium, low, pass int) *types.ScanResult {
		r := &types.ScanResult{}
		for i := 0; i < critical; i++ {
			r.Findings = append(r.Findings, types.Finding{
				Status:  types.StatusFail,
				Control: types.Control{Severity: types.SeverityCritical},
			})
		}
		for i := 0; i < high; i++ {
			r.Findings = append(r.Findings, types.Finding{
				Status:  types.StatusFail,
				Control: types.Control{Severity: types.SeverityHigh},
			})
		}
		for i := 0; i < medium; i++ {
			r.Findings = append(r.Findings, types.Finding{
				Status:  types.StatusFail,
				Control: types.Control{Severity: types.SeverityMedium},
			})
		}
		for i := 0; i < low; i++ {
			r.Findings = append(r.Findings, types.Finding{
				Status:  types.StatusFail,
				Control: types.Control{Severity: types.SeverityLow},
			})
		}
		for i := 0; i < pass; i++ {
			r.Findings = append(r.Findings, types.Finding{
				Status: types.StatusPass,
			})
		}
		r.Tally()
		return r
	}

	tests := []struct {
		name    string
		results []*types.ScanResult
		failOn  string
		want    int
	}{
		// ── critical threshold ──────────────────────────────
		{"critical threshold: no findings", []*types.ScanResult{mkResult(0, 0, 0, 0, 5)}, "critical", 0},
		{"critical threshold: only high", []*types.ScanResult{mkResult(0, 3, 0, 0, 2)}, "critical", 0},
		{"critical threshold: has critical", []*types.ScanResult{mkResult(1, 0, 0, 0, 5)}, "critical", 1},

		// ── high threshold ─────────────────────────────────
		{"high threshold: no high or critical", []*types.ScanResult{mkResult(0, 0, 2, 1, 5)}, "high", 0},
		{"high threshold: has high", []*types.ScanResult{mkResult(0, 1, 0, 0, 5)}, "high", 1},
		{"high threshold: has critical", []*types.ScanResult{mkResult(1, 0, 0, 0, 5)}, "high", 1},

		// ── medium threshold ───────────────────────────────
		{"medium threshold: only low", []*types.ScanResult{mkResult(0, 0, 0, 2, 5)}, "medium", 0},
		{"medium threshold: has medium", []*types.ScanResult{mkResult(0, 0, 1, 0, 5)}, "medium", 1},
		{"medium threshold: has high", []*types.ScanResult{mkResult(0, 1, 0, 0, 5)}, "medium", 1},

		// ── low threshold ──────────────────────────────────
		{"low threshold: all pass", []*types.ScanResult{mkResult(0, 0, 0, 0, 5)}, "low", 0},
		{"low threshold: has low", []*types.ScanResult{mkResult(0, 0, 0, 1, 5)}, "low", 1},

		// ── any threshold ──────────────────────────────────
		{"any threshold: all pass", []*types.ScanResult{mkResult(0, 0, 0, 0, 5)}, "any", 0},
		{"any threshold: has low", []*types.ScanResult{mkResult(0, 0, 0, 1, 5)}, "any", 1},
		{"any threshold: has critical", []*types.ScanResult{mkResult(1, 0, 0, 0, 0)}, "any", 1},

		// ── edge cases ─────────────────────────────────────
		{"empty results", nil, "critical", 0},
		{"empty result slice", []*types.ScanResult{}, "critical", 0},
		{"default (unknown) maps to critical", []*types.ScanResult{mkResult(0, 5, 0, 0, 0)}, "foobar", 0},
		{"default (unknown) with critical", []*types.ScanResult{mkResult(1, 0, 0, 0, 0)}, "foobar", 1},
		{"case insensitive", []*types.ScanResult{mkResult(1, 0, 0, 0, 0)}, "CRITICAL", 1},

		// ── multiple results ───────────────────────────────
		{"multi result: first triggers", []*types.ScanResult{
			mkResult(1, 0, 0, 0, 5),
			mkResult(0, 0, 0, 0, 5),
		}, "critical", 1},
		{"multi result: second triggers", []*types.ScanResult{
			mkResult(0, 0, 0, 0, 5),
			mkResult(0, 0, 1, 0, 5),
		}, "medium", 1},
		{"multi result: neither triggers", []*types.ScanResult{
			mkResult(0, 0, 0, 0, 5),
			mkResult(0, 0, 0, 0, 5),
		}, "critical", 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := computeExitCode(tc.results, tc.failOn)
			if got != tc.want {
				t.Errorf("computeExitCode(%q) = %d, want %d", tc.failOn, got, tc.want)
			}
		})
	}
}

func TestExitCodeError(t *testing.T) {
	err := &ExitCodeError{Code: 42}
	if err.Error() != "exit code 42" {
		t.Errorf("ExitCodeError.Error() = %q, want %q", err.Error(), "exit code 42")
	}
}

func TestValidateFormat(t *testing.T) {
	valid := []string{"table", "json", "markdown", "sarif", "junit", "TABLE", "JSON", "JUNIT"}
	for _, f := range valid {
		if err := validateFormat(f); err != nil {
			t.Errorf("validateFormat(%q) unexpected error: %v", f, err)
		}
	}
	invalid := []string{"xml", "csv", "yaml", ""}
	for _, f := range invalid {
		if err := validateFormat(f); err == nil {
			t.Errorf("validateFormat(%q) expected error, got nil", f)
		}
	}
}

func TestValidateFailOn(t *testing.T) {
	valid := []string{"critical", "high", "medium", "low", "any", "HIGH", "Any"}
	for _, f := range valid {
		if err := validateFailOn(f); err != nil {
			t.Errorf("validateFailOn(%q) unexpected error: %v", f, err)
		}
	}
	invalid := []string{"warn", "error", "info", ""}
	for _, f := range invalid {
		if err := validateFailOn(f); err == nil {
			t.Errorf("validateFailOn(%q) expected error, got nil", f)
		}
	}
}

func TestTruncateStr(t *testing.T) {
	tests := []struct {
		s    string
		n    int
		want string
	}{
		{"hello", 10, "hello"},
		{"hello world", 8, "hello..."},
		{"hi", 2, "hi"},
		{"", 5, ""},
	}
	for _, tc := range tests {
		got := truncateStr(tc.s, tc.n)
		if got != tc.want {
			t.Errorf("truncateStr(%q, %d) = %q, want %q", tc.s, tc.n, got, tc.want)
		}
	}
}

func TestFilterFindings(t *testing.T) {
	mkFindings := func() []*types.ScanResult {
		r := &types.ScanResult{
			Target:  "test",
			Scanner: "test",
			Findings: []types.Finding{
				{Control: types.Control{ID: "IMAGE-001", Severity: types.SeverityHigh}, Status: types.StatusFail},
				{Control: types.Control{ID: "IMAGE-005", Severity: types.SeverityMedium}, Status: types.StatusPass},
				{Control: types.Control{ID: "K8S-001", Severity: types.SeverityCritical}, Status: types.StatusFail},
				{Control: types.Control{ID: "RUNTIME-010", Severity: types.SeverityLow}, Status: types.StatusWarn},
			},
		}
		r.Tally()
		return []*types.ScanResult{r}
	}

	t.Run("no filters keeps all", func(t *testing.T) {
		results := mkFindings()
		filterFindings(results, nil, nil)
		if len(results[0].Findings) != 4 {
			t.Errorf("expected 4 findings, got %d", len(results[0].Findings))
		}
	})

	t.Run("exclude single check", func(t *testing.T) {
		results := mkFindings()
		filterFindings(results, nil, []string{"IMAGE-001"})
		if len(results[0].Findings) != 3 {
			t.Errorf("expected 3 findings, got %d", len(results[0].Findings))
		}
		for _, f := range results[0].Findings {
			if f.Control.ID == "IMAGE-001" {
				t.Error("IMAGE-001 should have been excluded")
			}
		}
	})

	t.Run("exclude multiple checks", func(t *testing.T) {
		results := mkFindings()
		filterFindings(results, nil, []string{"IMAGE-001", "K8S-001"})
		if len(results[0].Findings) != 2 {
			t.Errorf("expected 2 findings, got %d", len(results[0].Findings))
		}
	})

	t.Run("include only specific checks", func(t *testing.T) {
		results := mkFindings()
		filterFindings(results, []string{"IMAGE-001", "K8S-001"}, nil)
		if len(results[0].Findings) != 2 {
			t.Errorf("expected 2 findings, got %d", len(results[0].Findings))
		}
		ids := map[string]bool{}
		for _, f := range results[0].Findings {
			ids[f.Control.ID] = true
		}
		if !ids["IMAGE-001"] || !ids["K8S-001"] {
			t.Error("expected IMAGE-001 and K8S-001 to be present")
		}
	})

	t.Run("include overrides exclude", func(t *testing.T) {
		results := mkFindings()
		filterFindings(results, []string{"IMAGE-001", "K8S-001"}, []string{"IMAGE-001"})
		if len(results[0].Findings) != 1 {
			t.Errorf("expected 1 finding, got %d", len(results[0].Findings))
		}
		if results[0].Findings[0].Control.ID != "K8S-001" {
			t.Errorf("expected K8S-001, got %s", results[0].Findings[0].Control.ID)
		}
	})

	t.Run("case insensitive matching", func(t *testing.T) {
		results := mkFindings()
		filterFindings(results, nil, []string{"image-001"})
		if len(results[0].Findings) != 3 {
			t.Errorf("expected 3 findings, got %d", len(results[0].Findings))
		}
	})

	t.Run("tally is updated after filtering", func(t *testing.T) {
		results := mkFindings()
		filterFindings(results, nil, []string{"IMAGE-001", "K8S-001"})
		r := results[0]
		if r.Fail != 0 {
			t.Errorf("expected Fail=0 after excluding all failures, got %d", r.Fail)
		}
		if r.Pass != 1 {
			t.Errorf("expected Pass=1, got %d", r.Pass)
		}
		if r.Warn != 1 {
			t.Errorf("expected Warn=1, got %d", r.Warn)
		}
	})

	t.Run("exclude nonexistent check is no-op", func(t *testing.T) {
		results := mkFindings()
		filterFindings(results, nil, []string{"NONEXISTENT-999"})
		if len(results[0].Findings) != 4 {
			t.Errorf("expected 4 findings, got %d", len(results[0].Findings))
		}
	})

	t.Run("empty results is safe", func(t *testing.T) {
		filterFindings(nil, []string{"IMAGE-001"}, nil)
	})
}

func TestNewScanCmd(t *testing.T) {
	cmd := NewScanCmd()
	if cmd.Use != "scan" {
		t.Errorf("Use = %q, want scan", cmd.Use)
	}
	for _, flag := range []string{"format", "output", "fail-on"} {
		if cmd.Flags().Lookup(flag) == nil {
			t.Errorf("missing flag: %s", flag)
		}
	}
}

func TestNewImageCmd(t *testing.T) {
	cmd := NewImageCmd()
	if cmd.Use != "image [IMAGE...]" {
		t.Errorf("Use = %q, want %q", cmd.Use, "image [IMAGE...]")
	}
	for _, flag := range []string{"format", "output", "fail-on"} {
		if cmd.Flags().Lookup(flag) == nil {
			t.Errorf("missing flag: %s", flag)
		}
	}
}

func TestNewK8sCmd(t *testing.T) {
	cmd := NewK8sCmd()
	if cmd.Use != "k8s [PATH...]" {
		t.Errorf("Use = %q, want %q", cmd.Use, "k8s [PATH...]")
	}
	for _, flag := range []string{"format", "output", "fail-on"} {
		if cmd.Flags().Lookup(flag) == nil {
			t.Errorf("missing flag: %s", flag)
		}
	}
}

func TestNewTerraformCmd(t *testing.T) {
	cmd := NewTerraformCmd()
	if cmd.Use != "terraform [PATH...]" {
		t.Errorf("Use = %q, want %q", cmd.Use, "terraform [PATH...]")
	}
	for _, flag := range []string{"format", "output", "fail-on"} {
		if cmd.Flags().Lookup(flag) == nil {
			t.Errorf("missing flag: %s", flag)
		}
	}
}

func TestNewDockerCmd(t *testing.T) {
	cmd := NewDockerCmd()
	if cmd.Use != "docker [PATH...]" {
		t.Errorf("Use = %q, want %q", cmd.Use, "docker [PATH...]")
	}
	for _, flag := range []string{"format", "output", "fail-on", "exclude-check", "include-check"} {
		if cmd.Flags().Lookup(flag) == nil {
			t.Errorf("missing flag: %s", flag)
		}
	}
}

func TestNewReportCmd(t *testing.T) {
	cmd := NewReportCmd()
	if cmd.Use != "report" {
		t.Errorf("Use = %q, want report", cmd.Use)
	}
	if !cmd.HasSubCommands() {
		t.Error("report command should have subcommands")
	}
}
