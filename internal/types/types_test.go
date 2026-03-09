package types

import (
	"testing"
)

func TestSeverityIsValid(t *testing.T) {
	valid := []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInformation}
	for _, s := range valid {
		if !s.IsValid() {
			t.Errorf("Severity(%q).IsValid() = false, want true", s)
		}
	}
	invalid := []Severity{"UNKNOWN", "warning", ""}
	for _, s := range invalid {
		if s.IsValid() {
			t.Errorf("Severity(%q).IsValid() = true, want false", s)
		}
	}
}

func TestSeverities(t *testing.T) {
	list := Severities()
	if len(list) != 5 {
		t.Fatalf("Severities() has %d entries, want 5", len(list))
	}
	// First should be CRITICAL (highest priority).
	if list[0] != SeverityCritical {
		t.Errorf("Severities()[0] = %q, want %q", list[0], SeverityCritical)
	}
	// Last should be INFO (lowest priority).
	if list[len(list)-1] != SeverityInformation {
		t.Errorf("Severities()[last] = %q, want %q", list[len(list)-1], SeverityInformation)
	}
	// All entries should be valid.
	for _, s := range list {
		if !s.IsValid() {
			t.Errorf("Severity %q from Severities() is not valid", s)
		}
	}
}

func TestControlTypeIsValid(t *testing.T) {
	valid := []ControlType{ControlPreventive, ControlDetective, ControlCorrective}
	for _, ct := range valid {
		if !ct.IsValid() {
			t.Errorf("ControlType(%q).IsValid() = false, want true", ct)
		}
	}
	invalid := []ControlType{"Reactive", "unknown", ""}
	for _, ct := range invalid {
		if ct.IsValid() {
			t.Errorf("ControlType(%q).IsValid() = true, want false", ct)
		}
	}
}

func TestControlTypes(t *testing.T) {
	list := ControlTypes()
	if len(list) != 3 {
		t.Fatalf("ControlTypes() has %d entries, want 3", len(list))
	}
	for _, ct := range list {
		if !ct.IsValid() {
			t.Errorf("ControlType %q from ControlTypes() is not valid", ct)
		}
	}
}

func TestStatusIsValid(t *testing.T) {
	valid := []Status{StatusPass, StatusFail, StatusWarn, StatusSkipped, StatusError}
	for _, s := range valid {
		if !s.IsValid() {
			t.Errorf("Status(%q).IsValid() = false, want true", s)
		}
	}
	invalid := []Status{"UNKNOWN", "pass", ""}
	for _, s := range invalid {
		if s.IsValid() {
			t.Errorf("Status(%q).IsValid() = true, want false", s)
		}
	}
}

func TestStatuses(t *testing.T) {
	list := Statuses()
	if len(list) != 5 {
		t.Fatalf("Statuses() has %d entries, want 5", len(list))
	}
	for _, s := range list {
		if !s.IsValid() {
			t.Errorf("Status %q from Statuses() is not valid", s)
		}
	}
}

func TestTally(t *testing.T) {
	r := &ScanResult{
		Findings: []Finding{
			{Status: StatusPass, Control: Control{Severity: SeverityHigh}},
			{Status: StatusFail, Control: Control{Severity: SeverityCritical}},
			{Status: StatusFail, Control: Control{Severity: SeverityHigh}},
			{Status: StatusFail, Control: Control{Severity: SeverityMedium}},
			{Status: StatusFail, Control: Control{Severity: SeverityLow}},
			{Status: StatusFail, Control: Control{Severity: SeverityInformation}},
			{Status: StatusWarn},
			{Status: StatusSkipped},
			{Status: StatusError},
		},
	}
	r.Tally()

	checks := []struct {
		name string
		got  int
		want int
	}{
		{"Pass", r.Pass, 1},
		{"Fail", r.Fail, 5},
		{"Warn", r.Warn, 1},
		{"Skipped", r.Skipped, 1},
		{"Error", r.Error, 1},
		{"Critical", r.Critical, 1},
		{"High", r.High, 1},
		{"Medium", r.Medium, 1},
		{"Low", r.Low, 1},
		{"Info", r.Info, 1},
	}
	for _, tc := range checks {
		if tc.got != tc.want {
			t.Errorf("%s = %d, want %d", tc.name, tc.got, tc.want)
		}
	}
}

func TestTally_Empty(t *testing.T) {
	r := &ScanResult{}
	r.Tally()
	if r.Pass != 0 || r.Fail != 0 || r.Warn != 0 {
		t.Errorf("empty Tally: Pass=%d Fail=%d Warn=%d, want all 0", r.Pass, r.Fail, r.Warn)
	}
}

func TestTally_ResetCounts(t *testing.T) {
	r := &ScanResult{
		Findings: []Finding{
			{Status: StatusFail, Control: Control{Severity: SeverityCritical}},
			{Status: StatusPass},
		},
	}
	r.Tally()
	if r.Fail != 1 || r.Pass != 1 {
		t.Fatal("initial tally wrong")
	}

	r.Findings = r.Findings[1:]
	r.Tally()
	if r.Fail != 0 {
		t.Errorf("Fail = %d after removing failure, want 0", r.Fail)
	}
	if r.Critical != 0 {
		t.Errorf("Critical = %d after removing failure, want 0", r.Critical)
	}
	if r.Pass != 1 {
		t.Errorf("Pass = %d, want 1", r.Pass)
	}
}

func TestAllControls_NoDuplicateIDs(t *testing.T) {
	seen := make(map[string]bool, len(AllControls))
	for _, c := range AllControls {
		if c.ID == "" {
			t.Error("control has empty ID")
			continue
		}
		if seen[c.ID] {
			t.Errorf("duplicate control ID: %s", c.ID)
		}
		seen[c.ID] = true
	}
}

func TestAllControls_RequiredFields(t *testing.T) {
	for _, c := range AllControls {
		if c.Title == "" {
			t.Errorf("control %s has empty Title", c.ID)
		}
		if !c.Severity.IsValid() {
			t.Errorf("control %s has invalid Severity %q", c.ID, c.Severity)
		}
		if !c.Type.IsValid() {
			t.Errorf("control %s has invalid Type %q", c.ID, c.Type)
		}
	}
}
