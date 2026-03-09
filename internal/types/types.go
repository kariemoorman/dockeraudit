package types

// Severity of a finding.
//
// These are string-typed enums. For iota-based enums, go:generate stringer
// would be used; for string enums the equivalent helpers are IsValid() and
// Severities().
type Severity string

const (
	SeverityCritical    Severity = "CRITICAL"
	SeverityHigh        Severity = "HIGH"
	SeverityMedium      Severity = "MEDIUM"
	SeverityLow         Severity = "LOW"
	SeverityInformation Severity = "INFO"
)

// validSeverities is the set of recognized Severity values.
var validSeverities = map[Severity]bool{
	SeverityCritical: true, SeverityHigh: true, SeverityMedium: true,
	SeverityLow: true, SeverityInformation: true,
}

// IsValid reports whether s is a recognized Severity value.
func (s Severity) IsValid() bool { return validSeverities[s] }

// Severities returns all valid Severity values in descending order of priority.
func Severities() []Severity {
	return []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInformation}
}

// ControlType is the classification of the control.
type ControlType string

const (
	ControlPreventive ControlType = "Preventive"
	ControlDetective  ControlType = "Detective"
	ControlCorrective ControlType = "Corrective"
)

// validControlTypes is the set of recognized ControlType values.
var validControlTypes = map[ControlType]bool{
	ControlPreventive: true, ControlDetective: true, ControlCorrective: true,
}

// IsValid reports whether ct is a recognized ControlType value.
func (ct ControlType) IsValid() bool { return validControlTypes[ct] }

// ControlTypes returns all valid ControlType values.
func ControlTypes() []ControlType {
	return []ControlType{ControlPreventive, ControlDetective, ControlCorrective}
}

// Status of a check result.
type Status string

const (
	StatusPass    Status = "PASS"
	StatusFail    Status = "FAIL"
	StatusWarn    Status = "WARN"
	StatusSkipped Status = "SKIPPED"
	StatusError   Status = "ERROR"
)

// validStatuses is the set of recognized Status values.
var validStatuses = map[Status]bool{
	StatusPass: true, StatusFail: true, StatusWarn: true,
	StatusSkipped: true, StatusError: true,
}

// IsValid reports whether s is a recognized Status value.
func (s Status) IsValid() bool { return validStatuses[s] }

// Statuses returns all valid Status values.
func Statuses() []Status {
	return []Status{StatusPass, StatusFail, StatusWarn, StatusSkipped, StatusError}
}

// ComplianceMapping maps a control to compliance frameworks
type ComplianceMapping struct {
	CISDockerSection string `json:"cis_docker_section"`
	NIST80053        string `json:"nist_800_53"`
	NIST800190       string `json:"nist_800_190"`
	ISO27001         string `json:"iso_27001"`
	SOC2             string `json:"soc2"`
	DISACCI          string `json:"disa_cci"`
}

// Control defines a single hardening control
type Control struct {
	ID          string            `json:"id"`
	Domain      string            `json:"domain"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Severity    Severity          `json:"severity"`
	Type        ControlType       `json:"type"`
	Compliance  ComplianceMapping `json:"compliance"`
	Remediation string            `json:"remediation"`
}

// Finding is the result of evaluating a single control against a target
type Finding struct {
	Control     Control `json:"control"`
	Status      Status  `json:"status"`
	Target      string  `json:"target"`                 // image name, file path, resource name
	Detail      string  `json:"detail"`                 // human-readable explanation
	Evidence    string  `json:"evidence"`               // raw output that led to this result
	Remediation string  `json:"remediation"`
	SourceFile  string  `json:"source_file,omitempty"`  // file path for file-based scanners (K8s, Terraform)
	SourceLine  int     `json:"source_line,omitempty"`  // 1-based line number within SourceFile
}

// ScanResult aggregates findings from a scan run
type ScanResult struct {
	Target   string    `json:"target"`
	Scanner  string    `json:"scanner"`  // "image", "k8s", "terraform", "daemon"
	Findings []Finding `json:"findings"`
	// Summary counts
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Pass     int `json:"pass"`
	Fail     int `json:"fail"`
	Warn     int `json:"warn"`
	Skipped  int `json:"skipped"`
	Error    int `json:"error"`
}

func (r *ScanResult) Tally() {
	r.Critical = 0
	r.High = 0
	r.Medium = 0
	r.Low = 0
	r.Info = 0
	r.Pass = 0
	r.Fail = 0
	r.Warn = 0
	r.Skipped = 0
	r.Error = 0

	for _, f := range r.Findings {
		switch f.Status {
		case StatusPass:
			r.Pass++
		case StatusFail:
			r.Fail++
			switch f.Control.Severity {
			case SeverityCritical:
				r.Critical++
			case SeverityHigh:
				r.High++
			case SeverityMedium:
				r.Medium++
			case SeverityLow:
				r.Low++
			case SeverityInformation:
				r.Info++
			}
		case StatusWarn:
			r.Warn++
		case StatusSkipped:
			r.Skipped++
		case StatusError:
			r.Error++
		}
	}
}


