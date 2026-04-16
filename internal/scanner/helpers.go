package scanner

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/kariemoorman/dockeraudit/internal/types"
)

// ── controlByID lookup ──────────────────────────────────────────────────────── //

var (
	controlMap     map[string]types.Control
	controlMapOnce sync.Once
)

func controlByID(id string) types.Control {
	controlMapOnce.Do(func() {
		controlMap = make(map[string]types.Control, len(types.AllControls))
		for _, c := range types.AllControls {
			controlMap[c.ID] = c
		}
	})
	if c, ok := controlMap[id]; ok {
		return c
	}
	log.Printf("WARNING: unknown control ID %q requested; using placeholder", id)
	return types.Control{ID: id, Title: "Unknown control " + id}
}

// ── finding constructors ────────────────────────────────────────────────────── //

func pass(ctrl types.Control, target, detail string) types.Finding {
	return types.Finding{
		Control: ctrl,
		Status:  types.StatusPass,
		Target:  target,
		Detail:  detail,
	}
}

func fail(ctrl types.Control, target, detail, evidence, remediation string) types.Finding {
	return types.Finding{
		Control:     ctrl,
		Status:      types.StatusFail,
		Target:      target,
		Detail:      detail,
		Evidence:    evidence,
		Remediation: remediation,
	}
}

func warn(ctrl types.Control, target, detail, evidence string) types.Finding {
	return types.Finding{
		Control:  ctrl,
		Status:   types.StatusWarn,
		Target:   target,
		Detail:   detail,
		Evidence: evidence,
	}
}

func skipped(ctrl types.Control, target, detail string) types.Finding {
	return types.Finding{
		Control: ctrl,
		Status:  types.StatusSkipped,
		Target:  target,
		Detail:  detail,
	}
}

func errFinding(ctrl types.Control, target, detail string) types.Finding {
	return types.Finding{
		Control: ctrl,
		Status:  types.StatusError,
		Target:  target,
		Detail:  detail,
	}
}

// ── shared credential patterns ─────────────────────────────────────────── //

// credentialKeywords are env-var name substrings that indicate a secret value.
// Shared across docker.go, k8s.go, and compose checks so detection stays in sync.
var credentialKeywords = []string{
	"password", "passwd", "secret", "token", "api_key", "api-key",
	"apikey", "credential", "private_key", "access_key", "auth_token",
	"client_secret", "connection_string", "database_url",
}

// aiKeyPatterns are env-var name substrings indicating AI/vectorizer provider keys.
// Used for the more specific SECRETS-003 control.
var aiKeyPatterns = []string{
	"openai_apikey", "openai_api_key",
	"cohere_apikey", "cohere_api_key",
	"huggingface_apikey", "hf_token",
	"anthropic_api_key",
	"google_api_key", "gemini_api_key",
	"azure_openai_api_key",
}

// ── EOL image detection ───────────────────────────────────────────────────── //

// EOLEntry defines an end-of-life image that should trigger IMAGE-008.
// Exported so callers can supply custom entries via ImageScanner.CustomEOLImages
// or load them from a JSON file with --eol-file.
type EOLEntry struct {
	Name   string `json:"name"`   // lowercase image name (final path component, e.g. "postgres")
	Tag    string `json:"tag"`    // tag prefix; ends with "." for semver-prefix matches (e.g. "9.")
	Reason string `json:"reason"` // human-readable EOL description
}

// DefaultEOLImages is the built-in list of end-of-life images.
// Override by setting ImageScanner.CustomEOLImages.
var DefaultEOLImages = []EOLEntry{
	// ── Ubuntu ──
	{"ubuntu", "14.04", "Ubuntu 14.04 (Trusty) — EOL April 2019"},
	{"ubuntu", "16.04", "Ubuntu 16.04 (Xenial) — EOL April 2021"},
	{"ubuntu", "18.04", "Ubuntu 18.04 (Bionic) — EOL April 2023"},
	// ── Debian ──
	{"debian", "7", "Debian 7 (Wheezy) — EOL May 2018"},
	{"debian", "8", "Debian 8 (Jessie) — EOL June 2020"},
	{"debian", "9", "Debian 9 (Stretch) — EOL June 2022"},
	{"debian", "jessie", "Debian 8 (Jessie) — EOL June 2020"},
	{"debian", "stretch", "Debian 9 (Stretch) — EOL June 2022"},
	{"debian", "buster", "Debian 10 (Buster) — EOL June 2024"},
	// ── CentOS ──
	{"centos", "6", "CentOS 6 — EOL November 2020"},
	{"centos", "7", "CentOS 7 — EOL June 2024"},
	{"centos", "8", "CentOS 8 — EOL December 2021"},
	// ── Node.js ──
	{"node", "10", "Node.js 10 — EOL April 2021"},
	{"node", "12", "Node.js 12 — EOL April 2022"},
	{"node", "14", "Node.js 14 — EOL April 2023"},
	{"node", "16", "Node.js 16 — EOL September 2023"},
	{"node", "19", "Node.js 19 — EOL June 2023"},
	// ── Python ──
	{"python", "2.", "Python 2.x — EOL January 2020"},
	{"python", "3.6", "Python 3.6 — EOL December 2021"},
	{"python", "3.7", "Python 3.7 — EOL June 2023"},
	{"python", "3.8", "Python 3.8 — EOL October 2024"},
	{"python", "3.9", "Python 3.9 — EOL October 2025"},
	// ── Ruby ──
	{"ruby", "2.5", "Ruby 2.5 — EOL March 2021"},
	{"ruby", "2.6", "Ruby 2.6 — EOL March 2022"},
	{"ruby", "2.7", "Ruby 2.7 — EOL March 2023"},
	{"ruby", "3.0", "Ruby 3.0 — EOL March 2024"},
	{"ruby", "3.1", "Ruby 3.1 — EOL March 2025"},
	// ── PHP ──
	{"php", "5.", "PHP 5.x — EOL December 2018"},
	{"php", "7.0", "PHP 7.0 — EOL December 2019"},
	{"php", "7.1", "PHP 7.1 — EOL December 2019"},
	{"php", "7.2", "PHP 7.2 — EOL November 2020"},
	{"php", "7.3", "PHP 7.3 — EOL December 2021"},
	{"php", "7.4", "PHP 7.4 — EOL November 2022"},
	{"php", "8.0", "PHP 8.0 — EOL November 2023"},
	{"php", "8.1", "PHP 8.1 — EOL December 2024"},
	// ── Go ──
	{"golang", "1.16", "Go 1.16 — EOL August 2022"},
	{"golang", "1.17", "Go 1.17 — EOL February 2023"},
	{"golang", "1.18", "Go 1.18 — EOL August 2023"},
	{"golang", "1.19", "Go 1.19 — EOL February 2024"},
	{"golang", "1.20", "Go 1.20 — EOL August 2024"},
	{"golang", "1.21", "Go 1.21 — EOL February 2025"},
	// ── PostgreSQL ──
	{"postgres", "9.", "PostgreSQL 9.x — EOL November 2021"},
	{"postgres", "10", "PostgreSQL 10 — EOL November 2022"},
	{"postgres", "11", "PostgreSQL 11 — EOL November 2023"},
	{"postgres", "12", "PostgreSQL 12 — EOL November 2024"},
	{"postgres", "13", "PostgreSQL 13 — EOL November 2025"},
	// ── MySQL ──
	{"mysql", "5.6", "MySQL 5.6 — EOL February 2021"},
	{"mysql", "5.7", "MySQL 5.7 — EOL October 2023"},
	// ── MongoDB ──
	{"mongo", "4.", "MongoDB 4.x — EOL (4.0 Jan 2022, 4.2 Feb 2023, 4.4 Feb 2024)"},
	{"mongo", "5.", "MongoDB 5.0 — EOL October 2024"},
	// ── Redis ──
	{"redis", "5", "Redis 5 — EOL"},
	{"redis", "6.0", "Redis 6.0 — EOL March 2023"},
	// ── Elasticsearch ──
	{"elasticsearch", "6.", "Elasticsearch 6.x — EOL"},
	{"elasticsearch", "7.", "Elasticsearch 7.x — EOL August 2024"},
}

// eolTagMatches returns true when imageTag corresponds to the EOL tag spec.
// • If eolTag ends with "." → prefix match  (e.g. "9." matches "9.6.3-alpine")
// • Otherwise → exact match OR match with separator (-/./_ ) to avoid "10" matching "100".
func eolTagMatches(imageTag, eolTag string) bool {
	if strings.HasSuffix(eolTag, ".") {
		return strings.HasPrefix(imageTag, eolTag)
	}
	if imageTag == eolTag {
		return true
	}
	for _, sep := range []string{"-", ".", "_"} {
		if strings.HasPrefix(imageTag, eolTag+sep) {
			return true
		}
	}
	return false
}

// imageNameTag extracts (name, tag) from any image reference.
// Examples:
//
//	"docker.io/library/postgres:16-alpine" → ("postgres", "16-alpine")
//	"myregistry.com:5000/myapp:v2"         → ("myapp", "v2")
//	"ubuntu"                                → ("ubuntu", "latest")
func imageNameTag(ref string) (name, tag string) {
	// Strip digest suffix (@sha256:...)
	if idx := strings.Index(ref, "@"); idx >= 0 {
		ref = ref[:idx]
	}
	// Find the last slash to isolate the name:tag portion (avoids misparse of registry:port).
	slashIdx := strings.LastIndex(ref, "/")
	nameTag := ref
	if slashIdx >= 0 {
		nameTag = ref[slashIdx+1:]
	}
	if colonIdx := strings.Index(nameTag, ":"); colonIdx >= 0 {
		tag = nameTag[colonIdx+1:]
		nameTag = nameTag[:colonIdx]
	} else {
		tag = "latest"
	}
	return strings.ToLower(nameTag), strings.ToLower(tag)
}

// shortImage truncates the hex portion of a digest-pinned image reference to
// 12 characters for compact display; non-digest references are returned unchanged.
//
//	"nginx:1.25-alpine@sha256:abcdef1234567890..." → "nginx:1.25-alpine@sha256:abcdef123456…"
func shortImage(ref string) string {
	const marker = "@sha256:"
	idx := strings.Index(ref, marker)
	if idx < 0 {
		return ref
	}
	digest := ref[idx+len(marker):]
	if len(digest) <= 5 {
		return ref
	}
	return ref[:idx+len(marker)] + digest[:5] + "…"
}

// ── HOST-001: Minimal Base Image Classification ───────────────────────────── //

// imageMinimality represents the classification of an image's base OS minimality.
type imageMinimality int

const (
	imageMinimal    imageMinimality = iota // Known minimal image (alpine, distroless, scratch, slim, etc.)
	imageNonMinimal                        // Known full-OS image (ubuntu, debian, centos without minimal suffix)
	imageUnknown                           // Cannot determine (custom/private registry image)
)

// knownMinimalBases are image names that are inherently minimal (no tag check needed).
var knownMinimalBases = []string{
	"scratch",
	"alpine",
	"busybox",
	"wolfi",
	"static",
}

// knownMinimalRegistryPrefixes are registry path prefixes that indicate minimal images.
// These are checked against the full image reference (before extracting name/tag).
var knownMinimalRegistryPrefixes = []string{
	"gcr.io/distroless/",
	"ghcr.io/distroless/",
	"cgr.dev/chainguard/",
	"distroless/",
}

// minimalTagSuffixes are tag patterns that indicate a minimal variant of an otherwise
// non-minimal base. Checked as suffixes or infixes (e.g. "-alpine", "-slim").
var minimalTagSuffixes = []string{
	"-alpine",
	"-slim",
	"-minimal",
	"-distroless",
	"-static",
	"-musl",
	"-busybox",
	"-runtime",
	"-runtime-deps",
	"-tiny",
	"-micro",
	"-core",
	"-base",
	"-lite",
}

// knownNonMinimalBases are image names representing full OS distributions (exact match).
// Only flagged when the tag does NOT contain a minimal suffix.
var knownNonMinimalBases = []string{
	// Debian family
	"ubuntu",
	"debian",
	"kali",
	"parrot",
	"linuxmint",
	"raspbian",
	"devuan",
	// Red Hat family
	"rhel",
	"centos",
	"fedora",
	"rockylinux",
	"almalinux",
	"oraclelinux",
	"amazonlinux",
	// SUSE family
	"opensuse",
	// Arch family
	"archlinux",
	// Other full-OS distributions
	"clearlinux",
	"mageia",
	"altlinux",
	"nixos",
	"guix",
	"photon",
}

// knownNonMinimalPrefixes are image name prefixes that indicate full OS distributions.
// Matches any image name starting with these strings (e.g. "opensuse-tumbleweed", "sles15", "ubi9").
var knownNonMinimalPrefixes = []string{
	// SUSE variants: opensuse-leap, opensuse-tumbleweed, sles15, sles12, etc.
	"opensuse-",
	"suse",
	"sles",
	"bci-",
	// Red Hat UBI variants: ubi8, ubi9, ubi-minimal, ubi-micro, etc.
	"ubi",
	// Arch variants
	"archlinux-",
	// CentOS variants (centos-stream, etc.)
	"centos-",
	// Fedora variants
	"fedora-",
	// Rocky/Alma variants
	"rockylinux-",
	"almalinux-",
	// Oracle variants
	"oraclelinux-",
	// Photon variants
	"photon-",
	// NixOS variants
	"nixos-",
}

// classifyImageMinimality determines whether an image reference uses a minimal or
// non-minimal base OS. Returns (classification, detail) where detail explains why.
//
// Classification logic:
//  1. Known minimal registry paths (distroless, chainguard) → minimal
//  2. Known minimal base names (alpine, scratch, busybox, wolfi) → minimal
//  3. Tag contains minimal suffix (-alpine, -slim, -distroless, etc.) → minimal
//  4. Known full-OS base without minimal suffix → non-minimal
//  5. Everything else (custom/private images) → unknown
func classifyImageMinimality(imageRef string) (imageMinimality, string) {
	if imageRef == "" {
		return imageUnknown, ""
	}

	refLower := strings.ToLower(imageRef)

	// 1. Check registry prefixes (distroless, chainguard)
	for _, prefix := range knownMinimalRegistryPrefixes {
		if strings.Contains(refLower, prefix) {
			return imageMinimal, "distroless/chainguard minimal image"
		}
	}

	name, tag := imageNameTag(imageRef)

	// 2. Check known minimal base names
	for _, base := range knownMinimalBases {
		if name == base {
			return imageMinimal, name + " is a minimal base image"
		}
	}

	// 3. Check tag for minimal suffixes (e.g. python:3.12-alpine, node:22-slim)
	for _, suffix := range minimalTagSuffixes {
		if strings.Contains(tag, suffix[1:]) { // strip leading "-" for infix matching
			return imageMinimal, "tag contains minimal variant indicator: " + suffix[1:]
		}
	}

	// 4. Check known non-minimal bases (exact match)
	for _, base := range knownNonMinimalBases {
		if name == base {
			return imageNonMinimal, name + " is a full-OS distribution"
		}
	}

	// 4b. Check known non-minimal prefixes (e.g. opensuse-leap, sles15, ubi9)
	for _, prefix := range knownNonMinimalPrefixes {
		if strings.HasPrefix(name, prefix) {
			return imageNonMinimal, name + " is a full-OS distribution"
		}
	}

	// 5. Unknown — private/custom image, can't determine
	return imageUnknown, ""
}

// checkImageMinimality emits a HOST-001 finding based on the image reference.
// PASS for minimal images, WARN for full-OS distributions, skip for unknown.
func checkImageMinimality(imageRef, target string) []types.Finding {
	ctrl := controlByID("HOST-001")
	class, detail := classifyImageMinimality(imageRef)

	switch class {
	case imageMinimal:
		return []types.Finding{pass(ctrl, target,
			fmt.Sprintf("Minimal base image: %s (%s)", shortImage(imageRef), detail))}
	case imageNonMinimal:
		name, _ := imageNameTag(imageRef)
		return []types.Finding{warn(ctrl, target,
			fmt.Sprintf("Non-minimal base image %q — consider using %s-slim, %s:*-alpine, or distroless",
				shortImage(imageRef), name, name),
			fmt.Sprintf("image: %s — %s", shortImage(imageRef), detail))}
	default:
		return nil // Unknown/private image — skip silently
	}
}

// ── shared utilities ──────────────────────────────────────────────────────────

// relPath returns path relative to root for display purposes. When root is a
// file (not a directory), its parent directory is used as the base. Falls back
// to the base filename if filepath.Rel fails.
func relPath(root, path string) string {
	base := root
	if info, err := os.Stat(root); err != nil || !info.IsDir() {
		base = filepath.Dir(root)
	}
	rel, err := filepath.Rel(base, path)
	if err != nil {
		return filepath.Base(path)
	}
	return rel
}

// collectFiles recursively collects files with matching extensions from a root path.
// If root is a file, it is returned directly.
func collectFiles(root string, exts []string) ([]string, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []string{root}, nil
	}

	var files []string
	err = filepath.Walk(root, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		for _, e := range exts {
			if ext == e {
				files = append(files, path)
				break
			}
		}
		return nil
	})
	return files, err
}

// remarshal round-trips through JSON to convert between types.
func remarshal(src, dst interface{}) error {
	b, err := json.Marshal(src)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, dst)
}