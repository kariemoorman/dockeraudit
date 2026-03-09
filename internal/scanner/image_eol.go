package scanner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/kariemoorman/dockeraudit/internal/types"
)

// EOLEntry, DefaultEOLImages, eolTagMatches, and imageNameTag are defined in helpers.go
// so they can be shared across docker.go, image_eol.go, and k8s.go.

// LoadEOLFile reads a JSON file containing a list of EOLEntry objects.
// The file format is: [{"name":"node","tag":"18","reason":"Node 18 EOL"},...]
func LoadEOLFile(path string) ([]EOLEntry, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path from user-supplied --eol-file flag
	if err != nil {
		return nil, fmt.Errorf("read EOL file %s: %w", path, err)
	}
	var entries []EOLEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("parse EOL file %s: %w", path, err)
	}
	for i := range entries {
		entries[i].Name = strings.ToLower(entries[i].Name)
		entries[i].Tag = strings.ToLower(entries[i].Tag)
	}
	return entries, nil
}

// eolList returns the EOL list to use: custom overrides if set, otherwise the defaults.
func (s *ImageScanner) eolList() []EOLEntry {
	if len(s.CustomEOLImages) > 0 {
		return s.CustomEOLImages
	}
	return DefaultEOLImages
}

// fromHistoryRe matches FROM-like references in docker history output.
// History lines contain image references like "FROM python:3.7" or embedded in
// BuildKit-style provenance metadata.
var fromHistoryRe = regexp.MustCompile(`(?i)(?:FROM\s+|#\(nop\)\s+FROM\s+)([a-zA-Z0-9._/:-]+)`)

// checkEOLBaseImage detects end-of-life OS or runtime base images (IMAGE-008).
// Enhanced (TASK-9.27): checks s.Image, all inspect.RepoTags, AND parses
// docker history output to extract FROM instructions that reveal the actual
// base image (useful when the final image tag doesn't indicate the base).
func (s *ImageScanner) checkEOLBaseImage(inspect *imageInspect) types.Finding {
	ctrl := controlByID("IMAGE-008")
	refs := append([]string{s.Image}, inspect.RepoTags...)

	// Phase 1: Check direct image references and tags
	for _, ref := range refs {
		imgName, imgTag := imageNameTag(ref)
		if imgTag == "latest" {
			continue // can't determine EOL from :latest alone
		}
		for _, eol := range s.eolList() {
			if imgName == eol.Name && eolTagMatches(imgTag, eol.Tag) {
				return fail(ctrl, s.Image,
					fmt.Sprintf("End-of-life image detected: %s", eol.Reason),
					fmt.Sprintf("Image reference: %s (parsed name=%q tag=%q)", ref, imgName, imgTag),
					ctrl.Remediation)
			}
		}
	}

	return pass(ctrl, s.Image, "No known end-of-life base image detected")
}

// checkEOLFromHistory parses docker history output for FROM instructions
// and checks extracted base image references against the EOL list.
// Returns additional findings if EOL base images are found in history.
func (s *ImageScanner) checkEOLFromHistory(history string) []types.Finding {
	ctrl := controlByID("IMAGE-008")
	if history == "" {
		return []types.Finding{skipped(ctrl, s.Image, "No docker history available for EOL base image detection")}
	}

	var findings []types.Finding
	sc := bufio.NewScanner(strings.NewReader(history))
	for sc.Scan() {
		line := sc.Text()
		matches := fromHistoryRe.FindAllStringSubmatch(line, -1)
		for _, m := range matches {
			if len(m) < 2 {
				continue
			}
			ref := m[1]
			if ref == "scratch" || ref == "" {
				continue
			}
			imgName, imgTag := imageNameTag(ref)
			if imgTag == "latest" || imgTag == "" {
				continue
			}
			for _, eol := range s.eolList() {
				if imgName == eol.Name && eolTagMatches(imgTag, eol.Tag) {
					findings = append(findings, fail(ctrl, s.Image,
						fmt.Sprintf("EOL base image in build history: %s (FROM %s)", eol.Reason, ref),
						fmt.Sprintf("docker history shows FROM %s", ref),
						ctrl.Remediation))
				}
			}
		}
	}
	return findings
}
