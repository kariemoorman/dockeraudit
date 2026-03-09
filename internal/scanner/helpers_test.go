package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"https://github.com/kariemoorman/dockeraudit/internal/types"
)


func TestControlByID_Known(t *testing.T) {
	c := controlByID("IMAGE-001")
	if c.ID != "IMAGE-001" {
		t.Errorf("controlByID(IMAGE-001).ID = %q", c.ID)
	}
	if c.Title == "" {
		t.Error("controlByID(IMAGE-001).Title is empty")
	}
}

func TestControlByID_Unknown(t *testing.T) {
	c := controlByID("NONEXISTENT-999")
	if c.ID != "NONEXISTENT-999" {
		t.Errorf("ID = %q, want NONEXISTENT-999", c.ID)
	}
	if c.Title == "" {
		t.Error("unknown control should have a placeholder Title")
	}
}

func TestPass(t *testing.T) {
	ctrl := controlByID("IMAGE-001")
	f := pass(ctrl, "target", "detail")
	if f.Status != types.StatusPass {
		t.Errorf("expected PASS, got %s", f.Status)
	}
	if f.Target != "target" {
		t.Errorf("Target = %q, want target", f.Target)
	}
	if f.Detail != "detail" {
		t.Errorf("Detail = %q, want detail", f.Detail)
	}
	if f.Control.ID != "IMAGE-001" {
		t.Errorf("Control.ID = %q, want IMAGE-001", f.Control.ID)
	}
}

func TestFail(t *testing.T) {
	ctrl := controlByID("IMAGE-001")
	f := fail(ctrl, "target", "detail", "evidence", "remediation")
	if f.Status != types.StatusFail {
		t.Errorf("expected FAIL, got %s", f.Status)
	}
	if f.Target != "target" {
		t.Errorf("Target = %q, want target", f.Target)
	}
	if f.Detail != "detail" {
		t.Errorf("Detail = %q, want detail", f.Detail)
	}
	if f.Evidence != "evidence" {
		t.Errorf("Evidence = %q, want evidence", f.Evidence)
	}
	if f.Remediation != "remediation" {
		t.Errorf("Remediation = %q, want remediation", f.Remediation)
	}
	if f.Control.ID != "IMAGE-001" {
		t.Errorf("Control.ID = %q, want IMAGE-001", f.Control.ID)
	}
}

func TestWarn(t *testing.T) {
	ctrl := controlByID("IMAGE-001")
	f := warn(ctrl, "target", "detail", "evidence")
	if f.Status != types.StatusWarn {
		t.Errorf("expected WARN, got %s", f.Status)
	}
	if f.Target != "target" {
		t.Errorf("Target = %q, want target", f.Target)
	}
	if f.Detail != "detail" {
		t.Errorf("Detail = %q, want detail", f.Detail)
	}
	if f.Evidence != "evidence" {
		t.Errorf("Evidence = %q, want evidence", f.Evidence)
	}
	if f.Control.ID != "IMAGE-001" {
		t.Errorf("Control.ID = %q, want IMAGE-001", f.Control.ID)
	}
}

func TestSkipped(t *testing.T) {
	ctrl := controlByID("IMAGE-001")
	f := skipped(ctrl, "target", "detail")
	if f.Status != types.StatusSkipped {
		t.Errorf("expected SKIP, got %s", f.Status)
	}
	if f.Target != "target" {
		t.Errorf("Target = %q, want target", f.Target)
	}
	if f.Detail != "detail" {
		t.Errorf("Detail = %q, want detail", f.Detail)
	}
	if f.Control.ID != "IMAGE-001" {
		t.Errorf("Control.ID = %q, want IMAGE-001", f.Control.ID)
	}
}

func TestErrFinding(t *testing.T) {
	ctrl := controlByID("IMAGE-001")
	f := errFinding(ctrl, "target", "detail")
	if f.Status != types.StatusError {
		t.Errorf("expected ERROR, got %s", f.Status)
	}
	if f.Target != "target" {
		t.Errorf("Target = %q, want target", f.Target)
	}
	if f.Detail != "detail" {
		t.Errorf("Detail = %q, want detail", f.Detail)
	}
	if f.Control.ID != "IMAGE-001" {
		t.Errorf("Control.ID = %q, want IMAGE-001", f.Control.ID)
	}
}

func TestCollectFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte("resource"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "readme.md"), []byte("docs"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "vars.tf"), []byte("variable"), 0644); err != nil {
		t.Fatal(err)
	}

	files, err := collectFiles(dir, []string{".tf"})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Errorf("expected 2 .tf files, got %d", len(files))
	}
}

func TestCollectFiles_SingleFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "main.tf")
	
	if err := os.WriteFile(f, []byte("resource"), 0644); err != nil {
    	t.Fatal(err)
	}

	files, err := collectFiles(f, []string{".tf"})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0] != f {
		t.Errorf("expected [%s], got %v", f, files)
	}
}

func TestCollectFiles_NonExistentPath(t *testing.T) {
	_, err := collectFiles("/nonexistent/path/does/not/exist", []string{".tf"})
	if err == nil {
		t.Error("expected error for nonexistent path, got nil")
	}
}

func TestCollectFiles_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	files, err := collectFiles(dir, []string{".tf"})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Errorf("expected 0 files in empty dir, got %d", len(files))
	}
}

func TestRemarshal(t *testing.T) {
	type src struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}
	type dst struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}
	input := src{Name: "test", Value: 42}
	var output dst
	if err := remarshal(input, &output); err != nil {
		t.Fatal(err)
	}
	if output.Name != "test" || output.Value != 42 {
		t.Errorf("got %+v, want {test 42}", output)
	}
}

func TestRemarshal_InvalidInput(t *testing.T) {
	// remarshal should handle an unmarshalable input gracefully
	var output struct{ Name string }
	// Channel cannot be JSON-marshaled
	err := remarshal(make(chan int), &output)
	if err == nil {
		t.Error("expected error for unmarshalable input, got nil")
	}
}

// ── classifyImageMinimality tests ────────────────────────────────────────────

func TestClassifyImageMinimality_MinimalBases(t *testing.T) {
	minimalImages := []string{
		"alpine:3.19",
		"alpine",
		"busybox:latest",
		"scratch",
		"wolfi:latest",
		"gcr.io/distroless/static:nonroot",
		"gcr.io/distroless/base-debian12",
		"ghcr.io/distroless/static:latest",
		"cgr.dev/chainguard/go:latest",
		"cgr.dev/chainguard/python:latest-dev",
	}
	for _, img := range minimalImages {
		class, _ := classifyImageMinimality(img)
		if class != imageMinimal {
			t.Errorf("classifyImageMinimality(%q) = %d, want imageMinimal", img, class)
		}
	}
}

func TestClassifyImageMinimality_MinimalSuffixes(t *testing.T) {
	minimalImages := []string{
		"python:3.12-alpine",
		"node:22-alpine",
		"node:22-slim",
		"python:3.12-slim-bookworm",
		"nginx:1.25-alpine",
		"golang:1.22-alpine",
		"rust:1.77-slim",
		"ruby:3.3-alpine",
		"openjdk:21-slim",
		"postgres:16-alpine",
		"redis:7-alpine",
		"eclipse-temurin:21-alpine",
		"ubuntu:22.04-minimal",
		"myapp:v2-distroless",
		"myapp:v3-static",
		"myapp:v4-musl",
		"myapp:v5-busybox",
		"myapp:latest-tiny",
		"myapp:latest-micro",
		"myapp:latest-lite",
	}
	for _, img := range minimalImages {
		class, _ := classifyImageMinimality(img)
		if class != imageMinimal {
			t.Errorf("classifyImageMinimality(%q) = %d, want imageMinimal", img, class)
		}
	}
}

func TestClassifyImageMinimality_NonMinimalBases(t *testing.T) {
	nonMinimalImages := []string{
		// Debian family
		"ubuntu:22.04",
		"ubuntu:latest",
		"debian:bookworm",
		"debian:12",
		"kali:latest",
		"parrot:latest",
		"linuxmint:21",
		"raspbian:bullseye",
		"devuan:chimaera",
		// Red Hat family
		"centos:8",
		"fedora:39",
		"rockylinux:9",
		"almalinux:9",
		"oraclelinux:9",
		"amazonlinux:2023",
		"rhel:9",
		// SUSE family
		"opensuse:15.5",
		// Arch
		"archlinux:latest",
		// Other
		"clearlinux:latest",
		"mageia:9",
		"altlinux:p10",
		"nixos:23.11",
		"guix:latest",
		"photon:4.0",
	}
	for _, img := range nonMinimalImages {
		class, _ := classifyImageMinimality(img)
		if class != imageNonMinimal {
			t.Errorf("classifyImageMinimality(%q) = %d, want imageNonMinimal", img, class)
		}
	}
}

func TestClassifyImageMinimality_NonMinimalPrefixes(t *testing.T) {
	prefixImages := []string{
		// SUSE variants
		"opensuse-leap:15.5",
		"opensuse-tumbleweed:latest",
		"suse:15",
		"sles:15",
		"sles15:latest",
		"bci-base:15.5",
		"bci-python:3.11",
		// Red Hat UBI
		"ubi8:latest",
		"ubi9:latest",
		"ubi8-minimal:latest", // "minimal" is in the name not the tag, so ubi prefix matches
		// CentOS variants
		"centos-stream:9",
		// Fedora variants
		"fedora-toolbox:39",
		// Rocky/Alma variants
		"rockylinux-minimal:9",
		"almalinux-minimal:9",
		// Oracle variants
		"oraclelinux-slim:9",
		// Photon variants
		"photon-build:4.0",
		// NixOS variants
		"nixos-unstable:latest",
	}
	for _, img := range prefixImages {
		class, _ := classifyImageMinimality(img)
		if class != imageNonMinimal {
			t.Errorf("classifyImageMinimality(%q) = %d, want imageNonMinimal", img, class)
		}
	}
}

func TestClassifyImageMinimality_Unknown(t *testing.T) {
	unknownImages := []string{
		"registry.example.com/myapp:v2",
		"nginx:1.25",
		"python:3.12",
		"node:22",
		"postgres:16",
		"mycompany/backend:latest",
		"",
	}
	for _, img := range unknownImages {
		class, _ := classifyImageMinimality(img)
		if class != imageUnknown {
			t.Errorf("classifyImageMinimality(%q) = %d, want imageUnknown", img, class)
		}
	}
}

func TestCheckImageMinimality_Findings(t *testing.T) {
	// Minimal → PASS
	findings := checkImageMinimality("alpine:3.19", "test")
	if len(findings) != 1 || findings[0].Status != types.StatusPass {
		t.Errorf("alpine:3.19 should PASS, got %v", findings)
	}

	// Non-minimal → WARN
	findings = checkImageMinimality("ubuntu:22.04", "test")
	if len(findings) != 1 || findings[0].Status != types.StatusWarn {
		t.Errorf("ubuntu:22.04 should WARN, got %v", findings)
	}
	if findings[0].Control.ID != "HOST-001" {
		t.Errorf("expected HOST-001, got %s", findings[0].Control.ID)
	}

	// Unknown → nil (skip)
	findings = checkImageMinimality("registry.example.com/myapp:v2", "test")
	if findings != nil {
		t.Errorf("custom image should return nil, got %v", findings)
	}
}
