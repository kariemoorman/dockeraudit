package scanner

import (
	"testing"

	"github.com/kariemoorman/dockeraudit/internal/types"
)

// newTestSecretScanner creates a SecretScanner for testing.
func newTestSecretScanner() *SecretScanner {
	ctrl := controlByID("IMAGE-002")
	return NewSecretScanner("test-image", ctrl)
}

// assertDetected checks that the finding is either FAIL or WARN (not PASS/SKIP).
func assertDetected(t *testing.T, finding types.Finding, label string) {
	t.Helper()
	if finding.Status == types.StatusPass || finding.Status == types.StatusSkipped {
		t.Errorf("%s: expected detection (FAIL or WARN), got %s: %s", label, finding.Status, finding.Detail)
	}
}

// ── CheckSecrets: high-confidence patterns → FAIL ─────────────────────────────

func TestCheckSecrets_GitHubToken(t *testing.T) {
	s := newTestSecretScanner()
	finding := s.CheckSecrets("GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12")
	if finding.Status != types.StatusFail {
		t.Errorf("expected FAIL for clean GitHub token, got %s: %s", finding.Status, finding.Detail)
	}
}

func TestCheckSecrets_GitLabToken(t *testing.T) {
	s := newTestSecretScanner()
	finding := s.CheckSecrets("export GITLAB_TOKEN=glpat-abcdefghijklmnopqrst")
	if finding.Status != types.StatusFail {
		t.Errorf("expected FAIL for GitLab token, got %s: %s", finding.Status, finding.Detail)
	}
}

func TestCheckSecrets_StripeKey(t *testing.T) {
	s := newTestSecretScanner()
	finding := s.CheckSecrets("STRIPE_SECRET_KEY=sk_live_abcdefghijklmnopqrstuvwx")
	if finding.Status != types.StatusFail {
		t.Errorf("expected FAIL for Stripe key, got %s: %s", finding.Status, finding.Detail)
	}
}

func TestCheckSecrets_RSAPrivateKey(t *testing.T) {
	s := newTestSecretScanner()
	finding := s.CheckSecrets("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK...")
	if finding.Status != types.StatusFail {
		t.Errorf("expected FAIL for RSA private key, got %s: %s", finding.Status, finding.Detail)
	}
}

func TestCheckSecrets_PrivateKey(t *testing.T) {
	s := newTestSecretScanner()
	finding := s.CheckSecrets("-----BEGIN PRIVATE KEY-----\nMIIEvgIBADAN...")
	if finding.Status != types.StatusFail {
		t.Errorf("expected FAIL for private key, got %s: %s", finding.Status, finding.Detail)
	}
}

func TestCheckSecrets_DatabaseURL(t *testing.T) {
	s := newTestSecretScanner()
	finding := s.CheckSecrets("DATABASE_URL=postgres://admin:s3cretP@ss@db.host.com:5432/mydb")
	if finding.Status != types.StatusFail {
		t.Errorf("expected FAIL for database URL, got %s: %s", finding.Status, finding.Detail)
	}
}

func TestCheckSecrets_MongoURL(t *testing.T) {
	s := newTestSecretScanner()
	finding := s.CheckSecrets("MONGO_URL=mongodb://root:password123@mongo.internal:27017/appdb")
	if finding.Status != types.StatusFail {
		t.Errorf("expected FAIL for MongoDB URL, got %s: %s", finding.Status, finding.Detail)
	}
}

func TestCheckSecrets_SendGridKey(t *testing.T) {
	s := newTestSecretScanner()
	finding := s.CheckSecrets("SENDGRID_API_KEY=SG.abcdefghijklmnopqrstuv.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqr")
	if finding.Status != types.StatusFail {
		t.Errorf("expected FAIL for SendGrid key, got %s: %s", finding.Status, finding.Detail)
	}
}

func TestCheckSecrets_OpenAIKey(t *testing.T) {
	s := newTestSecretScanner()
	finding := s.CheckSecrets("OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv")
	if finding.Status != types.StatusFail {
		t.Errorf("expected FAIL for OpenAI key, got %s: %s", finding.Status, finding.Detail)
	}
}

func TestCheckSecrets_NPMToken(t *testing.T) {
	s := newTestSecretScanner()
	finding := s.CheckSecrets("//registry.npmjs.org/:_authToken=npm_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12")
	if finding.Status != types.StatusFail {
		t.Errorf("expected FAIL for NPM token, got %s: %s", finding.Status, finding.Detail)
	}
}

func TestCheckSecrets_GCPApiKey(t *testing.T) {
	s := newTestSecretScanner()
	finding := s.CheckSecrets("GCP_KEY=AIzaSyCdBfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjK")
	if finding.Status != types.StatusFail {
		t.Errorf("expected FAIL for GCP API key, got %s: %s", finding.Status, finding.Detail)
	}
}

func TestCheckSecrets_PasswordAssignment(t *testing.T) {
	s := newTestSecretScanner()
	finding := s.CheckSecrets(`password = "SuperSecretPass123!"`)
	if finding.Status != types.StatusFail {
		t.Errorf("expected FAIL for password assignment, got %s: %s", finding.Status, finding.Detail)
	}
}

func TestCheckSecrets_BearerToken(t *testing.T) {
	s := newTestSecretScanner()
	finding := s.CheckSecrets("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test")
	if finding.Status != types.StatusFail {
		t.Errorf("expected FAIL for bearer token, got %s: %s", finding.Status, finding.Detail)
	}
}

// ── Reduced-confidence: structural regex hit + FP indicator → WARN ────────────

func TestCheckSecrets_AWSKeyWithExample_Warn(t *testing.T) {
	s := newTestSecretScanner()
	// AKIAIOSFODNN7EXAMPLE is a valid AKIA pattern but contains "EXAMPLE"
	// regex score 1.0 − 0.5 penalty = 0.5 → WARN (not silently dropped)
	finding := s.CheckSecrets("ENV AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")
	assertDetected(t, finding, "AWS key with EXAMPLE")
	if finding.Status != types.StatusWarn {
		t.Errorf("expected WARN for AWS key containing 'EXAMPLE', got %s: %s", finding.Status, finding.Detail)
	}
}

func TestCheckSecrets_SlackWebhookWithZeros_Warn(t *testing.T) {
	s := newTestSecretScanner()
	// Slack webhook structural match, but contains "00000000" and "XXXX..."
	finding := s.CheckSecrets("WEBHOOK=https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX")
	assertDetected(t, finding, "Slack webhook with zeros/X's")
}

func TestCheckSecrets_AWSKeyClean_Fail(t *testing.T) {
	s := newTestSecretScanner()
	// Same pattern, no FP indicators → full FAIL
	finding := s.CheckSecrets("ENV AWS_ACCESS_KEY_ID=AKIAIOSFODNN7ABCDEFG")
	if finding.Status != types.StatusFail {
		t.Errorf("expected FAIL for clean AWS key, got %s: %s", finding.Status, finding.Detail)
	}
}

// ── Clean input: PASS expected ────────────────────────────────────────────────

func TestCheckSecrets_CleanHistory_Pass(t *testing.T) {
	s := newTestSecretScanner()
	history := `FROM golang:1.22-alpine
RUN apk add --no-cache git
COPY . /app
WORKDIR /app
RUN go build -o /bin/app
CMD ["/bin/app"]`
	finding := s.CheckSecrets(history)
	if finding.Status != types.StatusPass {
		t.Errorf("expected PASS for clean history, got %s: %s", finding.Status, finding.Detail)
	}
}

func TestCheckSecrets_EmptyInput_Pass(t *testing.T) {
	s := newTestSecretScanner()
	finding := s.CheckSecrets("")
	if finding.Status != types.StatusPass {
		t.Errorf("expected PASS for empty input, got %s: %s", finding.Status, finding.Detail)
	}
}

// ── Confidence scoring (fpPenalty) ────────────────────────────────────────────

func TestFpPenalty_UUID_FullPenalty(t *testing.T) {
	s := newTestSecretScanner()
	p := s.fpPenalty("550e8400-e29b-41d4-a716-446655440000")
	if p < 1.0 {
		t.Errorf("expected penalty >= 1.0 for UUID, got %f", p)
	}
}

func TestFpPenalty_SHA256_FullPenalty(t *testing.T) {
	s := newTestSecretScanner()
	p := s.fpPenalty("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	if p < 1.0 {
		t.Errorf("expected penalty >= 1.0 for SHA-256 hash, got %f", p)
	}
}

func TestFpPenalty_MD5_FullPenalty(t *testing.T) {
	s := newTestSecretScanner()
	p := s.fpPenalty("d41d8cd98f00b204e9800998ecf8427e")
	if p < 1.0 {
		t.Errorf("expected penalty >= 1.0 for MD5 hash, got %f", p)
	}
}

func TestFpPenalty_StrongPlaceholder_HighPenalty(t *testing.T) {
	s := newTestSecretScanner()
	cases := []struct {
		value   string
		minPen  float64
	}{
		{"your_key_here", 0.9},
		{"replace_with_real_token", 0.9},
		{"insert_your_api_key", 0.9},
	}
	for _, tc := range cases {
		p := s.fpPenalty(tc.value)
		if p < tc.minPen {
			t.Errorf("fpPenalty(%q) = %f, want >= %f", tc.value, p, tc.minPen)
		}
	}
}

func TestFpPenalty_WeakIndicator_ModeratePenalty(t *testing.T) {
	s := newTestSecretScanner()
	cases := []struct {
		value  string
		minPen float64
		maxPen float64
	}{
		{"AKIAIOSFODNN7EXAMPLE", 0.3, 0.7},  // "example" → 0.5 penalty
		{"dummy_value", 0.3, 0.7},            // "dummy" → 0.5 penalty
	}
	for _, tc := range cases {
		p := s.fpPenalty(tc.value)
		if p < tc.minPen || p > tc.maxPen {
			t.Errorf("fpPenalty(%q) = %f, want between %f and %f", tc.value, p, tc.minPen, tc.maxPen)
		}
	}
}

func TestFpPenalty_RealKey_ZeroPenalty(t *testing.T) {
	s := newTestSecretScanner()
	cases := []string{
		"AKIAIOSFODNN7ABCDEFG",
		"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12",
		"sk_live_abcdefghijklmnopqrstuvwx",
	}
	for _, v := range cases {
		p := s.fpPenalty(v)
		if p > 0.0 {
			t.Errorf("fpPenalty(%q) = %f, want 0.0 for clean value", v, p)
		}
	}
}

func TestFpPenalty_MultipleIndicators_Stack(t *testing.T) {
	s := newTestSecretScanner()
	// "changeme" (0.8) + "test_key" (0.7) should stack and cap at 1.0
	p := s.fpPenalty("changeme_test_key")
	if p < 1.0 {
		t.Errorf("expected stacked penalty >= 1.0, got %f", p)
	}
}

// ── isFalsePositive: only true for >= 1.0 penalty ────────────────────────────

func TestIsFalsePositive_UUID(t *testing.T) {
	s := newTestSecretScanner()
	if !s.isFalsePositive("550e8400-e29b-41d4-a716-446655440000") {
		t.Error("expected UUID to be a full false positive")
	}
}

func TestIsFalsePositive_SHA256(t *testing.T) {
	s := newTestSecretScanner()
	if !s.isFalsePositive("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") {
		t.Error("expected SHA-256 hash to be a full false positive")
	}
}

func TestIsFalsePositive_RealKey_NotFlagged(t *testing.T) {
	s := newTestSecretScanner()
	// A real AWS key with "EXAMPLE" has penalty 0.5 which is < 1.0
	if s.isFalsePositive("AKIAIOSFODNN7EXAMPLE") {
		t.Error("AKIAIOSFODNN7EXAMPLE should NOT be a full false positive — only penalized")
	}
}

func TestIsFalsePositive_StackedPlaceholder_IsFP(t *testing.T) {
	s := newTestSecretScanner()
	// Multiple strong indicators accumulate to >= 1.0
	if !s.isFalsePositive("changeme_test_key") {
		t.Error("stacked placeholder indicators should be a full false positive")
	}
}

// ── CheckLine: multi-match mode ───────────────────────────────────────────────

func TestCheckLine_AWSKey(t *testing.T) {
	s := newTestSecretScanner()
	matches := s.CheckLine("AKIAIOSFODNN7EXAMPLE")
	if len(matches) == 0 {
		t.Fatal("expected at least one match for AWS access key (even with reduced confidence)")
	}
	found := false
	for _, m := range matches {
		if m.PatternName == "AWS_ACCESS_KEY" {
			found = true
			if m.Confidence >= confidenceFail {
				t.Errorf("expected reduced confidence for key with 'EXAMPLE', got %.2f", m.Confidence)
			}
		}
	}
	if !found {
		t.Error("expected AWS_ACCESS_KEY pattern match")
	}
}

func TestCheckLine_CleanAWSKey(t *testing.T) {
	s := newTestSecretScanner()
	matches := s.CheckLine("AKIAIOSFODNN7ABCDEFG")
	if len(matches) == 0 {
		t.Fatal("expected match for clean AWS key")
	}
	for _, m := range matches {
		if m.PatternName == "AWS_ACCESS_KEY" && m.Confidence < confidenceFail {
			t.Errorf("expected full confidence for clean key, got %.2f", m.Confidence)
		}
	}
}

func TestCheckLine_NoMatch(t *testing.T) {
	s := newTestSecretScanner()
	matches := s.CheckLine("hello world")
	if len(matches) != 0 {
		t.Errorf("expected no matches for clean input, got %d", len(matches))
	}
}

func TestCheckLine_FalsePositiveSkipped(t *testing.T) {
	s := newTestSecretScanner()
	// "your_key_here" has penalty 0.9, "placeholder" has penalty 0.8 → stacked > 1.0
	// Even a regex match would score 1.0 - 1.0+ = < 0 → skipped
	matches := s.CheckLine("your_key_here_placeholder")
	if len(matches) != 0 {
		t.Errorf("expected no matches for heavy false positive, got %d", len(matches))
	}
}

// ── CheckSecretsMulti: returns all findings ───────────────────────────────────

func TestCheckSecretsMulti_MultipleSecrets(t *testing.T) {
	s := newTestSecretScanner()
	content := `ENV AWS_ACCESS_KEY_ID=AKIAIOSFODNN7ABCDEFG
ENV GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12
-----BEGIN RSA PRIVATE KEY-----`
	findings := s.CheckSecretsMulti(content)
	if len(findings) < 3 {
		t.Errorf("expected at least 3 findings for multi-secret content, got %d", len(findings))
		for _, f := range findings {
			t.Logf("  finding: %s %s: %s", f.Status, f.Control.ID, f.Detail)
		}
	}
}

func TestCheckSecretsMulti_MixedConfidence(t *testing.T) {
	s := newTestSecretScanner()
	// Line 1 has "EXAMPLE" → reduced confidence
	// Line 2 is clean → full confidence
	content := `AKIAIOSFODNN7EXAMPLE
ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12`
	findings := s.CheckSecretsMulti(content)

	var hasWarn, hasFail bool
	for _, f := range findings {
		if f.Status == types.StatusWarn {
			hasWarn = true
		}
		if f.Status == types.StatusFail {
			hasFail = true
		}
	}
	if !hasWarn {
		t.Error("expected at least one WARN finding for EXAMPLE-containing key")
	}
	if !hasFail {
		t.Error("expected at least one FAIL finding for clean GitHub token")
	}
}

func TestCheckSecretsMulti_NoSecrets(t *testing.T) {
	s := newTestSecretScanner()
	findings := s.CheckSecretsMulti("RUN apt-get update && apt-get install -y curl")
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean content, got %d", len(findings))
	}
}

// ── New secret patterns (session 3) ───────────────────────────────────────────

func TestCheckSecrets_VaultToken(t *testing.T) {
	s := newTestSecretScanner()
	finding := s.CheckSecrets("VAULT_TOKEN=hvs.CAESIJlGBPsPfA8wTezQBWheH6NI7IYXABCDEFGHIJKLmnop")
	if finding.Status != types.StatusFail {
		t.Errorf("expected FAIL for Vault token, got %s: %s", finding.Status, finding.Detail)
	}
}

func TestCheckSecrets_VaultBatchToken(t *testing.T) {
	s := newTestSecretScanner()
	finding := s.CheckSecrets("VAULT_TOKEN=hvb.AAAAAQKFMGhaTjA0eDFrcTI3ABCDEFGHIJKLMNOP")
	if finding.Status != types.StatusFail {
		t.Errorf("expected FAIL for Vault batch token, got %s: %s", finding.Status, finding.Detail)
	}
}

func TestCheckSecrets_TerraformCloudToken(t *testing.T) {
	s := newTestSecretScanner()
	finding := s.CheckSecrets("TFE_TOKEN=aBcDeFgHiJkLmN.atlasv1.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH")
	if finding.Status != types.StatusFail {
		t.Errorf("expected FAIL for Terraform Cloud token, got %s: %s", finding.Status, finding.Detail)
	}
}

func TestCheckSecrets_DigitalOceanToken(t *testing.T) {
	s := newTestSecretScanner()
	finding := s.CheckSecrets("DO_TOKEN=dop_v1_" + "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")
	if finding.Status != types.StatusFail {
		t.Errorf("expected FAIL for DigitalOcean token, got %s: %s", finding.Status, finding.Detail)
	}
}

func TestCheckSecrets_DopplerToken(t *testing.T) {
	s := newTestSecretScanner()
	finding := s.CheckSecrets("DOPPLER_TOKEN=dp.st.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq")
	if finding.Status != types.StatusFail {
		t.Errorf("expected FAIL for Doppler token, got %s: %s", finding.Status, finding.Detail)
	}
}

func TestCheckSecrets_DiscordWebhook(t *testing.T) {
	s := newTestSecretScanner()
	finding := s.CheckSecrets("WEBHOOK=https://discord.com/api/webhooks/1234567890/ABCDEFGHIJKLMNOPqrstuvwxyz0123456789_-ABCDEFGHIJKLMNOPqrstuvwx")
	if finding.Status != types.StatusFail {
		t.Errorf("expected FAIL for Discord webhook, got %s: %s", finding.Status, finding.Detail)
	}
}

func TestCheckLine_VaultToken(t *testing.T) {
	s := newTestSecretScanner()
	matches := s.CheckLine("hvs.CAESIJlGBPsPfA8wTezQBWheH6NI7IYX")
	found := false
	for _, m := range matches {
		if m.PatternName == "VAULT_TOKEN" {
			found = true
		}
	}
	if !found {
		t.Error("expected VAULT_TOKEN pattern match")
	}
}

func TestCheckLine_DigitalOceanToken(t *testing.T) {
	s := newTestSecretScanner()
	matches := s.CheckLine("dop_v1_" + "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")
	found := false
	for _, m := range matches {
		if m.PatternName == "DIGITALOCEAN_TOKEN" {
			found = true
		}
	}
	if !found {
		t.Error("expected DIGITALOCEAN_TOKEN pattern match")
	}
}

func TestCheckLine_DopplerToken(t *testing.T) {
	s := newTestSecretScanner()
	matches := s.CheckLine("dp.st.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq")
	found := false
	for _, m := range matches {
		if m.PatternName == "DOPPLER_TOKEN" {
			found = true
		}
	}
	if !found {
		t.Error("expected DOPPLER_TOKEN pattern match")
	}
}

// ── Entropy calculation ───────────────────────────────────────────────────────

func TestCalculateEntropy_EmptyString(t *testing.T) {
	e := calculateEntropy("")
	if e != 0.0 {
		t.Errorf("expected 0.0 entropy for empty string, got %f", e)
	}
}

func TestCalculateEntropy_SingleChar(t *testing.T) {
	e := calculateEntropy("aaaa")
	if e != 0.0 {
		t.Errorf("expected 0.0 entropy for repeated char, got %f", e)
	}
}

func TestCalculateEntropy_HighEntropy(t *testing.T) {
	e := calculateEntropy("aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7cD9eF")
	if e < 4.0 {
		t.Errorf("expected high entropy (>4.0) for random-looking string, got %f", e)
	}
}

func TestCalculateEntropy_LowEntropy(t *testing.T) {
	e := calculateEntropy("aaaaabbbbb")
	if e > 2.0 {
		t.Errorf("expected low entropy (<2.0) for repetitive string, got %f", e)
	}
}
