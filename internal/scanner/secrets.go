package scanner

import (
	"bufio"
	"fmt"
	"math"
	"regexp"
	"strings"
	"sync"

	"https://github.com/kariemoorman/dockeraudit/internal/types"
)

// Confidence thresholds for scoring-based false positive detection.
const (
	confidenceFail = 0.7 // >= this → FAIL
	confidenceWarn = 0.3 // >= this → WARN
	// < confidenceWarn → skip entirely
)

// Initial confidence scores by detection method.
const (
	scoreRegex   = 1.0 // structural regex match (AKIA..., ghp_..., etc.)
	scorePrefix  = 0.8 // keyword prefix match (password, secret, token, etc.)
	scoreEntropy = 0.5 // entropy-only detection
)

// fpPattern pairs a regex with the penalty it applies when matched.
type fpPattern struct {
	re      *regexp.Regexp
	penalty float64
}

// SecretScanner holds compiled patterns and prefix trie for high performance
type SecretScanner struct {
	Prefixes   []string
	Regexes    map[string]*regexp.Regexp
	EntropyMin float64

	ImageName string
	Ctrl      types.Control

	falsePositivePatterns []fpPattern
	uuidPattern           *regexp.Regexp
	hashPatterns          map[string]*regexp.Regexp
}

// Package-level cached compiled regexes, initialized once via sync.Once.
var (
	compiledRegexes     map[string]*regexp.Regexp
	compiledPrefixes    []string
	compiledRegexesOnce sync.Once
)

func initCompiledPatterns() {
	compiledRegexesOnce.Do(func() {
		compiledPrefixes = []string{
			"password", "passwd", "secret", "api_key", "api-key",
			"token", "credential", "aws_secret", "private_key",
			"-----BEGIN", "authorization:", "bearer ",
		}
		compiledRegexes = map[string]*regexp.Regexp{
			// AWS
			"AWS_ACCESS_KEY":        regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
			"AWS_SECRET_KEY":        regexp.MustCompile(`(?i)aws(.{0,20})?['"][0-9a-zA-Z/+]{40}['"]`),
			"AWS_MWS_KEY":           regexp.MustCompile(`amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
			"AWS_SESSION_TOKEN":     regexp.MustCompile(`(?i)aws(.{0,20})?session(.{0,20})?token['"]?\s*[:=]\s*['"][A-Za-z0-9+/]{100,}['"]`),

			// GCP
			"GCP_API_KEY":           regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
			"GCP_SERVICE_ACCOUNT":   regexp.MustCompile(`"type":\s*"service_account"`),
			"GCP_OAUTH_TOKEN":       regexp.MustCompile(`ya29\.[0-9A-Za-z\-_]+`),

			// Azure
			"AZURE_CLIENT_SECRET":   regexp.MustCompile(`(?i)azure(.{0,20})?['"][0-9a-zA-Z~_\.-]{34}['"]`),
			"AZURE_CONNECTION_STR":  regexp.MustCompile(`(?i)(?:DefaultEndpointsProtocol|AccountName|AccountKey|BlobEndpoint)=`),
			"AZURE_STORAGE_KEY":     regexp.MustCompile(`(?i)DefaultEndpointsProtocol=https;AccountName=[a-z0-9]+;AccountKey=[A-Za-z0-9+/]{88}==`),

			// GitHub
			"GITHUB_TOKEN":          regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}`),
			"GITHUB_OAUTH":          regexp.MustCompile(`gho_[0-9a-zA-Z]{36}`),
			"GITHUB_APP_TOKEN":      regexp.MustCompile(`(ghu|ghs)_[0-9a-zA-Z]{36}`),
			"GITHUB_REFRESH_TOKEN":  regexp.MustCompile(`ghr_[0-9a-zA-Z]{76}`),
			"GITHUB_FINE_GRAINED":   regexp.MustCompile(`github_pat_[0-9a-zA-Z_]{82}`),

			// GitLab
			"GITLAB_TOKEN":          regexp.MustCompile(`glpat-[0-9a-zA-Z\-_]{20}`),
			"GITLAB_RUNNER_TOKEN":   regexp.MustCompile(`glrt-[0-9a-zA-Z\-_]{20}`),
			"GITLAB_PIPELINE_TOKEN": regexp.MustCompile(`glptt-[0-9a-zA-Z\-_]{40}`),

			// Bitbucket
			"BITBUCKET_CLIENT_ID":     regexp.MustCompile(`(?i)bitbucket(.{0,20})?['"][0-9a-zA-Z]{32}['"]`),
			"BITBUCKET_CLIENT_SECRET": regexp.MustCompile(`(?i)bitbucket(.{0,20})?secret['"]?\s*[:=]\s*['"][0-9a-zA-Z]{64}['"]`),

			// Slack
			"SLACK_TOKEN":     regexp.MustCompile(`xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[0-9a-zA-Z]{24,32}`),
			"SLACK_WEBHOOK":   regexp.MustCompile(`https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+`),
			"SLACK_BOT_TOKEN": regexp.MustCompile(`xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}`),

			// Stripe
			"STRIPE_KEY":            regexp.MustCompile(`(sk|pk)_(test|live)_[0-9a-zA-Z]{24,99}`),
			"STRIPE_RESTRICTED":     regexp.MustCompile(`rk_(test|live)_[0-9a-zA-Z]{24}`),
			"STRIPE_WEBHOOK_SECRET": regexp.MustCompile(`whsec_[0-9a-zA-Z]{32,}`),

			// PayPal
			"PAYPAL_CLIENT_ID":     regexp.MustCompile(`(?i)paypal(.{0,20})?['"][0-9a-zA-Z\-_]{80}['"]`),
			"PAYPAL_CLIENT_SECRET": regexp.MustCompile(`(?i)paypal(.{0,20})?secret['"]?\s*[:=]\s*['"][0-9a-zA-Z\-_]{80}['"]`),

			// Square
			"SQUARE_ACCESS_TOKEN": regexp.MustCompile(`sq0atp-[0-9A-Za-z\-_]{22}`),
			"SQUARE_OAUTH_SECRET": regexp.MustCompile(`sq0csp-[0-9A-Za-z\-_]{43}`),

			// SendGrid
			"SENDGRID_KEY": regexp.MustCompile(`SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}`),

			// Twilio
			"TWILIO_API_KEY":    regexp.MustCompile(`SK[0-9a-fA-F]{32}`),
			"TWILIO_SID":        regexp.MustCompile(`AC[a-zA-Z0-9_\-]{32}`),
			"TWILIO_AUTH_TOKEN": regexp.MustCompile(`(?i)twilio(.{0,20})?auth(.{0,20})?token['"]?\s*[:=]\s*['"][a-zA-Z0-9]{32}['"]`),

			// MailChimp
			"MAILCHIMP_KEY": regexp.MustCompile(`[0-9a-f]{32}-us[0-9]{1,2}`),

			// Mailgun
			"MAILGUN_API_KEY": regexp.MustCompile(`key-[0-9a-zA-Z]{32}`),

			// OpenAI
			"OPENAI_API_KEY": regexp.MustCompile(`sk-[A-Za-z0-9]{48}`),
			"OPENAI_ORG_KEY": regexp.MustCompile(`sk-org-[A-Za-z0-9]{48}`),

			// Anthropic
			"ANTHROPIC_KEY": regexp.MustCompile(`sk-ant-api[0-9]{2}-[A-Za-z0-9\-_]{95}`),

			// Hugging Face
			"HUGGINGFACE_TOKEN": regexp.MustCompile(`hf_[A-Za-z0-9]{34}`),

			// JWT
			"JWT_TOKEN": regexp.MustCompile(`eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*`),

			// OAuth
			"OAUTH_ACCESS_TOKEN": regexp.MustCompile(`(?i)oauth(.{0,20})?token['"]?\s*[:=]\s*['"][a-zA-Z0-9\-_]{20,}['"]`),
			"BEARER_TOKEN":       regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9\-_\.=]+`),

			// Private Keys
			"RSA_PRIVATE_KEY":       regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`),
			"OPENSSH_PRIVATE_KEY":   regexp.MustCompile(`-----BEGIN OPENSSH PRIVATE KEY-----`),
			"DSA_PRIVATE_KEY":       regexp.MustCompile(`-----BEGIN DSA PRIVATE KEY-----`),
			"EC_PRIVATE_KEY":        regexp.MustCompile(`-----BEGIN EC PRIVATE KEY-----`),
			"PGP_PRIVATE_KEY":       regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----`),
			"PRIVATE_KEY":           regexp.MustCompile(`-----BEGIN PRIVATE KEY-----`),
			"ENCRYPTED_PRIVATE_KEY": regexp.MustCompile(`-----BEGIN ENCRYPTED PRIVATE KEY-----`),

			// Certificates
			"CERTIFICATE":         regexp.MustCompile(`-----BEGIN CERTIFICATE-----`),
			"CERTIFICATE_REQUEST": regexp.MustCompile(`-----BEGIN CERTIFICATE REQUEST-----`),

			// Database URLs
			"POSTGRES_URL": regexp.MustCompile(`postgres(?:\+[a-zA-Z0-9_]+)?://[a-zA-Z0-9_\-]+:[^@\s]+@[a-zA-Z0-9\.\-]+:[0-9]+/[a-zA-Z0-9_\-]+`),
			"MYSQL_URL":    regexp.MustCompile(`mysql(?:\+[a-zA-Z0-9_]+)?://[a-zA-Z0-9_\-]+:[^@\s]+@[a-zA-Z0-9\.\-]+:[0-9]+/[a-zA-Z0-9_\-]+`),
			"MONGODB_URL":  regexp.MustCompile(`mongodb(?:\+srv)?://[a-zA-Z0-9_\-]+:[^@\s]+@[a-zA-Z0-9\.\-]+(?:,[a-zA-Z0-9\.\-]+)*(:[0-9]+)?/[a-zA-Z0-9_\-]+`),
			"REDIS_URL":    regexp.MustCompile(`redis(?:\+sentinel)?://[a-zA-Z0-9_\-]*:[^@\s]+@[a-zA-Z0-9\.\-]+:[0-9]+`),
			"SQLSERVER_URL": regexp.MustCompile(`mssql(?:\+[a-zA-Z0-9_]+)?://[a-zA-Z0-9_\-]+:[^@\s]+@[a-zA-Z0-9\.\-]+:[0-9]+`),
			"NEO4J_URL": regexp.MustCompile(`(bolt|neo4j)(\+s)?://[a-zA-Z0-9_\-]+:[^@\s]+@[a-zA-Z0-9\.\-]+(:[0-9]+)?`),
			"WEAVIATE_URL": regexp.MustCompile(`https://[a-zA-Z0-9_\-]+:[^@\s]+@[a-zA-Z0-9\.\-]+(:[0-9]+)?`),
			"ELASTICSEARCH_URL": regexp.MustCompile(`https?://[a-zA-Z0-9_\-]+:[^@\s]+@[a-zA-Z0-9\.\-]+:[0-9]+`),

			// Discord
			"DISCORD_WEBHOOK": regexp.MustCompile(`https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+`),
			"DISCORD_BOT_TOKEN": regexp.MustCompile(`[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}`),

			// HashiCorp Vault
			"VAULT_TOKEN":         regexp.MustCompile(`hvs\.[A-Za-z0-9_-]{24,}`),
			"VAULT_SERVICE_TOKEN": regexp.MustCompile(`hvb\.[A-Za-z0-9_-]{24,}`),

			// Terraform Cloud
			"TERRAFORM_CLOUD_TOKEN": regexp.MustCompile(`[a-zA-Z0-9]{14}\.atlasv1\.[a-zA-Z0-9_-]{67}`),

			// DigitalOcean
			"DIGITALOCEAN_TOKEN":         regexp.MustCompile(`dop_v1_[a-f0-9]{64}`),
			"DIGITALOCEAN_OAUTH_TOKEN":   regexp.MustCompile(`doo_v1_[a-f0-9]{64}`),
			"DIGITALOCEAN_REFRESH_TOKEN": regexp.MustCompile(`dor_v1_[a-f0-9]{64}`),

			// Doppler
			"DOPPLER_TOKEN": regexp.MustCompile(`dp\.st\.[a-zA-Z0-9_-]{43,}`),

			// Docker
			"DOCKER_AUTH":   regexp.MustCompile(`"auth"\s*:\s*"[A-Za-z0-9+/=]{10,}"`),
			"DOCKER_CONFIG": regexp.MustCompile(`"auths"\s*:\s*\{`),

			// Heroku
			"HEROKU_API_KEY": regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`),

			// NPM
			"NPM_TOKEN": regexp.MustCompile(`npm_[a-zA-Z0-9]{36}`),

			// PyPI
			"PYPI_TOKEN": regexp.MustCompile(`pypi-[A-Za-z0-9\-_]{84,}`),

			// Generic Password Patterns
			"PASSWORD_IN_URL":       regexp.MustCompile(`[a-zA-Z]{3,10}://[^:\/\s]+:[^@\/\s]+@`),
			"PASSWORD_ASSIGNMENT":   regexp.MustCompile(`(?i)(password|passwd|pwd|secret|api_key|apikey|access_token|auth_token|private_key)\s*[=:]\s*['"][^'"]{8,}['"]`),
			"API_KEY_ASSIGNMENT":    regexp.MustCompile(`(?i)api[_\-]?key\s*[=:]\s*['"][a-zA-Z0-9\-_]{16,}['"]`),
			"SECRET_KEY_ASSIGNMENT": regexp.MustCompile(`(?i)secret[_\-]?key\s*[=:]\s*['"][a-zA-Z0-9\-_]{16,}['"]`),
		}
	})
}

// Package-level cached compiled false-positive filter patterns, initialized once via sync.Once.
var (
	compiledFPPatterns  []fpPattern
	compiledUUIDPattern *regexp.Regexp
	compiledHashPatterns map[string]*regexp.Regexp
	compiledFPOnce      sync.Once
)

func initCompiledFPPatterns() {
	compiledFPOnce.Do(func() {
		type entry struct {
			pattern string
			penalty float64
		}

		entries := []entry{
			// Strong indicators — value is almost certainly a placeholder
			{`(?i)your[_-]?key[_-]?here`, 0.9},
			{`(?i)replace[_-]?with`, 0.9},
			{`(?i)insert[_-]?your`, 0.9},
			{`(?i)put[_-]?your[_-]?`, 0.9},
			{`(?i)add[_-]?your[_-]?`, 0.9},
			{`(?i)<your[_-]`, 0.9},               // <your-api-key>
			{`(?i)\$\{[A-Z_]+\}`, 0.9},           // ${VAR_NAME} template ref

			// Medium indicators — common in docs/placeholder values
			{`(?i)placeholder`, 0.8},
			{`(?i)changeme`, 0.8},
			{`(?i)test[_-]?key`, 0.7},

			// Weak indicators — words that can appear as substrings in real keys
			{`(?i)example`, 0.5},
			{`(?i)dummy`, 0.5},
			{`(?i)sample`, 0.5},
			{`(?i)fake`, 0.5},
			{`(?i)todo`, 0.4},
			{`(?i)fixme`, 0.4},
			{`(?i)xxxx+`, 0.4},
			{`(?i)0000+`, 0.3},
			{`(?i)1234+`, 0.3},
		}

		compiledFPPatterns = make([]fpPattern, 0, len(entries))
		for _, e := range entries {
			compiledFPPatterns = append(compiledFPPatterns, fpPattern{
				re:      regexp.MustCompile(e.pattern),
				penalty: e.penalty,
			})
		}

		compiledUUIDPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

		compiledHashPatterns = map[string]*regexp.Regexp{
			"SHA1":       regexp.MustCompile(`(?i)^[0-9a-f]{40}$`),
			"SHA256":     regexp.MustCompile(`(?i)^[0-9a-f]{64}$`),
			"MD5":        regexp.MustCompile(`(?i)^[0-9a-f]{32}$`),
			"GIT_COMMIT": regexp.MustCompile(`(?i)^[0-9a-f]{40}$`),
		}
	})
}

// NewSecretScanner initializes all secret rules
func NewSecretScanner(imageName string, ctrl types.Control) *SecretScanner {
	initCompiledPatterns()
	initCompiledFPPatterns()

	scanner := &SecretScanner{
		Prefixes:              compiledPrefixes,
		Regexes:               compiledRegexes,
		EntropyMin:            5.5,
		ImageName:             imageName,
		Ctrl:                  ctrl,
		falsePositivePatterns: compiledFPPatterns,
		uuidPattern:           compiledUUIDPattern,
		hashPatterns:          compiledHashPatterns,
	}
	return scanner
}

// scoredFinding returns a FAIL, WARN, or nil finding based on the confidence
// score after false-positive penalty is applied.
func (s *SecretScanner) scoredFinding(initialScore float64, value, detail, evidence string) *types.Finding {
	penalty := s.fpPenalty(value)
	finalScore := initialScore - penalty

	if finalScore >= confidenceFail {
		f := fail(s.Ctrl, s.ImageName, detail, evidence, s.Ctrl.Remediation)
		return &f
	}
	if finalScore >= confidenceWarn {
		f := warn(s.Ctrl, s.ImageName,
			fmt.Sprintf("[low confidence: %.0f%%] %s", finalScore*100, detail),
			evidence)
		return &f
	}
	return nil // penalty too high, skip
}

// CheckSecrets scans history for secrets. Returns the first finding (FAIL or
// WARN) or PASS if nothing is detected. Confidence scoring ensures that a
// structural regex match containing a false-positive substring (e.g.
// AKIAIOSFODNN7EXAMPLE) is reported as a warning rather than silently dropped.
func (s *SecretScanner) CheckSecrets(history string) types.Finding {
	scanner := bufio.NewScanner(strings.NewReader(history))
	lineNum := 0

	// Collect warnings so we can return the first FAIL immediately,
	// or fall back to the first WARN if no FAIL was found.
	var firstWarn *types.Finding

	for scanner.Scan() {
		line := scanner.Text()
		lineNum++
		lower := strings.ToLower(line)

		// Prefix scan (medium confidence)
		for _, prefix := range s.Prefixes {
			if strings.Contains(lower, strings.ToLower(prefix)) {
				f := s.scoredFinding(scorePrefix, line,
					fmt.Sprintf("Potential secret indicator %q found at line %d", prefix, lineNum),
					"docker history --no-trunc output")
				if f != nil {
					if f.Status == types.StatusFail {
						return *f
					}
					if firstWarn == nil {
						firstWarn = f
					}
				}
			}
		}

		// Regex scan (high confidence)
		for name, pattern := range s.Regexes {
			if match := pattern.FindString(line); match != "" {
				f := s.scoredFinding(scoreRegex, match,
					fmt.Sprintf("Detected potential %s at line %d", name, lineNum),
					"docker history --no-trunc output")
				if f != nil {
					if f.Status == types.StatusFail {
						return *f
					}
					if firstWarn == nil {
						firstWarn = f
					}
				}
			}
		}

		// High-entropy scan (lower confidence)
		for _, word := range strings.Fields(line) {
			if len(word) >= 20 && calculateEntropy(word) > s.EntropyMin {
				f := s.scoredFinding(scoreEntropy, word,
					fmt.Sprintf("High-entropy string detected at line %d (entropy=%.2f)", lineNum, calculateEntropy(word)),
					"docker history --no-trunc output")
				if f != nil {
					if f.Status == types.StatusFail {
						return *f
					}
					if firstWarn == nil {
						firstWarn = f
					}
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return errFinding(s.Ctrl, s.ImageName,
			fmt.Sprintf("scanner error: %v", err))
	}

	if firstWarn != nil {
		return *firstWarn
	}
	return pass(s.Ctrl, s.ImageName, "No obvious secret patterns in image history")
}

// fpPenalty returns the total false-positive penalty for a value (0.0–1.0+).
// UUIDs and hashes return 1.0 (guaranteed false positive).
func (s *SecretScanner) fpPenalty(value string) float64 {
	trimmed := strings.TrimSpace(value)

	// UUID — full-value match → definite false positive
	if s.uuidPattern.MatchString(trimmed) {
		return 1.0
	}
	// Hash — full-value match → definite false positive
	for _, pattern := range s.hashPatterns {
		if pattern.MatchString(trimmed) {
			return 1.0
		}
	}

	// Accumulate penalties from substring/pattern indicators
	var total float64
	for _, fp := range s.falsePositivePatterns {
		if fp.re.MatchString(trimmed) {
			total += fp.penalty
		}
	}
	if total > 1.0 {
		total = 1.0
	}
	return total
}

// isFalsePositive is a convenience wrapper that returns true only when the
// penalty is high enough to fully suppress even a low-confidence match.
// For nuanced handling, callers should use fpPenalty + confidence scoring.
func (s *SecretScanner) isFalsePositive(value string) bool {
	return s.fpPenalty(value) >= 1.0
}

// SecretMatch represents a single secret detection result.
type SecretMatch struct {
	PatternName string
	Match       string
	Line        int
	Entropy     float64
	Confidence  float64 // final score after false-positive penalty
}

// CheckLine checks a single line against all secret patterns and returns all matches.
// Matches that score below confidenceWarn after false-positive penalties are excluded.
func (s *SecretScanner) CheckLine(value string) []SecretMatch {
	var matches []SecretMatch

	// Regex scan (high confidence)
	for name, pattern := range s.Regexes {
		if match := pattern.FindString(value); match != "" {
			score := scoreRegex - s.fpPenalty(match)
			if score >= confidenceWarn {
				matches = append(matches, SecretMatch{
					PatternName: name,
					Match:       match,
					Confidence:  score,
				})
			}
		}
	}

	// High-entropy scan (only if no pattern matched)
	if len(matches) == 0 {
		for _, word := range strings.Fields(value) {
			if len(word) >= 20 {
				entropy := calculateEntropy(word)
				if entropy > s.EntropyMin {
					score := scoreEntropy - s.fpPenalty(word)
					if score >= confidenceWarn {
						matches = append(matches, SecretMatch{
							PatternName: "HIGH_ENTROPY",
							Match:       word,
							Entropy:     entropy,
							Confidence:  score,
						})
					}
				}
			}
		}
	}

	return matches
}

// CheckSecretsMulti scans content and returns all findings (not just the first).
// Uses confidence scoring: high-confidence matches → FAIL, reduced → WARN.
func (s *SecretScanner) CheckSecretsMulti(content string) []types.Finding {
	var findings []types.Finding
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(strings.NewReader(content))
	lineNum := 0

	for scanner.Scan() {
		line := scanner.Text()
		lineNum++
		lower := strings.ToLower(line)

		// Prefix scan
		for _, prefix := range s.Prefixes {
			if strings.Contains(lower, strings.ToLower(prefix)) {
				key := fmt.Sprintf("prefix:%s", prefix)
				if !seen[key] {
					f := s.scoredFinding(scorePrefix, line,
						fmt.Sprintf("Potential secret indicator %q found at line %d", prefix, lineNum),
						fmt.Sprintf("line %d", lineNum))
					if f != nil {
						seen[key] = true
						findings = append(findings, *f)
					}
				}
			}
		}

		// Regex scan
		for name, pattern := range s.Regexes {
			if match := pattern.FindString(line); match != "" {
				key := fmt.Sprintf("regex:%s", name)
				if !seen[key] {
					f := s.scoredFinding(scoreRegex, match,
						fmt.Sprintf("Detected potential %s at line %d", name, lineNum),
						fmt.Sprintf("line %d", lineNum))
					if f != nil {
						seen[key] = true
						findings = append(findings, *f)
					}
				}
			}
		}

		// High-entropy scan
		for _, word := range strings.Fields(line) {
			if len(word) >= 20 && calculateEntropy(word) > s.EntropyMin {
				key := fmt.Sprintf("entropy:%d", lineNum)
				if !seen[key] {
					f := s.scoredFinding(scoreEntropy, word,
						fmt.Sprintf("High-entropy string detected at line %d (entropy=%.2f)", lineNum, calculateEntropy(word)),
						fmt.Sprintf("line %d", lineNum))
					if f != nil {
						seen[key] = true
						findings = append(findings, *f)
					}
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		findings = append(findings, errFinding(s.Ctrl, s.ImageName,
			fmt.Sprintf("scanner error: %v", err)))
	}

	return findings
}

// calculateEntropy calculates Shannon entropy of a string
func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}
	freq := make(map[rune]float64)
	for _, c := range s {
		freq[c]++
	}
	length := float64(len(s))
	var entropy float64
	for _, count := range freq {
		p := count / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}
