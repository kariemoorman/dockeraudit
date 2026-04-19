package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strings"

	"github.com/kariemoorman/dockeraudit/internal/types"

	"gopkg.in/yaml.v3"
)

// K8sScanner scans Kubernetes manifests or live cluster state.
type K8sScanner struct {
	ManifestPaths []string // local file paths or directories
	Kubeconfig    string
	Namespaces    []string // if empty, scans all
	LiveCluster   bool     // if true, scan live cluster via kubectl
}

func NewK8sScanner() *K8sScanner {
	return &K8sScanner{}
}

// kubeObject is a minimal representation of any Kubernetes resource.
type kubeObject struct {
	APIVersion string          `json:"apiVersion" yaml:"apiVersion"`
	Kind       string          `json:"kind" yaml:"kind"`
	Metadata   kubeObjectMeta  `json:"metadata" yaml:"metadata"`
	Spec       json.RawMessage `json:"spec" yaml:"spec"`
	Rules      json.RawMessage `json:"rules" yaml:"rules"` // Role/ClusterRole rules
	Type       string          `json:"type" yaml:"type"`    // Secret type
	Data       json.RawMessage `json:"data" yaml:"data"`    // Secret data
	StringData json.RawMessage `json:"stringData" yaml:"stringData"` // Secret stringData
}

type kubeObjectMeta struct {
	Name        string            `json:"name" yaml:"name"`
	Namespace   string            `json:"namespace" yaml:"namespace"`
	Annotations map[string]string `json:"annotations" yaml:"annotations"`
}

// podSpecWrapper allows uniform access to pod specs from Pod, Deployment, DaemonSet, etc.
type podSpec struct {
	HostPID                       bool        `json:"hostPID" yaml:"hostPID"`
	HostIPC                       bool        `json:"hostIPC" yaml:"hostIPC"`
	HostNetwork                   bool        `json:"hostNetwork" yaml:"hostNetwork"`
	Containers                    []container `json:"containers" yaml:"containers"`
	InitContainers                []container `json:"initContainers" yaml:"initContainers"`
	Volumes                       []volume    `json:"volumes" yaml:"volumes"`
	SecurityContext               *podSecCtx  `json:"securityContext" yaml:"securityContext"`
	AutomountServiceAccountToken  *bool       `json:"automountServiceAccountToken" yaml:"automountServiceAccountToken"`
	Affinity                      *affinity   `json:"affinity" yaml:"affinity"`
	TopologySpreadConstraints     []interface{} `json:"topologySpreadConstraints" yaml:"topologySpreadConstraints"`
}

type affinity struct {
	PodAntiAffinity *interface{} `json:"podAntiAffinity" yaml:"podAntiAffinity"`
}

type podSecCtx struct {
	RunAsNonRoot   *bool           `json:"runAsNonRoot" yaml:"runAsNonRoot"`
	RunAsUser      *int64          `json:"runAsUser" yaml:"runAsUser"`
	SeccompProfile *seccompProfile `json:"seccompProfile" yaml:"seccompProfile"`
	FSGroup        *int64          `json:"fsGroup" yaml:"fsGroup"`
	SELinuxOptions *seLinuxOptions `json:"seLinuxOptions" yaml:"seLinuxOptions"`
}

type seLinuxOptions struct {
	Type  string `json:"type" yaml:"type"`
	Level string `json:"level" yaml:"level"`
}

type seccompProfile struct {
	Type string `json:"type" yaml:"type"`
}

// probe is intentionally empty; the scanner only checks whether a container
// declares a probe (via nil-pointer check on container.LivenessProbe /
// container.ReadinessProbe), it never reads the probe's inner fields. Leaving
// the struct empty also avoids IntOrString parse errors on sub-fields like
// tcpSocket.port or httpGet.port, which Kubernetes allows as either an int
// port number or a named port string.
type probe struct{}

type containerPort struct {
	ContainerPort int32  `json:"containerPort" yaml:"containerPort"`
	HostPort      int32  `json:"hostPort" yaml:"hostPort"`
	Protocol      string `json:"protocol" yaml:"protocol"`
}

type volumeMount struct {
	Name      string `json:"name" yaml:"name"`
	MountPath string `json:"mountPath" yaml:"mountPath"`
	ReadOnly  bool   `json:"readOnly" yaml:"readOnly"`
}

type container struct {
	Name            string               `json:"name" yaml:"name"`
	Image           string               `json:"image" yaml:"image"`
	ImagePullPolicy string               `json:"imagePullPolicy" yaml:"imagePullPolicy"`
	Command         []string             `json:"command" yaml:"command"` // overrides image ENTRYPOINT
	Args            []string             `json:"args" yaml:"args"`       // overrides image CMD
	SecurityContext *containerSecCtx     `json:"securityContext" yaml:"securityContext"`
	Resources       resourceRequirements `json:"resources" yaml:"resources"`
	Env             []envVar             `json:"env" yaml:"env"`
	Ports           []containerPort      `json:"ports" yaml:"ports"`
	LivenessProbe   *probe               `json:"livenessProbe" yaml:"livenessProbe"`
	ReadinessProbe  *probe               `json:"readinessProbe" yaml:"readinessProbe"`
	VolumeMounts    []volumeMount        `json:"volumeMounts" yaml:"volumeMounts"`
}

type containerSecCtx struct {
	Privileged               *bool           `json:"privileged" yaml:"privileged"`
	AllowPrivilegeEscalation *bool           `json:"allowPrivilegeEscalation" yaml:"allowPrivilegeEscalation"`
	ReadOnlyRootFilesystem   *bool           `json:"readOnlyRootFilesystem" yaml:"readOnlyRootFilesystem"`
	RunAsNonRoot             *bool           `json:"runAsNonRoot" yaml:"runAsNonRoot"`
	RunAsUser                *int64          `json:"runAsUser" yaml:"runAsUser"`
	Capabilities             *capabilities   `json:"capabilities" yaml:"capabilities"`
	SeccompProfile           *seccompProfile `json:"seccompProfile" yaml:"seccompProfile"`
	SELinuxOptions           *seLinuxOptions `json:"seLinuxOptions" yaml:"seLinuxOptions"`
}

type capabilities struct {
	Drop []string `json:"drop" yaml:"drop"`
	Add  []string `json:"add" yaml:"add"`
}

type resourceRequirements struct {
	Limits struct {
		Memory string `json:"memory" yaml:"memory"`
		CPU    string `json:"cpu" yaml:"cpu"`
	} `json:"limits" yaml:"limits"`
	Requests struct {
		Memory string `json:"memory" yaml:"memory"`
		CPU    string `json:"cpu" yaml:"cpu"`
	} `json:"requests" yaml:"requests"`
}

type envVar struct {
	Name  string `json:"name" yaml:"name"`
	Value string `json:"value" yaml:"value"`
}

type emptyDir struct {
	Medium    string `json:"medium" yaml:"medium"`
	SizeLimit string `json:"sizeLimit" yaml:"sizeLimit"`
}

type volume struct {
	Name     string     `json:"name" yaml:"name"`
	HostPath *hostPath  `json:"hostPath" yaml:"hostPath"`
	EmptyDir *emptyDir  `json:"emptyDir" yaml:"emptyDir"`
}

type hostPath struct {
	Path string `json:"path" yaml:"path"`
}

// serviceSpec is used to parse Kubernetes Service resources.
type serviceSpec struct {
	Type  string        `json:"type" yaml:"type"`
	Ports []servicePort `json:"ports" yaml:"ports"`
}

type servicePort struct {
	Port     int32  `json:"port" yaml:"port"`
	NodePort int32  `json:"nodePort" yaml:"nodePort"`
	Protocol string `json:"protocol" yaml:"protocol"`
	// targetPort is deliberately omitted. Kubernetes allows it to be either
	// an int port number or a named port string (IntOrString), and the
	// scanner doesn't use it. Declaring it as int32 would cause json
	// unmarshal to fail on Services with named ports like `targetPort: http`.
}

// Scan scans YAML/JSON manifest files for security misconfigurations.
// It implements the Scanner interface.
func (s *K8sScanner) Scan(ctx context.Context) (*types.ScanResult, error) {
	result := &types.ScanResult{
		Target:  strings.Join(s.ManifestPaths, ", "),
		Scanner: "k8s-manifests",
	}

	for _, p := range s.ManifestPaths {
		scanRoot := p
		displayRoot := p
		isChart := false

		// Helm chart detection: render templates to valid YAML before scanning.
		if isHelmChart(p) {
			rendered, cleanup, err := renderHelmChart(ctx, p)
			if err != nil {
				if errors.Is(err, errHelmNotInstalled) {
					result.Findings = append(result.Findings, skipped(controlByID("K8S-003"), p,
						"Helm chart detected but `helm` binary not on PATH — install helm to render templates"))
					continue
				}
				result.Findings = append(result.Findings, types.Finding{
					Status: types.StatusError,
					Target: p,
					Detail: fmt.Sprintf("helm template rendering failed: %v", err),
				})
				continue
			}
			defer cleanup()
			scanRoot = rendered
			isChart = true
		}

		files, err := collectFiles(scanRoot, []string{".yaml", ".yml", ".json"})
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			relF := relPath(scanRoot, f)
			if isChart {
				relF = fmt.Sprintf("%s/%s (rendered)", displayRoot, relF)
			}
			findings, err := s.scanManifestFile(ctx, f, relF)
			if err != nil {
				result.Findings = append(result.Findings, types.Finding{
					Status: types.StatusError,
					Target: relF,
					Detail: fmt.Sprintf("parse error: %v", err),
				})
				continue
			}
			result.Findings = append(result.Findings, findings...)
		}
	}

	// K8S-003: IaC vulnerability scan using trivy/snyk
	result.Findings = append(result.Findings, runIaCVulnScan(ctx, s.ManifestPaths, controlByID("K8S-003"))...)

	// Scan-level aggregation: emit warnings for controls that require cluster-wide presence
	// but were not found in any scanned manifest.

	// NETWORK-001: If no NetworkPolicy was found at all, warn
	if !hasFindingForControlAny(result.Findings, "NETWORK-001") {
		result.Findings = append(result.Findings, warn(controlByID("NETWORK-001"),
			strings.Join(s.ManifestPaths, ", "),
			"No NetworkPolicy resources found in scanned manifests — all pod-to-pod traffic is allowed",
			"No Kind: NetworkPolicy found in any manifest file"))
	}

	// NETWORK-002: If no egress NetworkPolicy blocking metadata endpoint was found, warn
	if !hasFindingForControl(result.Findings, "NETWORK-002", types.StatusPass) {
		if hasFindingForControlAny(result.Findings, "NETWORK-001") {
			result.Findings = append(result.Findings, warn(controlByID("NETWORK-002"),
				strings.Join(s.ManifestPaths, ", "),
				"No egress NetworkPolicy blocking cloud metadata endpoint 169.254.169.254 found — containers may reach IMDS",
				"No NetworkPolicy with egress ipBlock.except containing 169.254.169.254/32 found in scanned manifests"))
		}
	}

	// SECRETS-001: If no external secret management evidence was found, warn
	if !hasFindingForControl(result.Findings, "SECRETS-001", types.StatusPass) {
		// Only warn if we actually saw secrets or workloads (skip for empty scans)
		if hasFindingForControlAny(result.Findings, "RUNTIME-002") {
			result.Findings = append(result.Findings, warn(controlByID("SECRETS-001"),
				strings.Join(s.ManifestPaths, ", "),
				"No external secret management (ExternalSecrets, SealedSecrets, Vault CSI) found — Kubernetes Secrets store credentials as base64",
				"No ExternalSecret, SealedSecret, or SecretProviderClass resources in scanned manifests"))
		}
	}

	// SUPPLY-001: If no image signing verification policy found, warn
	if !hasFindingForControl(result.Findings, "SUPPLY-001", types.StatusPass) {
		if hasFindingForControlAny(result.Findings, "RUNTIME-002") {
			result.Findings = append(result.Findings, warn(controlByID("SUPPLY-001"),
				strings.Join(s.ManifestPaths, ", "),
				"No image signature verification policy found — unsigned images can be deployed",
				"No Kyverno verifyImages ClusterPolicy or sigstore policy-controller in scanned manifests"))
		}
	}

	// MONITOR-001: If no runtime detection agent DaemonSet found, warn
	if !hasFindingForControl(result.Findings, "MONITOR-001", types.StatusPass) {
		if hasFindingForControlAny(result.Findings, "RUNTIME-002") {
			result.Findings = append(result.Findings, warn(controlByID("MONITOR-001"),
				strings.Join(s.ManifestPaths, ", "),
				"No runtime threat detection agent (Falco, Tetragon, Sysdig) found in scanned manifests",
				"No DaemonSet with known security agent image found"))
		}
	}

	// MONITOR-002: If no API server audit policy found, warn
	if !hasFindingForControl(result.Findings, "MONITOR-002", types.StatusPass) {
		if hasFindingForControlAny(result.Findings, "RUNTIME-002") {
			result.Findings = append(result.Findings, warn(controlByID("MONITOR-002"),
				strings.Join(s.ManifestPaths, ", "),
				"No Kubernetes API server audit policy (audit.k8s.io/v1 Policy) found in scanned manifests",
				"No audit.k8s.io Policy resource found — control plane activity may not be logged"))
		}
	}

	result.Tally()
	return result, nil
}

func (s *K8sScanner) scanManifestFile(ctx context.Context, path, displayPath string) ([]types.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path) // #nosec G304 -- path is a user-supplied manifest file from CLI --path flag
	if err != nil {
		return nil, err
	}

	// Handle multi-document YAML.
	// Decode each document through interface{} first, then re-marshal to JSON before
	// unmarshalling into kubeObject. This is necessary because yaml.v3 cannot populate
	// json.RawMessage fields directly — the Spec field would be nil otherwise.
	var findings []types.Finding
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	for docIdx := 0; ; docIdx++ {
		var raw interface{}
		err := decoder.Decode(&raw)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// yaml.v3 cannot reliably resync past a parse error, so surface it and stop.
			// This commonly trips on Helm templates with `{{ .Values.foo }}` syntax when
			// the chart was not rendered first.
			findings = append(findings, types.Finding{
				Status: types.StatusError,
				Target: displayPath,
				Detail: fmt.Sprintf("YAML parse error in document #%d: %v", docIdx+1, err),
			})
			break
		}
		if raw == nil {
			continue
		}

		// Convert YAML-decoded map → JSON → kubeObject so that Spec (json.RawMessage) is populated.
		jsonBytes, err := json.Marshal(raw)
		if err != nil {
			findings = append(findings, types.Finding{
				Status: types.StatusError,
				Target: displayPath,
				Detail: fmt.Sprintf("failed to marshal YAML document to JSON: %v", err),
			})
			continue
		}
		var obj kubeObject
		if err := json.Unmarshal(jsonBytes, &obj); err != nil {
			findings = append(findings, types.Finding{
				Status: types.StatusError,
				Target: displayPath,
				Detail: fmt.Sprintf("failed to parse Kubernetes object: %v", err),
			})
			continue
		}
		if obj.Kind == "" {
			continue
		}

		f := s.checkObject(obj, displayPath)
		findings = append(findings, f...)
	}

	return findings, nil
}

func (s *K8sScanner) checkObject(obj kubeObject, path string) []types.Finding {
	target := fmt.Sprintf("%s/%s (%s)", obj.Metadata.Namespace, obj.Metadata.Name, path)

	// Handle non-pod-bearing resource types
	switch obj.Kind {
	case "Service":
		var svc serviceSpec
		if obj.Spec != nil {
			if err := remarshal(obj.Spec, &svc); err != nil {
				return []types.Finding{errFinding(controlByID("DB-K8S-003"), target,
					fmt.Sprintf("failed to parse Service spec: %v", err))}
			}
		}
		return checkServiceExposure(svc, target)

	case "NetworkPolicy":
		var np networkPolicySpec
		if obj.Spec != nil {
			if err := remarshal(obj.Spec, &np); err != nil {
				return []types.Finding{errFinding(controlByID("NETWORK-001"), target,
					fmt.Sprintf("failed to parse NetworkPolicy spec: %v", err))}
			}
		}
		findings := checkNetworkPolicyDefaultDeny(np, target)
		findings = append(findings, checkNetworkPolicyMetadataBlock(np, target)...)
		return findings

	case "Role", "ClusterRole":
		var rules []rbacRule
		if obj.Rules != nil {
			if err := json.Unmarshal(obj.Rules, &rules); err != nil {
				return nil
			}
		}
		return checkRBACSecretAccess(rules, target)

	case "Secret":
		return checkPlaintextSecret(obj, target)

	case "ExternalSecret":
		return []types.Finding{pass(controlByID("SECRETS-001"), target,
			"ExternalSecret resource found — secrets managed via external operator")}

	case "SealedSecret":
		return []types.Finding{pass(controlByID("SECRETS-001"), target,
			"SealedSecret resource found — secrets encrypted at rest via Bitnami Sealed Secrets")}

	case "SecretProviderClass":
		return []types.Finding{pass(controlByID("SECRETS-001"), target,
			"SecretProviderClass found — secrets injected via CSI driver (Vault/AWS/Azure)")}

	case "ClusterPolicy":
		return checkKyvernoImageVerification(obj, target)

	case "Policy":
		// Distinguish audit.k8s.io Policy from Kyverno Policy by apiVersion
		if strings.HasPrefix(obj.APIVersion, "audit.k8s.io/") {
			return checkAuditPolicy(obj, target)
		}
		return checkKyvernoImageVerification(obj, target)
	}

	// Handle pod annotations/labels for all resource types
	var findings []types.Finding
	findings = append(findings, checkAnnotationsForSecrets(obj.Metadata, target)...)

	// Only check pod-bearing resources for security context
	var spec *podSpec
	switch obj.Kind {
	case "Pod":
		var ps podSpec
		if obj.Spec != nil {
			if err := remarshal(obj.Spec, &ps); err != nil {
				return append(findings, errFinding(controlByID("RUNTIME-002"), target,
					fmt.Sprintf("failed to parse Pod spec: %v", err)))
			}
		}
		spec = &ps
	case "Deployment", "DaemonSet", "StatefulSet", "Job", "ReplicaSet":
		var wrapper struct {
			Template struct {
				Metadata kubeObjectMeta `json:"metadata" yaml:"metadata"`
				Spec     podSpec        `json:"spec" yaml:"spec"`
			} `json:"template" yaml:"template"`
		}
		if obj.Spec != nil {
			if err := remarshal(obj.Spec, &wrapper); err != nil {
				return append(findings, errFinding(controlByID("RUNTIME-002"), target,
					fmt.Sprintf("failed to parse %s spec: %v", obj.Kind, err)))
			}
		}
		// Also check pod template annotations
		findings = append(findings, checkAnnotationsForSecrets(wrapper.Template.Metadata, target+"[template]")...)
		spec = &wrapper.Template.Spec
	case "CronJob":
		var wrapper struct {
			JobTemplate struct {
				Spec struct {
					Template struct {
						Metadata kubeObjectMeta `json:"metadata" yaml:"metadata"`
						Spec     podSpec        `json:"spec" yaml:"spec"`
					} `json:"template" yaml:"template"`
				} `json:"spec" yaml:"spec"`
			} `json:"jobTemplate" yaml:"jobTemplate"`
		}
		if obj.Spec != nil {
			if err := remarshal(obj.Spec, &wrapper); err != nil {
				return append(findings, errFinding(controlByID("RUNTIME-002"), target,
					fmt.Sprintf("failed to parse CronJob spec: %v", err)))
			}
		}
		findings = append(findings, checkAnnotationsForSecrets(wrapper.JobTemplate.Spec.Template.Metadata, target+"[template]")...)
		spec = &wrapper.JobTemplate.Spec.Template.Spec
	default:
		return findings
	}

	// MONITOR-001: Check if DaemonSet is a runtime threat detection agent
	if obj.Kind == "DaemonSet" {
		findings = append(findings, checkRuntimeDetectionAgent(*spec, target)...)
	}

	allContainers := slices.Concat(spec.Containers, spec.InitContainers)

	for _, c := range allContainers {
		ct := fmt.Sprintf("%s[%s]", target, c.Name)
		findings = append(findings, checkK8sPrivileged(c, ct)...)
		findings = append(findings, checkK8sCapabilities(c, ct)...)
		findings = append(findings, checkK8sReadOnly(c, ct)...)
		findings = append(findings, checkK8sNonRoot(c, *spec, ct)...)
		findings = append(findings, checkK8sNoPrivEsc(c, ct)...)
		findings = append(findings, checkK8sResources(c, ct)...)
		findings = append(findings, checkK8sSecrets(c, ct)...)
		findings = append(findings, checkK8sImageDigest(c, ct)...)
		findings = append(findings, checkK8sRegistryAuth(c, ct)...)
		findings = append(findings, checkK8sImagePullPolicy(c, ct)...)
		findings = append(findings, checkK8sEOLImage(c, ct)...)
		findings = append(findings, checkImageMinimality(c.Image, ct)...)
		findings = append(findings, checkK8sProbes(c, ct)...)
		findings = append(findings, checkK8sSeccomp(c, *spec, ct)...)
		findings = append(findings, checkK8sPrivilegedPorts(c, ct)...)
		findings = append(findings, checkDBAuthDisabledEnv(c, ct)...)
		findings = append(findings, checkDBMissingAuthConfig(c, ct)...)
		findings = append(findings, checkNeo4jApocSSRF(c, ct)...)
		findings = append(findings, checkK8sADDInstruction(c, ct)...)
		findings = append(findings, checkK8sAppArmorSELinux(c, obj.Metadata, *spec, ct)...)
	}

	findings = append(findings, checkK8sHostNamespaces(*spec, target)...)
	findings = append(findings, checkK8sHostPaths(*spec, target)...)
	findings = append(findings, checkDBEmptyDirData(*spec, target)...)
	findings = append(findings, checkDBFsGroup(*spec, target)...)
	findings = append(findings, checkK8sAutomountSA(*spec, target)...)
	findings = append(findings, checkK8sNamespace(obj.Metadata, target)...)
	findings = append(findings, checkK8sAntiAffinity(*spec, target)...)

	return findings
}

func checkK8sPrivileged(c container, target string) []types.Finding {
	ctrl := controlByID("RUNTIME-002")
	if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
		return []types.Finding{fail(ctrl, target,
			"Container is configured privileged: true",
			fmt.Sprintf("spec.containers[%s].securityContext.privileged: true", c.Name),
			ctrl.Remediation)}
	}
	return []types.Finding{pass(ctrl, target, "Privileged: false or unset")}
}

func checkK8sCapabilities(c container, target string) []types.Finding {
	ctrl := controlByID("RUNTIME-003")
	if c.SecurityContext == nil || c.SecurityContext.Capabilities == nil {
		return []types.Finding{fail(ctrl, target,
			"No capabilities defined — using Docker default capabilities",
			"securityContext.capabilities is not set",
			ctrl.Remediation)}
	}

	hasDropAll := false
	for _, d := range c.SecurityContext.Capabilities.Drop {
		if strings.ToUpper(d) == "ALL" {
			hasDropAll = true
		}
	}
	if !hasDropAll {
		return []types.Finding{fail(ctrl, target,
			"capabilities.drop does not include ALL",
			fmt.Sprintf("drop: %v", c.SecurityContext.Capabilities.Drop),
			ctrl.Remediation)}
	}
	return []types.Finding{pass(ctrl, target, "capabilities.drop: [ALL]")}
}

func checkK8sReadOnly(c container, target string) []types.Finding {
	ctrl := controlByID("RUNTIME-005")
	if c.SecurityContext == nil || c.SecurityContext.ReadOnlyRootFilesystem == nil || !*c.SecurityContext.ReadOnlyRootFilesystem {
		// Escalate to CRITICAL for Redis: writable rootfs enables CONFIG SET arbitrary file write exploit
		if strings.Contains(strings.ToLower(c.Image), "redis") {
			return []types.Finding{fail(ctrl, target,
				"Redis container has writable root filesystem — enables CONFIG SET dir arbitrary file write (RCE chain)",
				"securityContext.readOnlyRootFilesystem != true on Redis image",
				"Set readOnlyRootFilesystem: true. Mount emptyDir (medium: Memory) for /tmp and /var/run/redis.")}
		}
		return []types.Finding{warn(ctrl, target,
			"readOnlyRootFilesystem is not set to true",
			"securityContext.readOnlyRootFilesystem != true")}
	}
	return []types.Finding{pass(ctrl, target, "readOnlyRootFilesystem: true")}
}

func checkK8sNonRoot(c container, spec podSpec, target string) []types.Finding {
	ctrl := controlByID("RUNTIME-001")

	// Container-level check
	if c.SecurityContext != nil {
		if c.SecurityContext.RunAsUser != nil && *c.SecurityContext.RunAsUser == 0 {
			return []types.Finding{fail(ctrl, target,
				"Container explicitly sets runAsUser: 0 (root)",
				"securityContext.runAsUser: 0",
				ctrl.Remediation)}
		}
		if c.SecurityContext.RunAsNonRoot != nil && *c.SecurityContext.RunAsNonRoot {
			return []types.Finding{pass(ctrl, target, "runAsNonRoot: true (container level)")}
		}
	}

	// Pod-level check
	if spec.SecurityContext != nil {
		if spec.SecurityContext.RunAsNonRoot != nil && *spec.SecurityContext.RunAsNonRoot {
			return []types.Finding{pass(ctrl, target, "runAsNonRoot: true (pod level)")}
		}
		if spec.SecurityContext.RunAsUser != nil && *spec.SecurityContext.RunAsUser == 0 {
			return []types.Finding{fail(ctrl, target,
				"Pod-level runAsUser: 0 (root)",
				"spec.securityContext.runAsUser: 0",
				ctrl.Remediation)}
		}
	}

	return []types.Finding{warn(ctrl, target,
		"runAsNonRoot not explicitly set — container may run as root if image USER is 0",
		"Neither container nor pod securityContext sets runAsNonRoot")}
}

func checkK8sNoPrivEsc(c container, target string) []types.Finding {
	ctrl := controlByID("RUNTIME-004")
	if c.SecurityContext == nil || c.SecurityContext.AllowPrivilegeEscalation == nil || *c.SecurityContext.AllowPrivilegeEscalation {
		return []types.Finding{fail(ctrl, target,
			"allowPrivilegeEscalation not explicitly set to false",
			"securityContext.allowPrivilegeEscalation != false",
			ctrl.Remediation)}
	}
	return []types.Finding{pass(ctrl, target, "allowPrivilegeEscalation: false")}
}

func checkK8sResources(c container, target string) []types.Finding {
	ctrl := controlByID("RUNTIME-007")
	var issues []string
	if c.Resources.Limits.Memory == "" {
		issues = append(issues, "resources.limits.memory not set")
	}
	if c.Resources.Limits.CPU == "" {
		issues = append(issues, "resources.limits.cpu not set")
	}
	if c.Resources.Requests.Memory == "" {
		issues = append(issues, "resources.requests.memory not set")
	}
	if c.Resources.Requests.CPU == "" {
		issues = append(issues, "resources.requests.cpu not set")
	}
	if len(issues) > 0 {
		return []types.Finding{fail(ctrl, target,
			"Missing resource limits and/or requests: "+strings.Join(issues, "; "),
			strings.Join(issues, "; "),
			ctrl.Remediation)}
	}
	return []types.Finding{pass(ctrl, target,
		fmt.Sprintf("Limits: cpu=%s memory=%s; Requests: cpu=%s memory=%s",
			c.Resources.Limits.CPU, c.Resources.Limits.Memory,
			c.Resources.Requests.CPU, c.Resources.Requests.Memory))}
}

func checkK8sSecrets(c container, target string) []types.Finding {
	// Use shared credential patterns from helpers.go (credentialKeywords, aiKeyPatterns)

	// Initialize SecretScanner for regex-based value analysis
	secretCtrl := controlByID("IMAGE-002")
	secretScanner := NewSecretScanner(target, secretCtrl)

	var findings []types.Finding
	for _, env := range c.Env {
		if env.Value == "" {
			continue
		}
		nameL := strings.ToLower(env.Name)

		// _FILE suffix convention: the ENV var points to a secret file path, not a literal secret.
		// e.g. POSTGRES_PASSWORD_FILE=/run/secrets/pg-pass is the correct pattern — skip it.
		if strings.HasSuffix(nameL, "_file") {
			continue
		}
		// Also skip if the value itself looks like an absolute file path (starts with /)
		if strings.HasPrefix(env.Value, "/") {
			continue
		}

		// Check AI key patterns first (more specific control)
		matched := false
		for _, p := range aiKeyPatterns {
			if strings.Contains(nameL, p) {
				ctrl := controlByID("SECRETS-003")
				findings = append(findings, fail(ctrl, target,
					fmt.Sprintf("AI/vectorizer API key in literal ENV var %q", env.Name),
					fmt.Sprintf("env.%s has a literal value — use valueFrom.secretKeyRef", env.Name),
					ctrl.Remediation))
				matched = true
				break
			}
		}
		if matched {
			continue
		}
		// Check generic *_apikey or *_api_key suffix
		if (strings.HasSuffix(nameL, "_apikey") || strings.HasSuffix(nameL, "_api_key")) && env.Value != "" {
			ctrl := controlByID("SECRETS-003")
			findings = append(findings, fail(ctrl, target,
				fmt.Sprintf("API key in literal ENV var %q", env.Name),
				fmt.Sprintf("env.%s matches *_api_key pattern with literal value", env.Name),
				ctrl.Remediation))
			continue
		}

		// Standard credential check (name-based)
		for _, p := range credentialKeywords {
			if strings.Contains(nameL, p) {
				ctrl := controlByID("IMAGE-002")
				findings = append(findings, fail(ctrl, target,
					fmt.Sprintf("Plaintext secret in env var %q", env.Name),
					fmt.Sprintf("env.%s has a literal value — use valueFrom.secretKeyRef instead", env.Name),
					ctrl.Remediation))
				matched = true
				break
			}
		}
		if matched {
			continue
		}

		// Regex-based value analysis: detect secrets by value pattern even
		// if the env var name doesn't match credential keywords.
		matches := secretScanner.CheckLine(env.Value)
		for _, m := range matches {
			ctrl := controlByID("IMAGE-002")
			detail := fmt.Sprintf("Regex-detected %s in env var %q value", m.PatternName, env.Name)
			if m.PatternName == "HIGH_ENTROPY" {
				detail = fmt.Sprintf("High-entropy value (%.2f) in env var %q — possible secret", m.Entropy, env.Name)
			}
			findings = append(findings, fail(ctrl, target, detail,
				fmt.Sprintf("env.%s value matches %s pattern — use valueFrom.secretKeyRef", env.Name, m.PatternName),
				ctrl.Remediation))
		}
	}
	if len(findings) == 0 {
		return []types.Finding{pass(controlByID("IMAGE-002"), target, "No obvious plaintext secrets in env vars")}
	}
	return findings
}

func checkK8sImageDigest(c container, target string) []types.Finding {
	ctrl := controlByID("IMAGE-001")
	if !strings.Contains(c.Image, "@sha256:") {
		return []types.Finding{fail(ctrl, target,
			fmt.Sprintf("Image %q not pinned by digest", c.Image),
			c.Image,
			ctrl.Remediation)}
	}
	return []types.Finding{pass(ctrl, target, fmt.Sprintf("Image digest-pinned: %s", shortImage(c.Image)))}
}

// checkK8sRegistryAuth flags pod containers whose image field references an
// insecure or anonymous registry (REGISTRY-002).
func checkK8sRegistryAuth(c container, target string) []types.Finding {
	ctrl := controlByID("REGISTRY-002")
	if c.Image == "" {
		return []types.Finding{skipped(ctrl, target, "No image field to classify")}
	}
	posture, host, detail := classifyRegistryRef(c.Image)
	switch posture {
	case "insecure":
		return []types.Finding{fail(ctrl, target,
			fmt.Sprintf("Image uses insecure registry reference: %s", c.Image),
			detail, ctrl.Remediation)}
	case "anonymous":
		return []types.Finding{warn(ctrl, target,
			fmt.Sprintf("Image pulls from %s — %s", host, detail),
			fmt.Sprintf("image: %s", c.Image))}
	}
	return []types.Finding{pass(ctrl, target,
		fmt.Sprintf("Image references an authenticated registry: %s", host))}
}

func checkK8sHostNamespaces(spec podSpec, target string) []types.Finding {
	ctrl := controlByID("RUNTIME-006")
	var issues []string
	if spec.HostPID {
		issues = append(issues, "hostPID: true")
	}
	if spec.HostIPC {
		issues = append(issues, "hostIPC: true")
	}
	if spec.HostNetwork {
		issues = append(issues, "hostNetwork: true")
	}
	if len(issues) > 0 {
		return []types.Finding{fail(ctrl, target,
			"Pod shares host namespaces: "+strings.Join(issues, ", "),
			strings.Join(issues, ", "),
			ctrl.Remediation)}
	}
	return []types.Finding{pass(ctrl, target, "No host namespace sharing")}
}

var sensitivePaths = []string{
	"/etc", "/proc", "/sys", "/var/run",
	"/var/lib/docker", "/var/run/docker.sock",
	"/run/docker.sock", "/root",
}

func checkK8sHostPaths(spec podSpec, target string) []types.Finding {
	ctrl := controlByID("RUNTIME-009")
	ctrlDaemon := controlByID("DAEMON-001")
	var findings []types.Finding
	for _, v := range spec.Volumes {
		if v.HostPath == nil {
			continue
		}
		// DAEMON-001: Docker socket mount — defense-in-depth dual finding
		if strings.Contains(v.HostPath.Path, "docker.sock") {
			findings = append(findings, fail(ctrlDaemon, target,
				fmt.Sprintf("Docker socket mounted as volume %q", v.Name),
				fmt.Sprintf("volumes.%s.hostPath.path: %s", v.Name, v.HostPath.Path),
				ctrlDaemon.Remediation))
		}
		for _, sp := range sensitivePaths {
			if v.HostPath.Path == sp || strings.HasPrefix(v.HostPath.Path, sp+"/") {
				findings = append(findings, fail(ctrl, target,
					fmt.Sprintf("Sensitive hostPath %q mounted as volume %q", v.HostPath.Path, v.Name),
					fmt.Sprintf("volumes.%s.hostPath.path: %s", v.Name, v.HostPath.Path),
					ctrl.Remediation))
				break // one finding per volume — stop at first matching sensitive path
			}
		}
	}
	if len(findings) == 0 {
		return []types.Finding{pass(ctrl, target, "No sensitive hostPath mounts")}
	}
	return findings
}

// checkK8sProbes verifies that liveness and readiness probes are configured (RUNTIME-012 / CCI-002385).
func checkK8sProbes(c container, target string) []types.Finding {
	ctrl := controlByID("RUNTIME-012")
	var missing []string
	if c.LivenessProbe == nil {
		missing = append(missing, "livenessProbe")
	}
	if c.ReadinessProbe == nil {
		missing = append(missing, "readinessProbe")
	}
	if len(missing) > 0 {
		return []types.Finding{fail(ctrl, target,
			fmt.Sprintf("Missing health probe(s): %s", strings.Join(missing, ", ")),
			strings.Join(missing, ", ")+" not defined in container spec",
			ctrl.Remediation)}
	}
	return []types.Finding{pass(ctrl, target, "livenessProbe and readinessProbe are configured")}
}

// checkK8sSeccomp verifies that a seccomp profile is set at container or pod level (RUNTIME-008 / CIS 5.22).
func checkK8sSeccomp(c container, spec podSpec, target string) []types.Finding {
	ctrl := controlByID("RUNTIME-008")
	// Container-level
	if c.SecurityContext != nil && c.SecurityContext.SeccompProfile != nil &&
		c.SecurityContext.SeccompProfile.Type != "" {
		return []types.Finding{pass(ctrl, target,
			fmt.Sprintf("seccompProfile.type: %s (container level)", c.SecurityContext.SeccompProfile.Type))}
	}
	// Pod-level
	if spec.SecurityContext != nil && spec.SecurityContext.SeccompProfile != nil &&
		spec.SecurityContext.SeccompProfile.Type != "" {
		return []types.Finding{pass(ctrl, target,
			fmt.Sprintf("seccompProfile.type: %s (pod level)", spec.SecurityContext.SeccompProfile.Type))}
	}
	return []types.Finding{warn(ctrl, target,
		"No explicit seccompProfile configured — relying on runtime default",
		"Neither container nor pod securityContext sets seccompProfile")}
}

// checkK8sImagePullPolicy ensures imagePullPolicy is set to Always or IfNotPresent (IMAGE-001).
// An unset policy with a :latest tag defaults to Always, but explicit is preferred.
// A policy of "Never" is dangerous in multi-node clusters as it relies on pre-cached images.
func checkK8sImagePullPolicy(c container, target string) []types.Finding {
	ctrl := controlByID("IMAGE-001")
	policy := c.ImagePullPolicy

	if policy == "" {
		// Warn: unset policy — Kubernetes defaults vary based on tag
		if strings.Contains(c.Image, ":latest") || !strings.Contains(c.Image, ":") {
			return []types.Finding{warn(ctrl, target,
				fmt.Sprintf("imagePullPolicy not set for %s — defaults to Always but explicit is preferred", shortImage(c.Image)),
				"imagePullPolicy not set on latest/untagged image")}
		}
		return []types.Finding{warn(ctrl, target,
			fmt.Sprintf("imagePullPolicy not set for %s — defaults to IfNotPresent", shortImage(c.Image)),
			"imagePullPolicy not set — set explicitly for deterministic behavior")}
	}

	if policy == "Never" {
		return []types.Finding{fail(ctrl, target,
			"imagePullPolicy: Never — container may run outdated/unverified cached images",
			"imagePullPolicy: Never",
			ctrl.Remediation)}
	}

	return []types.Finding{pass(ctrl, target,
		fmt.Sprintf("imagePullPolicy: %s", policy))}
}

// checkK8sEOLImage detects end-of-life base images in Kubernetes container specs (IMAGE-008).
// Uses imageNameTag and DefaultEOLImages from helpers.go for consistent detection across scanners.
func checkK8sEOLImage(c container, target string) []types.Finding {
	ctrl := controlByID("IMAGE-008")
	if c.Image == "" {
		return []types.Finding{skipped(ctrl, target, "No image specified")}
	}

	name, tag := imageNameTag(c.Image)
	if tag == "latest" || tag == "" {
		return []types.Finding{skipped(ctrl, target, "Cannot determine EOL for :latest or untagged image")}
	}

	for _, eol := range DefaultEOLImages {
		if name == eol.Name && eolTagMatches(tag, eol.Tag) {
			return []types.Finding{fail(ctrl, target,
				fmt.Sprintf("End-of-life image detected: %s", eol.Reason),
				fmt.Sprintf("image: %s (parsed name=%q tag=%q)", shortImage(c.Image), name, tag),
				ctrl.Remediation)}
		}
	}
	return []types.Finding{pass(ctrl, target,
		fmt.Sprintf("Image %s is not a known end-of-life image", shortImage(c.Image)))}
}

// checkK8sADDInstruction checks container command/args for curl/wget pipe-to-shell (IMAGE-006)
// and emits IMAGE-014 SKIP because ADD vs COPY is a Dockerfile-layer concern, not a k8s
// manifest concern — image-layer analysis requires `dockeraudit image`.
func checkK8sADDInstruction(c container, target string) []types.Finding {
	ctrl006 := controlByID("IMAGE-006")
	ctrl014 := controlByID("IMAGE-014")

	allArgs := append(append([]string{}, c.Command...), c.Args...)
	combined := strings.Join(allArgs, " ")

	if strings.TrimSpace(combined) == "" {
		return []types.Finding{
			skipped(ctrl006, target, "No command or args to inspect"),
			skipped(ctrl014, target, "ADD vs COPY is a Dockerfile concern — use `dockeraudit image` to inspect built layers"),
		}
	}

	lower := strings.ToLower(combined)
	hasCurlWget := strings.Contains(lower, "curl") || strings.Contains(lower, "wget")
	isPackageInstall := strings.Contains(lower, "apt-get") || strings.Contains(lower, "apk add") ||
		strings.Contains(lower, "yum install") || strings.Contains(lower, "dnf install")

	var findings []types.Finding
	if hasCurlWget && !isPackageInstall {
		if strings.Contains(combined, "| sh") || strings.Contains(combined, "| bash") ||
			strings.Contains(combined, "|sh") || strings.Contains(combined, "|bash") {
			findings = append(findings, fail(ctrl006, target,
				"container command pipes remote content to a shell interpreter",
				fmt.Sprintf("command: %q", combined), ctrl006.Remediation))
		} else {
			findings = append(findings, warn(ctrl006, target,
				"container command contains remote fetch — ensure integrity verification",
				fmt.Sprintf("command: %q", combined)))
		}
	} else {
		findings = append(findings, pass(ctrl006, target, "No pipe-to-shell or unsafe remote fetch in command/args"))
	}

	// IMAGE-014 (ADD vs COPY) is a Dockerfile-layer concern, not a k8s manifest concern.
	findings = append(findings, skipped(ctrl014, target,
		"ADD vs COPY is a Dockerfile concern — use `dockeraudit image` to inspect built layers"))
	return findings
}

// checkK8sPrivilegedPorts flags containerPorts below 1024 (RUNTIME-011 / CIS 5.8 / CCI-001762).
func checkK8sPrivilegedPorts(c container, target string) []types.Finding {
	ctrl := controlByID("RUNTIME-011")
	var priv []string
	for _, p := range c.Ports {
		if p.ContainerPort > 0 && p.ContainerPort < 1024 {
			priv = append(priv, fmt.Sprintf("%d", p.ContainerPort))
		}
	}
	if len(priv) > 0 {
		return []types.Finding{fail(ctrl, target,
			fmt.Sprintf("Container exposes privileged port(s): %s", strings.Join(priv, ", ")),
			fmt.Sprintf("ports[].containerPort: %s", strings.Join(priv, ", ")),
			ctrl.Remediation)}
	}
	return []types.Finding{pass(ctrl, target, "No privileged ports (< 1024) in container spec")}
}

// dbKnownPorts is the set of well-known database ports that must only be exposed on ClusterIP Services.
var dbKnownPorts = map[int32]string{
	5432: "PostgreSQL", 3306: "MySQL", 3307: "MySQL (alt)", 1433: "MSSQL", 1521: "Oracle",
	27017: "MongoDB", 27018: "MongoDB", 27019: "MongoDB",
	6379: "Redis", 9042: "Cassandra", 5984: "CouchDB",
	7687: "Neo4j Bolt", 7474: "Neo4j HTTP", 8529: "ArangoDB",
	8080: "Weaviate", 50051: "Weaviate gRPC",
	6333: "Qdrant REST", 6334: "Qdrant gRPC",
	19530: "Milvus", 8000: "Chroma",
	3030: "Fuseki", 9999: "Blazegraph",
	7199: "Cassandra JMX", 9092: "H2 TCP", 1527: "Derby",
}

// checkServiceExposure ensures database Services use ClusterIP (DB-K8S-003 / CCI-001090).
func checkServiceExposure(svc serviceSpec, target string) []types.Finding {
	ctrl := controlByID("DB-K8S-003")
	svcType := svc.Type
	if svcType == "" {
		svcType = "ClusterIP" // default
	}
	if svcType == "ClusterIP" {
		return []types.Finding{pass(ctrl, target, fmt.Sprintf("Service type: %s", svcType))}
	}
	// Check if any exposed port is a known database port
	var exposed []string
	for _, p := range svc.Ports {
		if dbName, ok := dbKnownPorts[p.Port]; ok {
			exposed = append(exposed, fmt.Sprintf("%d (%s)", p.Port, dbName))
		}
	}
	if len(exposed) > 0 {
		return []types.Finding{fail(ctrl, target,
			fmt.Sprintf("Database port(s) %s exposed via Service type %s — bypasses NetworkPolicy",
				strings.Join(exposed, ", "), svcType),
			fmt.Sprintf("spec.type: %s, ports: %v", svcType, exposed),
			ctrl.Remediation)}
	}
	// Non-database NodePort/LoadBalancer: warn rather than fail
	return []types.Finding{warn(ctrl, target,
		fmt.Sprintf("Service type %s may expose non-database ports externally — verify intent", svcType),
		fmt.Sprintf("spec.type: %s", svcType))}
}

// dbAuthDisabledPatterns are ENV name=value combinations that explicitly disable authentication.
var dbAuthDisabledPatterns = []struct {
	name  string
	value string
	msg   string
}{
	{"POSTGRES_HOST_AUTH_METHOD", "trust", "PostgreSQL trust auth allows passwordless connections"},
	{"NEO4J_AUTH", "none", "Neo4j auth explicitly disabled — entire graph accessible without credentials"},
	{"ARANGO_NO_AUTH", "1", "ArangoDB auth disabled — full database access without credentials"},
	{"AUTHENTICATION_ANONYMOUS_ACCESS_ENABLED", "true", "Weaviate anonymous access enabled — all vector data is public"},
	{"CHROMA_ALLOW_RESET", "true", "Chroma reset endpoint enabled — single HTTP call deletes all collections"},
	{"SPRING_H2_CONSOLE_ENABLED", "true", "H2 web console enabled — allows arbitrary SQL execution (RCE via CREATE ALIAS)"},
	{"NEO4J_AUTH", "neo4j/neo4j", "Neo4j using default credentials — rotate immediately"},
	{"NEO4J_AUTH", "neo4j/password", "Neo4j using well-known default credentials"},
	{"MINIO_ACCESS_KEY", "minioadmin", "MinIO using default access key — exposes all Milvus vector storage"},
	{"MINIO_ROOT_USER", "minioadmin", "MinIO using default root user — exposes all Milvus vector storage"},
}

// dbDangerousFlags are command-line flags that disable authentication or critical security features.
var dbDangerousFlags = []struct {
	flag string
	msg  string
}{
	{"--noauth", "MongoDB --noauth disables authentication entirely"},
	{"--skip-grant-tables", "MySQL --skip-grant-tables grants all privileges to all users"},
	{"--skip-networking", "MySQL --skip-networking disables TCP but is often paired with --skip-grant-tables"},
	{"--auth=trust", "PostgreSQL --auth=trust allows passwordless connections from any host"},
	{"--protected-mode no", "Redis --protected-mode no removes bind/auth safeguards"},
	{"--protected-mode=no", "Redis --protected-mode=no removes bind/auth safeguards"},
}

// checkDBAuthDisabledEnv detects ENV vars or command flags that explicitly disable authentication (DB-K8S-001).
func checkDBAuthDisabledEnv(c container, target string) []types.Finding {
	ctrl := controlByID("DB-K8S-001")
	var findings []types.Finding

	// 1. Check ENV vars
	for _, env := range c.Env {
		nameU := strings.ToUpper(env.Name)
		valueL := strings.ToLower(env.Value)
		for _, p := range dbAuthDisabledPatterns {
			if nameU == strings.ToUpper(p.name) && (p.value == "" || strings.Contains(valueL, strings.ToLower(p.value))) {
				findings = append(findings, fail(ctrl, target,
					fmt.Sprintf("Auth-disabling ENV var: %s=%s — %s", env.Name, env.Value, p.msg),
					fmt.Sprintf("env.%s=%s", env.Name, env.Value),
					ctrl.Remediation))
			}
		}
	}

	// 2. Check container command/args for dangerous startup flags
	allArgs := make([]string, 0, len(c.Command)+len(c.Args))
	allArgs = append(allArgs, c.Command...)
	allArgs = append(allArgs, c.Args...)
	cmdLine := strings.Join(allArgs, " ")
	for _, df := range dbDangerousFlags {
		if strings.Contains(cmdLine, df.flag) {
			findings = append(findings, fail(ctrl, target,
				fmt.Sprintf("Auth-disabling startup flag in container command: %s — %s", df.flag, df.msg),
				fmt.Sprintf("command: %s", cmdLine),
				ctrl.Remediation))
		}
	}

	if len(findings) == 0 {
		return []types.Finding{pass(ctrl, target, "No auth-disabling ENV vars or startup flags detected")}
	}
	return findings
}

// dbMissingAuthConfig defines images and the ENV required to configure authentication.
var dbMissingAuthConfig = []struct {
	imageSubstr string
	requiredENV []string
	msg         string
}{
	{"qdrant/qdrant", []string{"QDRANT__SERVICE__API_KEY"}, "Qdrant has no auth by default — set QDRANT__SERVICE__API_KEY"},
	{"chromadb/chroma", []string{"CHROMA_SERVER_AUTH_PROVIDER"}, "Chroma has no auth by default — set CHROMA_SERVER_AUTH_PROVIDER"},
	{"ghcr.io/chroma-core", []string{"CHROMA_SERVER_AUTH_PROVIDER"}, "Chroma has no auth by default — set CHROMA_SERVER_AUTH_PROVIDER"},
	{"milvusdb/milvus", []string{"MILVUS_ROOT_PASSWORD", "MILVUS_AUTH_ENABLED"}, "Milvus auth not configured — set MILVUS_ROOT_PASSWORD"},
	{"semitechnologies/weaviate", []string{"AUTHENTICATION_APIKEY_ENABLED", "AUTHENTICATION_OIDC_ENABLED"}, "Weaviate auth not configured — set AUTHENTICATION_APIKEY_ENABLED=true or configure OIDC"},
}

// checkDBMissingAuthConfig detects databases deployed without any authentication configured (DB-K8S-002).
func checkDBMissingAuthConfig(c container, target string) []types.Finding {
	ctrl := controlByID("DB-K8S-002")
	imageL := strings.ToLower(c.Image)

	var findings []types.Finding
	for _, cfg := range dbMissingAuthConfig {
		if !strings.Contains(imageL, cfg.imageSubstr) {
			continue
		}
		// Check if at least one of the required ENVs is present
		found := false
		for _, req := range cfg.requiredENV {
			for _, env := range c.Env {
				if strings.ToUpper(env.Name) == req {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if found {
			findings = append(findings, pass(ctrl, target,
				fmt.Sprintf("Auth ENV found for %s", cfg.imageSubstr)))
		} else {
			findings = append(findings, fail(ctrl, target,
				cfg.msg,
				fmt.Sprintf("image: %s — none of %v found in env", shortImage(c.Image), cfg.requiredENV),
				ctrl.Remediation))
		}
	}
	if len(findings) == 0 {
		return []types.Finding{skipped(ctrl, target, "Not a known no-auth-by-default database image")}
	}
	return findings
}

// checkNeo4jApocSSRF detects Neo4j APOC plugin without URL-loading restrictions (DB-K8S-007).
func checkNeo4jApocSSRF(c container, target string) []types.Finding {
	ctrl := controlByID("DB-K8S-007")
	imageL := strings.ToLower(c.Image)
	if !strings.Contains(imageL, "neo4j") {
		return []types.Finding{skipped(ctrl, target, "Not a Neo4j image")}
	}

	hasAPOC := false
	hasImportDisabled := false
	hasCsvDisabled := false

	for _, env := range c.Env {
		nameU := strings.ToUpper(env.Name)
		valueL := strings.ToLower(env.Value)
		if nameU == "NEO4J_PLUGINS" && strings.Contains(valueL, "apoc") {
			hasAPOC = true
		}
		if nameU == "NEO4J_LABS_APOC_IMPORT_FILE_ENABLED" && valueL == "false" {
			hasImportDisabled = true
		}
		if strings.Contains(nameU, "ALLOW__CSV__IMPORT") && valueL == "false" {
			hasCsvDisabled = true
		}
	}

	if hasAPOC && (!hasImportDisabled || !hasCsvDisabled) {
		return []types.Finding{fail(ctrl, target,
			"Neo4j APOC plugin enabled without URL-loading restrictions — SSRF to cloud metadata endpoint possible",
			"NEO4J_PLUGINS contains 'apoc' but import restrictions not set",
			ctrl.Remediation)}
	}
	//nolint:errcheck // stdout write; broken pipe not recoverable
	if hasAPOC {
		return []types.Finding{pass(ctrl, target, "Neo4j APOC enabled with import restrictions configured")}
	}
	return []types.Finding{pass(ctrl, target, "Neo4j APOC plugin not installed — SSRF check not applicable")}
}

// dbDataPaths maps known database image substrings to their primary data directory paths.
var dbDataPaths = map[string]string{
	"postgres":   "/var/lib/postgresql/data",
	"mongo":      "/data/db",
	"redis":      "/data",
	"neo4j":      "/data",
	"weaviate":   "/var/lib/weaviate",
	"qdrant":     "/qdrant/storage",
	"milvus":     "/var/lib/milvus",
	"mysql":      "/var/lib/mysql",
	"mariadb":    "/var/lib/mysql",
	"cassandra":  "/var/lib/cassandra",
	"couchdb":    "/opt/couchdb/data",
	"arangodb":   "/var/lib/arangodb3",
	"chroma":     "/chroma",
	"influxdb":   "/var/lib/influxdb",
}

// checkDBEmptyDirData flags database data directories backed by non-persistent emptyDir (DB-K8S-004).
func checkDBEmptyDirData(spec podSpec, target string) []types.Finding {
	ctrl := controlByID("DB-K8S-004")

	// Build a map from volume name → emptyDir (non-memory only)
	emptyDirVols := map[string]bool{}
	for _, v := range spec.Volumes {
		if v.EmptyDir != nil && strings.ToLower(v.EmptyDir.Medium) != "memory" {
			emptyDirVols[v.Name] = true
		}
	}
	if len(emptyDirVols) == 0 {
		return []types.Finding{skipped(ctrl, target, "No emptyDir volumes to check against database data paths")}
	}

	// Sort dbDataPaths keys for deterministic iteration
	dbKeys := make([]string, 0, len(dbDataPaths))
	for k := range dbDataPaths {
		dbKeys = append(dbKeys, k)
	}
	sort.Strings(dbKeys)

	var findings []types.Finding
	allContainers := slices.Concat(spec.Containers, spec.InitContainers)
	for _, c := range allContainers {
		imageL := strings.ToLower(c.Image)
		dataPath := ""
		for _, imgSubstr := range dbKeys {
			if strings.Contains(imageL, imgSubstr) {
				dataPath = dbDataPaths[imgSubstr]
				break
			}
		}
		if dataPath == "" {
			continue
		}
		for _, vm := range c.VolumeMounts {
			if vm.MountPath == dataPath && emptyDirVols[vm.Name] {
				ct := fmt.Sprintf("%s[%s]", target, c.Name)
				findings = append(findings, fail(ctrl, ct,
					fmt.Sprintf("Database data directory %q is backed by emptyDir — data lost on pod restart", dataPath),
					fmt.Sprintf("volumeMount %s -> emptyDir volume %q", dataPath, vm.Name),
					ctrl.Remediation))
			}
		}
	}
	if len(findings) == 0 {
		return []types.Finding{pass(ctrl, target, "No database data directories backed by emptyDir")}
	}
	return findings
}

// checkDBFsGroup warns when database pods do not set fsGroup (DB-K8S-005).
func checkDBFsGroup(spec podSpec, target string) []types.Finding {
	ctrl := controlByID("DB-K8S-005")

	// Sort dbDataPaths keys for deterministic iteration
	dbKeys := make([]string, 0, len(dbDataPaths))
	for k := range dbDataPaths {
		dbKeys = append(dbKeys, k)
	}
	sort.Strings(dbKeys)

	var findings []types.Finding
	allContainers := slices.Concat(spec.Containers, spec.InitContainers)
	for _, c := range allContainers {
		imageL := strings.ToLower(c.Image)
		for _, imgSubstr := range dbKeys {
			if strings.Contains(imageL, imgSubstr) {
				if spec.SecurityContext == nil || spec.SecurityContext.FSGroup == nil {
					findings = append(findings, warn(ctrl, target,
						fmt.Sprintf("Database pod (%s image) missing spec.securityContext.fsGroup — volume ownership may be incorrect", imgSubstr),
						"spec.securityContext.fsGroup not set"))
				} else {
					findings = append(findings, pass(ctrl, target,
						fmt.Sprintf("fsGroup: %d", *spec.SecurityContext.FSGroup)))
				}
				break
			}
		}
	}
	if len(findings) == 0 {
		return []types.Finding{skipped(ctrl, target, "No database images found — fsGroup check not applicable")}
	}
	return findings
}

// credInAnnotationKeywords are fast substring pre-filters for annotation credential detection.
// If any of these match, we also run the full SecretScanner regex pass for higher-fidelity results.
var credInAnnotationKeywords = []string{
	"password=", "passwd=", "apikey=", "api_key=", "token=", "secret=",
	"://", // catches DSN formats (postgresql://, mongodb://, etc.)
}

// checkAnnotationsForSecrets scans pod/template annotations for embedded credentials (DB-K8S-006).
// Uses both fast keyword pre-filtering AND full SecretScanner regex analysis on annotation values.
func checkAnnotationsForSecrets(meta kubeObjectMeta, target string) []types.Finding {
	ctrl := controlByID("DB-K8S-006")
	secretScanner := NewSecretScanner(target, ctrl)

	// Sort annotation keys for deterministic iteration
	annotationKeys := make([]string, 0, len(meta.Annotations))
	for k := range meta.Annotations {
		annotationKeys = append(annotationKeys, k)
	}
	sort.Strings(annotationKeys)

	var findings []types.Finding
	for _, key := range annotationKeys {
		val := meta.Annotations[key]
		if val == "" {
			continue
		}
		combined := strings.ToLower(key + "=" + val)

		// 1. Fast keyword pre-filter
		for _, p := range credInAnnotationKeywords {
			if strings.Contains(combined, p) {
				// DSN-style patterns need a value that looks like a connection string
				if p == "://" && !strings.Contains(val, "@") {
					continue // likely just a URL without embedded creds
				}
				findings = append(findings, fail(ctrl, target,
					fmt.Sprintf("Potential credential pattern %q found in annotation %q", p, key),
					fmt.Sprintf("annotation %s=%s", key, val),
					ctrl.Remediation))
			}
		}

		// 2. Full regex analysis using SecretScanner (catches database URLs, tokens,
		// API keys, etc. that keyword matching alone would miss)
		matches := secretScanner.CheckLine(val)
		for _, m := range matches {
			detail := fmt.Sprintf("Regex-detected %s in annotation %q value", m.PatternName, key)
			if m.PatternName == "HIGH_ENTROPY" {
				detail = fmt.Sprintf("High-entropy value (%.2f) in annotation %q — possible credential", m.Entropy, key)
			}
			findings = append(findings, fail(ctrl, target, detail,
				fmt.Sprintf("annotation %s value matches %s pattern", key, m.PatternName),
				ctrl.Remediation))
		}
	}
	if len(findings) == 0 {
		return []types.Finding{pass(ctrl, target, "No credential patterns in annotations")}
	}
	return findings
}

// checkK8sAppArmorSELinux verifies that AppArmor or SELinux profiles are configured (RUNTIME-013).
func checkK8sAppArmorSELinux(c container, meta kubeObjectMeta, spec podSpec, target string) []types.Finding {
	ctrl := controlByID("RUNTIME-013")

	// Check AppArmor annotation (container.apparmor.security.beta.kubernetes.io/<name>)
	apparmorKey := "container.apparmor.security.beta.kubernetes.io/" + c.Name
	if val, ok := meta.Annotations[apparmorKey]; ok && val != "" {
		return []types.Finding{pass(ctrl, target,
			fmt.Sprintf("AppArmor profile configured: %s", val))}
	}

	// Check container-level SELinux
	if c.SecurityContext != nil && c.SecurityContext.SELinuxOptions != nil &&
		c.SecurityContext.SELinuxOptions.Type != "" {
		return []types.Finding{pass(ctrl, target,
			fmt.Sprintf("SELinux profile configured: %s", c.SecurityContext.SELinuxOptions.Type))}
	}

	// Check pod-level SELinux
	if spec.SecurityContext != nil && spec.SecurityContext.SELinuxOptions != nil &&
		spec.SecurityContext.SELinuxOptions.Type != "" {
		return []types.Finding{pass(ctrl, target,
			fmt.Sprintf("SELinux profile configured at pod level: %s", spec.SecurityContext.SELinuxOptions.Type))}
	}

	return []types.Finding{warn(ctrl, target,
		"No AppArmor annotation or SELinux profile configured — container lacks mandatory access control",
		"Neither AppArmor annotation nor seLinuxOptions set")}
}

// checkK8sAutomountSA checks that automountServiceAccountToken is false (RUNTIME-014).
func checkK8sAutomountSA(spec podSpec, target string) []types.Finding {
	ctrl := controlByID("RUNTIME-014")
	if spec.AutomountServiceAccountToken != nil && !*spec.AutomountServiceAccountToken {
		return []types.Finding{pass(ctrl, target, "automountServiceAccountToken: false")}
	}
	return []types.Finding{warn(ctrl, target,
		"automountServiceAccountToken is true or unset (default true) — pod mounts a service account token",
		"spec.automountServiceAccountToken != false")}
}

// checkK8sNamespace checks that the pod is not in the default namespace (K8S-001).
func checkK8sNamespace(meta kubeObjectMeta, target string) []types.Finding {
	ctrl := controlByID("K8S-001")
	ns := meta.Namespace
	if ns == "" || ns == "default" {
		return []types.Finding{warn(ctrl, target,
			"Workload is in the 'default' namespace — use dedicated namespaces for isolation",
			fmt.Sprintf("namespace: %q", ns))}
	}
	return []types.Finding{pass(ctrl, target,
		fmt.Sprintf("Workload in namespace %q (not default)", ns))}
}

// checkK8sAntiAffinity checks for pod anti-affinity or topology spread constraints (K8S-002).
func checkK8sAntiAffinity(spec podSpec, target string) []types.Finding {
	ctrl := controlByID("K8S-002")

	if len(spec.TopologySpreadConstraints) > 0 {
		return []types.Finding{pass(ctrl, target, "topologySpreadConstraints configured")}
	}
	if spec.Affinity != nil && spec.Affinity.PodAntiAffinity != nil {
		return []types.Finding{pass(ctrl, target, "podAntiAffinity configured")}
	}
	return []types.Finding{warn(ctrl, target,
		"No topologySpreadConstraints or podAntiAffinity — replicas may land on same node",
		"Neither topologySpreadConstraints nor affinity.podAntiAffinity set")}
}

// ── NETWORK-001: NetworkPolicy ────────────────────────────────────────────── //

type networkPolicySpec struct {
	PodSelector json.RawMessage `json:"podSelector" yaml:"podSelector"`
	PolicyTypes []string        `json:"policyTypes" yaml:"policyTypes"`
	Ingress     json.RawMessage `json:"ingress" yaml:"ingress"`
	Egress      json.RawMessage `json:"egress" yaml:"egress"`
}

func checkNetworkPolicyDefaultDeny(np networkPolicySpec, target string) []types.Finding {
	ctrl := controlByID("NETWORK-001")

	// Check if podSelector is empty {} (selects all pods = default-deny candidate)
	selectorStr := strings.TrimSpace(string(np.PodSelector))
	isEmptySelector := selectorStr == "{}" || selectorStr == "null" || selectorStr == ""

	if !isEmptySelector {
		// Non-empty podSelector means this targets specific pods, not a default-deny policy
		return []types.Finding{pass(ctrl, target,
			"NetworkPolicy with targeted podSelector found")}
	}

	// Empty podSelector with ingress or egress policy type = default-deny
	hasIngress := false
	hasEgress := false
	for _, pt := range np.PolicyTypes {
		if pt == "Ingress" {
			hasIngress = true
		}
		if pt == "Egress" {
			hasEgress = true
		}
	}

	ingressRulesEmpty := len(np.Ingress) == 0 || string(np.Ingress) == "null"
	egressRulesEmpty := len(np.Egress) == 0 || string(np.Egress) == "null"

	if hasIngress && ingressRulesEmpty {
		return []types.Finding{pass(ctrl, target,
			"Default-deny ingress NetworkPolicy found (podSelector: {}, policyTypes: [Ingress], no ingress rules)")}
	}
	if hasEgress && egressRulesEmpty {
		return []types.Finding{pass(ctrl, target,
			"Default-deny egress NetworkPolicy found (podSelector: {}, policyTypes: [Egress], no egress rules)")}
	}
	if (hasIngress && hasEgress) && ingressRulesEmpty && egressRulesEmpty {
		return []types.Finding{pass(ctrl, target,
			"Default-deny ingress+egress NetworkPolicy found")}
	}

	return []types.Finding{warn(ctrl, target,
		"NetworkPolicy with empty podSelector exists but allows some traffic — verify it acts as default-deny",
		fmt.Sprintf("policyTypes: %v, has ingress rules: %v, has egress rules: %v",
			np.PolicyTypes, !ingressRulesEmpty, !egressRulesEmpty))}
}

// ── NETWORK-002: Cloud Metadata Endpoint Blocked ──────────────────────────── //

// egressRule represents a single egress rule in a NetworkPolicy.
type egressRule struct {
	To []networkPolicyPeer `json:"to" yaml:"to"`
}

// networkPolicyPeer represents a peer in a NetworkPolicy rule.
type networkPolicyPeer struct {
	IPBlock *ipBlock `json:"ipBlock,omitempty" yaml:"ipBlock,omitempty"`
}

// ipBlock represents an IP block in a NetworkPolicy.
type ipBlock struct {
	CIDR   string   `json:"cidr" yaml:"cidr"`
	Except []string `json:"except,omitempty" yaml:"except,omitempty"`
}

func checkNetworkPolicyMetadataBlock(np networkPolicySpec, target string) []types.Finding {
	ctrl := controlByID("NETWORK-002")

	// Only check policies that have egress rules
	hasEgressType := false
	for _, pt := range np.PolicyTypes {
		if pt == "Egress" {
			hasEgressType = true
			break
		}
	}
	if !hasEgressType {
		return nil // Not an egress policy — nothing to check for NETWORK-002
	}

	// Parse egress rules
	if len(np.Egress) == 0 || string(np.Egress) == "null" {
		// Empty egress with Egress policyType = default deny all egress (blocks metadata too)
		return []types.Finding{pass(ctrl, target,
			"Default-deny egress NetworkPolicy blocks all outbound traffic including metadata endpoint 169.254.169.254")}
	}

	var rules []egressRule
	if err := json.Unmarshal(np.Egress, &rules); err != nil {
		return nil // Can't parse — skip
	}

	// Look for ipBlock rules that block 169.254.169.254/32
	for _, rule := range rules {
		for _, to := range rule.To {
			if to.IPBlock == nil {
				continue
			}
			for _, except := range to.IPBlock.Except {
				if except == "169.254.169.254/32" {
					return []types.Finding{pass(ctrl, target,
						fmt.Sprintf("Egress NetworkPolicy blocks cloud metadata endpoint (ipBlock.except: 169.254.169.254/32, cidr: %s)",
							to.IPBlock.CIDR))}
				}
			}
		}
	}

	return nil // No metadata block found in this policy; scan-level aggregation handles the WARN
}

// ── SECRETS-001: External Secrets / Plaintext Secret ──────────────────────── //

func checkPlaintextSecret(obj kubeObject, target string) []types.Finding {
	ctrl := controlByID("SECRETS-001")

	// System-managed secret types are acceptable
	if obj.Type == "kubernetes.io/service-account-token" ||
		obj.Type == "kubernetes.io/tls" ||
		obj.Type == "kubernetes.io/dockerconfigjson" ||
		obj.Type == "kubernetes.io/dockercfg" {
		return []types.Finding{pass(ctrl, target,
			fmt.Sprintf("Secret type %q is system-managed", obj.Type))}
	}

	// If stringData is present, secrets are in plaintext in the manifest
	if len(obj.StringData) > 0 && string(obj.StringData) != "null" {
		return []types.Finding{fail(ctrl, target,
			"Kubernetes Secret uses stringData with plaintext values in manifest — use external secret management",
			"Secret.stringData contains plaintext values",
			ctrl.Remediation)}
	}

	// Opaque secrets with data are base64 (not encrypted) — warn
	if (obj.Type == "" || obj.Type == "Opaque") && len(obj.Data) > 0 && string(obj.Data) != "null" {
		return []types.Finding{warn(ctrl, target,
			"Opaque Secret with base64-encoded data found — consider using ExternalSecrets, SealedSecrets, or Vault CSI",
			"Secret.data contains base64 values (not encrypted at application level)")}
	}

	return nil
}

// ── SECRETS-002: RBAC Secret Access ──────────────────────────────────────── //

type rbacRule struct {
	APIGroups     []string `json:"apiGroups" yaml:"apiGroups"`
	Resources     []string `json:"resources" yaml:"resources"`
	Verbs         []string `json:"verbs" yaml:"verbs"`
	ResourceNames []string `json:"resourceNames" yaml:"resourceNames"`
}

func checkRBACSecretAccess(rules []rbacRule, target string) []types.Finding {
	ctrl := controlByID("SECRETS-002")

	for _, rule := range rules {
		touchesSecrets := false
		for _, r := range rule.Resources {
			if r == "secrets" || r == "*" {
				touchesSecrets = true
				break
			}
		}
		if !touchesSecrets {
			continue
		}

		// Check for wildcard verbs
		hasWildcardVerb := false
		for _, v := range rule.Verbs {
			if v == "*" {
				hasWildcardVerb = true
				break
			}
		}

		// If resourceNames is empty, this is wildcard access to all secrets
		if len(rule.ResourceNames) == 0 {
			if hasWildcardVerb {
				return []types.Finding{fail(ctrl, target,
					"Role/ClusterRole grants wildcard access to all secrets (resources: [secrets/*], verbs: [*])",
					fmt.Sprintf("resources: %v, verbs: %v, resourceNames: (none)",
						rule.Resources, rule.Verbs),
					ctrl.Remediation)}
			}
			return []types.Finding{warn(ctrl, target,
				"Role/ClusterRole grants access to all secrets without named resource restriction",
				fmt.Sprintf("resources: %v, verbs: %v, resourceNames: (none)",
					rule.Resources, rule.Verbs))}
		}

		// resourceNames is populated — scoped access is acceptable
		return []types.Finding{pass(ctrl, target,
			fmt.Sprintf("Secret access scoped to named resources: %v", rule.ResourceNames))}
	}

	// No rules touch secrets — not applicable
	return nil
}

// ── SUPPLY-001: Kyverno Image Verification ───────────────────────────────── //

func checkKyvernoImageVerification(obj kubeObject, target string) []types.Finding {
	ctrl := controlByID("SUPPLY-001")

	if obj.Spec == nil {
		return nil
	}

	specStr := string(obj.Spec)
	if strings.Contains(specStr, "verifyImages") {
		return []types.Finding{pass(ctrl, target,
			"Kyverno ClusterPolicy/Policy with verifyImages rule found — image signatures verified at admission")}
	}

	// Policy exists but doesn't have verifyImages — not related to SUPPLY-001
	return nil
}

// ── MONITOR-001: Runtime Threat Detection Agent ──────────────────────────── //

var runtimeDetectionAgents = []string{
	"falco", "tetragon", "sysdig", "aquasec", "twistlock",
	"prismacloud", "lacework", "crowdstrike", "wiz",
}

func checkRuntimeDetectionAgent(spec podSpec, target string) []types.Finding {
	ctrl := controlByID("MONITOR-001")
	for _, c := range spec.Containers {
		imgLower := strings.ToLower(c.Image)
		for _, agent := range runtimeDetectionAgents {
			if strings.Contains(imgLower, agent) {
				return []types.Finding{pass(ctrl, target,
					fmt.Sprintf("Runtime threat detection agent found: %s", c.Image))}
			}
		}
	}
	// Don't fail individual DaemonSets — aggregated at Scan() level
	return nil
}

// ── MONITOR-002: Kubernetes API Server Audit Logging ─────────────────────── //

func checkAuditPolicy(obj kubeObject, target string) []types.Finding {
	ctrl := controlByID("MONITOR-002")

	if obj.Spec == nil {
		return []types.Finding{warn(ctrl, target,
			"Audit Policy found but spec is empty — no audit rules defined",
			"audit.k8s.io Policy with empty spec")}
	}

	// Check for rules in the audit policy spec
	specStr := string(obj.Spec)
	if strings.Contains(specStr, "rules") {
		return []types.Finding{pass(ctrl, target,
			"Kubernetes API server audit policy found — control plane activity is logged")}
	}

	return []types.Finding{warn(ctrl, target,
		"Audit Policy found but no rules defined",
		"audit.k8s.io Policy spec without rules")}
}

// ── Scan-level aggregation helpers ───────────────────────────────────────── //

func hasFindingForControl(findings []types.Finding, controlID string, status types.Status) bool {
	for _, f := range findings {
		if f.Control.ID == controlID && f.Status == status {
			return true
		}
	}
	return false
}

func hasFindingForControlAny(findings []types.Finding, controlID string) bool {
	for _, f := range findings {
		if f.Control.ID == controlID {
			return true
		}
	}
	return false
}

// Utilities (collectFiles, remarshal) are defined in helpers.go.
