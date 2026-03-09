# SUPPLY-002 — SBOM Generated and Attested per Image

This control checks whether built images have an SBOM (Software Bill of
Materials) attestation attached. SBOMs enable vulnerability tracking and
supply chain transparency.

Run: `dockeraudit image <image-name>`

---

## How the Scanner Checks

The scanner uses two methods to verify SBOM attestation:

### 1. Image Labels (Primary)

Checks `docker inspect` output for BuildKit SBOM labels:

```bash
docker inspect --format '{{json .Config.Labels}}' myapp:latest
```

**Vulnerable (FAIL)** — No SBOM labels:

```json
{
  "maintainer": "dev@example.com"
}
```

**Secure (PASS)** — SBOM labels present:

```json
{
  "io.buildkit.build.ref": "abc123",
  "org.opencontainers.image.source": "https://github.com/org/repo"
}
```

### 2. Cosign Attestation Tree (Secondary)

If `cosign` is installed, checks for attached attestation layers:

```bash
cosign tree registry.example.com/myapp@sha256:abc123...
```

**Vulnerable (FAIL)** — No attestations:

```
No attestation found for image
```

**Secure (PASS)** — SBOM attestation attached:

```
Attestations for an image tag:
└── sha256:def456...
    └── predicateType: https://spdx.dev/Document
```

---

## How to Build with SBOM Attestation

### Option A: BuildKit SBOM (Docker 24+)

```bash
docker buildx build --sbom=true -t myapp:latest .
```

This generates an SPDX SBOM and attaches it as an attestation layer.

### Option B: Cosign + Syft

```bash
# Generate SBOM with Syft
syft myapp:latest -o spdx-json > sbom.spdx.json

# Attach as cosign attestation
cosign attest --predicate sbom.spdx.json \
  --type spdxjson \
  --key cosign.key \
  registry.example.com/myapp@sha256:abc123...
```

### Option C: GitHub Actions

```yaml
- name: Build and push with SBOM
  uses: docker/build-push-action@v5
  with:
    push: true
    tags: registry.example.com/myapp:latest
    sbom: true
    provenance: true
```

---

## Scanner Output Examples

### No SBOM (FAIL)

```
FAIL  SUPPLY-002  No SBOM attestation found on image myapp:latest
                  Remediation: Build with --sbom=true or attach via cosign attest
```

### SBOM Present (PASS)

```
PASS  SUPPLY-002  SBOM attestation found on image myapp:latest
```

### Cosign Not Available (WARN)

```
WARN  SUPPLY-002  Cannot verify SBOM attestation (cosign not installed)
                  Install cosign for full SBOM verification
```

---

## Note

SUPPLY-002 is an image-level property, not a deployment property. K8s
manifests, Compose files, and Terraform configs do not carry SBOM
information. The check only runs in the `dockeraudit image` scanner.
