# Daemon & Host Control Examples

These controls require a live Docker daemon and cannot be demonstrated with
static fixture files. This document shows what the scanner checks and how to
trigger or resolve each finding.

Run: `dockeraudit daemon`

---

## DAEMON-004 — Docker Content Trust

**What it checks:** Whether Docker is configured to only pull/push signed images.

### Vulnerable (FAIL)

daemon.json missing content-trust config and `DOCKER_CONTENT_TRUST` unset:

```json
{
  "storage-driver": "overlay2",
  "log-driver": "json-file"
}
```

```bash
$ echo $DOCKER_CONTENT_TRUST
# (empty — not set)
```

### Secure (PASS)

Option A — Set in daemon.json:

```json
{
  "content-trust": {
    "mode": "enforced"
  }
}
```

Option B — Set as environment variable:

```bash
export DOCKER_CONTENT_TRUST=1
```

Option C — Set in Compose service environment:

```yaml
services:
  myapp:
    environment:
      DOCKER_CONTENT_TRUST: "1"
```

---

## HOST-002 — Kernel Version CVE Check

**What it checks:** The Docker host kernel version against known
container-escape CVEs.

### Vulnerable (FAIL)

```
$ docker info --format '{{.KernelVersion}}'
5.10.43-linuxkit
```

Scanner output:

```
FAIL  HOST-002  Kernel 5.10.43 vulnerable to CVE-2022-0847 (Dirty Pipe, fixed in 5.10.102)
FAIL  HOST-002  Kernel 5.10.43 vulnerable to CVE-2022-0185 (heap overflow, fixed in 5.10.93)
```

### Secure (PASS)

```
$ docker info --format '{{.KernelVersion}}'
5.15.49-linuxkit
```

Scanner output:

```
PASS  HOST-002  Kernel version 5.15.49 has no known container-escape CVEs
```

### Known CVEs checked

| CVE            | Description                 | Fixed in              |
|----------------|-----------------------------|-----------------------|
| CVE-2022-0847  | Dirty Pipe (pipe_write)     | 5.10.102, 5.15.25, 5.16.11 |
| CVE-2022-0185  | Heap overflow (fsconfig)    | 5.4.173, 5.10.93, 5.15.14 |

---

## HOST-005 — Auditd Rules for Docker Binary Files

**What it checks:** Whether auditd monitors critical Docker binaries and
config files for unauthorized modifications.

### Vulnerable (WARN)

```
$ auditctl -l
-w /etc/docker -p rwxa -k docker
-w /var/lib/docker -p rwxa -k docker
```

Missing rules for `/usr/bin/docker`, `/usr/bin/containerd`, `/usr/sbin/runc`,
`/etc/docker/daemon.json`, and `/etc/default/docker`.

Scanner output:

```
WARN  HOST-005  Auditd rule missing for /usr/bin/docker
WARN  HOST-005  Auditd rule missing for /usr/bin/containerd
WARN  HOST-005  Auditd rule missing for /usr/sbin/runc
WARN  HOST-005  Auditd rule missing for /etc/docker/daemon.json
WARN  HOST-005  Auditd rule missing for /etc/default/docker
```

### Secure (PASS)

```
$ auditctl -l
-w /usr/bin/docker -p rwxa -k docker
-w /usr/bin/containerd -p rwxa -k docker
-w /usr/sbin/runc -p rwxa -k docker
-w /etc/docker/daemon.json -p rwxa -k docker
-w /etc/default/docker -p rwxa -k docker
-w /etc/docker -p rwxa -k docker
-w /var/lib/docker -p rwxa -k docker
-w /usr/bin/dockerd -p rwxa -k docker
```

Add rules via `/etc/audit/rules.d/docker.rules`:

```
-w /usr/bin/docker -p rwxa -k docker
-w /usr/bin/containerd -p rwxa -k docker
-w /usr/sbin/runc -p rwxa -k docker
-w /etc/docker/daemon.json -p rwxa -k docker
-w /etc/default/docker -p rwxa -k docker
```

Then reload: `sudo auditctl -R /etc/audit/rules.d/docker.rules`

---

## HOST-006 — Auditd Rules for Docker Directories

**What it checks:** Whether auditd monitors Docker directories.

### Required paths

| Path               | Purpose                        |
|--------------------|--------------------------------|
| `/etc/docker`      | Docker configuration directory |
| `/var/lib/docker`  | Docker storage root            |
| `/usr/bin/dockerd` | Docker daemon binary           |

---

## DAEMON-001 — Docker Socket Not Mounted

**What it checks:** Whether running containers have `/var/run/docker.sock`
mounted (runtime check via `docker inspect`).

### Vulnerable (FAIL)

```bash
docker run -v /var/run/docker.sock:/var/run/docker.sock nginx
```

### Secure (PASS)

No containers have docker.sock mounted. Use Docker-in-Docker (DinD) or
rootless Docker instead:

```bash
docker run --privileged docker:dind  # DinD alternative
```

Note: DAEMON-001 is also checked in Compose and K8s scanners. See
`testdata/compose/insecure-compose.yml` and
`testdata/manifests/security-controls-insecure.yaml` for static examples.
