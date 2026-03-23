# Security Audit Report

## 1. Container Security Checklist

### Runs as non-root user
**Status:** YES, properly implemented.

**Explanation:** The Dockerfile uses `USER nonroot` (uid 65532) from the distroless base image. This is critical from an attacker's perspective because:
- **Privilege escalation prevention:** If an attacker gains code execution inside the container, they start with uid 65532 (an unprivileged user) rather than root (uid 0). This dramatically limits their ability to modify system files, install packages, or access sensitive system resources.
- **Lateral movement barrier:** Unprivileged users cannot read/write files owned by other users or root unless explicitly granted. This compartmentalizes damage.
- **Container escape mitigation:** Privilege escalation is a common vector for container breakout. Running as non-root eliminates the low-hanging fruit where an attacker could immediately become root inside the container.

---

### Uses a minimal/distroless base image in the final stage
**Status:** YES, properly implemented.

**Explanation:** The runtime stage uses `gcr.io/distroless/base-debian13:nonroot` instead of a full OS like Ubuntu or Alpine. This matters because:
- **Reduced attack surface:** Distroless images contain only the application runtime, libc, and minimal utilities—no shell, no package manager, no debugging tools. An attacker with code execution has far fewer tools available to pivot, establish persistence, or exfiltrate data.
- **No shell = no interactive access:** Without `/bin/sh` or `/bin/bash`, an attacker cannot easily execute arbitrary commands interactively, making post-exploitation significantly harder.
- **Smaller image = fewer vulnerable dependencies:** Fewer packages means fewer CVEs. Each binary and library in the image is a potential attack vector. Distroless eliminates thousands of them.
- **Build tool isolation:** By using a multi-stage build, Go compilation tools (compiler, linker, standard library source) are discarded in the final image. An attacker cannot recompile malware or inspect build artifacts.

---

### No secrets baked into the image or layers
**Status:** YES, properly implemented.

**Explanation:** The Dockerfile does not hardcode secrets. Instead:
- **docker-compose.yaml passes secrets via environment variables** from `.env` files (using `${DB_PASSWORD}` syntax).
- **No RUN commands echo or commit secrets** to the image layers.
- **Docker layer caching cannot expose secrets:** Even if someone inspects the image history, there are no exposed credentials.

From an attacker's perspective, this is crucial because:
- **Image distribution:** If secrets were baked in, anyone with access to the image (in a registry, on disk, etc.) would have credentials forever—image pull requests, CI/CD logs, backups, etc. Secrets would be impossible to rotate without rebuilding.
- **Layer history:** Docker image layers are immutable. Once a secret is committed in a layer, deleting it in a later layer doesn't remove it—attackers can still extract it by reverting to the earlier layer.
- **Environment variable security:** While imperfect (env vars can be inspected in `/proc/[pid]/environ` inside the container), they are runtime-only and do not persist across image distributions.

---

### Base image and dependencies are version-pinned (no `latest` tags)
**Status:** YES, properly implemented.

**Explanation:**
- **Dockerfile uses `golang:1.26`** (pinned to major.minor version) and **`gcr.io/distroless/base-debian13:nonroot`** (pinned to Debian 13).
- **docker-compose.yaml pins `postgres:18.3`** (pinned to major.minor.patch).

Why this matters:
- **Reproducibility and supply chain attacks:** Using `latest` tags means each build could pull a different image. An attacker could compromise the `latest` tag in a registry (or perform a MITM attack) to inject malware into future builds without code changes.
- **Unexpected vulnerabilities:** A newer `latest` image might introduce new bugs or regressions that break the application or open security holes. Version pinning lets you control when dependencies update.
- **Audit trails:** Pinned versions create an auditable record of exactly which code was deployed. With `latest`, historical builds are irreproducible and forensic analysis becomes impossible.
- **Rollback capability:** If a vulnerability is discovered in Go 1.27, you can safely continue using 1.26 until a patch is available, rather than being forced to upgrade.

---

### Uses `.dockerignore` to exclude sensitive files
**Status:** YES, properly implemented.

**Explanation:** A `.dockerignore` file is present and well-configured to prevent accidental inclusion of sensitive files:
- **Excluded files:** `.env`, `.env.local`, `.git`, `.gitignore`, `*.log`, `.vscode`, `.idea`, SSH configs, `.github` workflows, and more.
- **Environment-based secrets:** The compose file uses `${DB_PASSWORD}` from external sources, not baked-in files.
- **Documentation exclusion:** Markdown files (`*.md`) and `docs/` are excluded, reducing image size.

From an attacker's perspective, this is critical because:
- **Source code protection:** The `.git/` directory (which contains the entire repository history) is excluded. An attacker cannot inspect commit logs to find hardcoded secrets, sensitive comments, or past vulnerabilities.
- **Credential isolation:** `.env` files are excluded. If developers accidentally commit `.env.local` to git, the `.dockerignore` ensures it won't be copied into the container during `docker build`.
- **Reduced image size:** Excluding unnecessary files like documentation reduces the image size and attack surface.
- **Build context cleanliness:** The build context is smaller, reducing the risk of accidentally including sensitive files in the image layers.

**Current `.dockerignore` coverage:**
- Environment files (`.env`, `.env.local`, `.env.*.local`)
- Source control (`.git`, `.gitignore`, `.gitattributes`)
- IDE configs (`.vscode`, `.idea`)
- Documentation (`*.md`, `docs`, `LICENSE`)
- Logs (`*.log`)
- Node modules and Python artifacts
- OS files (`.DS_Store`)
- Temporary editor files (`*.swp`, `*.swo`, `*~`)

This is a comprehensive and well-configured `.dockerignore` file.

---

### Multi-stage build doesn't leak build tools into the production image
**Status:** YES, properly implemented.

**Explanation:** The Dockerfile uses a two-stage build:
1. **Stage 1 (`builder`):** Uses `golang:1.26` to compile the Go source code.
2. **Stage 2 (`runtime`):** Uses `gcr.io/distroless/base-debian13:nonroot` and only copies the compiled binary.

The `golang:1.26` image (which is ~500MB) is discarded; only the final ~20MB distroless image is tagged and deployed.

Why this prevents attacks:
- **Go compiler removal:** The Go compiler, standard library source, linker, and build tools are not in the final image. An attacker cannot recompile malware, craft custom Go binaries, or inspect application source code.
- **Reduced exploitable surface:** Each tool bundled in the production image is another attack vector. Removing build tools (which are complex and often have CVEs) significantly reduces the attack surface.
- **Layer isolation:** The builder stage is separate; if someone extracts the builder image, they get build artifacts, not the running container. Secrets in the builder stage don't leak to the runtime container (provided they're not copied over).

---

## 2. Attack Surface Analysis

### What is the minimal set of capabilities this container needs? Would you drop capabilities in production?

**Minimal Required Capabilities:**
The application is a web server (Go HTTP service) that needs to:
- **Bind to a port (8080):** Requires `CAP_NET_BIND_SERVICE` (only if binding to ports < 1024; port 8080 doesn't need this).
- **TCP socket operations:** Already permitted by default Linux capabilities.

**Actual Capabilities Needed:** None. By binding to port 8080 (> 1024), the application does not require any special Linux capabilities. The default capability set (which includes `CAP_NET_RAW`, `CAP_NET_BIND_SERVICE`, `CAP_SYS_CHROOT`, etc.) is overkill.

**Current Status in docker-compose.yaml:**
The docker-compose.yaml now drops all Linux capabilities:
```yaml
cap_drop:
  - ALL
```

**Impact from an attacker's perspective:**
Since all capabilities are dropped, an attacker with code execution cannot:
- **Escalate privileges via kernel bugs:** Even if an attacker finds a kernel vulnerability (e.g., `CVE-2016-5195` Dirty COW), they cannot exploit it because the required capabilities (like `CAP_SYS_ADMIN`) are dropped.
- **Modify system parameters:** Capabilities like `CAP_SYS_ADMIN`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN` are unavailable, blocking attempts to load kernel modules, modify kernel parameters, or reconfigure networking.
- **Expand attack scope:** Without capabilities, attackers are confined to user-space operations and cannot perform privileged kernel operations.

---

### If an attacker gains code execution inside the container, what can they access? What limits their movement?

**What an attacker can access:**
1. **Inside the container:**
   - The compiled Go binary (`/app/recipe`).
   - Application state in memory (database connection strings, session tokens, etc.).
   - Any files in the container filesystem (read-only root filesystem mitigates some of this).
   - Network traffic to the PostgreSQL database.

2. **Outside the container:**
   - **Network:** TCP connection to the PostgreSQL database (internal service on `postgres:5432`).
   - **Host system:** Extremely limited—containers are isolated via Linux namespaces (PID, network, mount, IPC, UTS, user).

**What limits their movement:**

1. **Read-only filesystem (`read_only: true` in compose):**
   - **Enabled:** The root filesystem is read-only. An attacker cannot write persistent malware, modify binaries, or create files.
   - **Impact:** Prevents persistence. Malware cannot establish a backdoor that survives container restart.
   - **Limitation:** Attackers can still write to `/tmp`, `/var/tmp`, or memory-backed filesystems in some configurations. Additionally, during the container lifetime, they have full access to memory.

2. **Non-root user (uid 65532):**
   - **Enabled:** The application runs as `nonroot`. Attacker code execution happens as this user.
   - **Impact:** Cannot modify files owned by root or other users. Cannot install packages (no `apt`, `yum`). Cannot modify system configuration.

3. **Dropped capabilities (`cap_drop: ALL`):** *(Not currently configured but recommended)*
   - Prevents kernel-level privilege escalation.

4. **Network isolation:**
   - The container can only reach `postgres` service and localhost within the container.
   - The port `127.0.0.1:8080` is bound to localhost only (not `0.0.0.0:8080`), so the app is only reachable from the host machine.
   - An attacker cannot make outbound connections to arbitrary external hosts.

5. **Limited container escape vectors:**
   - Linux namespaces isolate the container from the host. An attacker cannot directly access `/etc/passwd` on the host, host processes, or host filesystems.
   - Distroless image (no shell, no tools) makes it very difficult to craft a container escape exploit.

**Remaining risks:**
- **Database compromise:** If the attacker can extract the `DB_PASSWORD` from memory, environment variables, or application logs, they can directly access PostgreSQL and steal/modify all data.
- **Memory access:** A privileged attacker on the host could dump container memory and extract secrets.
- **Kernel bugs:** An unpatched kernel vulnerability could allow container escape, bypassing all namespace isolation.

---

### The database password is passed as an environment variable — what are the risks? What alternatives exist?

**Current Status:**
- Environment variables are passed at runtime through `docker-compose.yaml` (using `${DB_PASSWORD}` syntax from external sources, not baked into the image).
- Secrets are not hardcoded in the Dockerfile itself.

**Risks of this approach:**

1. **Visibility in process listings:** Any process with access to the container's filesystem can run `cat /proc/[pid]/environ` and extract the password directly from the running process.

2. **Container inspection:** If an attacker gains access to the Docker daemon (via `/var/run/docker.sock` or network access), they can run `docker inspect <container_id>` and read all environment variables including the database password.

3. **Log exposure:** Application logs might accidentally include environment variables. CI/CD logs might print environment variables if not masked. Docker daemon logs could capture startup environment.

4. **Credential rotation limitations:** Changing the database password requires restarting the container and redeploying the entire application. There's no way to rotate credentials without downtime.

5. **Accidental exposure:** Screenshots, terminal history, code dumps, or debug output could expose environment variables.

---

## 3. Find the Vulnerabilities

### Issues in `insecure-Dockerfile`:

#### **Vulnerability 1: `FROM golang:latest`**
**Security Issue:** Using the `latest` tag means the base image is not pinned to a specific version.

**What this enables:**
- **Supply chain attacks:** An attacker or compromised registry could push a malicious `golang:latest` image containing backdoors, rootkits, or cryptocurrency miners. Every new build would pull the compromised image without code changes.
- **Reproducibility breakdown:** Different builds on different days will have different Go toolchains, making it impossible to debug issues or reproduce production behavior.
- **Unexpected breaking changes:** A newer Go version might introduce incompatibilities or performance regressions that break the application.
- **CVE exposure:** If a critical CVE is found in the current `latest` version, you cannot control when your builds are affected—they'll always pull the vulnerable version until `latest` is updated.

---

#### **Vulnerability 2: No multi-stage build; build tools leak into production**
**Security Issue:** The entire `golang:latest` image (including the Go compiler, linker, standard library source) is the final production image.

**What this enables:**
- **Recompilation attacks:** An attacker with code execution can use the Go compiler to recompile malware or patch the application binary mid-execution.
- **Source code inspection:** The Go standard library source is included. An attacker can study it to find kernel call patterns, cryptographic operations, or other valuable information.
- **Build artifact extraction:** Any temporary files, object files, or debug symbols left by the build are in the production image.
- **Larger image = larger attack surface:** The golang image is ~500MB; each additional binary, library, or utility in the image is a potential attack vector.
- **Privilege escalation toolkit:** An attacker could use tools from the image to exploit kernel vulnerabilities.

---

#### **Vulnerability 3: Runs as root**
**Security Issue:** The Dockerfile does not specify a `USER` directive. The container runs as root (uid 0) by default.

**What this enables:**
- **Instant privilege escalation:** An attacker with code execution immediately has root privileges. No escalation needed.
- **System modification:** The attacker can install packages, modify binaries, load kernel modules, change firewall rules, or disable security features.
- **Data exfiltration:** The attacker can read all files on the system, including `/etc/shadow`, `/root/.ssh`, or other sensitive data.
- **Persistence:** Root can create system-wide backdoors that survive container restart (if the filesystem is writable).
- **Container escape:** With root inside the container, many container escape techniques become viable (e.g., exploiting cgroup vulnerabilities, modifying seccomp profiles).

---

#### **Vulnerability 4: `RUN apt-get install -y curl wget netcat vim`**
**Security Issue:** Installing debugging and network tools (`curl`, `wget`, `netcat`, `vim`) in the production image.

**What this enables:**
- **Lateral movement:** `curl` and `wget` allow an attacker to download and execute external payloads from the internet.
- **Network reconnaissance:** `netcat` can probe internal services, establish reverse shells, or establish persistence.
- **File modification:** `vim` (a full text editor) allows an attacker to modify application files, configuration, or system binaries.
- **Supply chain piping:** An attacker can use `curl | bash` pattern to fetch and execute arbitrary code from a remote server.
- **Increased CVE surface:** Each tool has its own vulnerabilities. `curl` alone has had critical CVEs. Including unnecessary tools expands the attack surface.

**Impact:** Even without these tools, an attacker can still execute code, but they must rely on what the Go runtime provides. With `curl`, they can fetch malware from the internet.

---

#### **Vulnerability 5: Hardcoded secrets in environment variables**
**Security Issue:** `ENV DB_PASSWORD=supersecretpassword123` and `ENV DB_USER=admin` are baked into the image.

**What this enables:**
- **Permanent credential exposure:** The password is committed to all image layers. It's visible in:
  - `docker history <image>`
  - `docker inspect <image>` (if checking layers)
  - Any image backup or snapshot
  - Container images pushed to registries
- **Inability to rotate:** The password is built into the image. Changing it requires rebuilding and redeploying the entire image.
- **Shared with everyone:** Anyone with access to the image (developers, CI/CD systems, registries) has the credentials.
- **Forensic visibility:** Old image versions in registries will forever have the old password, making credential revocation impossible.

---

#### **Vulnerability 6: Exposes port 22 (SSH)**
**Security Issue:** `EXPOSE 22` suggests SSH is available, but there's no SSH server configuration in the Dockerfile. This is misleading, but it signals intent to allow remote access.

**What this enables:**
- **False sense of remote access:** If SSH were actually running (which it's not in this image), it would allow an attacker to establish an interactive shell on the container.
- **Persistence and control:** SSH access would give an attacker a backdoor that survives container restarts (if keys are baked in).
- **Lateral movement:** SSH could be used to hop to other containers or the host system if misconfigured.

**Actual impact:** Low in this specific case since SSH isn't running, but it's a red flag indicating a security mindset problem.

---

#### **Vulnerability 7: No read-only filesystem**
**Security Issue:** The image doesn't specify a read-only filesystem, and the Dockerfile doesn't create restricted volumes.

**What this enables:**
- **Persistent malware:** An attacker can write to `/tmp`, `/var`, or other directories and create a backdoor that survives container restart.
- **Log tampering:** The attacker can modify or delete logs to cover their tracks.
- **Binary patching:** The attacker can overwrite the application binary mid-execution to inject code.
- **Privilege escalation staging:** Write exploits or payloads to disk to facilitate container escape.

---

#### **Vulnerability 8: No non-root user enforcement**
**Security Issue:** The Dockerfile doesn't create a restricted user or specify a `USER` directive.

**What this enables:** (Covered above in Vulnerability 3, but worth emphasizing)
- **Full root control:** Any process or attack immediately has uid 0 (root).
- **System-wide compromise:** The attacker can modify system files, install rootkits, or disable security features.

---

## Summary Table

| Issue | Severity | Impact |
|-------|----------|--------|
| `golang:latest` tag | HIGH | Supply chain attacks, non-reproducible builds, unexpected CVEs |
| No multi-stage build | HIGH | Compiler recompilation, larger attack surface, source code exposure |
| Runs as root | CRITICAL | Instant privilege, system modification, persistence, escape |
| Debug tools installed | HIGH | Lateral movement, remote code fetch, file modification |
| Hardcoded secrets (ENV) | CRITICAL | Permanent credential exposure, inability to rotate, registry leakage |
| SSH port exposed | MEDIUM | Confusing intent, unnecessary attack surface (not functional here) |
| No read-only filesystem | MEDIUM | Persistent malware, log tampering, binary patching |

---

## Secure Dockerfile Reference

Your production `Dockerfile` properly addresses all of these issues:
- Pinned Go version (`golang:1.26`)
- Multi-stage build (builder → distroless)
- Non-root user (`nonroot`)
- No debugging tools
- No hardcoded secrets
- No SSH
- No build artifacts leaked
- Minimal base image (distroless)

Your `docker-compose.yaml` adds:
- Read-only filesystem (`read_only: true`)
- Environment variables from external sources (not baked)
- Health checks for monitoring
- localhost-only port binding (`127.0.0.1:8080`)
- Dropped all Linux capabilities (`cap_drop: ALL`)


## Why Multi‑Platform Builds Matter for Supply Chain Security

Building images for both `amd64` and `arm64` reduces the risk of supply‑chain inconsistencies. If we only build for one architecture but deploy on another, several security issues can occur:

- **Silent architecture fallback:**  
  Some registries or orchestrators may automatically pull a different image variant (often an older or unmaintained one). Attackers can exploit this by poisoning a single‑arch image that only some systems use.

- **Inconsistent binaries across environments:**  
  If CI builds `amd64` but production nodes run `arm64`, the runtime environment may rebuild or reinterpret the image locally. This breaks reproducibility and makes it harder to verify that the deployed binary is the one we intended.

- **Reduced ability to verify signatures and SBOMs:**  
  Security tooling (signatures, attestations, SBOMs) must match the exact image digest. If only one architecture is built, but another is deployed, the verification chain breaks.

- **Attackers target the “forgotten” architecture:**  
  If only one architecture receives updates, the other may remain outdated and vulnerable. Multi‑platform builds ensure all architectures receive the same hardened, patched image.

In short, multi‑platform builds ensure **reproducibility**, **consistency**, and **uniform security guarantees** across all deployment environments.
