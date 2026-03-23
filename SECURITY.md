# Security Analysis – CI/CD Pipeline

This document analyzes the security aspects of the implemented CI/CD pipeline for the recipe API.  
The analysis focuses on the three required areas of the assignment: dependency trust, secrets management, and pipeline hardening.

---

## 1. Dependency Trust Audit

The pipeline currently uses the following GitHub Actions:

- `actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd`
- `actions/setup-go@v4`
- `golangci/golangci-lint-action@v3`
- `hadolint/hadolint-action@v3.1.0`
- `docker/setup-buildx-action@v3`
- `docker/login-action@v3`
- `docker/metadata-action@v5`
- `docker/build-push-action@0565240e2d4ab88bba5387d719585280857ece09`
- `aquasecurity/trivy-action@master`
- `github/codeql-action/upload-sarif@v3`
- `anchore/sbom-action@v0`

### actions/checkout

- **Maintainer:** GitHub
- **Verified organization:** Yes
- **Current pinning:** Full commit SHA
- **Risk if tag-based:** If a mutable tag such as `@v4` is used, the referenced code may change over time. If the upstream action is compromised, the pipeline may execute untrusted code.
- **Reason for pinning:** This action is used in every job and therefore has a large blast radius.

### actions/setup-go

- **Maintainer:** GitHub
- **Verified organization:** Yes
- **Current pinning:** Mutable tag (`@v4`)
- **Risk:** Even though the action is maintained by GitHub, mutable tags are still less deterministic than commit SHAs.

### golangci/golangci-lint-action

- **Maintainer:** golangci
- **Verified organization:** Not an official GitHub platform action
- **Current pinning:** Mutable tag (`@v3`)
- **Risk:** Third-party action, therefore broader trust boundary and possible supply chain exposure.

### hadolint/hadolint-action

- **Maintainer:** hadolint
- **Verified organization:** Not treated as an official GitHub platform action
- **Current pinning:** Mutable tag (`@v3.1.0`)
- **Risk:** Version tags are still mutable and weaker than full SHA pinning.

### docker/setup-buildx-action

- **Maintainer:** Docker
- **Verified organization:** Yes
- **Current pinning:** Mutable tag (`@v3`)
- **Risk:** This action affects the build environment and therefore has security relevance.

### docker/login-action

- **Maintainer:** Docker
- **Verified organization:** Yes
- **Current pinning:** Mutable tag (`@v3`)
- **Risk:** Sensitive because it handles authentication to Docker Hub.

### docker/metadata-action

- **Maintainer:** Docker
- **Verified organization:** Yes
- **Current pinning:** Mutable tag (`@v5`)
- **Risk:** Lower impact than build or login, but still part of the release chain.

### docker/build-push-action

- **Maintainer:** Docker
- **Verified organization:** Yes
- **Current pinning:** Full commit SHA
- **Risk if tag-based:** A compromised or moved tag could directly affect container image creation and publishing.
- **Reason for pinning:** This action directly builds and publishes images and therefore has very high impact.

### aquasecurity/trivy-action

- **Maintainer:** Aqua Security
- **Verified organization:** Reputable vendor
- **Current pinning:** Branch reference (`@master`)
- **Risk:** This is the weakest form of pinning. A branch can change at any time, which makes the pipeline less deterministic.

### github/codeql-action/upload-sarif

- **Maintainer:** GitHub
- **Verified organization:** Yes
- **Current pinning:** Mutable tag (`@v3`)
- **Risk:** Lower impact than build/push, but still mutable.

### anchore/sbom-action

- **Maintainer:** Anchore
- **Verified organization:** Reputable vendor
- **Current pinning:** Mutable tag (`@v0`)
- **Risk:** Still mutable and therefore less deterministic than SHA pinning.

---

### Risk of tag-based pinning

Using tags such as `@v3`, `@v4`, or `@master` is convenient, but it means the exact code being executed is not permanently fixed.  
If an upstream maintainer account is compromised, or if a tag is moved or re-released, the pipeline may execute different code without any change in this repository.

This is a known supply chain problem. The general lesson from GitHub Actions supply chain incidents is that **critical dependencies should be pinned to immutable references whenever possible**.

### Implemented improvement: SHA pinning

Two critical actions were pinned to immutable commit SHAs:

- `actions/checkout`
- `docker/build-push-action`

These two were selected because:

- `actions/checkout` is used in every job and has a large attack surface
- `docker/build-push-action` directly builds and publishes container images and therefore has especially high impact

Pinning to a full commit SHA improves:

- reproducibility
- determinism
- resistance against upstream tag changes
- protection against supply chain manipulation

---

## 2. Secrets Management

### Which secrets does the pipeline need?

The pipeline uses the following repository secrets:

- `DOCKER_USERNAME`
- `DOCKER_TOKEN`

### Minimum required permissions for these secrets

**DOCKER_USERNAME**

- only the account name needed for Docker Hub login

**DOCKER_TOKEN**

- push access only to the required Docker Hub repository
- no account-wide admin rights
- no delete permissions if not required
- scope should be as narrow as Docker Hub allows

### Blast radius if DOCKER_TOKEN is leaked

If `DOCKER_TOKEN` is leaked in CI logs or through a malicious action, an attacker could:

- push malicious images to the Docker Hub repository
- overwrite trusted tags such as `latest` or branch-related tags
- publish a backdoored image that downstream users may trust
- abuse the container registry as part of a supply chain attack

Because the registry is part of the software delivery path, the impact of such a leak is potentially serious.

### How to limit the blast radius

The impact can be reduced by:

- using a token with the smallest possible scope
- using a dedicated token only for this repository or project
- rotating the token regularly
- never printing secrets in logs
- limiting which jobs actually receive registry credentials
- only using the secret in jobs that really need it

### Why use `${{ secrets.GITHUB_TOKEN }}` instead of a PAT?

`GITHUB_TOKEN` is safer than a Personal Access Token (PAT) in most CI use cases because:

- it is automatically generated by GitHub for each workflow run
- it is short-lived
- it is scoped to the current repository and workflow permissions
- it fits the least-privilege model better

A PAT is riskier because:

- it is long-lived
- it is often over-scoped
- it may grant access across multiple repositories or broader account resources
- if leaked, the damage is usually greater than with `GITHUB_TOKEN`

### How to detect secret exfiltration via a malicious PR

A malicious pull request could attempt to exfiltrate secrets by:

- printing them to logs
- sending them to an external server
- hiding exfiltration in shell commands or third-party actions

Mitigations and detection measures include:

- not exposing secrets to untrusted forked pull requests
- reviewing changes to workflow files carefully
- monitoring workflow logs for suspicious outbound requests or encoded output
- restricting permissions at job level
- avoiding powerful secrets in untrusted PR-triggered workflows
- requiring review for changes in `.github/workflows/`
- using branch protection and code review

---

## 3. Pipeline Hardening

The assignment requires at least three hardening measures to be implemented and explained.  
The following measures were implemented in the pipeline.

### Hardening measure 1: Least-privilege permissions

**Implemented**

Each job defines explicit minimal permissions, for example:

```yaml
permissions:
  contents: read
```

Additional permissions are only granted where necessary, such as:

```yaml
packages: write
security-events: write
```

This reduces the attack surface. If a job or action is compromised, the attacker does not automatically receive broad repository permissions.

### Hardening measure 2: Prevent secret exposure on untrusted fork contexts

**Implemented**

Secret-using steps are guarded so they do not run in untrusted pull request contexts.  
For example, Docker Hub login is protected with a condition such as:

```yaml
if: github.event_name != 'pull_request' || github.event.pull_request.head.repo.fork == false
```

This reduces the risk of secret exposure through malicious external pull requests.

### Hardening measure 3: SBOM generation

**Implemented**

An SBOM (Software Bill of Materials) step was added using:

```yaml
- uses: anchore/sbom-action@v0
```

This improves transparency, helps track dependencies, and supports later auditing and incident response.

### Hardening measure 4: Security scan integrated into CI

**Implemented**

The pipeline scans the built image with Trivy and uploads the results in SARIF format to GitHub Security.

For this assignment, the scan is configured as non-blocking:

```yaml
exit-code: '0'
```

This keeps the full pipeline operational for Part A while still surfacing vulnerabilities in CI.

A stricter production-oriented configuration would be:

```yaml
exit-code: '1'
severity: HIGH,CRITICAL
```

That stricter version would block delivery when serious vulnerabilities are detected. In this project it was documented, but not kept as the default because it prevented the full pipeline from completing due to vulnerabilities inherited from upstream base images.

### Hardening measure 5: Image signing / provenance

**Considered improvement**

Another strong improvement would be signing container images or generating provenance data using tools such as `cosign` or SLSA.  
This would improve artifact authenticity and traceability.

---

## Conclusion

The implemented pipeline includes the required CI/CD stages and several concrete security improvements:

- linting for Dockerfile and Go code
- multi-architecture image builds
- image scanning with Trivy
- integration testing against a running database
- controlled image publishing
- least-privilege permissions
- SHA pinning for two critical actions
- restricted secret usage in trusted contexts
- SBOM generation

The main remaining weaknesses are:

- several non-critical actions still use mutable tags
- `aquasecurity/trivy-action` is still referenced via `@master`
- the current vulnerability scan is non-blocking to keep the full pipeline operational

The most valuable future improvements would be:

1. Pin more actions to commit SHAs
2. Pin Trivy to a fixed version or SHA instead of `@master`
3. Enable blocking vulnerability thresholds for production pipelines
4. Add image signing or provenance attestation
