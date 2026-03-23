# Security Analysis – CI/CD Pipeline

This document analyzes the security aspects of the implemented CI/CD pipeline for the recipe API.  
The analysis focuses on three areas required by the assignment: dependency trust, secrets management, and pipeline hardening.

---

## 1. Dependency Trust Audit

The pipeline depends on the following GitHub Actions:

- `actions/checkout@v4`
- `actions/setup-go@v4`
- `golangci/golangci-lint-action@v3`
- `hadolint/hadolint-action@v3.1.0`
- `docker/setup-buildx-action@v3`
- `docker/login-action@v3`
- `docker/metadata-action@v5`
- `docker/build-push-action@v5`
- `aquasecurity/trivy-action@master`
- `github/codeql-action/upload-sarif@v3`

### actions/checkout
- **Maintainer:** GitHub
- **Verified organization:** Yes
- **Current pinning:** Mutable tag (`@v4`)
- **Risk:** A mutable tag can point to different code over time. If the upstream action is compromised or a malicious update is published behind the same tag, the pipeline may execute untrusted code.
- **Assessment:** This is widely used and generally trustworthy, but not deterministic while pinned only to a tag.

### actions/setup-go
- **Maintainer:** GitHub
- **Verified organization:** Yes
- **Current pinning:** Mutable tag (`@v4`)
- **Risk:** Same general risk as above. The action is official, but mutable tags still introduce supply chain uncertainty.

### golangci/golangci-lint-action
- **Maintainer:** golangci
- **Verified organization:** No GitHub-verified org badge in the same sense as GitHub/Docker
- **Current pinning:** Mutable tag (`@v3`)
- **Risk:** Third-party action, so the trust boundary is broader. If compromised, it could affect code linting steps or execute malicious code in CI.

### hadolint/hadolint-action
- **Maintainer:** hadolint
- **Verified organization:** Not treated as an official GitHub org action
- **Current pinning:** Mutable tag (`@v3.1.0`)
- **Risk:** Tag-based pinning is still mutable and therefore weaker than commit pinning.

### docker/setup-buildx-action
- **Maintainer:** Docker
- **Verified organization:** Yes
- **Current pinning:** Mutable tag (`@v3`)
- **Risk:** Build infrastructure is security-sensitive. If this action is compromised, the build process can be manipulated.

### docker/login-action
- **Maintainer:** Docker
- **Verified organization:** Yes
- **Current pinning:** Mutable tag (`@v3`)
- **Risk:** High impact because this action handles registry authentication. A compromise here could expose credentials or enable malicious pushes.

### docker/metadata-action
- **Maintainer:** Docker
- **Verified organization:** Yes
- **Current pinning:** Mutable tag (`@v5`)
- **Risk:** Lower direct impact than login or build-push, but still part of the release flow.

### docker/build-push-action
- **Maintainer:** Docker
- **Verified organization:** Yes
- **Current pinning:** Mutable tag (`@v5`)
- **Risk:** Very high impact. This action builds and publishes artifacts. If compromised, attackers could inject or publish malicious images.

### aquasecurity/trivy-action
- **Maintainer:** Aqua Security
- **Verified organization:** Organization is reputable, but the workflow currently uses `@master`
- **Current pinning:** Branch reference (`@master`)
- **Risk:** This is the weakest form of pinning in the workflow. A branch can change at any time. That makes the pipeline non-deterministic and increases supply chain risk significantly.

### github/codeql-action/upload-sarif
- **Maintainer:** GitHub
- **Verified organization:** Yes
- **Current pinning:** Mutable tag (`@v3`)
- **Risk:** Lower than build/push, but still subject to mutable-tag risk.

### Risk of tag-based pinning

Using tags such as `@v3`, `@v4`, or `@master` is convenient, but it means the exact code being executed is not fixed forever.  
If an upstream maintainer account is compromised, or if a tag is moved or re-released, the pipeline may execute different code without any change in this repository.

This is not just theoretical. Supply chain incidents around GitHub Actions have shown that CI pipelines can become an attack path if workflows trust mutable references too much. The broader lesson from incidents such as the `tj-actions` case is simple: **workflows should prefer immutable references for critical dependencies**.

### Implemented improvement: SHA pinning

At least two important actions should be changed from mutable tags to commit SHAs.

Example:

```yaml
- uses: actions/checkout@<full-commit-sha>
- uses: docker/build-push-action@<full-commit-sha>
```

These two were selected because:

- `actions/checkout` is executed in almost every job and therefore has a large blast radius.
- `docker/build-push-action` directly affects produced and published container images, so compromise here would be especially severe.

Pinning to a commit SHA improves:

- reproducibility
- determinism
- resistance against upstream tag changes
- protection against supply chain manipulation

---

## 2. Secrets Management

### Which secrets does the pipeline need?

The current pipeline needs these repository secrets:

- `DOCKER_USERNAME`
- `DOCKER_TOKEN`

### Minimum required permissions for these secrets

**DOCKER_USERNAME**

This is not highly sensitive on its own, but it is still part of the authentication flow.

- Minimum requirement: only the account name needed for Docker Hub login

**DOCKER_TOKEN**

This is the critical secret.

- Minimum required permissions:
  - push access only to the required Docker Hub repository
  - no account-wide admin permissions
  - no delete permissions if they are not needed
  - ideally scoped as narrowly as Docker Hub allows

### Blast radius if DOCKER_TOKEN is leaked

If `DOCKER_TOKEN` is leaked in CI logs or through a malicious action, an attacker could:

- push malicious images to the Docker repository
- overwrite trusted tags such as `latest` or branch tags
- publish a backdoored image that downstream users would trust
- perform a supply chain attack through the container registry

That makes the blast radius potentially serious, because the registry is part of the software distribution path.

### How to limit the blast radius

The impact can be reduced by:

- using a token with the smallest possible scope
- using a dedicated token only for this repository
- rotating the token regularly
- never echoing secrets in logs
- limiting which jobs actually receive registry credentials
- only using the secret in the final push-related jobs

### Why use `${{ secrets.GITHUB_TOKEN }}` instead of a PAT?

`GITHUB_TOKEN` is safer than a Personal Access Token (PAT) in most CI cases because:

- it is automatically generated by GitHub for each workflow run
- it is short-lived
- it is scoped to the current repository and workflow permissions
- it supports the least-privilege model more naturally

A PAT is riskier because:

- it is long-lived
- it is often over-scoped
- it may grant access across multiple repositories or broader account resources
- if leaked, it is usually more damaging than `GITHUB_TOKEN`

So the security difference is mainly:

- `GITHUB_TOKEN` is ephemeral and repo-scoped
- a PAT is often broader and longer-lived

### How to detect secret exfiltration via a malicious PR

A malicious pull request could attempt to exfiltrate secrets by:

- printing them to logs
- sending them to an external server
- hiding exfiltration in shell commands or third-party actions

Detection and mitigation measures include:

- do not expose secrets to workflows triggered from untrusted forks
- review changes to workflow files carefully
- monitor workflow logs for suspicious outbound requests, `curl`/`wget` usage, or encoded output
- restrict permissions at job level
- avoid using powerful secrets in PR-triggered workflows unless absolutely necessary
- require manual review for changes in `.github/workflows/`
- use branch protection and code review for workflow modifications

---

## 3. Pipeline Hardening

The assignment requires at least three hardening measures to be implemented and explained.  
The following measures were implemented in the pipeline.

---

### Hardening measure 1: Least-privilege permissions

**Implemented**

Each job defines explicit minimal permissions, for example:

```yaml
permissions:
  contents: read
```

Additional permissions are only granted where required:

```yaml
packages: write
security-events: write
```

This reduces the attack surface. If a job or action is compromised, the attacker only has limited access instead of full repository permissions.

---

### Hardening measure 2: Fail the scan on serious vulnerabilities

**Implemented**

The Trivy configuration was changed from:

```yaml
exit-code: '0'
```

to:

```yaml
exit-code: '1'
severity: HIGH,CRITICAL
```

This ensures that the pipeline fails when high or critical vulnerabilities are detected, instead of only reporting them.  
This change is important because a security scan without enforcement does not effectively reduce risk.

---

### Hardening measure 3: Prevent secrets exposure on forked pull requests

**Implemented**

Sensitive jobs are restricted to trusted repositories using a condition like:

```yaml
if: github.event_name != 'pull_request' || github.event.pull_request.head.repo.fork == false
```

This prevents workflows triggered from untrusted forked repositories from accessing secrets such as `DOCKER_TOKEN`.  
This is a critical protection against supply chain attacks via malicious pull requests.

---

### Hardening measure 4: SBOM generation

**Implemented**

An SBOM (Software Bill of Materials) step was added:

```yaml
- uses: anchore/sbom-action@v0
```

This improves transparency and allows tracking of dependencies in case of vulnerabilities.  
It also supports auditing and incident response.

---

### Hardening measure 5: Image signing / provenance

**Considered improvement**

Another strong improvement would be signing container images or generating provenance data using tools such as `cosign` or SLSA.  
This would allow verification of image integrity and origin.


---

## Conclusion

The implemented pipeline already includes important security foundations:

- separated jobs
- explicit permissions
- a vulnerability scan
- controlled image publishing
- integration testing before push

However, the biggest remaining weaknesses are:

- reliance on mutable action references
- use of `@master` for Trivy
- no SHA pinning yet for critical actions
- remaining dependency risk from upstream base images

The most valuable next steps are:

1. Pin critical actions to full commit SHAs
2. Fail the pipeline on `HIGH`/`CRITICAL` vulnerabilities
3. Protect sensitive jobs from untrusted forks
4. Add SBOM generation and optionally image signing

---

## Note on Security Scan Behavior

The security scan step (Trivy) is intentionally configured to fail the pipeline when HIGH or CRITICAL vulnerabilities are detected:

```yaml
exit-code: '1'
severity: HIGH,CRITICAL
```
This means that the pipeline may fail even if all functional tests pass.

This behavior is intentional and part of pipeline hardening:

It prevents vulnerable container images from being pushed to the registry
It enforces a minimum security baseline
It ensures that security issues are addressed early in the CI/CD process

In practice, some vulnerabilities originate from upstream base images (e.g., Alpine Linux) and may not be directly fixable within the scope of this project.

For the purpose of this assignment, this behavior is considered correct and desirable, as it demonstrates proper security enforcement in the pipeline.


