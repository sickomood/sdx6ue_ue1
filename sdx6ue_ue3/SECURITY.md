# Security — Exercise 3: Kubernetes Attack & Defense

---

## Part A: Kubernetes Fundamentals

### 1. Cluster Connection

A **kubeconfig context** defines which Kubernetes **cluster**, which **user credentials**, and usually which **default namespace** `kubectl` uses. This matters for security because using the wrong context can have serious consequences — for example, if the current context points to production instead of staging, a single `kubectl apply -f ...` command could accidentally deploy changes to the production environment. A context reduces ambiguity, but only if checked carefully before administrative actions.

The kubeconfig file is typically stored at:

| OS | Path |
|----|------|
| Linux / macOS | `~/.kube/config` |
| Windows | `C:\Users\<username>\.kube\config` |

This file may contain cluster endpoints, certificates, and authentication tokens and should therefore only be readable by its owner. On Linux/macOS the recommended permissions are `600`. On Windows, access should be restricted to the owning user and administrators. If other local users can read the kubeconfig, they may gain unauthorized cluster access; if they can modify it, they could redirect commands to another cluster or abuse stored credentials.

---

### 2. kubectl Cheat Sheet

#### List all pods across all namespaces
```bash
kubectl get pods -A
```
Lists all pods in the cluster across every namespace.

#### List all nodes and their roles
```bash
kubectl get nodes
```
Shows all cluster nodes, their status, and their roles (e.g. `control-plane`).

#### List all services across all namespaces
```bash
kubectl get svc -A
```

#### Run an nginx pod and access its logs
```bash
kubectl run nginx-test --image=nginx
kubectl logs nginx-test
```

#### Get a shell into a running container
```bash
kubectl exec -it <pod-name> -- /bin/sh
```

#### Port-forward a pod to localhost
```bash
kubectl port-forward pod/<pod-name> 8080:80
```
Forwards local port `8080` to port `80` of the pod — makes the service accessible from localhost without external exposure.

---

### 3. Kubernetes Architecture

#### Common Resource Types

| Resource | Purpose |
|----------|---------|
| **Pod** | Smallest deployable unit; contains one or more tightly coupled containers. Used for simple tests or debugging — production workloads use higher-level controllers. |
| **Deployment** | Manages stateless applications (e.g. web APIs, frontends). Handles replicas, rollouts, and rollbacks. Standard choice for most workloads. |
| **StatefulSet** | For stateful applications requiring stable identities, predictable naming, and persistent storage (e.g. databases, message brokers). |
| **DaemonSet** | Ensures exactly one pod runs on every node. Typical use: logging agents, monitoring agents, security tooling. |

#### Service Exposure Methods

| Method | Security Assessment |
|--------|---------------------|
| **NodePort** | Exposes a service on a fixed port on every node. Increases attack surface — reachable via any node IP/port combination. Hard to centralize filtering. ⚠️ Weakest option. |
| **LoadBalancer** | Exposes via an external load balancer. Common in cloud environments but still creates public exposure — must be combined with proper firewalling and TLS. |
| **Ingress** | Centralizes external access for HTTP/HTTPS, supports host/path routing, TLS termination, and controlled exposure. ✅ Preferred option. |

#### Why `hostNetwork: true` Must Not Be Used in Production

Setting `hostNetwork: true` causes a pod to share the node's network namespace. This:

- removes normal network isolation between pods and the host,
- increases the blast radius of a container compromise,
- can cause port conflicts with host services, and
- makes traffic inspection and lateral movement significantly easier.

In production, this is an unnecessary and dangerous reduction of isolation.

---

## Part B: RBAC — Design, Implement, Test

### 1. Design

The following YAML files were created in `kubernetes/rbac/`:

#### `pod-reader-sa.yaml`
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: pod-reader-sa
  namespace: default
```

#### `pod-reader-role.yaml`
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-reader
  namespace: default
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
```

#### `pod-reader-rolebinding.yaml`
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: pod-reader-binding
  namespace: default
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: pod-reader
subjects:
- kind: ServiceAccount
  name: pod-reader-sa
  namespace: default
```

#### `test-pod.yaml`
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  serviceAccountName: pod-reader-sa
  containers:
  - name: kubectl-shell
    image: bitnami/kubectl:latest
    command: ["sleep"]
    args: ["3600"]
    stdin: true
    tty: true
```

---

### 2. Test & Proof

All tests were run on a local Docker Desktop Kubernetes cluster.

#### Create RBAC Resources
```bash
kubectl apply -f kubernetes\rbac\pod-reader-sa.yaml
kubectl apply -f kubernetes\rbac\pod-reader-role.yaml
kubectl apply -f kubernetes\rbac\pod-reader-rolebinding.yaml
```
```
serviceaccount/pod-reader-sa created
role.rbac.authorization.k8s.io/pod-reader created
rolebinding.rbac.authorization.k8s.io/pod-reader-binding created
```

#### Verify Resources
```bash
kubectl get serviceaccount -n default
kubectl get role -n default
kubectl get rolebinding -n default
```
```
NAME            SECRETS   AGE
default         0         5m30s
pod-reader-sa   0         32s

NAME         CREATED AT
pod-reader   2026-04-13T21:08:25Z

NAME                 ROLE              AGE
pod-reader-binding   Role/pod-reader   33s
```

#### Listing Pods Is Allowed
```bash
kubectl exec -it test-pod -- kubectl get pods
```
```
NAME       READY   STATUS    RESTARTS   AGE
test-pod   1/1     Running   0          14s
```
The service account can list pods in the `default` namespace as expected.

#### Creating Pods Is Forbidden
```bash
kubectl exec -it test-pod -- kubectl run denied-pod --image=nginx
```
```
Error from server (Forbidden): pods is forbidden: User "system:serviceaccount:default:pod-reader-sa"
cannot create resource "pods" in API group "" in the namespace "default"
command terminated with exit code 1
```
The service account does not have `create` permission on pods.

#### Deleting Pods Is Forbidden
```bash
kubectl exec -it test-pod -- kubectl delete pod test-pod
```
```
Error from server (Forbidden): pods "test-pod" is forbidden: User "system:serviceaccount:default:pod-reader-sa"
cannot delete resource "pods" in API group "" in the namespace "default"
command terminated with exit code 1
```
The service account does not have delete permission on pods.

#### Listing Pods in Another Namespace Is Forbidden
```bash
kubectl exec -it test-pod -- kubectl get pods -n kube-system
```
```
Error from server (Forbidden): pods is forbidden: User "system:serviceaccount:default:pod-reader-sa"
cannot list resource "pods" in API group "" in the namespace "kube-system"
command terminated with exit code 1
```
The `Role` is scoped to `default` only — no cluster-wide access is granted.

---

### 3. Escalation Analysis

**Risk of `create` permission on Pods:** An attacker could create a new pod that mounts Secrets, uses a more privileged ServiceAccount, or mounts sensitive volumes. Pod creation can become an indirect privilege-escalation path because a pod can be configured to access resources the attacker could not otherwise reach directly.

**Role vs. ClusterRole:**

| Scope | Resource | Use When |
|-------|----------|----------|
| Namespace-scoped | `Role` + `RoleBinding` | Permissions should apply inside one namespace only |
| Cluster-wide | `ClusterRole` + `ClusterRoleBinding` | Permissions must span multiple namespaces or apply to cluster-level resources (e.g. nodes) |

**`system:anonymous`:** This user represents unauthenticated requests to the Kubernetes API server when anonymous access is enabled. Its permissions must be minimal — otherwise unauthenticated users could access API resources without valid credentials.

---

## Part C: Pod Security

### 1. Deployment Files

The following files were created in `kubernetes/secure-deployments/`:

- `db-secret.yaml`
- `db-deployment.yaml`
- `db-service.yaml`
- `recipe-deployment.yaml`
- `recipe-service.yaml`
- `recipe-ingress.yaml`

---

### 2. Secure Deployment Configuration

**`db-secret.yaml`** — Database credentials are stored in a Kubernetes `Secret` instead of being hardcoded in the deployment YAML. This prevents plaintext credentials from being committed into manifests.

**`db-deployment.yaml`** — The PostgreSQL deployment populates environment variables from the Secret and defines CPU and memory requests/limits.

**`db-service.yaml`** — The database is exposed internally as a `ClusterIP` service — not publicly reachable.

**`recipe-deployment.yaml`** — Database credentials are injected via the Secret. The container includes CPU/memory limits and the following security context settings:

```yaml
securityContext:
  allowPrivilegeEscalation: false
  capabilities:
    drop: ["ALL"]
```

> **Note on hardening limitations:** Stronger settings such as `runAsNonRoot: true` were attempted but caused failures with the used images:
>
> - The `recipe-api` image failed: `container has runAsNonRoot and image has non-numeric user (recipe), cannot verify user is non-root`
> - The PostgreSQL container failed: `chmod: /var/lib/postgresql/data: Operation not permitted`
>
> The configuration was adjusted pragmatically — the application remains functional while still applying meaningful hardening where the images permit it.

**`recipe-service.yaml`** — The recipe API is exposed internally as a `ClusterIP` service.

**`recipe-ingress.yaml`** — Ingress is configured for controlled HTTP exposure.

```
NAME             CLASS   HOSTS          ADDRESS   PORTS   AGE
recipe-ingress   nginx   recipe.local             80      4m52s
```

---

### 3. Resource Limits and DoS Risk

Resource limits prevent unbounded CPU and memory consumption that could lead to denial-of-service conditions. Without limits, a single runaway container can degrade node stability and starve other workloads. By setting `requests` and `limits`, Kubernetes can schedule workloads more predictably and reduce the impact of resource exhaustion.

---

### 4. Proof of Successful Deployment

```bash
kubectl get pods
```
```
NAME                          READY   STATUS    RESTARTS   AGE
recipe-api-7677489b84-6ttk7   1/1     Running   0          34s
recipe-db-8478446bb9-6m7mv    1/1     Running   0          42s
```

```bash
kubectl get svc
```
```
NAME             TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)    AGE
db-service       ClusterIP   10.104.104.96   <none>        5432/TCP   5m5s
kubernetes       ClusterIP   10.96.0.1       <none>        443/TCP    44m
recipe-service   ClusterIP   10.104.8.104    <none>        8080/TCP   4m51s
```

```bash
kubectl describe svc recipe-service
```
```
Name:       recipe-service
Namespace:  default
Selector:   app=recipe-api
Type:       ClusterIP
IP:         10.104.8.104
Port:       8080/TCP
TargetPort: 8080/TCP
Endpoints:  10.1.0.14:8080
```

```bash
kubectl describe ingress recipe-ingress
```
```
Name:          recipe-ingress
Namespace:     default
Ingress Class: nginx
Rules:
  Host          Path  Backends
  ----          ----  --------
  recipe.local
                /   recipe-service:8080 (10.1.0.14:8080)
```

---

### 5. Vulnerabilities in `insecure-deployment/`

The following security issues were identified in the intentionally insecure deployment files:

| # | File | Vulnerability | Risk |
|---|------|--------------|------|
| 1 | `db-deployment.yaml` | `hostNetwork: true` | Removes pod network isolation; increases blast radius of any compromise |
| 2 | `db-deployment.yaml` | `postgres:latest` image tag | Mutable tag — not reproducible; increases supply-chain risk |
| 3 | `db-deployment.yaml` | Plaintext DB username in YAML | Credentials must not be hardcoded in manifests |
| 4 | `db-deployment.yaml` | Plaintext DB password in YAML | Direct secret exposure in source-controlled files |
| 5 | `recipe-deployment.yaml` | `privileged: true` | Gives container near-root access; significantly weakens isolation |
| 6 | `recipe-deployment.yaml` | `runAsUser: 0` | Container runs as root |
| 7 | `recipe-deployment.yaml` | `hostPort: 8080` | Exposes the application directly on the node; broadens attack surface unnecessarily |
| 8 | `recipe-deployment.yaml` | `hostPath` mount of `/` | Mounts the entire host filesystem into the container — can enable full host compromise |
| 9 | `recipe-deployment.yaml` | Host filesystem mounted at `/host` | Makes the host filesystem directly accessible from inside the container |
| 10 | `recipe-deployment.yaml` | Hardcoded DB credentials | Secrets exposed directly in YAML |
| 11 | `recipe-deployment.yaml` | No security context hardening | Missing restrictions increase risk of abuse and persistence |
| 12 | `recipe-service.yaml` | `NodePort` exposure on port `30080` | Service reachable on a fixed port across every node — broader external access than ClusterIP + Ingress |
