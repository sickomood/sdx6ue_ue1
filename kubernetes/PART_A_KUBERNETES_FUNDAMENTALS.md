# Part A: Kubernetes Fundamentals

## 1. What is Kubernetes?
Kubernetes is an open-source platform designed to automate deploying, scaling, and operating application containers.

## 2. What are kubeconfig contexts?
A kubeconfig file is used to configure access to Kubernetes clusters. It can define multiple contexts, each specifying a cluster, a user, and a namespace.

## 3. What commands are included in the kubectl cheat sheet?
- `kubectl get pods`: Lists all pods in the current namespace.
- `kubectl describe pod <pod-name>`: Shows detailed information about a specific pod.
- `kubectl apply -f <file>`: Applies a configuration file to a resource.
- `kubectl delete pod <pod-name>`: Deletes a specific pod.

## 4. What is Kubernetes architecture?
Kubernetes architecture consists of a master node and multiple worker nodes. The master node controls the cluster, while worker nodes run the actual applications. Essential components include:
- **API Server**: Serves the Kubernetes API.
- **Scheduler**: Assigns pods to nodes based on resource availability and requirements.
- **Controller Manager**: Regulates the state of the system.
- **etcd**: A distributed key-value store for configuration data.
- **Kubelet**: An agent running on each worker node, managing pod lifecycle.

## 5. What are Pods?
Pods are the smallest deployable units in Kubernetes and can hold one or more containers.

## 6. Describe Services in Kubernetes.
Services expose a set of pods as a network service, allowing communication between them both internally and externally.

## 7. What are Deployments?
Deployments provide declarative updates to manage application lifecycle, enabling features like scaling and rollback.
