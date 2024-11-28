# Kubernetes Customer Installation Process
The directions below aim to guide AWS customers with workloads running on either self-managed Kubernetes clusters. By the end of this tutorial, customers can expect to have Network Flow Monitor Agent Pods running on every Kubernetes Cluster Node and publishing TCP connection statistics.

## Pre-Installation
Run the checks below before attempting Network Flow Monitor Agent installation process:

### 1) Have a valid KubeConfig
Network Flow Monitor Agent installation process uses **Helm** which relies on underlying kubeconfig for managing target Kubernetes clusters. When running installation scripts, **Helm** will use standard `~/.kube/config` file for accessing target Kubernetes clusters by default. Defining $KUBECONFIG and $HELM_KUBECONTEXT environment variables is also available as an alternative way to configure the access to the target cluster.

See: https://helm.sh/docs/helm/helm/

### 2) Use an existing Kubernetes Namespace
Network Flow Monitor Agent Kubernetes application gets installed to 'amazon-network-flow-monitor' namespace by default. However, it DOES NOT try to create the namespace during installation, which will fail if the namespace hasn't been created yet. You can either 1) create 'amazon-network-flow-monitor' namespace upfront or 2) define a different namespace to be used during Network Flow Monitor Agent Kubernetes application installation by defining `NAMESPACE` environment variable.

## Installation
Network Flow Monitor Agent installation is done via Makefile target: `helm/install/customer`
```
# Overwriting kubeconfig files to be used
make helm/install/customer KUBECONFIG=<MY_KUBECONFIG_ABS_PATH>

# Overwriting which Kubernetes namespace to be used
make helm/install/customer NAMESPACE=<MY_K8S_NAMESPACE>
```

To verify if Network Flow Monitor Agent Kubernetes application Pods have been created and deployed successfully, ensure they are on **Running** state: `kubectl get pods -o wide -A | grep amazon-network-flow-monitor`

## Post-Installation
Extra manual work is required to enable Network Flow Monitor Agent executable to publish network statistics to Network Flow Monitor Ingestion APIs:

### 1) Add IAM Policy for access to Network Flow Monitor Ingestion APIs
Network Flow Monitor Agent executable requires access to Network Flow Monitor Ingestion APIs for publishing network statistics gathered locally. This access is granted by updating IAM Roles associated to EC2s Nodes part of the target Kubernetes cluster.

#### Update Kubernetes Cluster Nodes IAM Role
Identify which IAM Roles are associated to the target Kubernetes Cluster Nodes and have `CloudWatchNetworkFlowMonitorAgentPublishPolicy` managed IAM Policy attached to it. This IAM Policy contains all permissions required to enable access to Network Flow Monitor Ingestion APIs.

A common followed pattern has all Kubernetes Nodes sharing the same IAM Role, meaning updating a single IAM Role is often enough (EKS implements that by using the concept of NodeGroup and managing a single IAM Role for agiven NodeGroup). Confirm that you've updated all IAM Roles associated to all your Nodes.

#### Confirm 'Network Flow Monitor Agent' successfully hits Network Flow Monitor Ingestion APIs
This is done by finding HTTP 200 logs from 'Network Flow Monitor Agent' Pods:
```
# Get a random 'Network Flow MonitorMonitoringAgent' Pod Name:
RANDOM_NETFMON_AGENT_POD_NAME=$(kubectl get pods -o wide -A | grep amazon-network-flow-monitor | grep Running | head -n 1 | tr -s ' ' | cut -d " " -f 2)

# Grep all HTTP Logs (remember to change NAMESPACE if you've set something else)
NAMESPACE=amazon-network-flow-monitor
kubectl logs ${RANDOM_NETFMON_AGENT_POD_NAME} --namespace ${NAMESPACE} | grep HTTP
```

If access has been granted successfully, you should find logs like the following:
```
...
{"level":"INFO","message":"HTTP request complete","status":200,"target":"amzn_sonar_agent::reports::publisher_endpoint","timestamp":1729519236073}
{"level":"INFO","message":"HTTP request complete","status":200,"target":"amzn_sonar_agent::reports::publisher_endpoint","timestamp":1729519263143}
{"level":"INFO","message":"HTTP request complete","status":200,"target":"amzn_sonar_agent::reports::publisher_endpoint","timestamp":1729519293406}
```
- Note that 'Network Flow Monitor Agent' currently hits Network Flow Monitor Ingestion APIs every 30 seconds;

## Uninstalling
For Network Flow Monitor Agent removal use the following Makefile target: `helm/uninstall/customer`
```
# Overwriting kubeconfig files to be used
make helm/uninstall/customer KUBECONFIG=<MY_KUBECONFIG_ABS_PATH>

# Overwriting which Kubernetes namespace to be used
make helm/uninstall/customer NAMESPACE=<MY_K8S_NAMESPACE>
```