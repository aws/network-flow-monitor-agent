# Kubernetes Deployment

Deploy the Network Flow Monitor Agent to your current cluster (`kubectl config current-context`).

## Option A: Deploy the Publicly Available Image (from EKS ECR repository)

```bash
helm install amazon-network-flow-monitor-release charts/amazon-network-flow-monitor-agent/ \
  --namespace amazon-network-flow-monitor \
  --create-namespace \
  --set image.containerRegistry=602401143452.dkr.ecr.us-west-2.amazonaws.com \
  --set image.tag=v1.1.4-eksbuild.1
```

## Option B: Deploy Your Own Image

```bash

IMAGE_TAG_SUFFIX="any-custom-tag"
IMAGE_TAG="aws-network-sonar-agent:$IMAGE_TAG_SUFFIX"
ECR_REPO_CONTAINING_NFM_IMAGE="<your ecr url here / image will be pushed here>"

docker build -f Dockerfile.k8s -t $IMAGE_TAG .
docker tag $IMAGE_TAG $ECR_REPO_CONTAINING_NFM_IMAGE/$IMAGE_TAG
docker push $ECR_REPO_CONTAINING_NFM_IMAGE/$IMAGE_TAG

# Deploy
helm install amazon-network-flow-monitor-release charts/amazon-network-flow-monitor-agent/ \
  --namespace amazon-network-flow-monitor \
  --create-namespace \
  --set image.containerRegistry=$ECR_REPO_CONTAINING_NFM_IMAGE \
  --set image.tag=$IMAGE_TAG_SUFFIX
```

## Upgrade

```bash
helm upgrade amazon-network-flow-monitor-release charts/amazon-network-flow-monitor-agent/ \
  --namespace amazon-network-flow-monitor \
  --set image.containerRegistry=$ECR_REPO_CONTAINING_NFM_IMAGE \
  --set image.tag=$IMAGE_TAG_SUFFIX
```

## Uninstall

```bash
helm uninstall amazon-network-flow-monitor-release --namespace amazon-network-flow-monitor
```

## Configuration

Key values (override with `--set`):

### Image

| Parameter | Default | Description |
|-----------|---------|-------------|
| `image.containerRegistry` | `""` | ECR registry URL (required) |
| `image.tag` | `v1.1.4-eksbuild.1` | Image tag |
| `image.name` | `aws-network-sonar-agent` | Image name (ECR folder) |
| `image.override` | `""` | If set, used as the full canonical image name, ignoring registry/name/tag |

### Agent Behavior

| Parameter | Default | Description |
|-----------|---------|-------------|
| `env.RUST_LOG` | `info` | Log level (`error`, `warn`, `info`, `debug`, `trace`) |
| `env.OPEN_METRICS` | `"off"` | Enable OpenMetrics endpoint (`"on"` / `"off"`) |
| `env.OPEN_METRICS_PORT` | `"9109"` | Port for the metrics endpoint |
| `env.OPEN_METRICS_ADDRESS` | `"0.0.0.0"` | Bind address for the metrics endpoint |
| `env.DISABLE_PUBLISHING` | unset | Set to `"true"` to disable publishing to CloudWatch |
| `env.LOG_REPORTS` | unset | Set to `"on"` to log agent reports to stdout |
| `rmemMax` | `12800000` | Host `net.core.rmem_max` value; buffers conntrack messages. Lower values may reduce NAT resolution precision on high-throughput (>50k conn/s) hosts |

### Kubernetes Scheduling

| Parameter | Default | Description |
|-----------|---------|-------------|
| `tolerations` | `[{operator: Exists}]` | Pod tolerations; default tolerates all taints |
| `affinity` | excludes Fargate/Hybrid, amd64+arm64 only | Node affinity rules |
| `priorityClassName` | `""` | Pod priority class name |
| `podLabels` | `{}` | Additional labels on DaemonSet pods |
| `podAnnotations` | `{}` | Additional annotations on DaemonSet pods |

### Identity & RBAC

| Parameter | Default | Description |
|-----------|---------|-------------|
| `serviceAccount.name` | `aws-network-flow-monitor-agent-service-account` | Service account name |
| `serviceAccount.annotations` | `{}` | Service account annotations (e.g., IRSA role ARN) |
| `clusterRole.name` | `aws-network-flow-monitor-agent-role` | ClusterRole name |
| `daemonSet.name` | `aws-network-flow-monitor-agent` | DaemonSet and container name |

### Resources

| Parameter | Default | Description |
|-----------|---------|-------------|
| `resources.requests.cpu` | `50m` | CPU request |
| `resources.requests.memory` | `100Mi` | Memory request |
| `resources.limits.cpu` | `500m` | CPU limit |
| `resources.limits.memory` | `200Mi` | Memory limit |

### OpenMetrics

> **Note:** Enabling OpenMetrics adds `SYS_ADMIN` and `SYS_PTRACE` capabilities to the agent container (required for interface metrics collection via namespace introspection).
To enable the OpenMetrics interface metrics endpoint:

```bash
helm install amazon-network-flow-monitor-release charts/amazon-network-flow-monitor-agent/ \
  --namespace amazon-network-flow-monitor \
  --create-namespace \
  --set image.containerRegistry=602401143452.dkr.ecr.us-west-2.amazonaws.com \
  --set image.tag=v1.1.4-eksbuild.1 \
  --set env.OPEN_METRICS=on
```

## CA Certificate Bundle

Mount a custom CA bundle for environments with custom SSL certificates or corporate proxies.

### 1. Create the secret

```bash
kubectl create secret generic ca-cert-bundle \
  --from-file=ca-bundle.crt=/path/to/your/ca-bundle.crt \
  --namespace amazon-network-flow-monitor
```

### 2. Deploy with CA certs enabled

```bash
helm install amazon-network-flow-monitor-release charts/amazon-network-flow-monitor-agent/ \
  --namespace amazon-network-flow-monitor \
  --create-namespace \
  --set image.containerRegistry=602401143452.dkr.ecr.us-west-2.amazonaws.com \
  --set image.tag=v1.1.4-eksbuild.1 \
  --set caCerts.enabled=true \
  --set caCerts.secretName=ca-cert-bundle
```

| Parameter | Default | Description |
|-----------|---------|-------------|
| `caCerts.enabled` | `false` | Enable CA bundle mounting |
| `caCerts.secretName` | `"ca-cert-bundle"` | Secret name |
| `caCerts.secretKey` | `"ca-bundle.crt"` | Key in the secret |
| `caCerts.mountPath` | `"/etc/ssl/certs"` | Mount path |
| `caCerts.fileName` | `"ca-bundle.crt"` | File name in container |

When enabled, `AWS_CA_BUNDLE` and `SSL_CERT_FILE` environment variables are set automatically.
