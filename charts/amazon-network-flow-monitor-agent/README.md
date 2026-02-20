## Directions for self managed Kubernetes
The directions below will deploy the agent to your current cluster (`kubectl config current-context` to see your current cluster) under "nfm-addon" namespace.
If you want to use default namespace simply remove --namespace and --create-namespace lines.

Make sure that you have an image ready under "ECR_REPO_CONTAINING_NFM_IMAGE".
You can use the publicly available images, or build the agent and upload to your repo using following:

#### Set ECR repo (EKS Prod ECR by default, or your own custom)
ECR_REPO_CONTAINING_NFM_IMAGE="602401143452.dkr.ecr.eu-west-1.amazonaws.com"

#### Set an image tag
IMAGE_TAG_SUFFIX="v1.1.2-eksbuild.1"
IMAGE_TAG="aws-network-sonar-agent:$IMAGE_TAG_SUFFIX"

#### Build Docker image and publish it to your repo (SKIP if using 602401143452 (public ECR))
docker build -f Dockerfile.k8s -t $IMAGE_TAG .
docker tag $IMAGE_TAG $ECR_REPO_CONTAINING_NFM_IMAGE/$IMAGE_TAG
docker push $ECR_REPO_CONTAINING_NFM_IMAGE/$IMAGE_TAG

#### Build helm package
helm package charts/amazon-network-flow-monitor-agent/

#### Install the built template
helm install nfm-addon-release charts/amazon-network-flow-monitor-agent/ \
  --namespace nfm-addon \
  --create-namespace \
  --set image.containerRegistry=$ECR_REPO_CONTAINING_NFM_IMAGE \
  --set image.tag=$IMAGE_TAG_SUFFIX

##### Or upgrade the built template
helm upgrade nfm-addon-release charts/amazon-network-flow-monitor-agent/ \
  --namespace nfm-addon \
  --create-namespace \
  --set image.containerRegistry=$ECR_REPO_CONTAINING_NFM_IMAGE \
  --set image.tag=$IMAGE_TAG_SUFFIX

#### Or simply change the image of running daemonset with the new one
kubectl set image daemonset/aws-network-flow-monitor-agent \
  aws-network-flow-monitor-agent=$ECR_REPO_CONTAINING_NFM_IMAGE/$IMAGE_TAG \
  -n amazon-network-flow-monitor

## CA Certificate Bundle Configuration

This document explains how to configure a custom CA certificate bundle for the Amazon Network Flow Monitor Agent.

#### Overview

The helm chart supports mounting a custom CA certificate bundle from a Kubernetes Secret. This is useful when:
- Your AWS endpoints use custom SSL certificates
- You need to trust internal Certificate Authorities
- You're using a corporate proxy with SSL inspection

#### Prerequisites

1. Generation a CA certificate bundle file (PEM format)
2. Access to create Kubernetes Secrets in the target namespace

### Setup Instructions

#### Step 1: Create the Secret

Create a Kubernetes Secret containing your CA certificate bundle:

```bash
# Create secret from a file
kubectl create secret generic ca-cert-bundle \
  --from-file=ca-bundle.crt=/path/to/your/ca-bundle.crt \
  --namespace=<your-namespace>
```

Or using a YAML manifest:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: ca-cert-bundle
  namespace: <your-namespace>
type: Opaque
data:
  ca-bundle.crt: |
    <base64-encoded-ca-certificate-bundle>
```

#### Step 2: Configure the Helm Chart

Update your `values.yaml` or provide override values:

```yaml
caCerts:
  enabled: true
  secretName: "ca-cert-bundle"
  secretKey: "ca-bundle.crt"
  mountPath: "/etc/ssl/certs"
  fileName: "ca-bundle.crt"
```

#### Step 3: Deploy/Update the Helm Chart

```bash
helm upgrade --install aws-network-flow-monitor . \
  --namespace <your-namespace> \
  --values values.yaml
```

Or using `--set` flags:

```bash
helm upgrade --install aws-network-flow-monitor . \
  --namespace <your-namespace> \
  --set caCerts.enabled=true \
  --set caCerts.secretName=ca-cert-bundle
```

### Configuration Options

| Parameter | Description | Default |
|-----------|-------------|---------|
| `caCerts.enabled` | Enable CA certificate bundle mounting | `false` |
| `caCerts.secretName` | Name of the Secret containing the CA bundle | `"ca-cert-bundle"` |
| `caCerts.secretKey` | Key in the Secret containing the certificate | `"ca-bundle.crt"` |
| `caCerts.mountPath` | Mount path for the CA bundle | `"/etc/ssl/certs"` |
| `caCerts.fileName` | File name for the mounted certificate | `"ca-bundle.crt"` |

### Environment Variables Set

When CA certificates are enabled, the following environment variables are automatically set:

- `AWS_CA_BUNDLE`: Points to the CA bundle file for AWS SDK
- `SSL_CERT_FILE`: Points to the CA bundle file for general SSL operations

### Example: Complete Workflow

#### 1. Prepare your CA bundle

Combine multiple CA certificates into a single bundle:

```bash
cat company-root-ca.crt company-intermediate-ca.crt > ca-bundle.crt
```

#### 2. Create the Secret

```bash
kubectl create secret generic ca-cert-bundle \
  --from-file=ca-bundle.crt=./ca-bundle.crt \
  --namespace network-monitor
```

#### 3. Update values.yaml

```yaml
caCerts:
  enabled: true
  secretName: "ca-cert-bundle"
  secretKey: "ca-bundle.crt"
  mountPath: "/etc/ssl/certs"
  fileName: "ca-bundle.crt"
```

#### 4. Deploy the chart

```bash
helm upgrade --install aws-network-flow-monitor . \
  --namespace network-monitor \
  --values values.yaml
```

#### 5. Verify the configuration

```bash
# Check if the secret is mounted
kubectl describe pod -n network-monitor -l name=aws-network-flow-monitor-agent

# Check environment variables
kubectl exec -n network-monitor -it <pod-name> -- env | grep -E 'AWS_CA_BUNDLE|SSL_CERT_FILE'

# Verify the file exists in the pod
kubectl exec -n network-monitor -it <pod-name> -- cat /etc/ssl/certs/ca-bundle.crt
```

## Troubleshooting

### Secret not found error

**Error**: `couldn't find key ca-bundle.crt in Secret`

**Solution**: Ensure the secret key matches the configuration:
```bash
kubectl get secret ca-cert-bundle -n <namespace> -o jsonpath='{.data}'
```

### Certificate not being used

**Symptom**: SSL errors still occurring

**Solution**:
1. Verify the certificate bundle is valid PEM format
2. Check the certificate chain is complete
3. Ensure the environment variables are set correctly
4. Restart the pods after creating/updating the secret

### Permission denied errors

**Solution**: Ensure the secret exists in the same namespace as the DaemonSet and that the service account has access to read secrets.

### Notes

- The CA certificate bundle must be in PEM format
- Multiple certificates can be concatenated in a single bundle
- The secret must exist before deploying the helm chart
- Changes to the secret require a pod restart to take effect
