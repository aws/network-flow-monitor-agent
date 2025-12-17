## Directions for self managed Kubernetes
The directions below will deploy the agent to your current cluster (`kubectl config current-context` to see your current cluster) under "nfm-addon" namespace.
If you want to use default namespace simply remove --namespace and --create-namespace lines.

Make sure that you have an image ready under "ECR_REPO_CONTAINING_NFM_IMAGE".
You can use the publicly available images, or build the agent and upload to your repo using following:
```
docker build -f Dockerfile.k8s -t aws-network-sonar-agent:v1.1.2-eksbuild.1 .
docker tag aws-network-sonar-agent:v1.1.2-eksbuild.1 $ECR_REPO_CONTAINING_NFM_IMAGE/aws-network-sonar-agent:v1.1.2-eksbuild.1
docker push $ECR_REPO_CONTAINING_NFM_IMAGE/aws-network-sonar-agent:v1.1.2-eksbuild.1
```

#### Build helm package
helm package charts/amazon-network-flow-monitor-agent/

#### Set ECR repo (EKS Prod ECR by default, or your own custom)
ECR_REPO_CONTAINING_NFM_IMAGE="602401143452.dkr.ecr.us-west-2.amazonaws.com"

#### Install the built template
helm install nfm-addon-release charts/amazon-network-flow-monitor-agent/ \
  --namespace nfm-addon \
  --create-namespace \
  --set image.containerRegistry=$ECR_REPO_CONTAINING_NFM_IMAGE \
  --set image.tag=v1.1.2-eksbuild.1

##### Or upgrade the built template
helm upgrade nfm-addon-release charts/amazon-network-flow-monitor-agent/ \
  --namespace nfm-addon \
  --create-namespace \
  --set image.containerRegistry=$ECR_REPO_CONTAINING_NFM_IMAGE \
  --set image.tag=v1.1.2-eksbuild.1
