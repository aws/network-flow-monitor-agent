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