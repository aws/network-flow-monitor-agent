# Helm installs 'Amazon CloudWatch Network Flow Monitor Agent' to an existing K8s Cluster
.PHONY: helm/install/customer
helm/install/customer:
	./bin/agent-k8s-install.sh

# Helm uninstalls 'Amazon CloudWatch Network Flow Monitor Agent' from an existing K8s Cluster
.PHONY: helm/uninstall/customer
helm/uninstall/customer:
	UNINSTALL=true ./bin/agent-k8s-install.sh

# Eksclt configures IRSA (IAM Role for Service Account) so that 'Amazon CloudWatch Network Flow Monitor Agent' can finally authenticate to Ingestion APIs
# - Ensure to add CLUSTER_NAME to have IRSA configured when calling this make target. Ex: make eksctl/irsa/customer CLUSTER_NAME=my-cluster
# - Ensure to add REGION to have IRSA configured when calling this make target. Ex: make eksctl/irsa/customer REGION=us-west-2
# - Similarly, a custom IAM Role name can be defined when calling this make target: Ex: make eksctl/irsa/customer CLUSTER_NAME=my-cluster NFM_AGENT_PUBLISH_ROLE=MyNFMAgentPublishRole
# - Similarly, a custom Kubernetes namespace can be defined when calling this make target: Ex: make eksctl/irsa/customer CLUSTER_NAME=my-cluster NAMESPACE=MyNamespace
.PHONY: eksctl/install/irsa
eksctl/install/irsa:
	./bin/irsa-setup.sh

# Eksclt deletes previously configured IRSA (IAM Role for Service Account)
# - Deleting IRSA is required prior to re-installing 'Amazon CloudWatch Network Flow Monitor Agent'
.PHONY: eksctl/uninstall/irsa
eksctl/uninstall/irsa:
	UNINSTALL=true ./bin/irsa-setup.sh

# Kubectl forces a new DaemonSet rollout
# - This assumes 'Amazon CloudWatch Network Flow Monitor Agent' DaemonSet has been already installed via 'helm/install/customer'
.PHONY: kubectl/daemonset/restart
kubectl/daemonset/restart:
	./bin/daemonset-rollout.sh