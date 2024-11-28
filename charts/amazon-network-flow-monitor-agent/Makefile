# Helm installs 'Amazon CloudWatch Network Flow Monitor Agent' to an existing K8s Cluster
.PHONY: helm/install/customer
helm/install/customer:
	./bin/agent-k8s-install.sh

# Helm uninstalls 'Amazon CloudWatch Network Flow Monitor Agent' from an existing K8s Cluster
.PHONY: helm/uninstall/customer
helm/uninstall/customer:
	UNINSTALL=true ./bin/agent-k8s-install.sh
