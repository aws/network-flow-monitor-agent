# Amazon CloudWatch Network Flow Monitor Agent

'Amazon CloudWatch Network Flow Monitor Agent' Kubernetes application to support collecting TCP connections statistics from all nodes within a Kubernetes cluster and publishing network flows reports to 'Amazon CloudWatch Network Flow Monitor' Ingestion APIs.

## Before you begin

Before you start the installation process, follow the steps in this section to make sure that your environment is set up to successfully install agents on the right Kubernetes clusters.
 
### Ensure that your version of Kubernetes is supported 
'Amazon CloudWatch Network Flow Monitor Agent' installation requires Kubernetes Version 1.25, or a more recent version.
 
### Ensure that you have installed required tools 
The scripts that you use for this installation process require that you install the following tools. If you don’t have the tools installed already, see the provided links for more information. 

* The AWS Command Line Interface. For more information, see [Installing or updating to the latest version of the AWS Command Line Interface](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) in the AWS Command Line Interface Reference Guide. 
     
* The Helm package manager. For more information, see [Installing Helm](https://helm.sh/docs/intro/install/) on the Helm website. 
     
* The `kubectl` command line tool. For more information, see [Install kubectl](https://kubernetes.io/docs/tasks/tools/#kubectl) on the Kubernetes website. 
     
* The `make` Linux command dependency. For more information, see the following blog post: [Intro to make Linux Command: Installation and Usage](https://ioflood.com/blog/install-make-command-linux/)
    * For example, do one of the following:
        * For Debian based distributions, such as Ubuntu, use the following command: `sudo apt-get install make`
        * For RPM-based distributions, such as CentOS, use the following command: `sudo yum install make`

Ensure that you have valid, correctly configured KubeConfig environment variables. 'Amazon CloudWatch Network Flow Monitor Agent' installation uses the Helm package manager tool, which uses the kubeconfig variable, `$HELM_KUBECONTEXT`, to determine the target Kubernetes clusters to work with. Also, be aware that when Helm runs installation scripts, by default, it references the standard `~/.kube/config` file. You can change the configuration environment variables, to use a different config file (by updating `$KUBECONFIG`) or to define the target cluster you want to work with (by updating `$HELM_KUBECONTEXT`). 

### Create a 'Amazon CloudWatch Network Flow Monitor Agent' Kubernetes namespace

'Amazon CloudWatch Network Flow Monitor Agent' Kubernetes application installs its resources into a specific namespace. The namespace must exist for the installation to succeed. To ensure that the required namespace is in place, you can do one of the following:

* Create the default namespace, `amazon-network-flow-monitor`, before you begin.
* Create a different namespace, and then define it in the `$NAMESPACE` environment variable when you run the installation make targets.

## Setup
'Amazon CloudWatch Network Flow Monitor Agent' Helm Charts and Makefile containing installation make targets are located in `./charts/amazon-network-flow-monitor-agent` directory.

You install 'Amazon CloudWatch Network Flow Monitor Agent' by using the following Makefile target: `helm/install/customer`

You can customize the installation if you like, for example, by doing the following:
```
# Overwrite the kubeconfig files to use
make helm/install/customer KUBECONFIG=<MY_KUBECONFIG_ABS_PATH> 

# Overwrite the Kubernetes namespace to use
make helm/install/customer NAMESPACE=<MY_K8S_NAMESPACE>              
```

To verify that the 'Amazon CloudWatch Network Flow Monitor Agent' Pods have been created and deployed successfully, check to be sure that their state is `Running`. You can check state of the agents by running the following command: `kubectl get pods -o wide -A | grep amazon-network-flow-monitor`

## IAM Policy
'Amazon CloudWatch Network Flow Monitor Agent' must have permission to access the 'Amazon CloudWatch Network Flow Monitor Agent' ingestion APIs so they can deliver network flow reports that they've collected for each instance. You grant this access by appending `CloudWatchNetworkFlowMonitorAgentPublishPolicy` managed IAM Policy to the permissions chain associated to 'Amazon CloudWatch Network Flow Monitor Agent' Pods.

### Setup IAM Roles for Service Accounts (IRSA)

IAM roles for service accounts (IRSA) provide the ability to manage credentials for your applications, similar to the way that Amazon EC2 instance profiles provide credentials to Amazon EC2 instances. Using IRSA is the recommended way to provide all permissions required by 'Amazon CloudWatch Network Flow Monitor Agent' Pods to successfully communicate with 'Amazon CloudWatch Network Flow Monitor Agent' Ingestion APIs. For more information on how to implement IRSA: https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html

Few important information for your IRSA Setup:
1. **ServiceAccount:** 'Amazon CloudWatch Network Flow Monitor Agent' Pods run using 'aws-network-flow-monitoring-agent-service-account' ServiceAccount. This will be used when defining your IAM Role trust policy;
1. **Namespace:** All 'Amazon CloudWatch Network Flow Monitor Agent' resources are defined under 'amazon-network-flow-monitor' namespace;
1. **Temporary credentials deployment:** By the time you are configuring permissions, 'Amazon CloudWatch Network Flow Monitor Agent' Pods have already been deployed, meaning Kubernetes WILL NOT try to deploy IAM Role credentials after ServiceAccount gets annotated with your IAM Role. A new DaemonSet rollout needs to be issued so that 'Amazon CloudWatch Network Flow Monitor Agent' Pods acquire IAM Role credentials: `kubectl rollout restart daemonset  -n amazon-network-flow-monitor aws-network-flow-monitoring-agent`

### Confirm that 'Amazon CloudWatch Network Flow Monitor Agent' is successfully communicating with 'Amazon CloudWatch Network Flow Monitor Agent' ingestion APIs

You can check to make sure that your 'Amazon CloudWatch Network Flow Monitor Agent' Pods have permissions set correctly by looking up for HTTP 200 logs. For example, you can do the following: 

1. Locate a 'Amazon CloudWatch Network Flow Monitor Agent' Pod name. For example, you can use the following command:

```
RANDOM_AGENT_POD_NAME=$(kubectl get pods -o wide -A | grep amazon-network-flow-monitor | grep Running | head -n 1 | tr -s ' ' | cut -d " " -f 2)
```

2. Grep all the HTTP logs for that Pod. If you've changed the NAMESPACE, make sure that you use the new one.
```
NAMESPACE=amazon-network-flow-monitor
kubectl logs $RANDOM_AGENT_POD_NAME --namespace ${NAMESPACE} | grep HTTP
```

If access has been granted successfully, you should see log entries similar to the following:
```
{"level":"INFO","message":"HTTP request complete","status":200,"target":"amzn_sonar_agent::reports::publisher_endpoint","timestamp":1732879893535}
{"level":"INFO","message":"HTTP request complete","status":200,"target":"amzn_sonar_agent::reports::publisher_endpoint","timestamp":1732879928102}
{"level":"INFO","message":"HTTP request complete","status":200,"target":"amzn_sonar_agent::reports::publisher_endpoint","timestamp":1732879954342}
```
                        

Note that 'Amazon CloudWatch Network Flow Monitor Agent' publishes network flow reports to 'Amazon CloudWatch Network Flow Monitor Agent' ingestion APIs every 30 seconds.


## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This project is licensed under the Apache-2.0 License.

