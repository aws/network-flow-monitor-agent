#!/usr/bin/env python3

import boto3
import time
import json
import os
import base64
from typing import List, Dict, Optional

class EC2PerformanceTestRunner:
    def __init__(self, region: str = 'us-east-1'):
        self.ec2 = boto3.client('ec2', region_name=region)
        self.ssm = boto3.client('ssm', region_name=region)
        self.s3 = boto3.client('s3', region_name=region)
        self.region = region
        self.instances = []
        self.bucket_name = f'network-flow-monitor-perf-{int(time.time())}'
        
    def create_instances(self, count: int = 2, instance_type: str = 't3.medium') -> List[str]:
        """Create EC2 instances with SSM agent enabled"""
        
        # User data script to install SSM agent and dependencies
        user_data = """#!/bin/bash
yum update -y
yum install -y amazon-ssm-agent
systemctl enable amazon-ssm-agent
systemctl start amazon-ssm-agent
mkdir -p /opt/network-flow-monitor
"""
        
        response = self.ec2.run_instances(
            ImageId='ami-0c02fb55956c7d316',  # Amazon Linux 2023
            MinCount=count,
            MaxCount=count,
            InstanceType=instance_type,
            IamInstanceProfile={'Name': 'EC2-SSM-Role'},  # Assumes this role exists
            UserData=user_data,
            TagSpecifications=[{
                'ResourceType': 'instance',
                'Tags': [
                    {'Key': 'Name', 'Value': 'network-flow-monitor-perf-test'},
                    {'Key': 'Purpose', 'Value': 'performance-testing'}
                ]
            }]
        )
        
        instance_ids = [i['InstanceId'] for i in response['Instances']]
        self.instances.extend(instance_ids)
        
        print(f"Created instances: {instance_ids}")
        return instance_ids
    
    def wait_for_instances_ready(self, instance_ids: List[str], timeout: int = 300):
        """Wait for instances to be running and SSM-ready"""
        print("Waiting for instances to be ready...")
        
        # Wait for instances to be running
        waiter = self.ec2.get_waiter('instance_running')
        waiter.wait(InstanceIds=instance_ids, WaiterConfig={'Delay': 15, 'MaxAttempts': 20})
        
        # Wait for SSM connectivity
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                response = self.ssm.describe_instance_information(
                    Filters=[{'Key': 'InstanceIds', 'Values': instance_ids}]
                )
                ready_instances = [i['InstanceId'] for i in response['InstanceInformation']]
                if len(ready_instances) == len(instance_ids):
                    print("All instances are SSM-ready")
                    return
            except Exception as e:
                print(f"Waiting for SSM connectivity: {e}")
            
            time.sleep(10)
        
        raise TimeoutError("Instances did not become SSM-ready within timeout")
    
    def upload_agent_to_s3(self, agent_path: str = 'target/release/network-flow-monitor-agent') -> str:
        """Upload agent binary to S3 and return the URL"""
        if not os.path.exists(agent_path):
            raise FileNotFoundError(f"Agent binary not found at {agent_path}")
        
        # Create temporary bucket
        self.s3.create_bucket(Bucket=self.bucket_name)
        
        # Upload agent
        key = 'network-flow-monitor-agent'
        self.s3.upload_file(agent_path, self.bucket_name, key)
        
        # Generate presigned URL (valid for 1 hour)
        url = self.s3.generate_presigned_url(
            'get_object',
            Params={'Bucket': self.bucket_name, 'Key': key},
            ExpiresIn=3600
        )
        
        print(f"Agent uploaded to S3: {url}")
        return url
    
    def upload_agent(self, instance_ids: List[str], agent_path: str = 'target/release/network-flow-monitor-agent'):
        """Download agent binary from S3 to instances"""
        s3_url = self.upload_agent_to_s3(agent_path)
        
        # Create download script
        download_script = f"""#!/bin/bash
curl -o /opt/network-flow-monitor/network-flow-monitor-agent '{s3_url}'
chmod +x /opt/network-flow-monitor/network-flow-monitor-agent
"""
        
        for instance_id in instance_ids:
            print(f"Downloading agent to {instance_id}")
            self.run_command(instance_id, download_script)
    
    def run_command(self, instance_id: str, command: str, timeout: int = 60) -> Dict:
        """Execute a command on an instance via SSM"""
        response = self.ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName='AWS-RunShellScript',
            Parameters={'commands': [command]},
            TimeoutSeconds=timeout
        )
        
        command_id = response['Command']['CommandId']
        
        # Wait for command completion
        while True:
            result = self.ssm.get_command_invocation(
                CommandId=command_id,
                InstanceId=instance_id
            )
            
            status = result['Status']
            if status in ['Success', 'Failed', 'Cancelled', 'TimedOut']:
                return {
                    'status': status,
                    'stdout': result.get('StandardOutputContent', ''),
                    'stderr': result.get('StandardErrorContent', ''),
                    'exit_code': result.get('ResponseCode', -1)
                }
            
            time.sleep(2)
    
    def run_performance_tests(self, instance_ids: List[str]):
        """Run the actual performance tests"""
        print("Running performance tests...")
        
        for i, instance_id in enumerate(instance_ids):
            print(f"\n=== Testing on instance {instance_id} ===")
            
            # Setup cgroup
            setup_cmd = """
mkdir -p /mnt/cgroup-nfm
mount -t cgroup2 none /mnt/cgroup-nfm || true
"""
            result = self.run_command(instance_id, setup_cmd)
            print(f"Setup result: {result['status']}")
            
            # Run the agent for a short test
            test_cmd = """
cd /opt/network-flow-monitor
timeout 30s ./network-flow-monitor-agent --cgroup /mnt/cgroup-nfm --publish-reports off --log-reports on > agent_output.log 2>&1 || true
echo "=== Agent Output ==="
cat agent_output.log
echo "=== System Info ==="
uname -a
free -h
"""
            result = self.run_command(instance_id, test_cmd, timeout=120)
            print(f"Test output:\n{result['stdout']}")
            if result['stderr']:
                print(f"Test errors:\n{result['stderr']}")
    
    def collect_logs(self, instance_ids: List[str]) -> Dict[str, str]:
        """Collect logs from all instances"""
        logs = {}
        
        for instance_id in instance_ids:
            log_cmd = """
echo "=== System Logs ==="
journalctl --no-pager -n 50
echo "=== Agent Logs ==="
cat /opt/network-flow-monitor/agent_output.log 2>/dev/null || echo "No agent logs found"
"""
            result = self.run_command(instance_id, log_cmd)
            logs[instance_id] = result['stdout']
        
        return logs
    
    def cleanup(self):
        """Terminate all created instances and cleanup S3 bucket"""
        if self.instances:
            print(f"Terminating instances: {self.instances}")
            self.ec2.terminate_instances(InstanceIds=self.instances)
            
            # Wait for termination
            waiter = self.ec2.get_waiter('instance_terminated')
            waiter.wait(InstanceIds=self.instances, WaiterConfig={'Delay': 15, 'MaxAttempts': 20})
            print("All instances terminated")
        
        # Cleanup S3 bucket
        try:
            self.s3.delete_object(Bucket=self.bucket_name, Key='network-flow-monitor-agent')
            self.s3.delete_bucket(Bucket=self.bucket_name)
            print("S3 bucket cleaned up")
        except Exception as e:
            print(f"S3 cleanup warning: {e}")

def main():
    runner = EC2PerformanceTestRunner()
    
    try:
        # Create and setup instances
        instance_ids = runner.create_instances(count=2)
        runner.wait_for_instances_ready(instance_ids)
        
        # Upload agent and run tests
        runner.upload_agent(instance_ids)
        runner.run_performance_tests(instance_ids)
        
        # Collect logs
        logs = runner.collect_logs(instance_ids)
        for instance_id, log_content in logs.items():
            print(f"\n=== Logs from {instance_id} ===")
            print(log_content)
        
        print("\nPerformance tests completed successfully!")
        
    except Exception as e:
        print(f"Performance test failed: {e}")
        raise
    finally:
        runner.cleanup()

if __name__ == '__main__':
    main()