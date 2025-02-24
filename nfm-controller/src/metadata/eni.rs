// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::env_metadata_provider::{EnvMetadata, EnvMetadataProvider, NetworkDevice};
use crate::reports::report::ReportValue;
use crate::utils::{CommandRunner, RealCommandRunner};
use aws_config::imds::Client;

use hashbrown::HashMap;
use log::{error, warn};

const KEY_INSTANCE_ID: &str = "instance-id";
const KEY_INSTANCE_TYPE: &str = "instance-type";

/// Metadata provider related to AWS. Only supports IMDSv2.
pub struct EniMetadataProvider {
    pub(crate) client: Client,
    pub(crate) instance_id: String,
    pub(crate) instance_type: String,
    pub(crate) network: Vec<NetworkInterfaceInfo>,
    pub(crate) command_runner: Box<dyn CommandRunner>,
}

#[derive(Debug)]
#[cfg_attr(test, derive(Default))]
pub(crate) struct NetworkInterfaceInfo {
    pub(crate) mac: String,
    pub(crate) interface_id: String,
}

impl EniMetadataProvider {
    pub fn new() -> EniMetadataProvider {
        let client = Client::builder().build();
        let instance_id = retrieve_instance_id(&client);
        let instance_type = retrieve_instance_type(&client);
        let network = retrieve_network_information(&client);
        EniMetadataProvider {
            client,
            instance_id,
            instance_type,
            network,
            command_runner: Box::new(RealCommandRunner {}),
        }
    }

    // Gets the network devices associated with the current host.
    pub fn get_network_devices(&mut self) -> Vec<NetworkDevice> {
        let mut mac_to_device: HashMap<String, String> = HashMap::new();

        let output = self.command_runner.run("ip", &["-br", "link"]);
        if let Err(err) = output {
            error!(error = err.to_string(); "Failed to get IP link device names");
            return vec![];
        }

        for line in String::from_utf8_lossy(&output.unwrap().stdout).lines() {
            let parts = line.split_ascii_whitespace().collect::<Vec<_>>();
            if parts.len() == 4 {
                mac_to_device.insert(parts[2].to_string(), parts[0].to_string());
            }
        }

        let mut net_devices: Vec<NetworkDevice> = Vec::new();
        for net_info in &self.network {
            if let Some(dev_name) = mac_to_device.get(&net_info.mac) {
                net_devices.push(NetworkDevice {
                    device_name: dev_name.clone(),
                    interface_id: net_info.interface_id.clone(),
                });
            }
        }

        net_devices
    }
}

impl Default for EniMetadataProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl EnvMetadataProvider for EniMetadataProvider {
    fn refresh(&mut self) {
        if self.instance_id.is_empty() {
            self.instance_id = retrieve_instance_id(&self.client);
        }
        if self.instance_type.is_empty() {
            self.instance_type = retrieve_instance_type(&self.client);
        }
        self.network = retrieve_network_information(&self.client);
    }

    fn get_metadata(&self) -> EnvMetadata {
        let mut metadata = EnvMetadata::new();

        // Instance metadata
        metadata.insert(
            KEY_INSTANCE_ID.into(),
            ReportValue::String(self.instance_id.clone()),
        );
        metadata.insert(
            KEY_INSTANCE_TYPE.into(),
            ReportValue::String(self.instance_type.clone()),
        );

        metadata
    }
}

fn retrieve_imds_metadata(client: &aws_config::imds::Client, path: String) -> String {
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(err) => {
            error!(error = err.to_string(); "Error creating tokio runtime");
            return "".into();
        }
    };

    match rt.block_on(client.get(&path)) {
        Ok(instance_id) => instance_id.into(),
        Err(err) => {
            error!(error = err.to_string(), path = path; "Error retrieving imds metadata");
            "".into()
        }
    }
}

fn retrieve_instance_id(client: &aws_config::imds::Client) -> String {
    retrieve_imds_metadata(client, "/latest/meta-data/instance-id".to_string())
}

fn retrieve_instance_type(client: &aws_config::imds::Client) -> String {
    retrieve_imds_metadata(client, "/latest/meta-data/instance-type".to_string())
}

fn retrieve_network_information(client: &aws_config::imds::Client) -> Vec<NetworkInterfaceInfo> {
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(err) => {
            error!(error = err.to_string(); "Error creating tokio runtime");
            return vec![];
        }
    };

    rt.block_on(async {
        match client
            .get("/latest/meta-data/network/interfaces/macs/")
            .await
        {
            Ok(macs) => {
                let mut network_information = vec![];
                let macs = String::from(macs);
                for mac in macs.split('\n') {
                    // There is trailing backslash in each line.
                    let mut mac = mac.to_string();
                    if !mac.is_empty() && mac.ends_with('/') {
                        mac.pop();
                    }

                    network_information.extend(retrieve_mac_information(client, mac).await)
                }
                network_information
            }
            Err(err) => {
                error!(error = err.to_string(); "Error retrieving network information");
                vec![]
            }
        }
    })
}

async fn retrieve_mac_information(
    client: &aws_config::imds::Client,
    mac: String,
) -> Vec<NetworkInterfaceInfo> {
    vec![NetworkInterfaceInfo {
        mac: mac.clone(),
        interface_id: get_mac_attribute(client, &mac, "interface-id").await,
    }]
}

async fn get_mac_attribute(
    client: &aws_config::imds::Client,
    mac: &String,
    attribute: &str,
) -> String {
    match client
        .get(format!("/latest/meta-data/network/interfaces/macs/{mac}/{attribute}").as_str())
        .await
    {
        Ok(attribute) => attribute.into(),
        Err(err) => {
            warn!(error = err.to_string(); "Error retrieving {attribute} for {mac}");
            "".to_string()
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::utils::FakeCommandRunner;
    use std::os::unix::process::ExitStatusExt;
    use std::process::{ExitStatus, Output};

    #[test]
    fn test_instance_id() {
        let mut ec2_provider = EniMetadataProvider::default();
        ec2_provider.refresh();
        let metadata = ec2_provider.get_metadata();
        assert!(metadata.contains_key("instance-id"));
    }

    #[test]
    fn test_network_information() {
        let ec2_provider = EniMetadataProvider {
            client: Client::builder().build(),
            instance_id: "the-instance-id".into(),
            instance_type: "the-instance-type".into(),
            network: vec![NetworkInterfaceInfo {
                mac: "the-mac".into(),
                interface_id: "the-interface-id".into(),
            }],
            command_runner: Box::new(FakeCommandRunner::new()),
        };
        let metadata = ec2_provider.get_metadata();

        assert_eq!(metadata.len(), 2);
        assert_eq!(
            metadata.get("instance-id").unwrap(),
            &ReportValue::String("the-instance-id".into())
        );
        assert_eq!(
            metadata.get("instance-type").unwrap(),
            &ReportValue::String("the-instance-type".into())
        );
    }

    #[test]
    fn test_network_in_ec2() {
        if !running_on_ec2() {
            // If are not running on EC2, ignore test
            return;
        }
        let mut ec2_provider = EniMetadataProvider::new();
        ec2_provider.refresh();
        let metadata = ec2_provider.get_metadata();

        assert!(!metadata.is_empty());
        assert!(metadata.contains_key("instance-id"));

        let network_info = retrieve_network_information(&Client::builder().build());
        for network in network_info {
            assert!(!network.mac.is_empty());
            assert!(network.interface_id.starts_with("eni-"));
        }
    }

    #[test]
    fn test_get_network_devices() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "ip",
            &["-br", "link"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: r#"
                    lo               UNKNOWN        11:00:00:00:00:00 <LOOPBACK,UP,LOWER_UP> 
                    eth1             UP             22:00:00:00:00:00 <BROADCAST,MULTICAST,UP,LOWER_UP> 
                    docker0          DOWN           33:00:00:00:00:00 <NO-CARRIER,BROADCAST,MULTICAST,UP> 
                    eth2             UP             44:00:00:00:00:00 <BROADCAST,MULTICAST,UP,LOWER_UP> 
                "#
                .as_bytes()
                .to_vec(),
                stderr: vec![],
            }),
        );

        let net_infos: Vec<NetworkInterfaceInfo> = vec![
            NetworkInterfaceInfo {
                mac: "22:00:00:00:00:00".to_string(),
                interface_id: "ifc-id1".to_string(),
                ..Default::default()
            },
            NetworkInterfaceInfo {
                mac: "44:00:00:00:00:00".to_string(),
                interface_id: "ifc-id2".to_string(),
                ..Default::default()
            },
        ];

        let mut eni_provider = EniMetadataProvider {
            client: Client::builder().build(),
            instance_id: "inst-id1".to_string(),
            instance_type: "the-instance-type".into(),
            network: net_infos,
            command_runner: Box::new(fake_runner.clone()),
        };

        let expected_net_devs: Vec<NetworkDevice> = vec![
            NetworkDevice {
                interface_id: "ifc-id1".to_string(),
                device_name: "eth1".to_string(),
            },
            NetworkDevice {
                interface_id: "ifc-id2".to_string(),
                device_name: "eth2".to_string(),
            },
        ];

        let actual_net_devs = eni_provider.get_network_devices();
        assert_eq!(actual_net_devs, expected_net_devs);
        assert!(fake_runner.expectations.lock().unwrap().is_empty());
    }

    fn running_on_ec2() -> bool {
        !retrieve_instance_id(&Client::builder().build()).is_empty()
            && !retrieve_network_information(&Client::builder().build()).is_empty()
    }
}
