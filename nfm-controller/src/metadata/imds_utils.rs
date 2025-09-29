use log::error;

pub(crate) fn retrieve_imds_metadata(client: &aws_config::imds::Client, path: String) -> String {
    // Check if we're already in a Tokio runtime context
    if tokio::runtime::Handle::try_current().is_ok() {
        // We're already in a runtime, use the current context
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async {
                    match client.get(&path).await {
                        Ok(instance_id) => instance_id.into(),
                        Err(err) => {
                            error!(error = err.to_string(), path = path; "Error retrieving imds metadata");
                            "".into()
                        }
                    }
                })
        })
    } else {
        // Not in a runtime, create a new one
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
}

pub(crate) fn retrieve_instance_id(client: &aws_config::imds::Client) -> String {
    retrieve_imds_metadata(client, "/latest/meta-data/instance-id".to_string())
}

pub(crate) fn retrieve_instance_type(client: &aws_config::imds::Client) -> String {
    retrieve_imds_metadata(client, "/latest/meta-data/instance-type".to_string())
}
