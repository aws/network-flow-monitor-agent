use log::error;

/// Runtime executor that handles both existing and new runtime contexts
pub(crate) enum RuntimeExecutor {
    Existing(tokio::runtime::Handle),
    New(tokio::runtime::Runtime),
}

impl RuntimeExecutor {
    pub fn block_on<F>(&self, future: F) -> F::Output
    where
        F: std::future::Future,
    {
        match self {
            RuntimeExecutor::Existing(handle) => {
                tokio::task::block_in_place(|| handle.block_on(future))
            }
            RuntimeExecutor::New(runtime) => runtime.block_on(future),
        }
    }
}

/// Gets or creates a runtime executor for async operations
pub(crate) fn get_runtime_executor() -> Option<RuntimeExecutor> {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        Some(RuntimeExecutor::Existing(handle))
    } else {
        // Not in a runtime, creating one.
        match tokio::runtime::Runtime::new() {
            Ok(rt) => Some(RuntimeExecutor::New(rt)),
            Err(err) => {
                error!(error = err.to_string(); "Error creating tokio runtime");
                None
            }
        }
    }
}

pub fn retrieve_imds_metadata(client: &aws_config::imds::Client, path: String) -> String {
    match get_runtime_executor() {
        Some(executor) => match executor.block_on(client.get(&path)) {
            Ok(instance_id) => instance_id.into(),
            Err(err) => {
                error!(error = err.to_string(), path = path; "Error retrieving imds metadata");
                "".into()
            }
        },
        None => {
            error!(path = path; "Failed to get runtime executor for IMDS metadata");
            "".into()
        }
    }
}

pub(crate) fn retrieve_instance_id(client: &aws_config::imds::Client) -> String {
    retrieve_imds_metadata(client, "/latest/meta-data/instance-id".to_string())
}

pub(crate) fn retrieve_instance_type(client: &aws_config::imds::Client) -> String {
    retrieve_imds_metadata(client, "/latest/meta-data/instance-type".to_string())
}
