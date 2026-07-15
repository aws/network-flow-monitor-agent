// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Hand-written types for the Kubelet PodResources v1 gRPC API (GA, additive-only changes).
//! Avoids a protoc/tonic-build dependency; prost ignores unknown fields so upstream additions are safe.
//! Based on: https://github.com/kubernetes/kubernetes/blob/master/staging/src/k8s.io/kubelet/pkg/apis/podresources/v1/api.proto

#[derive(Clone, PartialEq, prost::Message)]
pub struct ListPodResourcesRequest {}

#[derive(Clone, PartialEq, prost::Message)]
pub struct ListPodResourcesResponse {
    #[prost(message, repeated, tag = "1")]
    pub pod_resources: Vec<PodResources>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct PodResources {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(string, tag = "2")]
    pub namespace: String,
    #[prost(message, repeated, tag = "3")]
    pub containers: Vec<ContainerResources>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct ContainerResources {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(message, repeated, tag = "2")]
    pub devices: Vec<ContainerDevices>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct ContainerDevices {
    #[prost(string, tag = "1")]
    pub resource_name: String,
    #[prost(string, repeated, tag = "2")]
    pub device_ids: Vec<String>,
}

pub mod pod_resources_lister_client {
    use super::{ListPodResourcesRequest, ListPodResourcesResponse};

    #[derive(Clone)]
    pub struct PodResourcesListerClient<T> {
        inner: tonic::client::Grpc<T>,
    }

    impl PodResourcesListerClient<tonic::transport::Channel> {
        pub fn new(channel: tonic::transport::Channel) -> Self {
            let inner = tonic::client::Grpc::new(channel);
            Self { inner }
        }
    }

    impl<T> PodResourcesListerClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::Body>,
        T::Error: Into<Box<dyn std::error::Error + Send + Sync>> + std::fmt::Display,
        T::ResponseBody: tonic::codegen::Body<Data = tonic::codegen::Bytes> + Send + 'static,
        <T::ResponseBody as tonic::codegen::Body>::Error:
            Into<Box<dyn std::error::Error + Send + Sync>> + Send,
    {
        pub async fn list(
            &mut self,
            request: impl tonic::IntoRequest<ListPodResourcesRequest>,
        ) -> Result<tonic::Response<ListPodResourcesResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(tonic::Code::Unknown, format!("Service not ready: {}", e))
            })?;
            let codec = tonic_prost::ProstCodec::default();
            let path =
                tonic::codegen::http::uri::PathAndQuery::from_static("/v1.PodResourcesLister/List");
            self.inner.unary(request.into_request(), path, codec).await
        }
    }
}
