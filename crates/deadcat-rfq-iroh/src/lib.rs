//! Native Iroh transport for authenticated Deadcat RFQ requests.
//!
//! RFQ transport uses a dedicated ALPN and exactly one request and response
//! on each bidirectional stream. Client and server identities are supplied by
//! their callers so reservation ownership remains stable across restarts.

pub mod client;
pub mod handler;
pub mod server;

pub use client::{Client, ClientConfig, ClientError};
pub use handler::{ClientId, RequestHandler};
pub use server::{DiscoveryMode, Server, ServerConfig, ServerError, SpawnedServer};

pub use deadcat_rfq_rpc::ALPN;

// Keep Iroh identity types behind the transport dependency boundary.
pub use iroh::{EndpointAddr, EndpointId, SecretKey};
