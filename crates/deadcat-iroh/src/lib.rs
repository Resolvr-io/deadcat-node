//! Native Iroh transport for Deadcat RPC.

pub mod client;
pub mod handler;
pub mod server;
pub mod wire;

pub const ALPN: &[u8] = b"deadcat/1";

pub use client::{Client, ClientConfig, ClientError, EventStream};
pub use handler::{ClientId, RequestHandler, Subscription, SubscriptionItem};
pub use server::{DiscoveryMode, Server, ServerConfig, ServerError, SpawnedServer};

// Keep Iroh identity types behind the transport dependency boundary.
pub use iroh::{EndpointAddr, EndpointId, SecretKey};
