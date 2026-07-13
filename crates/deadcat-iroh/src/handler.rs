//! Transport-facing request handler implemented by the node router.

use deadcat_rpc::{EventEnvelope, Request, RequestEnvelope, Response, RpcError, SubscriptionEnd};
use deadcat_types::EventCursor;
use tokio::sync::mpsc;

/// Authenticated Iroh endpoint identity of the connected client.
pub type ClientId = [u8; 32];

/// A bounded, durable-event subscription prepared by the node router.
///
/// The transport sends `through` in the opening frame, then forwards events
/// from `events`. A bounded Tokio channel is intentional: an implementation
/// cannot accidentally hand the transport an unbounded in-memory queue.
pub struct Subscription {
    pub through: EventCursor,
    pub events: mpsc::Receiver<SubscriptionItem>,
}

/// Bounded subscription message supplied by the node router.
pub enum SubscriptionItem {
    Event(EventEnvelope),
    End(SubscriptionEnd),
}

/// Dispatch target for the Iroh server adapter.
pub trait RequestHandler: Send + Sync + 'static {
    /// Validate an envelope before its request is dispatched.
    ///
    /// The default enforces the RPC schema version. Implementations may add
    /// cheap, synchronous policy checks, but method authorization belongs in
    /// [`Self::handle`] or [`Self::subscribe`].
    fn validate(&self, _peer: ClientId, envelope: &RequestEnvelope) -> Result<(), RpcError> {
        envelope.validate_version()
    }

    /// Handle a non-subscription request.
    fn handle(
        &self,
        peer: ClientId,
        request: Request,
    ) -> impl Future<Output = Result<Response, RpcError>> + Send;

    /// Open a durable event subscription.
    fn subscribe(
        &self,
        peer: ClientId,
        request: Request,
    ) -> impl Future<Output = Result<Subscription, RpcError>> + Send;
}
