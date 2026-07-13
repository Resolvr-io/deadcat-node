//! Bounded `[u32-LE length][UTF-8 JSON]` framing.

use std::io;
use std::sync::Arc;

use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Semaphore;

pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
pub const DEFAULT_INBOUND_BUDGET_BYTES: usize = 32 * 1024 * 1024;

/// Process-wide inbound byte budget shared by all concurrent stream readers.
#[derive(Clone, Debug)]
pub struct InboundBudget {
    permits: Arc<Semaphore>,
}

impl Default for InboundBudget {
    fn default() -> Self {
        Self::new(DEFAULT_INBOUND_BUDGET_BYTES)
    }
}

impl InboundBudget {
    #[must_use]
    pub fn new(bytes: usize) -> Self {
        assert!(bytes <= usize::try_from(u32::MAX).expect("u32 fits usize"));
        Self {
            permits: Arc::new(Semaphore::new(bytes)),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WireError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("frame exceeds {MAX_FRAME_BYTES} byte limit ({len} bytes)")]
    FrameTooLarge { len: usize },
    #[error("zero-length JSON frame")]
    EmptyFrame,
    #[error("stream ended before a complete frame arrived")]
    UnexpectedEof,
    #[error("inbound byte budget closed")]
    BudgetClosed,
}

pub async fn write_message<W, T>(writer: &mut W, value: &T) -> Result<(), WireError>
where
    W: AsyncWrite + Unpin,
    T: Serialize + ?Sized,
{
    let bytes = serde_json::to_vec(value)?;
    if bytes.is_empty() {
        return Err(WireError::EmptyFrame);
    }
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(WireError::FrameTooLarge { len: bytes.len() });
    }
    let len = u32::try_from(bytes.len()).expect("bounded by MAX_FRAME_BYTES");
    writer.write_all(&len.to_le_bytes()).await?;
    writer.write_all(&bytes).await?;
    Ok(())
}

pub async fn read_message<R, T>(reader: &mut R, budget: &InboundBudget) -> Result<T, WireError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut len_bytes = [0_u8; 4];
    if let Err(error) = reader.read_exact(&mut len_bytes).await {
        return if error.kind() == io::ErrorKind::UnexpectedEof {
            Err(WireError::UnexpectedEof)
        } else {
            Err(WireError::Io(error))
        };
    }

    let len = u32::from_le_bytes(len_bytes) as usize;
    if len == 0 {
        return Err(WireError::EmptyFrame);
    }
    if len > MAX_FRAME_BYTES {
        return Err(WireError::FrameTooLarge { len });
    }

    let permits = u32::try_from(len).expect("bounded by MAX_FRAME_BYTES");
    let _permit = budget
        .permits
        .acquire_many(permits)
        .await
        .map_err(|_| WireError::BudgetClosed)?;

    // `take + read_to_end` grows incrementally rather than eagerly allocating
    // the attacker-declared frame size before body bytes arrive.
    let mut bytes = Vec::with_capacity(len.min(64 * 1024));
    let mut body = reader.take(len as u64);
    body.read_to_end(&mut bytes).await?;
    if bytes.len() != len {
        return Err(WireError::UnexpectedEof);
    }
    Ok(serde_json::from_slice(&bytes)?)
}

#[cfg(test)]
mod tests {
    use deadcat_rpc::{Request, RequestEnvelope, RequestId, SCHEMA_VERSION};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, duplex};

    use super::*;

    fn request() -> RequestEnvelope {
        RequestEnvelope {
            schema_version: SCHEMA_VERSION,
            request_id: RequestId(7),
            request: Request::GetInfo,
        }
    }

    #[tokio::test]
    async fn round_trip_uses_little_endian_prefix() {
        let expected = request();
        let expected_json = serde_json::to_vec(&expected).expect("json");
        let (mut writer, mut reader) = duplex(4096);

        write_message(&mut writer, &expected).await.expect("write");
        let mut prefix = [0_u8; 4];
        reader.read_exact(&mut prefix).await.expect("prefix");
        assert_eq!(prefix, (expected_json.len() as u32).to_le_bytes());
        let mut body = vec![0_u8; expected_json.len()];
        reader.read_exact(&mut body).await.expect("body");
        assert_eq!(body, expected_json);

        let (mut writer, mut reader) = duplex(4096);
        write_message(&mut writer, &expected).await.expect("write");
        let decoded: RequestEnvelope = read_message(&mut reader, &InboundBudget::default())
            .await
            .expect("read");
        assert_eq!(decoded, expected);
    }

    #[tokio::test]
    async fn rejects_empty_oversize_and_truncated_frames() {
        let (mut writer, mut reader) = duplex(64);
        writer.write_all(&0_u32.to_le_bytes()).await.expect("write");
        assert!(matches!(
            read_message::<_, serde_json::Value>(&mut reader, &InboundBudget::default()).await,
            Err(WireError::EmptyFrame)
        ));

        let (mut writer, mut reader) = duplex(64);
        writer
            .write_all(&((MAX_FRAME_BYTES + 1) as u32).to_le_bytes())
            .await
            .expect("write");
        assert!(matches!(
            read_message::<_, serde_json::Value>(&mut reader, &InboundBudget::default()).await,
            Err(WireError::FrameTooLarge { .. })
        ));

        let (mut writer, mut reader) = duplex(64);
        writer.write_all(&5_u32.to_le_bytes()).await.expect("write");
        writer.write_all(b"{}").await.expect("write");
        writer.shutdown().await.expect("shutdown");
        assert!(matches!(
            read_message::<_, serde_json::Value>(&mut reader, &InboundBudget::default()).await,
            Err(WireError::UnexpectedEof)
        ));
    }
}
