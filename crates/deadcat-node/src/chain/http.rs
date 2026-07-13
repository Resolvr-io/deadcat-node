use std::time::Duration;

use reqwest::{Client, Response, StatusCode};

use super::ChainSourceError;

pub(super) const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub(super) const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
pub(super) const DEFAULT_MAX_RESPONSE_BYTES: usize = 32 * 1024 * 1024;

pub(super) fn build_client(
    connect_timeout: Duration,
    request_timeout: Duration,
) -> Result<Client, ChainSourceError> {
    Client::builder()
        .connect_timeout(connect_timeout)
        .timeout(request_timeout)
        .build()
        .map_err(|error| {
            ChainSourceError::Unavailable(format!("cannot build HTTP client: {error}"))
        })
}

pub(super) async fn read_bounded(
    mut response: Response,
    max_bytes: usize,
) -> Result<(StatusCode, Vec<u8>), ChainSourceError> {
    let status = response.status();
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        return Err(ChainSourceError::InvalidData(format!(
            "HTTP response exceeds {max_bytes} byte limit"
        )));
    }

    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| transport_error(&error))?
    {
        let new_length = body.len().checked_add(chunk.len()).ok_or_else(|| {
            ChainSourceError::InvalidData("HTTP response length overflow".to_owned())
        })?;
        if new_length > max_bytes {
            return Err(ChainSourceError::InvalidData(format!(
                "HTTP response exceeds {max_bytes} byte limit"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok((status, body))
}

pub(super) fn transport_error(error: &reqwest::Error) -> ChainSourceError {
    let kind = if error.is_timeout() {
        "HTTP request timed out"
    } else if error.is_connect() {
        "cannot connect to backend"
    } else {
        "HTTP transport failed"
    };
    ChainSourceError::Unavailable(format!("{kind}: {error}"))
}

pub(super) fn utf8_text(body: Vec<u8>, context: &str) -> Result<String, ChainSourceError> {
    String::from_utf8(body).map_err(|_| {
        ChainSourceError::InvalidData(format!("{context} response is not valid UTF-8"))
    })
}

pub(super) fn error_excerpt(body: &[u8]) -> String {
    const MAX_CHARS: usize = 512;
    let text = String::from_utf8_lossy(body);
    let trimmed = text.trim();
    let mut excerpt = trimmed.chars().take(MAX_CHARS).collect::<String>();
    if trimmed.chars().count() > MAX_CHARS {
        excerpt.push('…');
    }
    if excerpt.is_empty() {
        "empty response body".to_owned()
    } else {
        excerpt
    }
}
