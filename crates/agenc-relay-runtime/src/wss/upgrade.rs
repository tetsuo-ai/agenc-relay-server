use std::time::Duration;

use agenc_relay_client_wire::WebSocketSubprotocol;
use agenc_relay_client_wire::websocket_transport::{
    HTTP_UPGRADE_BYTES, UpgradeError, UpgradeResponse, parse_upgrade, upgrade_response,
};
use agenc_relay_crypto::websocket_accept_digest;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::time::Instant;
use zeroize::Zeroizing;

use super::WssStream;
use crate::budget::MemoryBudget;
use crate::cancel::CancellationToken;
use crate::listener::RefusalReason;
use crate::tls::CLOSE_NOTIFY_GRACE;

const UPGRADE_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) async fn upgrade<T, F>(
    mut stream: T,
    tls_completed: std::time::Instant,
    budget: &MemoryBudget,
    origin_allowed: F,
    token: &CancellationToken,
) -> Result<WssStream<T>, RefusalReason>
where
    T: AsyncRead + AsyncWrite + Unpin,
    F: Fn(Option<&str>) -> bool,
{
    let deadline = Instant::from_std(tls_completed) + UPGRADE_TIMEOUT;
    let request = tokio::select! {
        () = token.cancelled() => return Err(RefusalReason::Admission),
        outcome = tokio::time::timeout_at(deadline, read_request(&mut stream, origin_allowed)) =>
            outcome.unwrap_or(Err(UpgradeError::Timeout)),
    };
    let (protocol, response) = match request {
        Ok(request) => request,
        Err(error) => {
            let _ = tokio::time::timeout(CLOSE_NOTIFY_GRACE, async {
                stream.write_all(error.response()).await?;
                stream.flush().await?;
                stream.shutdown().await
            })
            .await;
            return Err(RefusalReason::Admission);
        }
    };
    // Allocate and charge all steady framing before acknowledging the upgrade.
    let mut stream =
        WssStream::new(stream, protocol, budget).map_err(|_| RefusalReason::MemoryExhausted)?;
    tokio::select! {
        () = token.cancelled() => return Err(RefusalReason::Admission),
        outcome = tokio::time::timeout_at(deadline, stream.write_upgrade(response.as_bytes())) => {
            outcome.map_err(|_| RefusalReason::Admission)?.map_err(|_| RefusalReason::Admission)?;
        }
    }
    Ok(stream)
}

async fn read_request<T, F>(
    stream: &mut T,
    origin_allowed: F,
) -> Result<(WebSocketSubprotocol, UpgradeResponse), UpgradeError>
where
    T: AsyncRead + Unpin,
    F: Fn(Option<&str>) -> bool,
{
    let mut allocation = Vec::new();
    allocation
        .try_reserve_exact(HTTP_UPGRADE_BYTES)
        .map_err(|_| UpgradeError::Headers)?;
    allocation.resize(HTTP_UPGRADE_BYTES, 0);
    let mut buffer = Zeroizing::new(allocation);
    let mut filled = 0_usize;
    loop {
        if let Some(request) = parse_upgrade(buffer.get(..filled).ok_or(UpgradeError::Headers)?)? {
            // This load is the admission boundary for live Origin policy.
            if !origin_allowed(request.origin()) {
                return Err(UpgradeError::Origin);
            }
            let protocol = request.subprotocol();
            return Ok((
                protocol,
                upgrade_response(&websocket_accept_digest(request.key()), protocol)?,
            ));
        }
        if filled == HTTP_UPGRADE_BYTES {
            return Err(UpgradeError::Headers);
        }
        let count = stream
            .read(buffer.get_mut(filled..).ok_or(UpgradeError::Headers)?)
            .await
            .map_err(|_| UpgradeError::Malformed)?;
        if count == 0 {
            return Err(UpgradeError::Malformed);
        }
        filled = filled.checked_add(count).ok_or(UpgradeError::Headers)?;
    }
}

#[cfg(test)]
mod tests;
