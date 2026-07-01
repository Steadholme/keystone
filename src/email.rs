//! Non-blocking, fire-and-forget transactional email emitter -> Corvid.
//!
//! [`EmailSink`] holds a bounded `tokio::mpsc` sender drained by a spawned background worker
//! that POSTs each message to `CORVID_SEND_URL` (`Authorization: Bearer MAIL_SEND_TOKEN`) over
//! plain HTTP/1.1 with a short timeout. [`EmailSink::send`] is sync + infallible: it `try_send`s
//! and DROPS (warn + counter) when the queue is full or the worker is gone, so a slow or down
//! Corvid NEVER blocks, slows, or fails the request path. When email is disabled (no URL and/or
//! no token — the default) the sink logs the intended message and skips, exactly like the audit
//! sink — registration/reset still succeed; the user simply never gets an email in dev.
//!
//! This is a deliberate structural twin of [`crate::audit`]: same bounded-queue + background
//! worker + hand-rolled HTTP/1.1-over-raw-TCP shape (no reqwest, no OpenSSL). The internal hop
//! to Corvid is plaintext for v0, so no TLS client is needed.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::config::MAIL_FROM;

/// Bounded queue depth. Beyond this, messages are dropped rather than blocking the caller.
const QUEUE_CAPACITY: usize = 512;
/// Per-POST budget (connect + write + read). Corvid is in-network; keep it short.
const POST_TIMEOUT: Duration = Duration::from_secs(5);

/// One outbound email. `from` is fixed to [`MAIL_FROM`]; producers fill `to`/`subject`/`body`.
#[derive(Debug, Clone, Serialize)]
pub struct EmailMessage {
    pub from: String,
    pub to: String,
    pub subject: String,
    pub body: String,
}

/// Non-blocking email sink. Cheap to clone (shared sender + drop counter behind `Arc`).
/// A disabled sink (`inner == None`) makes [`send`](Self::send) log-and-skip.
#[derive(Clone)]
pub struct EmailSink {
    inner: Option<Inner>,
}

#[derive(Clone)]
struct Inner {
    tx: mpsc::Sender<EmailMessage>,
    dropped: Arc<AtomicU64>,
}

impl EmailSink {
    /// Disabled sink: `send` logs the intended message and skips. No channel, no worker.
    pub fn disabled() -> Self {
        EmailSink { inner: None }
    }

    /// Build the sink from config and (when both URL + token are present) spawn the worker.
    ///
    /// Returns a disabled sink when the send URL or token is missing, or when the URL is
    /// unparseable — those only warn and turn email OFF; they never fail startup or the request
    /// path. Must be called from within a tokio runtime when enabled (the worker is spawned).
    pub fn start(send_url: Option<&str>, token: Option<&str>) -> Self {
        let Some(url) = send_url.filter(|u| !u.is_empty()) else {
            tracing::info!("CORVID_SEND_URL unset — transactional email disabled (log + skip)");
            return Self::disabled();
        };
        let Some(token) = token.filter(|t| !t.is_empty()) else {
            tracing::warn!("CORVID_SEND_URL set but MAIL_SEND_TOKEN is empty — email disabled");
            return Self::disabled();
        };
        let Some(target) = Target::parse(url) else {
            tracing::warn!(url = %url, "invalid CORVID_SEND_URL — email disabled");
            return Self::disabled();
        };

        let (tx, rx) = mpsc::channel::<EmailMessage>(QUEUE_CAPACITY);
        let dropped = Arc::new(AtomicU64::new(0));
        tokio::spawn(worker(rx, target, token.to_string()));
        tracing::info!(url = %url, "transactional email enabled (corvid)");
        EmailSink {
            inner: Some(Inner { tx, dropped }),
        }
    }

    /// Queue one email. Sync, non-blocking, infallible: `try_send` only; on a full queue or a
    /// dead worker the message is DROPPED (drop counter + warn). This NEVER blocks or errors the
    /// calling request path. On a disabled sink it logs the subject/recipient and returns.
    pub fn send(&self, to: &str, subject: &str, body: &str) {
        let msg = EmailMessage {
            from: MAIL_FROM.to_string(),
            to: to.to_string(),
            subject: subject.to_string(),
            body: body.to_string(),
        };
        let Some(inner) = &self.inner else {
            tracing::info!(to = %to, subject = %subject, "email disabled — logged, not sent");
            return;
        };
        if let Err(e) = inner.tx.try_send(msg) {
            let total = inner.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            match e {
                mpsc::error::TrySendError::Full(m) => tracing::warn!(
                    to = %m.to,
                    dropped_total = total,
                    "email queue full — message dropped"
                ),
                mpsc::error::TrySendError::Closed(m) => tracing::warn!(
                    to = %m.to,
                    dropped_total = total,
                    "email worker gone — message dropped"
                ),
            }
        }
    }

    /// Total messages dropped so far (full queue or dead worker). `0` for a disabled sink.
    pub fn dropped(&self) -> u64 {
        self.inner
            .as_ref()
            .map(|i| i.dropped.load(Ordering::Relaxed))
            .unwrap_or(0)
    }
}

/// Drain the queue and POST each message. Delivery failures only warn — a message is never
/// retried and a down Corvid never affects anything but this background task.
async fn worker(mut rx: mpsc::Receiver<EmailMessage>, target: Target, token: String) {
    while let Some(msg) = rx.recv().await {
        let body = match serde_json::to_string(&msg) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error = %e, "email message serialize failed — skipped");
                continue;
            }
        };
        match tokio::time::timeout(POST_TIMEOUT, post(&target, &token, &body)).await {
            Ok(Ok(status)) if (200..300).contains(&status) => {
                tracing::debug!(to = %msg.to, status, "email delivered")
            }
            Ok(Ok(status)) => {
                tracing::warn!(to = %msg.to, status, "corvid rejected email")
            }
            Ok(Err(e)) => tracing::warn!(to = %msg.to, error = %e, "email POST failed"),
            Err(_) => tracing::warn!(to = %msg.to, "email POST timed out"),
        }
    }
}

/// Send one `POST` to the Corvid send endpoint. Hand-rolled HTTP/1.1 over a raw TCP stream
/// (the target is the internal plaintext `http://corvid:8800`, so no TLS client is needed —
/// mirrors the audit emitter). Returns the response status code.
async fn post(target: &Target, token: &str, body: &str) -> std::io::Result<u16> {
    let mut stream = TcpStream::connect((target.host.as_str(), target.port)).await?;
    let req = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {authority}\r\n\
         Authorization: Bearer {token}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\r\n{body}",
        path = target.path,
        authority = target.authority,
        len = body.len(),
    );
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;
    let mut buf = Vec::with_capacity(256);
    stream.read_to_end(&mut buf).await?;
    parse_status(&buf)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "no HTTP status line"))
}

/// Parse the numeric status from an HTTP response's first line (`HTTP/1.1 200 OK`).
fn parse_status(buf: &[u8]) -> Option<u16> {
    let line_end = buf.iter().position(|&b| b == b'\n').unwrap_or(buf.len());
    let line = std::str::from_utf8(&buf[..line_end]).ok()?;
    line.split_whitespace().nth(1)?.parse().ok()
}

/// Parsed Corvid target: where to connect (`host`/`port`), the `Host` header authority, and
/// the request `path`. Unlike the audit target, the CONFIGURED URL already carries the full
/// path (e.g. `/api/send`), so it is used verbatim (defaulting to `/` when omitted).
struct Target {
    host: String,
    port: u16,
    authority: String,
    path: String,
}

impl Target {
    /// Parse `http://host[:port][/path]` into a connect target. Only plain `http` is accepted
    /// (the internal hop is plaintext for v0); anything else returns `None` (disables + warns).
    fn parse(url: &str) -> Option<Target> {
        let rest = url.strip_prefix("http://")?;
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        if authority.is_empty() {
            return None;
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().ok()?),
            None => (authority.to_string(), 80u16),
        };
        if host.is_empty() {
            return None;
        }
        let path = if path.is_empty() { "/" } else { path };
        Some(Target {
            host,
            port,
            authority: authority.to_string(),
            path: path.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_sink_logs_and_never_drops() {
        let sink = EmailSink::disabled();
        for _ in 0..1000 {
            sink.send("u@example.com", "Verify", "link");
        }
        assert_eq!(sink.dropped(), 0);
    }

    #[test]
    fn target_parse_uses_full_path_verbatim() {
        let t = Target::parse("http://corvid:8800/api/send").unwrap();
        assert_eq!(t.host, "corvid");
        assert_eq!(t.port, 8800);
        assert_eq!(t.authority, "corvid:8800");
        assert_eq!(t.path, "/api/send");

        // Default port + no path -> "/".
        let t = Target::parse("http://corvid").unwrap();
        assert_eq!(t.port, 80);
        assert_eq!(t.path, "/");

        // Rejections: non-http scheme and empty authority.
        assert!(Target::parse("https://corvid:8800/api/send").is_none());
        assert!(Target::parse("corvid:8800").is_none());
        assert!(Target::parse("http://").is_none());
    }

    #[test]
    fn message_serializes_with_fixed_from() {
        let sink = EmailSink::disabled();
        // Compile-time shape check via the public send + a direct message build.
        sink.send("a@b.com", "s", "b");
        let msg = EmailMessage {
            from: MAIL_FROM.to_string(),
            to: "a@b.com".to_string(),
            subject: "s".to_string(),
            body: "b".to_string(),
        };
        let v: serde_json::Value = serde_json::from_str(&serde_json::to_string(&msg).unwrap()).unwrap();
        let mut keys: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        assert_eq!(keys, vec!["body", "from", "subject", "to"]);
        assert_eq!(v["from"], "no-reply@w33d.xyz");
    }

    /// `send` must return immediately and never block even when Corvid is unreachable.
    #[tokio::test]
    async fn send_never_blocks_when_sink_unreachable() {
        let sink = EmailSink::start(Some("http://127.0.0.1:1/api/send"), Some("token"));
        for _ in 0..(QUEUE_CAPACITY * 8) {
            sink.send("u@example.com", "Verify", "link");
        }
        assert!(
            sink.dropped() > 0,
            "expected drops once the bounded queue saturated, got {}",
            sink.dropped()
        );
    }
}
