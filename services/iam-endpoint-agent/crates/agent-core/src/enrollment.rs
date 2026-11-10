use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum EnrollmentAuthError {
    #[error("failed to bind a local loopback port: {0}")]
    Bind(std::io::Error),
    #[error("failed to accept the browser callback: {0}")]
    Accept(std::io::Error),
    #[error("failed to launch the system browser: {0}")]
    LaunchBrowser(std::io::Error),
    #[error("invalid enrollment login URL: {0}")]
    InvalidUrl(String),
    #[error("callback state did not match -- ignoring a callback this agent did not start")]
    StateMismatch,
    #[error("sign-in service reported an error: {0}")]
    Remote(String),
    #[error("callback was missing or had a malformed {0}")]
    MalformedCallback(&'static str),
}

/// What iam-login-portal's /device-enroll hands back after the user signs in: a single-use,
/// short-lived enrollment transaction already bound (server-side) to this agent's key thumbprint.
/// Deliberately *not* a session token -- the agent never holds one (least privilege).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentAuthorization {
    pub enrollment_transaction_id: Uuid,
    pub nonce: String,
}

/// Abstracts "open this URL in the user's default browser" -- deliberately not implemented in this
/// crate (agent-core stays OS-free). The binary crate's platform module provides the real one.
pub trait BrowserLauncher {
    fn open(&self, url: &str) -> std::io::Result<()>;
}

/// RFC 8252 loopback-redirect flow against iam-login-portal's /device-enroll route:
///  1. bind an ephemeral loopback port,
///  2. open the browser at `{login_url}?redirect_uri=http://127.0.0.1:<port>/callback&key_thumbprint=..&state=..`,
///  3. the user signs in normally (password + second factor -- the password never touches the agent),
///  4. the portal starts enrollment server-side and redirects back here with the transaction.
///
/// `state` (RFC 6749 Section 10.12 / RFC 8252 Section 8.9) means a callback forged by some other
/// local process -- which can't know this random value -- is rejected.
pub async fn obtain_enrollment_authorization_via_browser(
    login_url: &str,
    key_thumbprint: &str,
    launcher: &dyn BrowserLauncher,
) -> Result<EnrollmentAuthorization, EnrollmentAuthError> {
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(EnrollmentAuthError::Bind)?;
    let port = listener.local_addr().map_err(EnrollmentAuthError::Bind)?.port();
    let state = random_state();

    let mut url = reqwest::Url::parse(login_url).map_err(|e| EnrollmentAuthError::InvalidUrl(e.to_string()))?;
    url.query_pairs_mut()
        .append_pair("redirect_uri", &format!("http://127.0.0.1:{port}/callback"))
        .append_pair("key_thumbprint", key_thumbprint)
        .append_pair("state", &state);
    launcher.open(url.as_str()).map_err(EnrollmentAuthError::LaunchBrowser)?;

    await_callback(listener, port, &state).await
}

fn random_state() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes) // 43 chars, within /device-enroll's accepted 16-128 range
}

/// The accept/parse/respond half, split out so tests can drive it over a real socket they control.
async fn await_callback(listener: TcpListener, port: u16, expected_state: &str) -> Result<EnrollmentAuthorization, EnrollmentAuthError> {
    let (mut socket, _) = listener.accept().await.map_err(EnrollmentAuthError::Accept)?;
    let mut buf = [0u8; 8192];
    let n = socket.read(&mut buf).await.map_err(EnrollmentAuthError::Accept)?;
    let request = String::from_utf8_lossy(&buf[..n]);
    let request_line = request.lines().next().unwrap_or("");

    let result = parse_callback(request_line, port, expected_state);

    let body = if result.is_ok() {
        "<html><body>Device registration started. You can close this window and return to the endpoint agent.</body></html>"
    } else {
        "<html><body>Device registration did not complete. Please try again from the endpoint agent.</body></html>"
    };
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body,
    );
    let _ = socket.write_all(response.as_bytes()).await;

    result
}

fn parse_callback(request_line: &str, port: u16, expected_state: &str) -> Result<EnrollmentAuthorization, EnrollmentAuthError> {
    // Request line looks like "GET /callback?enrollment_transaction_id=..&nonce=..&state=.. HTTP/1.1".
    let path_and_query = request_line.split_whitespace().nth(1).ok_or(EnrollmentAuthError::MalformedCallback("request line"))?;
    let url = reqwest::Url::parse(&format!("http://127.0.0.1:{port}"))
        .and_then(|base| base.join(path_and_query))
        .map_err(|_| EnrollmentAuthError::MalformedCallback("URL"))?;
    let param = |name: &str| url.query_pairs().find(|(k, _)| k == name).map(|(_, v)| v.into_owned());

    // State first: an unverified callback's other parameters (including `error`) are not trusted.
    if param("state").as_deref() != Some(expected_state) {
        return Err(EnrollmentAuthError::StateMismatch);
    }
    if let Some(error) = param("error") {
        return Err(EnrollmentAuthError::Remote(error));
    }
    let enrollment_transaction_id = param("enrollment_transaction_id")
        .and_then(|v| Uuid::parse_str(&v).ok())
        .ok_or(EnrollmentAuthError::MalformedCallback("enrollment_transaction_id"))?;
    let nonce = param("nonce").filter(|v| !v.is_empty()).ok_or(EnrollmentAuthError::MalformedCallback("nonce"))?;

    Ok(EnrollmentAuthorization { enrollment_transaction_id, nonce })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpStream;

    const STATE: &str = "expected-state-value-0123456789";

    #[test]
    fn a_well_formed_callback_yields_the_transaction() {
        let tx = Uuid::new_v4();
        // nonce is standard base64, so '+', '/' and '=' arrive percent-encoded and must decode back.
        let line = format!("GET /callback?enrollment_transaction_id={tx}&nonce=ab%2Bc%2Fd%3D&state={STATE} HTTP/1.1");
        let auth = parse_callback(&line, 9999, STATE).unwrap();
        assert_eq!(auth.enrollment_transaction_id, tx);
        assert_eq!(auth.nonce, "ab+c/d=");
    }

    #[test]
    fn a_callback_with_the_wrong_state_is_rejected_before_anything_else_is_read() {
        let line = format!("GET /callback?enrollment_transaction_id={}&nonce=n&state=forged HTTP/1.1", Uuid::new_v4());
        assert!(matches!(parse_callback(&line, 9999, STATE), Err(EnrollmentAuthError::StateMismatch)));
    }

    #[test]
    fn a_callback_with_no_state_is_rejected() {
        let line = format!("GET /callback?enrollment_transaction_id={}&nonce=n HTTP/1.1", Uuid::new_v4());
        assert!(matches!(parse_callback(&line, 9999, STATE), Err(EnrollmentAuthError::StateMismatch)));
    }

    #[test]
    fn a_remote_error_is_surfaced_once_state_is_verified() {
        let line = format!("GET /callback?error=temporarily_unavailable&state={STATE} HTTP/1.1");
        match parse_callback(&line, 9999, STATE) {
            Err(EnrollmentAuthError::Remote(e)) => assert_eq!(e, "temporarily_unavailable"),
            other => panic!("expected Remote error, got {other:?}"),
        }
    }

    #[test]
    fn a_malformed_transaction_id_is_rejected() {
        let line = format!("GET /callback?enrollment_transaction_id=not-a-uuid&nonce=n&state={STATE} HTTP/1.1");
        assert!(matches!(parse_callback(&line, 9999, STATE), Err(EnrollmentAuthError::MalformedCallback("enrollment_transaction_id"))));
    }

    #[test]
    fn random_state_is_url_safe_and_unique() {
        let a = random_state();
        assert_eq!(a.len(), 43);
        assert_ne!(a, random_state());
    }

    /// Real loopback socket, real accept/read/respond path -- a fake "browser" sends the redirect
    /// GET exactly as iam-login-portal's /device-enroll would.
    #[tokio::test]
    async fn the_full_loopback_round_trip_extracts_the_transaction() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move { await_callback(listener, port, STATE).await });

        let tx = Uuid::new_v4();
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client
            .write_all(format!("GET /callback?enrollment_transaction_id={tx}&nonce=abc&state={STATE} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").as_bytes())
            .await
            .unwrap();

        let auth = server.await.unwrap().unwrap();
        assert_eq!(auth.enrollment_transaction_id, tx);
        assert_eq!(auth.nonce, "abc");
    }
}
