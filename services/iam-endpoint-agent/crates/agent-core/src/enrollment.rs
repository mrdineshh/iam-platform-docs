use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
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
    #[error("sign-in was not completed within {0:?}")]
    TimedOut(Duration),
}

/// How long the agent waits for the user to finish signing in before giving up. Matches the backend's
/// enrollment-transaction lifetime (5 minutes): waiting longer could only end in an expired transaction.
const SIGN_IN_TIMEOUT: Duration = Duration::from_secs(300);
/// How long one connection may take to send its request line before it is dropped as idle.
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(2);

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
    obtain_with_timeout(login_url, key_thumbprint, launcher, SIGN_IN_TIMEOUT).await
}

async fn obtain_with_timeout(
    login_url: &str,
    key_thumbprint: &str,
    launcher: &dyn BrowserLauncher,
    timeout: Duration,
) -> Result<EnrollmentAuthorization, EnrollmentAuthError> {
    // Validated before anything is bound or opened: this URL is handed to the operating system to open, so
    // only http(s) is ever acceptable -- never file:, javascript:, ms-msdt: or any other protocol handler.
    let mut url = reqwest::Url::parse(login_url).map_err(|e| EnrollmentAuthError::InvalidUrl(e.to_string()))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(EnrollmentAuthError::InvalidUrl(format!("only http and https URLs can be opened, not {}:", url.scheme())));
    }

    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(EnrollmentAuthError::Bind)?;
    let port = listener.local_addr().map_err(EnrollmentAuthError::Bind)?.port();
    let state = random_state();

    url.query_pairs_mut()
        .append_pair("redirect_uri", &format!("http://127.0.0.1:{port}/callback"))
        .append_pair("key_thumbprint", key_thumbprint)
        .append_pair("state", &state);
    launcher.open(url.as_str()).map_err(EnrollmentAuthError::LaunchBrowser)?;

    // Never an unbounded wait (ENGINEERING_GUARDRAILS section 2).
    tokio::time::timeout(timeout, await_callback(listener, port, &state)).await.map_err(|_| EnrollmentAuthError::TimedOut(timeout))?
}

fn random_state() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes) // 43 chars, within /device-enroll's accepted 16-128 range
}

/// The accept/parse/respond half, split out so tests can drive it over a real socket they control.
///
/// Keeps listening until the genuine callback arrives. Anything else that touches the port is answered and
/// ignored rather than treated as the outcome: browsers open speculative connections to redirect targets
/// and ask for /favicon.ico, and any local process can connect to a loopback port. If one stray connection
/// could end the wait, a speculative preconnect would break sign-in and a hostile process could cancel
/// every enrollment. Only a request carrying this attempt's secret `state` can complete -- or fail -- it.
async fn await_callback(listener: TcpListener, port: u16, expected_state: &str) -> Result<EnrollmentAuthorization, EnrollmentAuthError> {
    loop {
        let (mut socket, _) = listener.accept().await.map_err(EnrollmentAuthError::Accept)?;
        let Some(request_line) = read_request_line(&mut socket).await else {
            continue; // connected and sent nothing (preconnect), or too slow
        };

        match parse_callback(&request_line, port, expected_state) {
            Ok(authorization) => {
                respond(&mut socket, "200 OK", "Device registration started. You can close this window and return to the endpoint agent.").await;
                return Ok(authorization);
            }
            // Not our callback: a stray request, a favicon fetch, or a forgery without the right state.
            Err(EnrollmentAuthError::StateMismatch) | Err(EnrollmentAuthError::MalformedCallback("request line" | "URL")) => {
                respond(&mut socket, "400 Bad Request", "Not a valid sign-in callback.").await;
            }
            // Carried the right state, so it genuinely came from the sign-in flow -- and it says it failed.
            Err(terminal) => {
                respond(&mut socket, "200 OK", "Device registration did not complete. Please try again from the endpoint agent.").await;
                return Err(terminal);
            }
        }
    }
}

async fn read_request_line(socket: &mut TcpStream) -> Option<String> {
    let mut buf = [0u8; 8192];
    let n = tokio::time::timeout(REQUEST_READ_TIMEOUT, socket.read(&mut buf)).await.ok()?.ok()?;
    if n == 0 {
        return None;
    }
    String::from_utf8_lossy(&buf[..n]).lines().next().map(str::to_string)
}

async fn respond(socket: &mut TcpStream, status: &str, message: &str) {
    let body = format!("<html><body>{message}</body></html>");
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len(),
    );
    let _ = socket.write_all(response.as_bytes()).await;
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

    struct MustNotOpen;
    impl BrowserLauncher for MustNotOpen {
        fn open(&self, url: &str) -> std::io::Result<()> {
            panic!("the browser must not be launched for {url}");
        }
    }

    #[tokio::test]
    async fn only_http_and_https_login_urls_are_ever_opened() {
        for bad in ["file:///C:/Windows/System32/cmd.exe", "javascript:alert(1)", "ms-msdt:/id", "calc.exe", ""] {
            let result = obtain_enrollment_authorization_via_browser(bad, "thumb", &MustNotOpen).await;
            assert!(matches!(result, Err(EnrollmentAuthError::InvalidUrl(_))), "{bad:?} must be rejected, got {result:?}");
        }
    }

    struct Recording(std::sync::Mutex<Option<String>>);
    impl BrowserLauncher for Recording {
        fn open(&self, url: &str) -> std::io::Result<()> {
            *self.0.lock().unwrap() = Some(url.to_string());
            Ok(())
        }
    }

    /// The URL handed to the OS must carry all three parameters intact (a Windows `cmd /C start` launcher
    /// once truncated it at the first `&`), and answering the redirect_uri it names must complete the flow.
    #[tokio::test]
    async fn the_url_handed_to_the_browser_is_complete_and_its_redirect_uri_works() {
        let launcher = Recording(Default::default());
        let tx = Uuid::new_v4();

        let flow = obtain_enrollment_authorization_via_browser("https://acme.example.com/device-enroll", "the-thumbprint", &launcher);
        let browser = async {
            let url = loop {
                if let Some(u) = launcher.0.lock().unwrap().clone() {
                    break u;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            };
            let url = reqwest::Url::parse(&url).unwrap();
            let get = |k: &str| url.query_pairs().find(|(name, _)| name == k).map(|(_, v)| v.into_owned());
            assert_eq!(url.path(), "/device-enroll");
            assert_eq!(get("key_thumbprint").as_deref(), Some("the-thumbprint"));
            let state = get("state").expect("state");
            assert_eq!(state.len(), 43);
            let redirect = reqwest::Url::parse(&get("redirect_uri").expect("redirect_uri")).unwrap();
            assert_eq!((redirect.scheme(), redirect.host_str(), redirect.path()), ("http", Some("127.0.0.1"), "/callback"));

            let mut sock = TcpStream::connect(("127.0.0.1", redirect.port().unwrap())).await.unwrap();
            sock.write_all(format!("GET /callback?enrollment_transaction_id={tx}&nonce=n0nce&state={state} HTTP/1.1\r\n\r\n").as_bytes()).await.unwrap();
        };

        let (result, ()) = tokio::join!(flow, browser);
        assert_eq!(result.unwrap().enrollment_transaction_id, tx);
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

    async fn spawn_waiter(state: &'static str) -> (u16, tokio::task::JoinHandle<Result<EnrollmentAuthorization, EnrollmentAuthError>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        (port, tokio::spawn(async move { await_callback(listener, port, state).await }))
    }

    async fn send(port: u16, request: &str) {
        let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        s.write_all(request.as_bytes()).await.unwrap();
    }

    #[tokio::test]
    async fn a_connection_that_sends_nothing_does_not_end_the_wait() {
        // What a browser's speculative preconnect looks like: open a socket, say nothing, close it.
        let (port, waiter) = spawn_waiter(STATE).await;
        drop(TcpStream::connect(("127.0.0.1", port)).await.unwrap());
        let tx = Uuid::new_v4();
        send(port, &format!("GET /callback?enrollment_transaction_id={tx}&nonce=n&state={STATE} HTTP/1.1\r\n\r\n")).await;
        assert_eq!(waiter.await.unwrap().unwrap().enrollment_transaction_id, tx);
    }

    #[tokio::test]
    async fn favicon_requests_and_forged_callbacks_do_not_abort_or_complete_enrollment() {
        let (port, waiter) = spawn_waiter(STATE).await;
        send(port, "GET /favicon.ico HTTP/1.1\r\n\r\n").await;
        send(port, &format!("GET /callback?enrollment_transaction_id={}&nonce=evil&state=guessed HTTP/1.1\r\n\r\n", Uuid::new_v4())).await;
        send(port, "garbage that is not http").await;
        tokio::time::sleep(Duration::from_millis(200)).await; // let the waiter process all three
        assert!(!waiter.is_finished(), "stray requests must not end the wait");

        let tx = Uuid::new_v4();
        send(port, &format!("GET /callback?enrollment_transaction_id={tx}&nonce=real&state={STATE} HTTP/1.1\r\n\r\n")).await;
        let authorization = waiter.await.unwrap().unwrap();
        assert_eq!((authorization.enrollment_transaction_id, authorization.nonce.as_str()), (tx, "real"));
    }

    #[tokio::test]
    async fn an_error_reported_with_the_right_state_ends_the_wait_with_that_error() {
        let (port, waiter) = spawn_waiter(STATE).await;
        send(port, &format!("GET /callback?error=temporarily_unavailable&state={STATE} HTTP/1.1\r\n\r\n")).await;
        assert!(matches!(waiter.await.unwrap(), Err(EnrollmentAuthError::Remote(e)) if e == "temporarily_unavailable"));
    }

    #[tokio::test]
    async fn waiting_gives_up_instead_of_hanging_forever() {
        let result = obtain_with_timeout("https://acme.example.com/device-enroll", "t", &Recording(Default::default()), Duration::from_millis(150)).await;
        assert!(matches!(result, Err(EnrollmentAuthError::TimedOut(_))), "got {result:?}");
    }
}
