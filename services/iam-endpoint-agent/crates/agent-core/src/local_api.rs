//! The agent's local (loopback) endpoint for device-bound sign-in (docs/specs/device-bound-signin-SPEC.md, PDF 4.2).
//!
//! The company login page, running in the user's browser, asks this endpoint to sign a one-time challenge the platform
//! issued, which proves the sign-in comes from this enrolled laptop. The platform verifies the signature against the key
//! registered at enrollment; the agent never decides anything about trust.
//!
//! **Why this is deliberately narrow.** Any web page the user visits can send requests to 127.0.0.1. So this must never be
//! a general signing service:
//! * it listens on 127.0.0.1 only;
//! * the `Host` header must be this exact loopback address and port (DNS-rebinding defence);
//! * the `Origin` header must be exactly the company login origin, else 403 with no CORS headers (so no other site's
//!   script can read an answer, and a browser tab on another site is refused outright);
//! * it signs ONE fixed, domain-separated structure and nothing else, built here from validated fields, never "sign these
//!   bytes". The platform only accepts challenges it issued itself, so a signature has no use without a live challenge.
//!
//! Limit, stated plainly: a program already running on this laptop can send any `Origin` header it likes. It still needs a
//! live platform challenge (which it can only get through the login page flow) and the user's password to turn that into a
//! session, so this adds no ability it did not already have, but it is not a defence against local malware.

use crate::key_provider::KeyProvider;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Semaphore};
use uuid::Uuid;

/// Tried in order; the login page tries the same list. A fixed list (not a random port) is what lets a web page find us.
pub const PORTS: [u16; 5] = [47631, 47632, 47633, 47634, 47635];

const MAX_HEAD_BYTES: usize = 8 * 1024;
const MAX_BODY_BYTES: usize = 4 * 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_CONCURRENT: usize = 8;

pub struct LocalApiContext {
    pub tenant_id: Uuid,
    pub device_id: Uuid,
    /// scheme://host[:port] of the login page, e.g. `https://login.example.com`; the only origin ever served.
    pub allowed_origin: String,
    pub agent_version: String,
    pub signer: Arc<dyn KeyProvider>,
}

/// `https://login.example.com/device-enroll?tenant=x` -> `https://login.example.com`, exactly as a browser sends it in the
/// `Origin` header (default ports omitted).
pub fn origin_of(url: &str) -> Option<String> {
    let parsed = reqwest::Url::parse(url).ok()?;
    parsed.host_str()?;
    Some(parsed.origin().ascii_serialization())
}

/// The exact bytes the agent signs. MUST stay identical to `DeviceLoginProofService.canonicalPayload` in iam-tenant-svc.
pub fn login_payload(tenant_id: Uuid, device_id: Uuid, challenge_id: Uuid, nonce: &str, origin: &str) -> String {
    ["iam-device-login-v1", &tenant_id.to_string(), &device_id.to_string(), &challenge_id.to_string(), nonce, origin].join("\n")
}

#[derive(Debug)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    /// Names lower-cased.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }
}

#[derive(Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl HttpResponse {
    fn json(status: u16, body: String) -> Self {
        Self { status, headers: vec![("Content-Type".into(), "application/json".into())], body }
    }
    fn text(status: u16, body: &str) -> Self {
        Self { status, headers: vec![("Content-Type".into(), "text/plain".into())], body: body.to_string() }
    }
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SignLoginRequest {
    challenge_id: String,
    nonce: String,
    origin: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SignLoginResponse {
    device_id: Uuid,
    signature: String,
}

fn valid_nonce(nonce: &str) -> bool {
    (16..=128).contains(&nonce.len()) && nonce.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Pure request handling: everything security-relevant is decided here, so it is unit-tested without a socket.
pub fn handle(request: &HttpRequest, port: u16, ctx: &LocalApiContext) -> HttpResponse {
    let mut response = route(request, port, ctx);
    response.headers.push(("Cache-Control".into(), "no-store".into()));
    // Only an allowed origin ever gets CORS headers, and only once it has passed the Host and Origin checks above.
    if response.status != 403 {
        response.headers.push(("Access-Control-Allow-Origin".into(), ctx.allowed_origin.clone()));
        response.headers.push(("Access-Control-Allow-Private-Network".into(), "true".into()));
        response.headers.push(("Vary".into(), "Origin".into()));
    }
    response
}

fn route(request: &HttpRequest, port: u16, ctx: &LocalApiContext) -> HttpResponse {
    let host_ok = matches!(request.header("host"), Some(h) if h == format!("127.0.0.1:{port}") || h == format!("localhost:{port}"));
    if !host_ok {
        return HttpResponse::text(403, "forbidden");
    }
    if request.header("origin") != Some(ctx.allowed_origin.as_str()) {
        return HttpResponse::text(403, "forbidden");
    }

    match (request.method.as_str(), request.path.as_str()) {
        ("OPTIONS", "/v1/identity" | "/v1/sign-login") => {
            let mut r = HttpResponse::text(204, "");
            r.headers.push(("Access-Control-Allow-Methods".into(), "GET, POST, OPTIONS".into()));
            r.headers.push(("Access-Control-Allow-Headers".into(), "content-type".into()));
            r.headers.push(("Access-Control-Max-Age".into(), "60".into()));
            r
        }
        ("GET", "/v1/identity") => HttpResponse::json(
            200,
            serde_json::json!({ "deviceId": ctx.device_id, "tenantId": ctx.tenant_id, "agentVersion": ctx.agent_version }).to_string(),
        ),
        ("POST", "/v1/sign-login") => sign_login(request, ctx),
        _ => HttpResponse::text(404, "not found"),
    }
}

fn sign_login(request: &HttpRequest, ctx: &LocalApiContext) -> HttpResponse {
    // A JSON content type cannot be sent by a plain cross-site HTML form, so this also forces a CORS preflight.
    if !request.header("content-type").is_some_and(|c| c.to_ascii_lowercase().starts_with("application/json")) {
        return HttpResponse::text(415, "expected application/json");
    }
    let Ok(body) = serde_json::from_slice::<SignLoginRequest>(&request.body) else {
        return HttpResponse::text(400, "bad request");
    };
    let Ok(challenge_id) = Uuid::parse_str(&body.challenge_id) else {
        return HttpResponse::text(400, "bad challengeId");
    };
    if !valid_nonce(&body.nonce) {
        return HttpResponse::text(400, "bad nonce");
    }
    // The page must claim the same origin it was served from; a mismatch means something is trying to get a signature
    // bound to a different origin.
    if body.origin != ctx.allowed_origin {
        return HttpResponse::text(400, "bad origin");
    }
    let payload = login_payload(ctx.tenant_id, ctx.device_id, challenge_id, &body.nonce, &body.origin);
    let signature = ctx.signer.sign(payload.as_bytes());
    HttpResponse::json(200, serde_json::to_string(&SignLoginResponse { device_id: ctx.device_id, signature }).expect("serialisable"))
}

// ---------------------------------------------------------------------------------------------------------------------
// The socket half.

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        _ => "Error",
    }
}

async fn read_request(socket: &mut TcpStream) -> Result<HttpRequest, u16> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let head_end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
        if buf.len() > MAX_HEAD_BYTES {
            return Err(413);
        }
        let n = tokio::time::timeout(READ_TIMEOUT, socket.read(&mut chunk)).await.map_err(|_| 400u16)?.map_err(|_| 400u16)?;
        if n == 0 {
            return Err(400);
        }
        buf.extend_from_slice(&chunk[..n]);
    };

    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or("").split_whitespace();
    let (Some(method), Some(path)) = (first.next(), first.next()) else { return Err(400) };
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string())))
        .collect();

    let content_length = headers.iter().find(|(k, _)| k == "content-length").and_then(|(_, v)| v.parse::<usize>().ok()).unwrap_or(0);
    if content_length > MAX_BODY_BYTES {
        return Err(413);
    }
    let mut body = buf[head_end + 4..].to_vec();
    while body.len() < content_length {
        let n = tokio::time::timeout(READ_TIMEOUT, socket.read(&mut chunk)).await.map_err(|_| 400u16)?.map_err(|_| 400u16)?;
        if n == 0 {
            return Err(400);
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(content_length);
    // The path is matched exactly; a query string is not used by any route, so it is simply not part of a match.
    Ok(HttpRequest { method: method.to_string(), path: path.to_string(), headers, body })
}

async fn write_response(socket: &mut TcpStream, response: &HttpResponse) {
    let mut out = format!("HTTP/1.1 {} {}\r\n", response.status, reason(response.status));
    for (k, v) in &response.headers {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str(&format!("Content-Length: {}\r\nConnection: close\r\n\r\n{}", response.body.len(), response.body));
    let _ = socket.write_all(out.as_bytes()).await;
    let _ = socket.shutdown().await;
}

/// Serves on an already-bound listener until `shutdown` fires. Split from [`run`] so tests can use an ephemeral port.
pub async fn serve(listener: TcpListener, ctx: Arc<LocalApiContext>, mut shutdown: watch::Receiver<bool>) {
    let port = match listener.local_addr() {
        Ok(a) => a.port(),
        Err(_) => return,
    };
    let limit = Arc::new(Semaphore::new(MAX_CONCURRENT));
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((mut socket, peer)) = accepted else { continue };
                // Loopback only is guaranteed by the bind address; this is a second, explicit check.
                if !peer.ip().is_loopback() {
                    continue;
                }
                let Ok(permit) = limit.clone().try_acquire_owned() else { continue };
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    let response = match read_request(&mut socket).await {
                        Ok(request) => handle(&request, port, &ctx),
                        Err(status) => HttpResponse::text(status, "bad request"),
                    };
                    write_response(&mut socket, &response).await;
                    drop(permit);
                });
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
            }
        }
    }
}

/// Binds the first free port of [`PORTS`] on 127.0.0.1 and serves until shutdown. Never fails the agent: if no port is
/// free (another program holds them all) it logs and returns, and device-bound sign-in is simply unavailable.
pub async fn run(ctx: LocalApiContext, shutdown: watch::Receiver<bool>) {
    for port in PORTS {
        match TcpListener::bind(("127.0.0.1", port)).await {
            Ok(listener) => {
                tracing::info!(port, "device sign-in endpoint listening on 127.0.0.1");
                serve(listener, Arc::new(ctx), shutdown).await;
                tracing::info!("device sign-in endpoint stopped");
                return;
            }
            Err(err) => tracing::debug!(port, %err, "port unavailable"),
        }
    }
    tracing::warn!("no local port free for the device sign-in endpoint; device-bound sign-in is unavailable on this laptop");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_provider::SoftwareEd25519KeyProvider;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    const ORIGIN: &str = "https://login.example.com";
    const NONCE: &str = "abcdefghijklmnopqrstuvwxyz0123456789_-AB";

    fn ctx() -> (LocalApiContext, VerifyingKey) {
        let (provider, _) = SoftwareEd25519KeyProvider::generate();
        let spki = STANDARD.decode(provider.public_key_base64()).unwrap();
        let verifying = VerifyingKey::from_bytes(spki[spki.len() - 32..].try_into().unwrap()).unwrap();
        let ctx = LocalApiContext {
            tenant_id: Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap(),
            device_id: Uuid::parse_str("22222222-2222-4222-8222-222222222222").unwrap(),
            allowed_origin: ORIGIN.to_string(),
            agent_version: "9.9.9".into(),
            signer: Arc::new(provider),
        };
        (ctx, verifying)
    }

    fn req(method: &str, path: &str, headers: &[(&str, &str)], body: &str) -> HttpRequest {
        HttpRequest {
            method: method.into(),
            path: path.into(),
            headers: headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            body: body.as_bytes().to_vec(),
        }
    }

    const PORT: u16 = 47631;
    fn good_headers() -> Vec<(&'static str, &'static str)> {
        vec![("host", "127.0.0.1:47631"), ("origin", ORIGIN), ("content-type", "application/json")]
    }

    fn sign_body(challenge: &str, nonce: &str, origin: &str) -> String {
        format!(r#"{{"challengeId":"{challenge}","nonce":"{nonce}","origin":"{origin}"}}"#)
    }

    const CHALLENGE: &str = "33333333-3333-4333-8333-333333333333";

    #[test]
    fn origin_of_matches_what_a_browser_sends() {
        assert_eq!(origin_of("https://login.example.com/device-enroll?tenant=x").as_deref(), Some("https://login.example.com"));
        assert_eq!(origin_of("https://login.example.com:443/x").as_deref(), Some("https://login.example.com"));
        assert_eq!(origin_of("https://login.example.com:8443/x").as_deref(), Some("https://login.example.com:8443"));
        assert_eq!(origin_of("not a url"), None);
    }

    #[test]
    fn the_payload_has_the_exact_shape_the_platform_verifies() {
        let p = login_payload(Uuid::nil(), Uuid::nil(), Uuid::nil(), "nonce", "https://o");
        assert_eq!(p, "iam-device-login-v1\n00000000-0000-0000-0000-000000000000\n00000000-0000-0000-0000-000000000000\n00000000-0000-0000-0000-000000000000\nnonce\nhttps://o");
    }

    #[test]
    fn a_good_request_returns_a_signature_that_verifies_over_the_exact_payload() {
        let (ctx, verifying) = ctx();
        let r = handle(&req("POST", "/v1/sign-login", &good_headers(), &sign_body(CHALLENGE, NONCE, ORIGIN)), PORT, &ctx);
        assert_eq!(r.status, 200, "{}", r.body);
        let json: serde_json::Value = serde_json::from_str(&r.body).unwrap();
        assert_eq!(json["deviceId"], "22222222-2222-4222-8222-222222222222");
        let sig_bytes = STANDARD.decode(json["signature"].as_str().unwrap()).unwrap();
        let signature = Signature::from_bytes(&sig_bytes.try_into().unwrap());
        let payload = login_payload(ctx.tenant_id, ctx.device_id, Uuid::parse_str(CHALLENGE).unwrap(), NONCE, ORIGIN);
        assert!(verifying.verify(payload.as_bytes(), &signature).is_ok());
        assert_eq!(r.header("access-control-allow-origin"), Some(ORIGIN));
        assert_eq!(r.header("access-control-allow-private-network"), Some("true"));
        assert_eq!(r.header("cache-control"), Some("no-store"));
    }

    #[test]
    fn another_website_is_refused_with_no_cors_headers() {
        let (ctx, _) = ctx();
        let r = handle(&req("POST", "/v1/sign-login", &[("host", "127.0.0.1:47631"), ("origin", "https://evil.example"), ("content-type", "application/json")], &sign_body(CHALLENGE, NONCE, ORIGIN)), PORT, &ctx);
        assert_eq!(r.status, 403);
        assert_eq!(r.header("access-control-allow-origin"), None);
    }

    #[test]
    fn a_request_with_no_origin_is_refused() {
        let (ctx, _) = ctx();
        let r = handle(&req("GET", "/v1/identity", &[("host", "127.0.0.1:47631")], ""), PORT, &ctx);
        assert_eq!(r.status, 403);
    }

    #[test]
    fn a_lookalike_origin_is_refused() {
        let (ctx, _) = ctx();
        for o in ["https://login.example.com.evil.example", "http://login.example.com", "https://login.example.com:444", "https://login.example.comx", "https://LOGIN.example.com"] {
            let r = handle(&req("GET", "/v1/identity", &[("host", "127.0.0.1:47631"), ("origin", o)], ""), PORT, &ctx);
            assert_eq!(r.status, 403, "{o}");
        }
    }

    #[test]
    fn a_wrong_host_header_is_refused_dns_rebinding() {
        let (ctx, _) = ctx();
        for h in ["evil.example", "evil.example:47631", "127.0.0.1", "127.0.0.1:9999", ""] {
            let r = handle(&req("GET", "/v1/identity", &[("host", h), ("origin", ORIGIN)], ""), PORT, &ctx);
            assert_eq!(r.status, 403, "{h:?}");
        }
        let ok = handle(&req("GET", "/v1/identity", &[("host", "localhost:47631"), ("origin", ORIGIN)], ""), PORT, &ctx);
        assert_eq!(ok.status, 200);
    }

    #[test]
    fn the_preflight_answers_with_private_network_access() {
        let (ctx, _) = ctx();
        let r = handle(&req("OPTIONS", "/v1/sign-login", &[("host", "127.0.0.1:47631"), ("origin", ORIGIN)], ""), PORT, &ctx);
        assert_eq!(r.status, 204);
        assert_eq!(r.header("access-control-allow-private-network"), Some("true"));
        assert_eq!(r.header("access-control-allow-methods"), Some("GET, POST, OPTIONS"));
    }

    #[test]
    fn identity_reports_the_device_and_tenant_but_no_secret() {
        let (ctx, _) = ctx();
        let r = handle(&req("GET", "/v1/identity", &good_headers(), ""), PORT, &ctx);
        assert_eq!(r.status, 200);
        let json: serde_json::Value = serde_json::from_str(&r.body).unwrap();
        assert_eq!(json["tenantId"], "11111111-1111-4111-8111-111111111111");
        assert_eq!(json["agentVersion"], "9.9.9");
        assert_eq!(json.as_object().unwrap().len(), 3);
    }

    #[test]
    fn malformed_signing_requests_are_refused_and_nothing_is_signed() {
        let (ctx, _) = ctx();
        let cases = [
            sign_body("not-a-uuid", NONCE, ORIGIN),
            sign_body(CHALLENGE, "short", ORIGIN),
            sign_body(CHALLENGE, &"a".repeat(129), ORIGIN),
            sign_body(CHALLENGE, "has a space and newline\n_1234567890", ORIGIN),
            sign_body(CHALLENGE, NONCE, "https://evil.example"),
            r#"{"challengeId":"33333333-3333-4333-8333-333333333333","nonce":"abcdefghijklmnopqrstuvwxyz0123456789_-AB","origin":"https://login.example.com","extra":"x"}"#.to_string(),
            "not json".to_string(),
            String::new(),
        ];
        for body in cases {
            let r = handle(&req("POST", "/v1/sign-login", &good_headers(), &body), PORT, &ctx);
            assert_eq!(r.status, 400, "{body}");
            assert!(!r.body.contains("signature"));
        }
    }

    #[test]
    fn signing_needs_a_json_content_type() {
        let (ctx, _) = ctx();
        let r = handle(&req("POST", "/v1/sign-login", &[("host", "127.0.0.1:47631"), ("origin", ORIGIN), ("content-type", "text/plain")], &sign_body(CHALLENGE, NONCE, ORIGIN)), PORT, &ctx);
        assert_eq!(r.status, 415);
    }

    #[test]
    fn unknown_routes_and_methods_are_not_found() {
        let (ctx, _) = ctx();
        for (m, p) in [("GET", "/"), ("GET", "/v1/sign-login"), ("POST", "/v1/identity"), ("DELETE", "/v1/identity"), ("GET", "/v2/identity"), ("POST", "/v1/sign")] {
            assert_eq!(handle(&req(m, p, &good_headers(), ""), PORT, &ctx).status, 404, "{m} {p}");
        }
    }

    // ---- over a real socket -------------------------------------------------------------------------------------

    async fn start() -> (u16, watch::Sender<bool>, VerifyingKey) {
        let (ctx, verifying) = ctx();
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = watch::channel(false);
        tokio::spawn(serve(listener, Arc::new(ctx), rx));
        (port, tx, verifying)
    }

    async fn raw(port: u16, request: &str) -> String {
        let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        s.write_all(request.as_bytes()).await.unwrap();
        let mut out = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out)).await.unwrap().unwrap();
        String::from_utf8_lossy(&out).into_owned()
    }

    #[tokio::test]
    async fn over_a_real_socket_the_right_origin_gets_a_signature_and_another_origin_does_not() {
        let (port, _tx, _) = start().await;
        let body = sign_body(CHALLENGE, NONCE, ORIGIN);
        let ok = raw(port, &format!("POST /v1/sign-login HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: {ORIGIN}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len())).await;
        assert!(ok.starts_with("HTTP/1.1 200 OK"), "{ok}");
        assert!(ok.contains("\"signature\""));
        assert!(ok.to_ascii_lowercase().contains("access-control-allow-origin: https://login.example.com"));

        let evil = raw(port, &format!("POST /v1/sign-login HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: https://evil.example\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len())).await;
        assert!(evil.starts_with("HTTP/1.1 403"), "{evil}");
        assert!(!evil.contains("signature"));
    }

    #[tokio::test]
    async fn an_oversized_body_is_refused_without_reading_it() {
        let (port, _tx, _) = start().await;
        let r = raw(port, &format!("POST /v1/sign-login HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: {ORIGIN}\r\nContent-Type: application/json\r\nContent-Length: 999999\r\n\r\n")).await;
        assert!(r.starts_with("HTTP/1.1 413"), "{r}");
    }

    #[tokio::test]
    async fn garbage_does_not_hurt_the_server_and_it_keeps_answering() {
        let (port, _tx, _) = start().await;
        let junk = raw(port, "\u{0}\u{1}not http at all\r\n\r\n").await;
        // Refused one way or another (400 malformed, or 403 because it has no Host/Origin): never served, never a crash.
        assert!(junk.starts_with("HTTP/1.1 400") || junk.starts_with("HTTP/1.1 403"), "{junk}");
        assert!(!junk.contains("signature"));
        let r = raw(port, &format!("GET /v1/identity HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: {ORIGIN}\r\n\r\n")).await;
        assert!(r.starts_with("HTTP/1.1 200 OK"), "{r}");
    }

    #[tokio::test]
    async fn shutdown_stops_the_server() {
        let (port, tx, _) = start().await;
        tx.send(true).unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(TcpStream::connect(("127.0.0.1", port)).await.is_err() || {
            // The listener is dropped when serve returns; a connect may race once, but a request gets no answer.
            let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            let _ = s.write_all(b"GET / HTTP/1.1\r\n\r\n").await;
            let mut out = Vec::new();
            let _ = tokio::time::timeout(Duration::from_millis(500), s.read_to_end(&mut out)).await;
            out.is_empty()
        });
    }
}
