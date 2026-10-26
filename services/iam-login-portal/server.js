// Custom server, not `next start`, for one reason only: this is the actual
// front door for the OIDC login flow now (BUILD_PLAN.md diagram, Service
// 13 -- see docs/specs/iam-login-portal-SPEC.md Section 0), and the real
// client IP has to be read off the raw TCP socket, the same fix
// iam-oidcprovider-svc made in Service 11 and which moves here now that
// oidcprovider-svc no longer receives the literal browser form submission.
// Next's App Router has no supported way to reach `req.socket.remoteAddress`
// from inside a Server Action/Route Handler on a self-hosted Node server, so
// this wraps the request before handing it to Next and injects the real
// address under an internal header name -- overwriting (not trusting) any
// client-supplied value under that same name, so it can't be spoofed.
const { createServer } = require("node:http");
const next = require("next");

const port = Number(process.env.PORT || 3000);
const dev = process.env.NODE_ENV !== "production";

const app = next({ dev });
const handle = app.getRequestHandler();

const REAL_IP_HEADER = "x-iam-internal-real-ip";

// Bug found live (docs/DECISIONS.md, Service 13 entry): Node's dual-stack
// socket reports an IPv4 client as "::ffff:x.x.x.x", not plain "x.x.x.x" --
// unlike the Java servlet API iam-oidcprovider-svc used to rely on for the
// same real-IP fix in Service 11, which normalizes this automatically. Left
// un-normalized, iam-geo-svc's IPv4-only contract correctly rejects it with
// a 400 (not a bug there -- see contracts/iam-geo-svc.yaml), which iam-auth-
// svc's soft-fail wrapper doesn't treat as "unresolved" (only unreachability
// is caught there), so the whole login 500'd. Fixed at the source: this is
// where the real bug is, not in either already-published, already-tested
// service.
function normalizeIp(address) {
  const prefix = "::ffff:";
  return address.startsWith(prefix) ? address.slice(prefix.length) : address;
}

// Second bug found live: in the real deployment this process never sees the
// browser's TCP connection directly -- Caddy (host-level reverse proxy,
// infra/ outside docker-compose) terminates TLS and connects to this
// container over the Docker bridge network, so req.socket.remoteAddress is
// always Caddy's own bridge-gateway address (e.g. 172.18.0.1), not the
// visitor's. Caddy's reverse_proxy directive always sets X-Forwarded-For
// itself to the address it actually saw the connection from (appending to,
// not trusting, anything already in that header), so that's the value to
// use whenever present -- the raw socket address remains the fallback for
// a genuinely direct connection (local dev with no Caddy in front).
const TRUSTED_PROXY_COUNT = 1;

function extractRealIp(req) {
  const forwardedFor = req.headers["x-forwarded-for"];
  if (forwardedFor) {
    const hops = String(forwardedFor).split(",").map((ip) => ip.trim());
    // The last TRUSTED_PROXY_COUNT hop(s) were appended by proxies we
    // control; anything earlier in the list is client-supplied and
    // unverifiable. With exactly one trusted proxy (Caddy) in front, that's
    // simply the last entry.
    const trusted = hops[hops.length - TRUSTED_PROXY_COUNT];
    if (trusted) return normalizeIp(trusted);
  }
  return normalizeIp(req.socket.remoteAddress || "");
}

app.prepare().then(() => {
  createServer((req, res) => {
    // Assignment, not append -- always replaces whatever the client sent.
    req.headers[REAL_IP_HEADER] = extractRealIp(req);
    handle(req, res);
  }).listen(port, () => {
    console.log(`iam-login-portal listening on port ${port}`);
  });
});
