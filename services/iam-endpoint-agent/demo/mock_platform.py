#!/usr/bin/env python3
"""LOCAL DEMO STAND-IN for the IAM platform's endpoint API. Not the real platform, and not for production.

It lets the real iam-endpoint-agent.exe run its whole lifecycle on one machine with nothing else deployed:
sign-in handoff, enrollment, approval, signed policy, heartbeat and posture reporting, and shows what it received
in a browser dashboard. It re-implements, independently of the Kotlin backend, the wire protocol and the signed
policy format (`iam-device-policy-v1`), so a successful run is also a cross-check of the agent against the spec.

Safety: listens on 127.0.0.1 only; keeps everything in memory; the demo "transit" key is generated fresh each run.
Needs the `cryptography` package.   Usage:   python mock_platform.py --out <folder for the generated config.json>
"""

import argparse
import base64
import hashlib
import html
import json
import os
import re
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

TENANT_ID = "11111111-1111-1111-1111-111111111111"
TRANSIT_KEY = Ed25519PrivateKey.generate()
TRANSIT_PUBLIC_B64 = base64.b64encode(
    TRANSIT_KEY.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
).decode()

# ---- agent updates (P1-26). An independent implementation of the OPERATOR side: its own signing key and its own statement
# builder, so a mistake in the agent's verifier cannot be hidden by sharing code with it.
RELEASE_KEY = Ed25519PrivateKey.generate()
RELEASE_PUBLIC_B64 = base64.b64encode(
    RELEASE_KEY.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
).decode()
OTHER_KEY = Ed25519PrivateKey.generate()          # what an attacker who does not hold the real key would sign with
UPDATE_SCENARIO = "none"                          # none | forged | older | tampered | good | file
UPDATE_FILE = None                                # for "file": (path, version) of a REAL installer signed with RELEASE_KEY
UPDATE_BYTES = b"this is not a real installer, it only proves the download and verification path " * 64
RELEASE_ID = str(uuid.uuid4())


def verify_device_signature(public_key, signature_b64, data):
    """Device signatures: Ed25519 (software key) or ECDSA P-256 over SHA-256 as the raw 64-byte r||s pair that Windows CNG
    (the TPM) produces. Raises InvalidSignature / ValueError on anything else -- the same acceptance rules as the real backend."""
    signature = base64.b64decode(signature_b64)
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        if public_key.curve.name != "secp256r1":
            raise ValueError("only P-256 is accepted")
        if len(signature) == 64:
            signature = encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
    else:
        public_key.verify(signature, data)


def release_statement(version, sha256_hex):
    return "\n".join(["iam-agent-release-v1", "WINDOWS", "x86_64", version, sha256_hex])


def update_offer():
    """The offer for the configured scenario, or None (HTTP 204)."""
    if UPDATE_SCENARIO == "none":
        return None
    version = "0.0.1" if UPDATE_SCENARIO == "older" else "9.9.9"
    payload = UPDATE_BYTES
    if UPDATE_SCENARIO == "file":
        path, version = UPDATE_FILE
        payload = open(path, "rb").read()
    sha = hashlib.sha256(payload).hexdigest()
    key = OTHER_KEY if UPDATE_SCENARIO == "forged" else RELEASE_KEY
    signature = "vault:v1:" + base64.b64encode(key.sign(release_statement(version, sha).encode())).decode()
    return {"releaseId": RELEASE_ID, "version": version, "platform": "WINDOWS", "architecture": "x86_64",
            "sha256": sha, "signature": signature, "sizeBytes": len(payload)}


def update_package():
    """What the download returns: for 'tampered' the signed hash no longer matches the bytes."""
    if UPDATE_SCENARIO == "tampered":
        return UPDATE_BYTES[:-1] + b"X"
    if UPDATE_SCENARIO == "file":
        return open(UPDATE_FILE[0], "rb").read()
    return UPDATE_BYTES


LOCK = threading.Lock()
DEVICES = {}        # id -> dict
TRANSACTIONS = {}   # id -> dict
LOG = []            # most recent first
HEARTBEAT_SECONDS, POSTURE_SECONDS = 30, 60  # the agent's own minimums, so the demo shows activity quickly


def log(line):
    entry = f"{datetime.now().strftime('%H:%M:%S')}  {line}"
    print(entry, flush=True)
    with LOCK:
        LOG.insert(0, entry)
        del LOG[60:]


def b64url_nopad(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def iso(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def evaluate(signals):
    """The server's judgement of the agent's facts (mirrors PostureEvaluator in iam-tenant-svc)."""
    required = [
        ("Disk encryption (BitLocker)", signals.get("diskEncryption")),
        ("Antivirus real-time protection", signals.get("antivirus")),
        ("Firewall", signals.get("firewall")),
    ]
    disabled = unknown = 0
    reasons = []
    for name, value in required:
        v = (value or "").strip().upper()
        if v == "ENABLED":
            continue
        if v == "DISABLED":
            disabled += 1
            reasons.append(f"{name} is off")
        else:
            unknown += 1
            reasons.append(f"{name} could not be determined")
    status = "NON_COMPLIANT" if disabled else "UNKNOWN" if unknown else "COMPLIANT"
    return status, min(100, disabled * 40 + unknown * 10), reasons


def canonical_policy(tenant, device, policy_id, version, issued, expires, status, hb, posture, mode, apps):
    # Byte-for-byte the format of DevicePolicyCanonical.kt / policy_verifier.rs (apps empty here).
    return "|".join(["iam-device-policy-v1", tenant, device, policy_id, str(version), str(issued), str(expires), status, str(hb), str(posture), mode, ""])


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # we log meaningful events ourselves
        pass

    # ---- helpers
    def send(self, code, body=b"", ctype="application/json", headers=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        length = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(length) or b"{}")

    def device_from_proof(self, device_id):
        """The same device-authentication scheme as the real backend: a signature over 'deviceId:timestamp'."""
        device = DEVICES.get(device_id)
        timestamp = self.headers.get("X-Device-Timestamp", "")
        signature = self.headers.get("X-Device-Signature", "")
        if not device:
            return None, (404, {"message": "unknown device"})
        try:
            age = abs(time.time() - datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())
            verify_device_signature(device["public_key"], signature, f"{device_id}:{timestamp}".encode())
        except (ValueError, InvalidSignature):
            return None, (401, {"message": "device signature did not verify"})
        if age > 120:
            return None, (401, {"message": "timestamp outside the freshness window"})
        device["last_seen"] = time.time()
        return device, None

    # ---- GET
    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/":
            return self.send(200, dashboard(), "text/html; charset=utf-8")
        if url.path == "/api/state":
            return self.send(200, state())
        if url.path == "/device-enroll":
            return self.device_enroll(parse_qs(url.query))
        m = re.fullmatch(r"/api/v1/endpoint/devices/([0-9a-f-]{36})/policy", url.path)
        if m:
            return self.policy(m.group(1))
        m = re.fullmatch(r"/api/v1/endpoint/devices/([0-9a-f-]{36})/agent-update", url.path)
        if m:
            return self.agent_update(m.group(1), parse_qs(url.query))
        m = re.fullmatch(r"/api/v1/endpoint/devices/([0-9a-f-]{36})/agent-releases/([0-9a-f-]{36})/package", url.path)
        if m:
            return self.agent_package(m.group(1))
        self.send(404, {"message": "not found"})

    def agent_update(self, device_id, query):
        device, error = self.device_from_proof(device_id)
        if error:
            return self.send(*error)
        current = (query.get("currentVersion") or [""])[0]
        offer = update_offer()
        log(f"device {device_id[:8]}... asked for updates (running {current}); scenario '{UPDATE_SCENARIO}' -> "
            + ("nothing newer" if offer is None else f"offering {offer['version']}"))
        if offer is None:
            return self.send(204)
        self.send(200, offer)

    def agent_package(self, device_id):
        device, error = self.device_from_proof(device_id)
        if error:
            return self.send(*error)
        log(f"device {device_id[:8]}... downloaded the update package")
        self.send(200, update_package(), "application/octet-stream")

    def device_enroll(self, q):
        """Stands in for iam-login-portal's /device-enroll: same validation, then 'signs in' a demo user."""
        redirect = (q.get("redirect_uri") or [""])[0]
        thumb = (q.get("key_thumbprint") or [""])[0]
        agent_state = (q.get("state") or [""])[0]
        r = urlparse(redirect)
        ok = (
            r.scheme == "http" and r.hostname in ("127.0.0.1", "::1") and r.port and r.path == "/callback"
            and not r.query and not r.fragment and not r.username
            and re.fullmatch(r"[A-Za-z0-9_-]{43}", thumb) and re.fullmatch(r"[A-Za-z0-9_-]{16,128}", agent_state)
        )
        if not ok:
            log("GET  /device-enroll      -> 400 (rejected: not a valid loopback redirect / key thumbprint / state)")
            return self.send(400, page("Invalid request", "<p>This device registration link is invalid.</p>"), "text/html; charset=utf-8")
        tx_id, nonce = str(uuid.uuid4()), base64.b64encode(os.urandom(32)).decode()
        with LOCK:
            TRANSACTIONS[tx_id] = {"nonce": nonce, "thumbprint": thumb, "created": time.time(), "used": False}
        target = f"{redirect}?enrollment_transaction_id={tx_id}&nonce={nonce.replace('+', '%2B').replace('/', '%2F').replace('=', '%3D')}&state={agent_state}"
        log("GET  /device-enroll      -> signed in 'demo.user@example.com', handing a one-time enrollment back to the agent")
        body = page(
            "Signed in",
            f'<p>Signed in as <b>demo.user@example.com</b> (demo platform).</p><p>Registering this device...</p>'
            f'<p><a href="{html.escape(target)}">Continue</a> if this page does not move on by itself.</p>',
            refresh=(1, target),
        )
        self.send(200, body, "text/html; charset=utf-8", {"Referrer-Policy": "no-referrer"})

    def policy(self, device_id):
        device, error = self.device_from_proof(device_id)
        if error:
            log(f"GET  .../policy          -> {error[0]} {error[1]['message']}")
            return self.send(*error)
        now = int(time.time())
        issued, expires = now, now + HEARTBEAT_SECONDS * 3
        canonical = canonical_policy(TENANT_ID, device_id, device_id, 0, issued, expires, device["status"], HEARTBEAT_SECONDS, POSTURE_SECONDS, "RISK_BASED", None)
        signature = "vault:v1:" + base64.b64encode(TRANSIT_KEY.sign(canonical.encode())).decode()
        log(f"GET  .../policy          -> 200 signed policy (device is {device['status']}), valid for {expires - issued}s")
        self.send(200, {
            "tenantId": TENANT_ID, "deviceId": device_id, "policyId": device_id, "policyVersion": 0,
            "issuedAt": iso(issued), "expiresAt": iso(expires), "deviceStatus": device["status"],
            "heartbeatIntervalSeconds": HEARTBEAT_SECONDS, "postureIntervalSeconds": POSTURE_SECONDS,
            "agentFailureMode": "RISK_BASED", "applications": [], "signature": signature,
        })

    # ---- POST / PATCH
    def do_POST(self):
        url = urlparse(self.path)
        if url.path == "/api/v1/endpoint/enrollment/complete":
            return self.enrollment_complete()
        m = re.fullmatch(r"/api/v1/endpoint/devices/([0-9a-f-]{36})/(heartbeat|events)", url.path)
        if m:
            return self.device_report(m.group(1), m.group(2))
        if url.path == "/update-scenario":
            global UPDATE_SCENARIO
            name = (parse_qs(url.query).get("name") or [""])[0]
            if name in ("none", "forged", "older", "tampered", "good"):
                UPDATE_SCENARIO = name
                log(f"ADMIN set the update scenario to '{name}'")
            return self.send(303, b"", "text/plain", {"Location": "/"})
        if url.path == "/approve":
            device_id = (parse_qs(url.query).get("id") or [""])[0]
            with LOCK:
                if device_id in DEVICES and DEVICES[device_id]["status"] == "PENDING_APPROVAL":
                    DEVICES[device_id]["status"] = "APPROVED"
            log(f"ADMIN approved device {device_id[:8]}... -> its next policy will say APPROVED")
            return self.send(303, b"", "text/plain", {"Location": "/"})
        self.send(404, {"message": "not found"})

    def do_PATCH(self):
        m = re.fullmatch(r"/api/v1/endpoint/devices/([0-9a-f-]{36})/posture", urlparse(self.path).path)
        if m:
            return self.device_report(m.group(1), "posture")
        self.send(404, {"message": "not found"})

    def enrollment_complete(self):
        body = self.read_json()
        tx = TRANSACTIONS.get(body.get("enrollmentTransactionId", ""))
        if not tx or tx["used"] or time.time() - tx["created"] > 300:
            log("POST .../enrollment/complete -> 401 (unknown, used or expired enrollment)")
            return self.send(401, {"message": "Enrollment transaction invalid"})
        tx["used"] = True  # burned on first use, success or not
        try:
            der = base64.b64decode(body["publicKey"])
            if b64url_nopad(hashlib.sha256(der).digest()) != tx["thumbprint"]:
                raise ValueError("Public key does not match the key this enrollment was started for")
            public_key = serialization.load_der_public_key(der)
            verify_device_signature(public_key, body["proofOfPossession"], tx["nonce"].encode())
        except (ValueError, KeyError, InvalidSignature) as e:
            log(f"POST .../enrollment/complete -> 401 ({e})")
            return self.send(401, {"message": "Proof of possession failed"})
        device_id = str(uuid.uuid4())
        status = "PENDING_APPROVAL" if body.get("ownership") == "BYOD" else "APPROVED"
        with LOCK:
            DEVICES[device_id] = {
                "id": device_id, "public_key": public_key, "status": status, "ownership": body.get("ownership"),
                "hostname": body.get("hostname"), "model": f"{body.get('manufacturer') or ''} {body.get('model') or ''}".strip(),
                "os": body.get("osVersion"), "agent_version": body.get("agentVersion"), "assurance": body.get("assuranceLevel"),
                "enrolled": time.time(), "last_seen": None, "health": None, "policy_version": None, "posture": None, "events": [],
            }
        log(f"POST .../enrollment/complete -> 201 device {device_id[:8]}... {status} (key proved, key-bound to the sign-in)")
        self.send(201, {"deviceId": device_id, "status": status, "approvalType": "MANUAL" if status != "APPROVED" else "AUTOMATIC",
                        "certificateStatus": "NOT_ISSUED", "certificatePem": None, "issuingCaPem": None, "policyVersion": 0,
                        "message": "Device registration submitted" if status != "APPROVED" else "Device approved"})

    def device_report(self, device_id, kind):
        device, error = self.device_from_proof(device_id)
        if error:
            log(f"{kind:9} -> {error[0]} {error[1]['message']}")
            return self.send(*error)
        body = self.read_json()
        if kind == "heartbeat":
            device.update(health=body.get("healthStatus"), policy_version=body.get("policyVersion"), agent_version=body.get("agentVersion"))
            log(f"POST .../heartbeat       -> 204 health={body.get('healthStatus')} policyVersion={body.get('policyVersion')}")
        elif kind == "posture":
            signals = body.get("signals") or {}
            verdict = evaluate(signals)
            device["posture"] = {"signals": signals, "verdict": verdict[0], "risk": verdict[1], "reasons": verdict[2], "at": time.time()}
            log(f"PATCH .../posture        -> 204 server verdict: {verdict[0]} (risk {verdict[1]}/100)")
        else:
            device["events"].insert(0, {"type": body.get("eventType"), "severity": body.get("severity"), "meta": body.get("metadataJson"), "at": time.time()})
            log(f"POST .../events          -> 204 {body.get('severity')} {body.get('eventType')}")
        self.send(204)


def state():
    with LOCK:
        devices = []
        for d in DEVICES.values():
            devices.append({k: v for k, v in d.items() if k != "public_key"})
        return {"devices": devices, "log": list(LOG)}


def page(title, body, refresh=None):
    meta = f'<meta http-equiv="refresh" content="{refresh[0]};url={html.escape(refresh[1])}">' if refresh else ""
    return (f"<!doctype html><meta charset=utf-8>{meta}<title>{html.escape(title)}</title>"
            "<body style='font-family:Segoe UI,sans-serif;background:#0b1220;color:#e8eef6;max-width:560px;margin:80px auto'>"
            f"<h2>{html.escape(title)}</h2>{body}<p style='color:#93a3b8'>LOCAL DEMO PLATFORM</p></body>")


def tri(value):
    v = (value or "").upper()
    cls, text = ("on", "On") if v == "ENABLED" else ("off", "Off") if v == "DISABLED" else ("unk", "Unknown")
    return f"<span class='b {cls}'>{text}</span>"


def ago(t):
    return "never" if not t else f"{int(time.time() - t)}s ago"


def dashboard():
    e = html.escape
    cards = []
    with LOCK:
        for d in DEVICES.values():
            p = d["posture"]
            rows = ""
            if p:
                s = p["signals"]
                rows = (
                    f"<table><tr><td>Disk encryption (BitLocker) <small>required</small></td><td>{tri(s.get('diskEncryption'))}</td></tr>"
                    f"<tr><td>Antivirus real-time protection <small>required</small></td><td>{tri(s.get('antivirus'))} <small>{e(str(s.get('antivirusProduct') or ''))}</small></td></tr>"
                    f"<tr><td>Firewall <small>required</small></td><td>{tri(s.get('firewall'))}</td></tr>"
                    f"<tr><td>TPM present</td><td>{tri(s.get('tpmPresent'))}</td></tr><tr><td>Secure Boot</td><td>{tri(s.get('secureBoot'))}</td></tr>"
                    f"<tr><td>Operating system</td><td>{e(str(s.get('osName') or ''))} {e(str(s.get('osVersion') or ''))}</td></tr>"
                    f"<tr><td>Most recent update</td><td>{e(str(s.get('lastHotfixDate') or 'Unknown'))}</td></tr></table>"
                    f"<p>Server verdict: <b>{e(p['verdict'])}</b> &middot; risk {p['risk']}/100 &middot; checked {ago(p['at'])}</p>"
                    + ("<ul>" + "".join(f"<li>{e(r)}</li>" for r in p["reasons"]) + "</ul>" if p["reasons"] else ""))
            else:
                rows = "<p><i>No posture report yet (the agent sends one about a minute after it starts).</i></p>"
            approve = (f"<form method=post action='/approve?id={e(d['id'])}'><button>Approve this device</button></form>"
                       if d["status"] == "PENDING_APPROVAL" else "")
            cards.append(
                f"<div class=card><h3>{e(d['hostname'] or 'unnamed')} <span class='b st'>{e(d['status'])}</span></h3>"
                f"<p>{e(d['model'])} &middot; {e(d['ownership'] or '')} &middot; key assurance: <b>{e(d['assurance'] or '')}</b> &middot; agent {e(d['agent_version'] or '')}</p>"
                f"<p>Last heartbeat {ago(d['last_seen'])} &middot; health <b>{e(str(d['health']))}</b></p>{approve}{rows}"
                + ("<h4>Events from the agent</h4><ul>" + "".join(f"<li>{e(str(x['severity']))} {e(str(x['type']))} {e(str(x['meta'] or ''))}</li>" for x in d["events"][:5]) + "</ul>" if d["events"] else "")
                + "</div>")
        logs = "".join(f"<div>{e(x)}</div>" for x in LOG[:25])
    return (
        "<!doctype html><meta charset=utf-8><meta http-equiv=refresh content=3><title>Demo platform</title><style>"
        "body{font-family:Segoe UI,sans-serif;background:#0b1220;color:#e8eef6;margin:0;padding:24px 32px}"
        ".banner{background:#7c2d12;padding:8px 14px;border-radius:6px;margin-bottom:18px}"
        ".card{background:#111c30;border:1px solid #243452;border-radius:10px;padding:16px 20px;margin-bottom:18px}"
        "table{border-collapse:collapse}td{padding:5px 22px 5px 0}small{color:#93a3b8}"
        ".b{padding:2px 9px;border-radius:10px;font-size:.85em}.on{background:#14532d}.off{background:#7f1d1d}.unk{background:#374151}.st{background:#1e3a8a}"
        "button{background:#0f766e;color:#fff;border:0;padding:7px 14px;border-radius:6px;cursor:pointer}"
        ".log{font-family:Consolas,monospace;font-size:.85em;color:#93a3b8;margin-top:24px}</style>"
        "<div class=banner><b>LOCAL DEMO PLATFORM</b> &mdash; a stand-in on this machine, not the real IAM platform. "
        "It shows what the real agent sends. Refreshes every 3 s.</div>"
        "<h2>Endpoint Security (demo)</h2>"
        + ("".join(cards) or "<p><i>No devices yet. Run the agent with --enroll.</i></p>")
        + f"<div class=log><b>What the agent just did</b>{logs}</div>"
    )


class QuietServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        # A client that disconnects mid-request (e.g. the agent being stopped) is normal, not worth a traceback.
        import sys
        if not isinstance(sys.exc_info()[1], (ConnectionResetError, BrokenPipeError, ConnectionAbortedError)):
            super().handle_error(request, client_address)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True, help="folder to write the generated demo config.json into")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--update-scenario", default="none", choices=["none", "forged", "older", "tampered", "good", "file"])
    parser.add_argument("--update-file", help="a REAL installer to offer as the update (scenario 'file')")
    parser.add_argument("--update-version", help="its version, signed into the release statement")
    parser.add_argument("--release-key-out", help="write the throwaway release PUBLIC key here (never reuse it for real)")
    args = parser.parse_args()
    global UPDATE_SCENARIO, UPDATE_FILE
    UPDATE_SCENARIO = args.update_scenario
    if args.update_file:
        UPDATE_FILE = (args.update_file, args.update_version)
    if args.release_key_out:
        open(args.release_key_out, "w").write(RELEASE_PUBLIC_B64)
    os.makedirs(args.out, exist_ok=True)
    base = f"http://127.0.0.1:{args.port}"
    config = {
        "backend_base_url": base, "enrollment_login_url": f"{base}/device-enroll", "tenant_id": TENANT_ID,
        "device_policy_public_key_base64": TRANSIT_PUBLIC_B64, "heartbeat_interval_seconds": HEARTBEAT_SECONDS,
        "release_public_key_base64": RELEASE_PUBLIC_B64,
    }
    with open(os.path.join(args.out, "config.json"), "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)
    server = QuietServer(("127.0.0.1", args.port), Handler)
    print(f"LOCAL DEMO PLATFORM listening on {base}  (config written to {args.out})", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
