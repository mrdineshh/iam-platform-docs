// Device-bound sign-in (docs/specs/device-bound-signin-SPEC.md): shared, dependency-free pieces used by both the browser
// (talking to the endpoint agent on the user's own laptop) and the server (forwarding the result to iam-auth-svc).
//
// The one rule that shapes all of it: a device proof can only ADD a device to a sign-in. Nothing here is allowed to make
// signing in fail, so every function either returns a usable value or "nothing", and never throws.

export interface DeviceProof {
  challengeId: string;
  deviceId: string;
  signature: string;
  origin: string;
}

export interface DeviceChallenge {
  challengeId: string;
  nonce: string;
}

/** Where the agent listens on 127.0.0.1 (the agent tries these in order and takes the first free one). */
export const AGENT_PORTS = [47631, 47632, 47633, 47634, 47635];

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const BASE64 = /^[A-Za-z0-9+/_-]+={0,2}$/;

export function isUuid(value: unknown): value is string {
  return typeof value === "string" && UUID.test(value);
}

/**
 * Strict shape check. iam-auth-svc rejects a structurally broken proof with HTTP 400, which would block the sign-in, so
 * anything that is not exactly well-formed is dropped here instead of being sent.
 */
export function isWellFormedProof(value: unknown): value is DeviceProof {
  if (typeof value !== "object" || value === null) return false;
  const p = value as Record<string, unknown>;
  return (
    isUuid(p.challengeId) &&
    isUuid(p.deviceId) &&
    typeof p.signature === "string" &&
    p.signature.length >= 8 &&
    p.signature.length <= 512 &&
    BASE64.test(p.signature) &&
    typeof p.origin === "string" &&
    p.origin.length <= 200 &&
    /^https?:\/\/[^\s/]+$/.test(p.origin)
  );
}

/** The hidden form field's value -> a proof, or undefined (empty, not JSON, or malformed). */
export function parseDeviceProofField(raw: string | null | undefined): DeviceProof | undefined {
  if (!raw || raw.length > 2048) return undefined;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!isWellFormedProof(parsed)) return undefined;
    // Only the four known fields are forwarded, whatever else the browser sent.
    const { challengeId, deviceId, signature, origin } = parsed;
    return { challengeId, deviceId, signature, origin };
  } catch {
    return undefined;
  }
}

type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export interface ObtainProofDeps {
  /** `window.location.origin`: what the agent will insist the request came from. */
  origin: string;
  /** Asks the portal's server for a one-time challenge (null when the tenant does not use device sign-in). */
  requestChallenge: () => Promise<DeviceChallenge | null>;
  fetchFn?: FetchLike;
  ports?: number[];
  probeTimeoutMs?: number;
  signTimeoutMs?: number;
  /** A warm-up (see warmUpAgentPermission) still waiting for the person to answer the browser's permission prompt. */
  waitFor?: Promise<void>;
  waitForMs?: number;
}

async function fetchWithTimeout(fetchFn: FetchLike, url: string, init: RequestInit, timeoutMs: number): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetchFn(url, { ...init, signal: controller.signal, cache: "no-store", credentials: "omit", mode: "cors" });
  } finally {
    clearTimeout(timer);
  }
}

/** The first agent port that answers /v1/identity like our agent, or null. All ports are tried at once. */
async function findAgentPort(fetchFn: FetchLike, ports: number[], timeoutMs: number): Promise<number | null> {
  return new Promise((resolve) => {
    let pending = ports.length;
    let done = false;
    const finish = (port: number | null) => {
      if (!done) {
        done = true;
        resolve(port);
      }
    };
    if (pending === 0) finish(null);
    for (const port of ports) {
      (async () => {
        try {
          const res = await fetchWithTimeout(fetchFn, `http://127.0.0.1:${port}/v1/identity`, { method: "GET" }, timeoutMs);
          if (res.ok) {
            const body = (await res.json()) as { deviceId?: unknown };
            if (isUuid(body.deviceId)) return finish(port);
          }
        } catch {
          // closed port, refused by the browser, timed out: just "not here"
        }
        pending -= 1;
        if (pending === 0) finish(null);
      })();
    }
  });
}

/**
 * Asks the endpoint agent on this laptop to sign a platform-issued challenge. Resolves to a proof or null; NEVER rejects.
 * No agent, a browser that blocks calls to the local machine, a slow answer, an agent that refuses: all give null and the
 * sign-in simply carries on without a device.
 */
export async function obtainDeviceProof(deps: ObtainProofDeps): Promise<DeviceProof | null> {
  const fetchFn: FetchLike = deps.fetchFn ?? ((input, init) => fetch(input, init));
  try {
    if (deps.waitFor) {
      // The browser's one-time "access other apps and services on this device" prompt is probably still on screen:
      // give the person a little time to answer it rather than skipping the check they are about to approve.
      await Promise.race([deps.waitFor, new Promise<void>((resolve) => setTimeout(resolve, deps.waitForMs ?? 15000))]);
    }
    const port = await findAgentPort(fetchFn, deps.ports ?? AGENT_PORTS, deps.probeTimeoutMs ?? 800);
    if (port === null) return null;

    const challenge = await deps.requestChallenge();
    if (!challenge || !isUuid(challenge.challengeId) || typeof challenge.nonce !== "string") return null;

    const res = await fetchWithTimeout(
      fetchFn,
      `http://127.0.0.1:${port}/v1/sign-login`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ challengeId: challenge.challengeId, nonce: challenge.nonce, origin: deps.origin }),
      },
      deps.signTimeoutMs ?? 2000,
    );
    if (!res.ok) return null;
    const body = (await res.json()) as { deviceId?: unknown; signature?: unknown };
    const proof = { challengeId: challenge.challengeId, deviceId: body.deviceId, signature: body.signature, origin: deps.origin };
    return isWellFormedProof(proof) ? proof : null;
  } catch {
    return null;
  }
}

/**
 * Touches the agent once when the sign-in page loads, for one reason only: Chrome and Edge ask the person to allow a
 * website to reach "other apps and services on this device" the first time it does so, and that prompt must appear while
 * they are still typing their password, not at the moment they press Sign in (where nobody can answer it in time).
 * The answer is remembered by the browser. Never rejects and never has any other effect.
 */
export async function warmUpAgentPermission(deps: { fetchFn?: FetchLike; port?: number; timeoutMs?: number } = {}): Promise<void> {
  const fetchFn: FetchLike = deps.fetchFn ?? ((input, init) => fetch(input, init));
  try {
    await fetchWithTimeout(fetchFn, `http://127.0.0.1:${deps.port ?? AGENT_PORTS[0]}/v1/identity`, { method: "GET" }, deps.timeoutMs ?? 30000);
  } catch {
    // no agent, refused, blocked, or still unanswered after the time limit: all fine, this is only a prompt trigger
  }
}
