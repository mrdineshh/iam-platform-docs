import { describe, expect, it } from "vitest";
import { obtainDeviceProof, parseDeviceProofField, isWellFormedProof, warmUpAgentPermission } from "./deviceProof";

const CH = "33333333-3333-4333-8333-333333333333";
const DEV = "22222222-2222-4222-8222-222222222222";
const ORIGIN = "https://login.example.com";
const goodProof = { challengeId: CH, deviceId: DEV, signature: "c2lnbmF0dXJlLWJ5dGVz", origin: ORIGIN };

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

describe("parseDeviceProofField", () => {
  it("accepts a well-formed proof and forwards only the four known fields", () => {
    expect(parseDeviceProofField(JSON.stringify({ ...goodProof, extra: "x" }))).toEqual(goodProof);
  });

  it("ignores empty, missing and non-JSON values", () => {
    expect(parseDeviceProofField("")).toBeUndefined();
    expect(parseDeviceProofField(undefined)).toBeUndefined();
    expect(parseDeviceProofField(null)).toBeUndefined();
    expect(parseDeviceProofField("not json")).toBeUndefined();
    expect(parseDeviceProofField("[]")).toBeUndefined();
  });

  it("drops anything iam-auth-svc would reject with a 400, so a bad proof can never block a sign-in", () => {
    const bad = [
      { ...goodProof, challengeId: "not-a-uuid" },
      { ...goodProof, deviceId: "x" },
      { ...goodProof, signature: "" },
      { ...goodProof, signature: "has spaces and ! symbols" },
      { ...goodProof, signature: "A".repeat(600) },
      { ...goodProof, origin: "javascript:alert(1)" },
      { ...goodProof, origin: "https://a.example/with/path" },
      { ...goodProof, origin: "https://" + "a".repeat(300) },
      { challengeId: CH },
    ];
    for (const b of bad) expect(parseDeviceProofField(JSON.stringify(b)), JSON.stringify(b)).toBeUndefined();
  });

  it("refuses an oversized field", () => {
    expect(parseDeviceProofField("{" + " ".repeat(3000) + "}")).toBeUndefined();
  });

  it("isWellFormedProof rejects non-objects", () => {
    expect(isWellFormedProof(null)).toBe(false);
    expect(isWellFormedProof("x")).toBe(false);
  });
});

describe("obtainDeviceProof", () => {
  const challenge = async () => ({ challengeId: CH, nonce: "abcdefghijklmnopqrstuvwxyz0123456789_-AB" });

  it("returns a proof when an agent answers on one of the ports", async () => {
    const calls: string[] = [];
    const fetchFn = async (url: string) => {
      calls.push(url);
      if (url === "http://127.0.0.1:47632/v1/identity") return json({ deviceId: DEV });
      if (url.endsWith("/v1/identity")) throw new Error("connection refused");
      return json({ deviceId: DEV, signature: "c2lnbmF0dXJlLWJ5dGVz" });
    };
    const proof = await obtainDeviceProof({ origin: ORIGIN, requestChallenge: challenge, fetchFn });
    expect(proof).toEqual(goodProof);
    expect(calls).toContain("http://127.0.0.1:47632/v1/sign-login");
  });

  it("returns null, without asking the server for a challenge, when no agent is there", async () => {
    let asked = false;
    const proof = await obtainDeviceProof({
      origin: ORIGIN,
      requestChallenge: async () => {
        asked = true;
        return null;
      },
      fetchFn: async () => {
        throw new Error("connection refused");
      },
    });
    expect(proof).toBeNull();
    expect(asked).toBe(false);
  });

  it("returns null when the tenant does not use device sign-in (no challenge issued)", async () => {
    const fetchFn = async () => json({ deviceId: DEV });
    expect(await obtainDeviceProof({ origin: ORIGIN, requestChallenge: async () => null, fetchFn })).toBeNull();
  });

  it("returns null when the agent refuses to sign", async () => {
    const fetchFn = async (url: string) => (url.endsWith("/v1/identity") ? json({ deviceId: DEV }) : json({}, 403));
    expect(await obtainDeviceProof({ origin: ORIGIN, requestChallenge: challenge, fetchFn })).toBeNull();
  });

  it("returns null when the agent's answer is malformed", async () => {
    const fetchFn = async (url: string) => (url.endsWith("/v1/identity") ? json({ deviceId: DEV }) : json({ deviceId: DEV, signature: "no good!" }));
    expect(await obtainDeviceProof({ origin: ORIGIN, requestChallenge: challenge, fetchFn })).toBeNull();
  });

  it("ignores something that answers on the port but is not our agent", async () => {
    const fetchFn = async () => json({ hello: "world" });
    expect(await obtainDeviceProof({ origin: ORIGIN, requestChallenge: challenge, fetchFn })).toBeNull();
  });

  it("gives up on a hung agent instead of stalling the sign-in", async () => {
    const hang = (_url: string, init?: RequestInit) =>
      new Promise<Response>((_resolve, reject) => init?.signal?.addEventListener("abort", () => reject(new Error("aborted"))));
    const started = Date.now();
    const proof = await obtainDeviceProof({ origin: ORIGIN, requestChallenge: challenge, fetchFn: hang, probeTimeoutMs: 50 });
    expect(proof).toBeNull();
    expect(Date.now() - started).toBeLessThan(1500);
  });

  it("never throws, even when the challenge request itself fails", async () => {
    const fetchFn = async () => json({ deviceId: DEV });
    const proof = await obtainDeviceProof({
      origin: ORIGIN,
      requestChallenge: async () => {
        throw new Error("server down");
      },
      fetchFn,
    });
    expect(proof).toBeNull();
  });

  it("sends the page origin and the challenge, and nothing else, to the agent", async () => {
    let body: unknown;
    const fetchFn = async (url: string, init?: RequestInit) => {
      if (url.endsWith("/v1/identity")) return json({ deviceId: DEV });
      body = JSON.parse(String(init?.body));
      return json({ deviceId: DEV, signature: "c2lnbmF0dXJlLWJ5dGVz" });
    };
    await obtainDeviceProof({ origin: ORIGIN, requestChallenge: challenge, fetchFn });
    expect(body).toEqual({ challengeId: CH, nonce: "abcdefghijklmnopqrstuvwxyz0123456789_-AB", origin: ORIGIN });
  });
});

describe("warmUpAgentPermission", () => {
  it("makes exactly one local request, to the first agent port, and resolves", async () => {
    const calls: string[] = [];
    await warmUpAgentPermission({
      fetchFn: async (url) => {
        calls.push(url);
        return json({});
      },
    });
    expect(calls).toEqual(["http://127.0.0.1:47631/v1/identity"]);
  });

  it("never rejects, whatever happens", async () => {
    await expect(
      warmUpAgentPermission({
        fetchFn: async () => {
          throw new Error("refused");
        },
      }),
    ).resolves.toBeUndefined();
  });

  it("gives up on an unanswered prompt after its time limit instead of hanging", async () => {
    const hang = (_url: string, init?: RequestInit) =>
      new Promise<Response>((_r, reject) => init?.signal?.addEventListener("abort", () => reject(new Error("aborted"))));
    const started = Date.now();
    await warmUpAgentPermission({ fetchFn: hang, timeoutMs: 60 });
    expect(Date.now() - started).toBeLessThan(1500);
  });
});

describe("obtainDeviceProof while the permission prompt is still open", () => {
  const challenge = async () => ({ challengeId: CH, nonce: "abcdefghijklmnopqrstuvwxyz0123456789_-AB" });
  const agent = async (url: string) => (url.endsWith("/v1/identity") ? json({ deviceId: DEV }) : json({ deviceId: DEV, signature: "c2lnbmF0dXJlLWJ5dGVz" }));

  it("waits for the warm-up to finish, then succeeds", async () => {
    let release!: () => void;
    const waitFor = new Promise<void>((resolve) => {
      release = resolve;
    });
    let probed = false;
    const fetchFn = async (url: string) => {
      probed = true;
      return agent(url);
    };
    const pending = obtainDeviceProof({ origin: ORIGIN, requestChallenge: challenge, fetchFn, waitFor });
    await new Promise((r) => setTimeout(r, 30));
    expect(probed, "must not probe before the prompt was answered").toBe(false);
    release();
    expect(await pending).toEqual(goodProof);
  });

  it("does not wait forever if the prompt is never answered", async () => {
    const waitFor = new Promise<void>(() => {});
    const started = Date.now();
    const proof = await obtainDeviceProof({
      origin: ORIGIN,
      requestChallenge: challenge,
      fetchFn: async () => {
        throw new Error("blocked");
      },
      waitFor,
      waitForMs: 80,
    });
    expect(proof).toBeNull();
    expect(Date.now() - started).toBeLessThan(1500);
  });
});
