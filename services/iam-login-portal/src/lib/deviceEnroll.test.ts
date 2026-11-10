import { describe, expect, it } from "vitest";
import { isValidKeyThumbprint, isValidState, loopbackCallbackUrl, parseLoopbackRedirectUri, safePostLoginNext } from "./deviceEnroll";

describe("parseLoopbackRedirectUri", () => {
  it("accepts IPv4 and IPv6 loopback literals with an explicit port and the /callback path", () => {
    expect(parseLoopbackRedirectUri("http://127.0.0.1:53124/callback")?.port).toBe("53124");
    expect(parseLoopbackRedirectUri("http://[::1]:53124/callback")?.port).toBe("53124");
  });

  it.each([
    ["https is not loopback-redirect form", "https://127.0.0.1:5000/callback"],
    ["localhost can resolve off-box (RFC 8252 8.3)", "http://localhost:5000/callback"],
    ["any non-loopback host", "http://evil.example.com:5000/callback"],
    ["a loopback-looking subdomain", "http://127.0.0.1.evil.example.com:5000/callback"],
    ["a non-127.0.0.1 address", "http://10.0.0.1:5000/callback"],
    ["no explicit port", "http://127.0.0.1/callback"],
    ["a different path", "http://127.0.0.1:5000/steal"],
    ["a pre-filled query string", "http://127.0.0.1:5000/callback?x=1"],
    ["a fragment", "http://127.0.0.1:5000/callback#x"],
    ["userinfo", "http://user:pw@127.0.0.1:5000/callback"],
    ["not a URL", "not a url"],
    ["empty", ""],
  ])("rejects %s", (_reason, uri) => {
    expect(parseLoopbackRedirectUri(uri)).toBeNull();
  });

  it("rejects null and absurdly long values", () => {
    expect(parseLoopbackRedirectUri(null)).toBeNull();
    expect(parseLoopbackRedirectUri(`http://127.0.0.1:5000/callback${"a".repeat(300)}`)).toBeNull();
  });
});

describe("isValidKeyThumbprint", () => {
  it("accepts a 43-character base64url SHA-256", () => {
    expect(isValidKeyThumbprint("ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0")).toBe(true);
  });

  it("rejects padding, standard-base64 characters, and wrong lengths", () => {
    expect(isValidKeyThumbprint("ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0")).toBe(false);
    expect(isValidKeyThumbprint("ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0=")).toBe(false);
    expect(isValidKeyThumbprint("short")).toBe(false);
    expect(isValidKeyThumbprint(null)).toBe(false);
  });
});

describe("isValidState", () => {
  it("accepts 16-128 url-safe characters only", () => {
    expect(isValidState("a".repeat(16))).toBe(true);
    expect(isValidState("a".repeat(15))).toBe(false);
    expect(isValidState("a".repeat(129))).toBe(false);
    expect(isValidState("abc<script>defghijk")).toBe(false);
    expect(isValidState(null)).toBe(false);
  });
});

describe("safePostLoginNext", () => {
  it("allows only same-origin /device-enroll URLs", () => {
    expect(safePostLoginNext("/device-enroll?redirect_uri=x")).toBe("/device-enroll?redirect_uri=x");
  });

  it.each(["https://evil.example.com/device-enroll?x", "//evil.example.com/device-enroll?x", "/apps", "/device-enroll\\evil", undefined])(
    "ignores %s",
    (value) => {
      expect(safePostLoginNext(value)).toBeNull();
    },
  );
});

describe("loopbackCallbackUrl", () => {
  it("appends parameters to the validated loopback URL without altering its origin", () => {
    const base = parseLoopbackRedirectUri("http://127.0.0.1:5000/callback")!;
    const url = new URL(loopbackCallbackUrl(base, { enrollment_transaction_id: "tx", nonce: "a+b/c=", state: "s" }));
    expect(url.origin).toBe("http://127.0.0.1:5000");
    expect(url.pathname).toBe("/callback");
    expect(url.searchParams.get("nonce")).toBe("a+b/c=");
  });
});
