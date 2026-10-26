// Small fetch wrapper -- this module has no Resilience4j equivalent (no JVM
// here), so it implements the two pieces of Guardrails Section 2 that
// actually apply to a UI-only service calling already-resilient backends:
// an explicit timeout per call (never an unbounded wait -- the push case
// needs a longer one, see config.ts), and a single typed error shape so
// callers don't each re-parse the backend's ErrorResponse body.

export class UpstreamError extends Error {
  constructor(
    public readonly status: number,
    message: string,
    public readonly errorCode?: string,
  ) {
    super(message);
  }
}

// The shared ErrorResponse shape every backend service returns
// (iam-service-kit's ErrorResponse.kt). errorCode is optional/additive --
// only iam-auth-svc populates it today (Service 13 interview, OQ-3).
interface BackendErrorBody {
  message?: string;
  errorCode?: string;
}

export async function postJson<T>(
  url: string,
  body: unknown,
  opts: { correlationId: string; timeoutMs: number },
): Promise<T> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), opts.timeoutMs);
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Correlation-Id": opts.correlationId,
      },
      body: JSON.stringify(body),
      signal: controller.signal,
      cache: "no-store",
    });

    if (!res.ok) {
      const errorBody = await safeParseError(res);
      throw new UpstreamError(res.status, errorBody.message ?? `Request to ${url} failed with ${res.status}`, errorBody.errorCode);
    }

    if (res.status === 204) {
      return undefined as T;
    }
    return (await res.json()) as T;
  } catch (err) {
    if (err instanceof UpstreamError) throw err;
    if (err instanceof Error && err.name === "AbortError") {
      throw new UpstreamError(0, `Request to ${url} timed out after ${opts.timeoutMs}ms`);
    }
    throw new UpstreamError(0, `Request to ${url} failed: ${(err as Error).message}`);
  } finally {
    clearTimeout(timeout);
  }
}

export async function getJson<T>(
  url: string,
  opts: { correlationId: string; timeoutMs: number; headers?: Record<string, string> },
): Promise<T | null> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), opts.timeoutMs);
  try {
    const res = await fetch(url, {
      method: "GET",
      headers: { "X-Correlation-Id": opts.correlationId, ...(opts.headers ?? {}) },
      signal: controller.signal,
      cache: "no-store",
    });
    if (res.status === 404) return null;
    if (!res.ok) {
      const errorBody = await safeParseError(res);
      throw new UpstreamError(res.status, errorBody.message ?? `Request to ${url} failed with ${res.status}`, errorBody.errorCode);
    }
    return (await res.json()) as T;
  } catch (err) {
    if (err instanceof UpstreamError) throw err;
    if (err instanceof Error && err.name === "AbortError") {
      throw new UpstreamError(0, `Request to ${url} timed out after ${opts.timeoutMs}ms`);
    }
    throw new UpstreamError(0, `Request to ${url} failed: ${(err as Error).message}`);
  } finally {
    clearTimeout(timeout);
  }
}

async function safeParseError(res: Response): Promise<BackendErrorBody> {
  try {
    return (await res.json()) as BackendErrorBody;
  } catch {
    return {};
  }
}
