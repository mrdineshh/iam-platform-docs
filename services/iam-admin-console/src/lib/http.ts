// Small fetch wrapper -- browser equivalent of iam-login-portal's
// src/lib/http.ts. No Resilience4j equivalent here either; this implements
// an explicit timeout per call and a single typed error shape, same
// reasoning as that module.

export class UpstreamError extends Error {
  constructor(
    public readonly status: number,
    message: string,
    public readonly errorCode?: string,
  ) {
    super(message);
  }
}

interface BackendErrorBody {
  message?: string;
  errorCode?: string;
}

function correlationId(): string {
  return crypto.randomUUID();
}

async function request<T>(
  method: "GET" | "POST" | "PUT" | "PATCH",
  url: string,
  opts: { body?: unknown; sessionToken?: string; timeoutMs?: number } = {},
): Promise<T> {
  const controller = new AbortController();
  const timeoutMs = opts.timeoutMs ?? 10_000;
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const headers: Record<string, string> = { "X-Correlation-Id": correlationId() };
    if (opts.body !== undefined) headers["Content-Type"] = "application/json";
    if (opts.sessionToken) headers["X-Session-Token"] = opts.sessionToken;

    const res = await fetch(url, {
      method,
      headers,
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
      signal: controller.signal,
    });

    if (res.status === 204) return undefined as T;

    if (!res.ok) {
      const errorBody = await safeParseError(res);
      throw new UpstreamError(res.status, errorBody.message ?? `${method} ${url} failed with ${res.status}`, errorBody.errorCode);
    }
    return (await res.json()) as T;
  } catch (err) {
    if (err instanceof UpstreamError) throw err;
    if (err instanceof Error && err.name === "AbortError") {
      throw new UpstreamError(0, `${method} ${url} timed out after ${timeoutMs}ms`);
    }
    throw new UpstreamError(0, `${method} ${url} failed: ${(err as Error).message}`);
  } finally {
    clearTimeout(timeout);
  }
}

export const http = {
  get: <T>(url: string, opts?: { sessionToken?: string; timeoutMs?: number }) => request<T>("GET", url, opts),
  post: <T>(url: string, body: unknown, opts?: { sessionToken?: string; timeoutMs?: number }) =>
    request<T>("POST", url, { ...opts, body }),
  put: <T>(url: string, body: unknown, opts?: { sessionToken?: string; timeoutMs?: number }) =>
    request<T>("PUT", url, { ...opts, body }),
  patch: <T>(url: string, body: unknown, opts?: { sessionToken?: string; timeoutMs?: number }) =>
    request<T>("PATCH", url, { ...opts, body }),
};

async function safeParseError(res: Response): Promise<BackendErrorBody> {
  try {
    return (await res.json()) as BackendErrorBody;
  } catch {
    return {};
  }
}
