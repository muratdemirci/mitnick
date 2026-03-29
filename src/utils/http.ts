/**
 * HTTP client wrapper using native fetch (Node 18+).
 *
 * Provides typed fetch helpers with timeout support and
 * structured error handling via discriminated unions.
 */

// ─── Result Type ──────────────────────────────────────────

interface HttpSuccess<T> {
  readonly ok: true;
  readonly data: T;
  readonly status: number;
}

interface HttpError {
  readonly ok: false;
  readonly error: HttpErrorKind;
  readonly message: string;
  readonly status?: number;
}

export type HttpResult<T> = HttpSuccess<T> | HttpError;

type HttpErrorKind =
  | 'network'
  | 'timeout'
  | 'not_found'
  | 'rate_limited'
  | 'server_error'
  | 'parse_error';

// ─── Options ──────────────────────────────────────────────

interface FetchOptions {
  readonly timeout?: number;
  readonly headers?: Readonly<Record<string, string>>;
  readonly method?: string;
  readonly body?: string;
}

const DEFAULT_TIMEOUT = 30_000;

// ─── Helpers ──────────────────────────────────────────────

function classifyStatus(status: number): HttpErrorKind | null {
  if (status >= 200 && status < 300) return null;
  if (status === 404) return 'not_found';
  if (status === 429) return 'rate_limited';
  if (status >= 500) return 'server_error';
  return 'network';
}

function classifyError(error: unknown): HttpError {
  if (error instanceof DOMException && error.name === 'AbortError') {
    return { ok: false, error: 'timeout', message: 'Request timed out' };
  }
  const message = error instanceof Error ? error.message : String(error);
  return { ok: false, error: 'network', message };
}

// ─── Typed Fetch ──────────────────────────────────────────

/**
 * Fetch JSON from a URL with timeout support and typed response.
 * Returns a discriminated union so callers handle errors explicitly.
 *
 * **Note:** The generic type parameter `T` is applied via an `as T` cast on the
 * parsed JSON. Callers are responsible for validating the returned `data`
 * (e.g., with zod) before relying on its shape.
 */
export async function fetchJson<T>(
  url: string,
  options: FetchOptions = {},
): Promise<HttpResult<T>> {
  const { timeout = DEFAULT_TIMEOUT, headers, method, body } = options;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  try {
    const init: RequestInit = {
      method: method ?? 'GET',
      headers: {
        Accept: 'application/json',
        ...headers,
      },
      signal: controller.signal,
    };
    if (body !== undefined) {
      init.body = body;
    }
    const response = await fetch(url, init);

    const errorKind = classifyStatus(response.status);
    if (errorKind !== null) {
      const text = await response.text().catch(() => '');
      return {
        ok: false,
        error: errorKind,
        message: text !== '' ? text : `HTTP ${response.status}`,
        status: response.status,
      };
    }

    try {
      const data = (await response.json()) as T;
      return { ok: true, data, status: response.status };
    } catch {
      return {
        ok: false,
        error: 'parse_error',
        message: 'Failed to parse JSON response',
        status: response.status,
      };
    }
  } catch (error: unknown) {
    return classifyError(error);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Fetch raw bytes from a URL. Used for tarball downloads.
 */
export async function fetchBuffer(
  url: string,
  options: FetchOptions = {},
): Promise<HttpResult<Buffer>> {
  const { timeout = DEFAULT_TIMEOUT, headers, method } = options;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  try {
    const response = await fetch(url, {
      method: method ?? 'GET',
      headers: { ...headers },
      signal: controller.signal,
    });

    const errorKind = classifyStatus(response.status);
    if (errorKind !== null) {
      const text = await response.text().catch(() => '');
      return {
        ok: false,
        error: errorKind,
        message: text !== '' ? text : `HTTP ${response.status}`,
        status: response.status,
      };
    }

    const arrayBuffer = await response.arrayBuffer();
    return { ok: true, data: Buffer.from(arrayBuffer), status: response.status };
  } catch (error: unknown) {
    return classifyError(error);
  } finally {
    clearTimeout(timer);
  }
}
