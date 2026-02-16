export interface TweakClientConfig {
  host: string;
  port: number;
  timeoutMs: number;
}

export interface TweakResponse {
  ok: boolean;
  status: number;
  data: unknown;
  raw: string;
  error?: string;
}

export class TweakClient {
  private readonly config: TweakClientConfig;

  constructor(config: TweakClientConfig) {
    this.config = config;
  }

  async request(endpoint: string, method: string = "GET", body?: unknown): Promise<TweakResponse> {
    const url = `http://${this.config.host}:${this.config.port}${endpoint}`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.timeoutMs);

    try {
      const response = await fetch(url, {
        method,
        headers: {
          "content-type": "application/json",
        },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: controller.signal,
      });

      const raw = await response.text();
      const data = safeJsonParse(raw);

      return {
        ok: response.ok,
        status: response.status,
        data,
        raw,
      };
    } catch (error) {
      return {
        ok: false,
        status: 0,
        data: null,
        raw: "",
        error: error instanceof Error ? error.message : String(error),
      };
    } finally {
      clearTimeout(timeout);
    }
  }
}

function safeJsonParse(input: string): unknown {
  try {
    return JSON.parse(input);
  } catch {
    return input;
  }
}
