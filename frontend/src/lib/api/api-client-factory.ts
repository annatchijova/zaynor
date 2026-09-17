import type { ZaynorApiClient } from "./api-client";
import { HttpApiClient } from "./http-api-client";
import { MockApiClient } from "./mock-api-client";

export type ApiClientMode = "http" | "mock";

export interface ApiClientConfiguration {
  readonly baseUrl?: string;
  readonly mode: ApiClientMode;
}

export function resolveApiClientConfiguration({
  mode,
  baseUrl,
}: {
  readonly mode: string | undefined;
  readonly baseUrl: string | undefined;
}): ApiClientConfiguration {
  if (!mode || mode === "mock") {
    return { mode: "mock" };
  }

  if (mode !== "http") {
    throw new TypeError("NEXT_PUBLIC_ZAYNOR_API_MODE must be either 'mock' or 'http'.");
  }

  if (!baseUrl?.trim()) {
    throw new TypeError("NEXT_PUBLIC_ZAYNOR_API_BASE_URL is required when HTTP mode is enabled.");
  }

  return { mode: "http", baseUrl };
}

export function createApiClient(configuration: ApiClientConfiguration): ZaynorApiClient {
  if (configuration.mode === "http") {
    return new HttpApiClient({ baseUrl: configuration.baseUrl ?? "" });
  }

  return new MockApiClient();
}
