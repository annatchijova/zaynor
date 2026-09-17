import type { ZaynorApiClient } from "./api-client";
import { HttpApiClient } from "./http-api-client";
import { MockApiClient } from "./mock-api-client";

export type ApiClientMode = "http" | "mock";

export interface ApiClientConfiguration {
  readonly baseUrl?: string;
  readonly mode: ApiClientMode;
  readonly reportDownloadBaseUrl?: string;
}

export function resolveApiClientConfiguration({
  mode,
  baseUrl,
  reportDownloadBaseUrl,
}: {
  readonly mode: string | undefined;
  readonly baseUrl: string | undefined;
  readonly reportDownloadBaseUrl?: string;
}): ApiClientConfiguration {
  if (!mode || mode === "mock") {
    return { mode: "mock" };
  }

  if (mode !== "http") {
    throw new TypeError("NEXT_PUBLIC_ZAYNOR_API_MODE must be either 'mock' or 'http'.");
  }

  if (!baseUrl?.trim()) {
    throw new TypeError("An API base URL is required when HTTP mode is enabled.");
  }

  return { mode: "http", baseUrl, reportDownloadBaseUrl };
}

export function createApiClient(configuration: ApiClientConfiguration): ZaynorApiClient {
  if (configuration.mode === "http") {
    return new HttpApiClient({
      baseUrl: configuration.baseUrl ?? "",
      reportDownloadBaseUrl: configuration.reportDownloadBaseUrl,
    });
  }

  return new MockApiClient();
}
