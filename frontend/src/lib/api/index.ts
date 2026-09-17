import { createApiClient, resolveApiClientConfiguration } from "./api-client-factory";

const configuration = resolveApiClientConfiguration({
  mode: process.env.NEXT_PUBLIC_ZAYNOR_API_MODE,
  baseUrl: process.env.NEXT_PUBLIC_ZAYNOR_API_BASE_URL,
});

export const api = createApiClient(configuration);

export { ApiClientError } from "./api-client-error";
export { HttpApiClient } from "./http-api-client";
export type { ZaynorApiClient } from "./api-client";
export type * from "./contracts";
