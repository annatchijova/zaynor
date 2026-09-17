import { createApiClient, resolveApiClientConfiguration } from "./api-client-factory";

export const serverApi = createApiClient(
  resolveApiClientConfiguration({
    mode: process.env.NEXT_PUBLIC_ZAYNOR_API_MODE,
    baseUrl: process.env.ZAYNOR_API_BASE_URL,
  }),
);
