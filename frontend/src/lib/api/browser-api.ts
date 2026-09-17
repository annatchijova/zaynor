"use client";

import { createApiClient, resolveApiClientConfiguration } from "./api-client-factory";

const mode = process.env.NEXT_PUBLIC_ZAYNOR_API_MODE;

export const browserApi = createApiClient(
  resolveApiClientConfiguration({
    mode,
    baseUrl: mode === "http" ? "/api/zaynor" : undefined,
  }),
);
