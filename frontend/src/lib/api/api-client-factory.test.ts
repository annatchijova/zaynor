import assert from "node:assert/strict";
import test from "node:test";

import { createApiClient, resolveApiClientConfiguration } from "./api-client-factory";
import { HttpApiClient } from "./http-api-client";
import { MockApiClient } from "./mock-api-client";

test("uses the fixture client unless HTTP mode is explicitly enabled", () => {
  const configuration = resolveApiClientConfiguration({ mode: undefined, baseUrl: undefined });

  assert.equal(configuration.mode, "mock");
  assert.ok(createApiClient(configuration) instanceof MockApiClient);
});

test("requires an explicit base URL before enabling the HTTP client", () => {
  assert.throws(
    () => resolveApiClientConfiguration({ mode: "http", baseUrl: undefined }),
    /API base URL is required/i,
  );
});

test("creates the HTTP client only from an explicit valid configuration", () => {
  const configuration = resolveApiClientConfiguration({
    mode: "http",
    baseUrl: "http://127.0.0.1:8000",
  });

  assert.ok(createApiClient(configuration) instanceof HttpApiClient);
});
