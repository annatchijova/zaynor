import assert from "node:assert/strict";
import test from "node:test";

import { createZaynorBff } from "./zaynor-bff";

test("forwards only allowlisted case-console reads without client credentials", async () => {
  let requestUrl = "";
  let requestInit: RequestInit | undefined;
  const handler = createZaynorBff({
    backendBaseUrl: "http://127.0.0.1:8420/",
    fetchImplementation: async (url, init) => {
      requestUrl = url;
      requestInit = init;
      return new Response("report bytes", {
        headers: {
          "Content-Disposition": 'attachment; filename="case.pdf"',
          "Content-Type": "application/pdf",
          "Set-Cookie": "must-not-be-forwarded=true",
        },
      });
    },
  });

  const response = await handler(
    new Request("http://console.local/api/zaynor/cases/CASE-001/reports/pdf/download", {
      headers: { Cookie: "operator-session=secret" },
    }),
    ["cases", "CASE-001", "reports", "pdf", "download"],
  );

  assert.equal(requestUrl, "http://127.0.0.1:8420/cases/CASE-001/reports/pdf/download");
  assert.equal(requestInit?.method, "GET");
  assert.equal(new Headers(requestInit?.headers).get("cookie"), null);
  assert.equal(response.headers.get("Cache-Control"), "no-store");
  assert.equal(response.headers.get("Content-Disposition"), 'attachment; filename="case.pdf"');
  assert.equal(response.headers.get("Set-Cookie"), null);
  assert.equal(await response.text(), "report bytes");
});

test("rejects paths outside the BFF allowlist before contacting the backend", async () => {
  let called = false;
  const handler = createZaynorBff({
    backendBaseUrl: "http://127.0.0.1:8420",
    fetchImplementation: async () => {
      called = true;
      return Response.json({});
    },
  });

  const unsupportedResponse = await handler(
    new Request("http://console.local/api/zaynor/v1/chat/completions"),
    ["v1", "chat", "completions"],
  );
  const traversalResponse = await handler(
    new Request("http://console.local/api/zaynor/cases/CASE-001/../audit"),
    ["cases", "CASE-001", "..", "audit"],
  );

  assert.equal(unsupportedResponse.status, 404);
  assert.equal(traversalResponse.status, 404);
  assert.equal(called, false);
  assert.equal(unsupportedResponse.headers.get("Cache-Control"), "no-store");
});

test("forwards JSON only to the dedicated policy-gated proposal endpoint", async () => {
  let requestUrl = "";
  let requestInit: RequestInit | undefined;
  const handler = createZaynorBff({
    backendBaseUrl: "http://127.0.0.1:8420",
    fetchImplementation: async (url, init) => {
      requestUrl = url;
      requestInit = init;
      return Response.json({ proposal_id: "P001" });
    },
  });

  const response = await handler(
    new Request("http://console.local/api/zaynor/cases/CASE-001/investigations/proposals", {
      body: JSON.stringify({ question: "What additional evidence is available?" }),
      headers: { "Content-Type": "application/json", Authorization: "Bearer unforwarded" },
      method: "POST",
    }),
    ["cases", "CASE-001", "investigations", "proposals"],
  );

  assert.equal(requestUrl, "http://127.0.0.1:8420/cases/CASE-001/investigations/proposals");
  assert.equal(requestInit?.method, "POST");
  assert.equal(new Headers(requestInit?.headers).get("authorization"), null);
  assert.equal(new Headers(requestInit?.headers).get("Content-Type"), "application/json");
  assert.deepEqual(
    JSON.parse(new TextDecoder().decode(requestInit?.body as ArrayBuffer)),
    { question: "What additional evidence is available?" },
  );
  assert.equal(response.status, 200);
});

test("rejects query strings and non-JSON mutation payloads", async () => {
  const handler = createZaynorBff({
    backendBaseUrl: "http://127.0.0.1:8420",
    fetchImplementation: async () => Response.json({}),
  });

  const queryResponse = await handler(
    new Request("http://console.local/api/zaynor/cases/CASE-001?debug=true"),
    ["cases", "CASE-001"],
  );
  const contentTypeResponse = await handler(
    new Request("http://console.local/api/zaynor/cases/CASE-001/chat", { body: "question", method: "POST" }),
    ["cases", "CASE-001", "chat"],
  );

  assert.equal(queryResponse.status, 400);
  assert.equal(contentTypeResponse.status, 415);
});
