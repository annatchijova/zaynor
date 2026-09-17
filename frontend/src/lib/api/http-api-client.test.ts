import assert from "node:assert/strict";
import test from "node:test";

import { case001 } from "./fixtures";
import { ApiClientError } from "./api-client-error";
import { HttpApiClient } from "./http-api-client";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

test("requests a case through the target console endpoint and validates its payload", async () => {
  const requests: Array<{ readonly init: RequestInit | undefined; readonly url: string }> = [];
  const client = new HttpApiClient({
    baseUrl: "http://127.0.0.1:8000/",
    fetchImplementation: async (url, init) => {
      requests.push({ url, init });
      return jsonResponse(case001);
    },
  });

  const caseOverview = await client.getCase("CASE-001");

  assert.equal(caseOverview.authoritative_result.result_sha256, case001.authoritative_result.result_sha256);
  assert.equal(requests[0]?.url, "http://127.0.0.1:8000/cases/CASE-001");
  assert.equal(requests[0]?.init?.method, "GET");
});

test("accepts the same-origin BFF base path used by browser components", async () => {
  let requestUrl = "";
  const client = new HttpApiClient({
    baseUrl: "/api/zaynor",
    fetchImplementation: async (url) => {
      requestUrl = url;
      return jsonResponse(case001);
    },
  });

  await client.getCase("CASE-001");

  assert.equal(requestUrl, "/api/zaynor/cases/CASE-001");
});

test("resolves a backend report descriptor against the configured API origin", async () => {
  const client = new HttpApiClient({
    baseUrl: "http://127.0.0.1:8420",
    fetchImplementation: async () =>
      jsonResponse({
        content_type: "application/pdf",
        download_url: "/cases/CASE-001/reports/pdf/download",
        format: "pdf",
      }),
  });

  const report = await client.getReport("CASE-001", "pdf");

  assert.equal(report.download_url, "http://127.0.0.1:8420/cases/CASE-001/reports/pdf/download");
});

test("keeps private backend origins out of server-rendered report links", async () => {
  const client = new HttpApiClient({
    baseUrl: "http://127.0.0.1:8420",
    reportDownloadBaseUrl: "/api/zaynor",
    fetchImplementation: async () =>
      jsonResponse({
        content_type: "text/markdown",
        download_url: "/cases/CASE-001/reports/md/download",
        format: "md",
      }),
  });

  const report = await client.getReport("CASE-001", "md");

  assert.equal(report.download_url, "/api/zaynor/cases/CASE-001/reports/md/download");
});

test("rejects report descriptors that escape the configured backend contract", async () => {
  const client = new HttpApiClient({
    baseUrl: "http://127.0.0.1:8420",
    fetchImplementation: async () =>
      jsonResponse({
        content_type: "application/pdf",
        download_url: "https://untrusted.example/report.pdf",
        format: "pdf",
      }),
  });

  await assert.rejects(client.getReport("CASE-001", "pdf"), (error: unknown) => {
    assert.ok(error instanceof ApiClientError);
    assert.equal(error.code, "INTERNAL_ERROR");
    assert.match(error.message, /enlace de descarga incompatible/i);
    return true;
  });
});

test("rejects a descriptor whose declared format differs from the requested artifact", async () => {
  const client = new HttpApiClient({
    baseUrl: "http://127.0.0.1:8420",
    fetchImplementation: async () =>
      jsonResponse({
        content_type: "application/pdf",
        download_url: "/cases/CASE-001/reports/pdf/download",
        format: "html",
      }),
  });

  await assert.rejects(client.getReport("CASE-001", "pdf"), ApiClientError);
});

test("maps typed backend errors without converting them into successful payloads", async () => {
  const client = new HttpApiClient({
    baseUrl: "http://127.0.0.1:8000",
    fetchImplementation: async () =>
      jsonResponse(
        {
          code: "SEAL_VERIFICATION_FAILED",
          message: "The stored seal does not verify.",
          request_id: "req-001",
        },
        409,
      ),
  });

  await assert.rejects(client.getCase("CASE-001"), (error: unknown) => {
    assert.ok(error instanceof ApiClientError);
    assert.equal(error.code, "SEAL_VERIFICATION_FAILED");
    assert.equal(error.requestId, "req-001");
    return true;
  });
});

test("rejects a successful HTTP response whose body does not match the authoritative contract", async () => {
  const client = new HttpApiClient({
    baseUrl: "http://127.0.0.1:8000",
    fetchImplementation: async () => jsonResponse({ case_id: "CASE-001" }),
  });

  await assert.rejects(client.getCase("CASE-001"), (error: unknown) => {
    assert.ok(error instanceof ApiClientError);
    assert.equal(error.code, "INTERNAL_ERROR");
    assert.match(error.message, /payload incompatible/i);
    return true;
  });
});

test("sends investigation proposals only to the dedicated policy-gated endpoint", async () => {
  let requestUrl = "";
  let requestInit: RequestInit | undefined;
  const proposal = case001.investigation.proposals[0];
  assert.ok(proposal);

  const client = new HttpApiClient({
    baseUrl: "http://127.0.0.1:8000",
    fetchImplementation: async (url, init) => {
      requestUrl = url;
      requestInit = init;
      return jsonResponse(proposal);
    },
  });

  const result = await client.proposeInvestigation("CASE-001", {
    question: "¿Existe una aprobación de cambio?",
    requested_tool: "query_change_records",
    arguments: { host: "srv-files-01" },
  });

  assert.equal(result.proposal_id, proposal.proposal_id);
  assert.equal(requestUrl, "http://127.0.0.1:8000/cases/CASE-001/investigations/proposals");
  assert.equal(requestInit?.method, "POST");
  assert.deepEqual(JSON.parse(String(requestInit?.body)), {
    question: "¿Existe una aprobación de cambio?",
    requested_tool: "query_change_records",
    arguments: { host: "srv-files-01" },
  });
});
