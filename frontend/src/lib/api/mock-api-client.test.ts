import assert from "node:assert/strict";
import test from "node:test";

import { ApiClientError } from "./api-client-error";
import {
  MockApiClient,
  emptyMockDataset,
  rejectedNarrationMockDataset,
  unavailableNarrationMockDataset,
} from "./mock-api-client";

test("returns the CASE-001 fixture without an HTTP dependency", async () => {
  const api = new MockApiClient();

  const [summary] = await api.listCases();
  const overview = await api.getCase("CASE-001");

  assert.equal(summary?.case_id, "CASE-001");
  assert.equal(overview.snapshot.status, "VERIFIED");
  assert.equal(overview.authoritative_result.verdict, "ABSTAIN");
});

test("keeps the authoritative result unchanged when a proposal is recorded", async () => {
  const api = new MockApiClient();

  const proposal = await api.proposeInvestigation("CASE-001", {
    question: "¿Hay telemetría retenida para el proceso?",
  });
  const investigation = await api.getInvestigationSession("CASE-001");
  const result = await api.getAuthoritativeResult("CASE-001");

  assert.equal(proposal.status, "PROPOSED");
  assert.equal(investigation.authoritative_result_unchanged, true);
  assert.equal(result.verdict, "ABSTAIN");
});

test("rejects a missing case with a typed client error", async () => {
  const api = new MockApiClient(emptyMockDataset);

  await assert.rejects(api.getCase("CASE-404"), (error: unknown) => {
    assert.ok(error instanceof ApiClientError);
    assert.equal(error.code, "CASE_NOT_FOUND");
    return true;
  });
});

test("returns bounded narration only for prepared questions", async () => {
  const api = new MockApiClient();

  const answer = await api.explain("CASE-001", "¿Qué pasó?");

  assert.equal(answer.certainty, "AUTHORIZED");
  assert.equal(answer.disclaimer, "Esta explicación no modifica el veredicto autoritativo.");
  assert.deepEqual(answer.finding_refs, ["F001", "F002"]);
});

test("models unavailable and rejected narration as typed non-authoritative failures", async () => {
  const unavailableClient = new MockApiClient(unavailableNarrationMockDataset);
  const rejectedClient = new MockApiClient(rejectedNarrationMockDataset);

  await assert.rejects(unavailableClient.explain("CASE-001", "¿Qué pasó?"), (error: unknown) => {
    assert.ok(error instanceof ApiClientError);
    assert.equal(error.code, "OLLAMA_UNAVAILABLE");
    return true;
  });

  await assert.rejects(rejectedClient.explain("CASE-001", "¿Qué pasó?"), (error: unknown) => {
    assert.ok(error instanceof ApiClientError);
    assert.equal(error.code, "POLICY_REJECTED");
    return true;
  });
});

test("keeps a recorded observation separate from the sealed authoritative result", async () => {
  const api = new MockApiClient();

  const [session, result] = await Promise.all([
    api.getInvestigationSession("CASE-001"),
    api.getAuthoritativeResult("CASE-001"),
  ]);

  assert.equal(session.observations[0]?.status, "OBSERVED");
  assert.equal(session.authoritative_result_unchanged, true);
  assert.equal(result.result_sha256, "9ccdc8e2843eac95c35de5c70ece54c7d124acd2226f1d98106aa2237a5a2dc1");
});
