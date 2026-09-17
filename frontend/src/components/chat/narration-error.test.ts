import assert from "node:assert/strict";
import test from "node:test";

import { ApiClientError } from "@/lib/api";

import { presentNarrationError } from "./narration-error";

test("describes unavailable local narration without downgrading the authoritative result", () => {
  const error = new ApiClientError({
    code: "OLLAMA_UNAVAILABLE",
    message: "Local narration is unavailable.",
    request_id: null,
  });

  const presentation = presentNarrationError(error);

  assert.equal(presentation.title, "La narración local no está disponible");
  assert.match(presentation.detail, /no fue modificado/i);
});

test("does not present rejected narration as an authoritative answer", () => {
  const error = new ApiClientError({
    code: "POLICY_REJECTED",
    message: "Policy rejected the request.",
    request_id: null,
  });

  const presentation = presentNarrationError(error);

  assert.equal(presentation.title, "La solicitud no puede narrarse");
  assert.match(presentation.detail, /excede el paquete autoritativo/i);
});
