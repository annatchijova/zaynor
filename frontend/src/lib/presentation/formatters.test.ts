import assert from "node:assert/strict";
import test from "node:test";

import { formatConfidence, formatEvidenceRefs, formatFileSize, formatHash } from "./formatters";

test("formats display-only values without changing their meaning", () => {
  assert.equal(formatConfidence("MEDIUM"), "Media");
  assert.equal(formatHash("a".repeat(64)), "aaaaaaaaaaaa…aaaaaaaa");
  assert.equal(formatFileSize(1536), "1,5 KiB");
  assert.equal(
    formatEvidenceRefs([
      { artifact: "E001", lineage_id: "lineage-a" },
      { artifact: "E002", lineage_id: "lineage-b" },
    ]),
    "E001, E002",
  );
});
