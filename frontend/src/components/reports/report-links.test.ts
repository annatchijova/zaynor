import assert from "node:assert/strict";
import test from "node:test";

import { isSafeReportUrl } from "./report-url";

test("allows only relative and HTTP(S) report artifact URLs", () => {
  assert.equal(isSafeReportUrl("/reports/CASE-001.md"), true);
  assert.equal(isSafeReportUrl("https://reports.local/CASE-001.pdf"), true);
  assert.equal(isSafeReportUrl("http://127.0.0.1:8000/reports/CASE-001.html"), true);
});

test("does not render unsupported report URL schemes as browser links", () => {
  assert.equal(isSafeReportUrl("mock://reports/CASE-001.md"), false);
  assert.equal(isSafeReportUrl("javascript:alert(1)"), false);
  assert.equal(isSafeReportUrl("//untrusted.example/report.pdf"), false);
});
