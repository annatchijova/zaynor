# Ground truth — INC-2026-DEMO-001 (test/evaluation use only)

This file is deliberately kept outside `scenarios/` and outside anything a
case freezer, tool, or investigator ever reads. It exists only so tests can
assert the system reaches the right reconstruction — it must never be copied
into a case's frozen evidence tree.

A privileged credential (`admin.rojas`) was used without authorization from
a non-inventoried device (`DEV-UNKNOWN-17`). That session opened a remote
SSH session to `srv-files-01`, created `collection.zip`, altered its
declared `modified_time` to appear earlier than the login (`file:E004`), and
produced an outbound connection (`net:E005`).

This fixture does **not** establish: how the credential was obtained, who
was physically at the keyboard, whether the full file was transferred, or
who controlled the destination `203.0.113.44`. Any reconstruction that
claims certainty on those points is wrong by construction of this fixture.
