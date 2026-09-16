# SKILLS — Engineering Discipline Skill Set

**Language:** English · [Español](README.es.md)

A collection of 58 skills for Claude Code that encode disciplined software engineering, forensic reasoning, and security-first construction for ZAYNOR's local DFIR and detection pipeline. Each skill activates automatically when the conversation matches its trigger conditions, injecting methodology without requiring the user to ask for it.

These skills form a coherent system built on Charles Sanders Peirce's triadic semiotics and the abductive inference loop (abduction → deduction → induction). They cover the full engineering lifecycle: investigation, construction, patching, testing, auditing, and hardening.

---

## Skills

| Source ID | Skill | Category | Activates when |
|---:|---|---|---|
| 1 | `abductive-engineering` | Core reasoning | Debugging, root-cause analysis, incident response, or architectural decisions under uncertainty. |
| 2 | `red-team-auditing` | Core reasoning | Security audits, adversarial review, threat modeling, or invariant analysis. |
| 3 | `secure-by-construction` | Core reasoning | Writing, extending, refactoring, or reviewing code with security boundaries. |
| 4 | `software-archaeology` | Core reasoning | Modifying legacy, inherited, or unfamiliar code without breaking behavior. |
| 5 | `diagnosing-bugs` | Core reasoning | Investigating hard bugs and performance regressions through controlled probes and regression tests. |
| 6 | `codebase-health-assessment` | Core reasoning | Classifying dead, fossil, live, and out-of-scope modules before changing a codebase. |
| 7 | `reverse-engineering` | Core reasoning | Reconstructing undocumented systems, binaries, protocols, file formats, or opaque APIs without readable source. |
| 8 | `daubert-defensible-writing` | Core reasoning | Writing findings and reports that separate evidence, inference, uncertainty, and opinion. |
| 9 | `deterministic-core` | Determinism & integrity | Producing bit-for-bit reproducible and tamper-evident decisions with canonical serialization and SHA-256 sealing. |
| 10 | `llm-out-of-the-loop` | Determinism & integrity | Keeping consequential decisions outside the LLM path and sealing results before optional narration. |
| 11 | `tamper-evident-audit-chain` | Determinism & integrity | Building or verifying append-only logs that detect alteration, insertion, reordering, or deletion. |
| 14 | `surgical-patcher` | Patching & editing | Applying anchored, verified, reversible changes instead of rewriting entire source files. |
| 15 | `audit-before-patch` | Patching & editing | Validating an audit finding against the current file before changing any code. |
| 16 | `validate-at-the-boundary` | Input & data | Validating untrusted input at the system boundary with clear errors. |
| 17 | `honest-degradation` | Input & data | Handling degraded, legacy, reconstructed, or unverifiable input without returning plausible-looking wrong results. |
| 19 | `git-discipline` | Process | Keeping AI-assisted coding sessions recoverable, reviewable, and free from unsafe history rewriting. |
| 20 | `claim-provenance-discipline` | Evidence governance | Preserving each claim's origin, epistemic level, scope bound, and falsifier across summaries and handoffs. |
| 21 | `attack-surface-triage` | Adversarial validation | Enumerating an authorized target's surface into a reproducible, falsifiable candidate queue — before any payload. |
| 22 | `purple-team-exercise` | Adversarial validation | Turning each technique into a detection hypothesis, detonating it minimally and marked, and measuring what the blue side saw. |
| 23 | `detection-engineering` | Adversarial validation | Turning a detection requirement into a tested, budgeted, versioned rule — with a benign twin that must not fire. |
| 24 | `agent-trust-boundaries` | Agent architecture | Keeping retrieved content as data, tool authority in deterministic policy, and the untrusted/private/egress trifecta broken. |
| 25 | `falsifiable-testing` | Verification | Writing tests that can actually fail — red first, negative controls, oracle strength, and flakes treated as findings. |
| 26 | `incident-timeline-reconstruction` | Evidence governance | Ordering events across clock domains, separating recorded from actual time, and labeling every gap by kind. |
| 27 | `irreversible-action-gate` | Process | Classifying actions by reversibility and blast radius, then gating them with preview, count assertion, and a written undo plan. |
| 28 | `dependency-provenance` | Supply chain | Knowing what is actually shipped, establishing package identity before trust, and treating advisories as candidates until reachability is shown. |
| 29 | `secret-lifecycle-discipline` | Credentials | Treating credentials as a lifecycle — redaction at the boundary, rotation rehearsed before it is needed, rotate-first on exposure. |
| 30 | `decision-record-discipline` | Process | Capturing forces, rejected alternatives, load-bearing assumptions, and revisit triggers while the context still exists. |
| 32 | `forensic-logging-design` | Evidence governance | Deciding what to record today so tomorrow's reconstruction is possible — decisions, correlation, and legible silence. |
| 33 | `invariant-hunting` | Core reasoning | Hunting violations of a declared or implied security invariant across a transition — a property established at T0 that a later state change must preserve. |
| 34 | `beyond-the-sink` | Core reasoning | An investigation stalls — looking past the sink-grep keyword list, the exhausted question family, or a single implementation when the obvious layer is dry. |
| 35 | `discriminating-proof` | Verification | Turning a plausible hypothesis into an earned verdict with the cheapest experiment that can kill it — binary oracle, canary value, negative control. |
| 36 | `forensic-persistence` | Core reasoning | A hunt, audit, or debug session returns zero findings, hypotheses keep getting refuted, or a target looks too hardened to continue. |
| 37 | `oracle-driven-fuzzing` | Verification | Bugs must be found by generated input — property-based, structure-aware, differential and metamorphic oracles, corpus discipline, shrinking, and crash triage. |
| 38 | `parser-differential-hunting` | Adversarial validation | Two components read the same bytes and disagree — the checkpoint decides on one meaning while the sink acts on another. |
| 39 | `authorization-surface-mapping` | Adversarial validation | Building the actor × resource × action matrix and testing the cells nobody wrote a test for — because a missing check looks like nothing. |
| 40 | `assume-breach-modeling` | Adversarial validation | A position is already held — mapping what that identity reaches, and finding the choke point whose removal cuts the most paths. |
| 41 | `resource-exhaustion-review` | Input & data | A small input buys a large amount of work or memory — asymmetry ratios, unbounded allocation, super-linear algorithms, missing backpressure. |
| 42 | `remediation-driven-reporting` | Adversarial validation | Writing the report so the class gets fixed, not the instance — surviving triage, severity scored to demonstrated impact, and verifying the patch against the class. |
| 43 | `finding-custody` | Evidence governance | A confirmed finding after it is reported — instance vs class vs method, the patch-diffing window, custody of the PoC, and a disclosure decision with a revisit trigger. |
| 48 | `beyond-the-fix` | Core reasoning | Auditing the fixes themselves — a patch proves someone knew something was wrong there, never that it is now right; eight ways a fix falls short, and the pre-fix control that tells them apart. |
| 49 | `dual-use-behavior-adjudication` | Security operations | Deciding malicious vs benign when the tool itself is legitimate — the living-off-the-land problem, where the verdict lives in provenance, baseline, and sequence, never in the artifact. |
| 50 | `threat-attribution-restraint` | Security operations | Resisting the pull to name an actor — every overlap that points at APT-X is contact between datasets, not identity of hands, and most of it is cheap to plant. |
| 51 | `credential-material-triage` | Credentials | Turning "we found a credential" into a finding — what it authenticates as, authorizes, for how long, and how to revoke it, without inflating a hash into a compromise. |
| 53 | `untrusted-sample-handling` | Security operations | Examining a hostile artifact safely — never let it execute where it can reach anything real, never confuse what it can do with what it was aimed at. |
| 54 | `exploitability-triage` | Security operations | CVSS is not risk — a vulnerability is a candidate until the vulnerable code is shown reachable, reached by attacker input, and exploitable given the mitigations actually present. |
| 55 | `hypothesis-driven-hunting` | Security operations | A threat hunt is a falsifiable hypothesis, not a keyword sweep — state before you query what would refute it and what "found nothing" really proves. |
| 56 | `intel-source-evaluation` | Security operations | Grade the source and the indicator before acting — an IOC is a claim with a shelf life; auto-actioning ungraded intel blocks benign traffic and burns trust. |
| 57 | `traffic-as-evidence` | Security operations | Network traffic is evidence under encryption and base-rate limits, never a verdict — beaconing and fingerprints are weak signals whose meaning lives in baseline. |
| 58 | `alert-triage-economics` | Security operations | Analyst attention is the scarce resource — triage by expected loss, not the severity label; the queue that trains dismissal is the real vulnerability. |
| 59 | `container-trust-boundary` | Security operations | A container is isolation, not a security boundary — the real perimeter is the shared kernel, the image provenance, and the orchestration identity it holds. |
| 60 | `containment-under-uncertainty` | Security operations | Contain before scope is known, in reversible-vs-irreversible moves — acting tips off the adversary, waiting lets the bleed continue; never let "unsure" become "nothing". |
| 62 | `pipeline-trust` | Supply chain | CI/CD runs attacker-influenceable code with production credentials — the build is a privileged execution environment, not config, and rarely in the threat model. |
| 63 | `zero-trust-as-a-claim` | Security operations | "Zero trust" is a per-request property to verify, not a product — find the implicit trust that survives: a flat network, a mesh that authenticates but never authorizes. |
| 66 | `crypto-misuse-reasoning` | Cryptography | The danger is the misuse, not the algorithm — "we use AES" says nothing; the breaks are nonce reuse, ECB, unauthenticated ciphertext, a homemade KDF, a downgrade. |
| 71 | `root-of-trust-reasoning` | Determinism & integrity | You cannot verify a system from inside it — a compromise below your vantage point controls what you see; anchor integrity to a root below the layer that could lie. |
| 72 | `data-provenance-mapping` | Evidence governance | You cannot delete, protect, or scope a breach of data whose real flow you never mapped — the forgotten copy in a log, a backup, or a vendor is the failed DSAR. |
| 73 | `variant-analysis` | Adversarial validation | A known bug (CVE/advisory/fix commit) or one you just found — extract the violated invariant, hunt the same class across shared deps and sibling sinks, and settle dedupe and fix-coverage before filing. |
| 74 | `dont-fall-in-love-with-the-bug` | Adversarial validation | A finding reproduces and is about to be written up — the gate that makes you earn the report: root cause, variant sweep, bypass-the-fix, blast radius, and severity against a named comparable. |

### Adversarial validation loop

`attack-surface-triage` opens the loop and `red-team-auditing` is the
confirmation step; the hunting skills feed candidates in, and the impact and
containment skills carry a confirmed finding back out to the blue side:

```
                 attack-surface-triage → ranked candidates
                              │
   ┌──────────────────────────┼──────────────────────────┐
   │  where candidates come from (the hunt)              │
   │  invariant-hunting · parser-differential-hunting    │
   │  authorization-surface-mapping · beyond-the-sink    │
   │  oracle-driven-fuzzing · resource-exhaustion-review │
   │  beyond-the-fix (the fix history is the map)        │
   └──────────────────────────┼──────────────────────────┘
                              ▼
      discriminating-proof → red-team-auditing → confirmed / refuted
                              │                        │
                              │            forensic-persistence (refuted → next axis)
                              ▼
      assume-breach-modeling → impact, choke points, containment
                              ▼
      purple-team-exercise → detection gaps
                              ▼
      detection-engineering → proven rule → (retest closes the loop)

   when the target is someone else's:
      remediation-driven-reporting → the class gets fixed, not the instance
      finding-custody → what you did NOT say, and what reopens the decision
```

Everything on the offensive side of this library exists to produce a defensive
artifact: a bound, a bulkhead, a generated negative test, or a rule that has
fired for the right reason.

### Scope boundary

This catalog intentionally excludes machine-learning training and evaluation,
cloud, OT, client-side, database, generic concurrency, backup, acquisition,
social-engineering, and deception-specific practices. Those topics may be
useful elsewhere, but they are not part of ZAYNOR's current local DFIR and
detection slice. The catalog can grow when the implementation adds a concrete
contract that needs one of them.

---

## Repository Structure

Each skill lives in its own directory and is a self-contained `SKILL.md` file:

```
<skill-name>/
  SKILL.md      # YAML frontmatter (name + description) followed by the full methodology
```

The `description` field is the trigger surface — it must name the situations,
phrasings, and artifacts that should activate the skill, and it must stay under
1024 characters. The body is loaded only once the skill triggers.

Some skills also ship `scripts/` or `references/` subdirectories when executable
helpers or long reference material do not belong in the always-loaded body.

---

## Design Principles

- **No LLM in the decision path.** Consequential outputs are sealed deterministically before any model is called.
- **Abduction before deduction.** Every diagnosis generates a falsifiable hypothesis, derives a testable prediction, and confirms or refutes it against the real system.
- **Eco's razor.** Before acting on any hypothesis, attempt to refute it. A refuted hypothesis is a result, not a failure.
- **Honest degradation over false confidence.** Three states, not two: PASS / WARN / FAIL. ABSTAIN is a valid verdict.
- **Surgical patching over rewriting.** Regenerating a file from memory is the largest source of silent regressions.
- **Never trust a green you have not seen red.** A test — or a detection rule — that has never failed for the right reason measures nothing.
- **Authority comes from the channel, not the content.** Retrieved documents, tool output, and other agents' summaries are data; none of them can grant themselves permission.
- **Proportional gates before irreversible actions.** Preview the exact targets, assert the expected count before seeing it, and write the undo plan before acting — not after.
- **Red exists to produce blue.** A confirmed finding is not the deliverable; the bound, the bulkhead, the generated negative test, and the detection requirement are.
- **You cannot grep for an absence.** Missing checks, unenumerated cells, and unstated limits are invisible in a diff — they are found by enumerating what the system claims to enforce and testing the gaps.
- **A finding is not finished when it is patched.** The instance dies with the fix; the class does not. Reporting, custody, and the decision not to publish all have their own discipline.
- **A result that looks too good is a bug report.** In every other domain a defect makes something fail; leakage makes everything look better, so the alarm has to be inverted.
- **A fix proves the past, not the present.** That someone fixed it means they fixed that, and nothing else — the patched file is the least-reviewed code in the repository and the likeliest place for the next bug.

---

## Related

- [vigia-intent-analysis](https://github.com/annatchijova/vigia-intent-analysis) — VIGÍA forensic intent analysis engine (SANS FIND EVIL Hackathon 2026). These skills encode its engineering invariants.

---


                    ┌─────────────────────────┐
                    │     INQUIRY / REASONING │
                    │                         │
                    │ abductive-engineering   │
                    │ diagnosing-bugs         │
                    │ software-archaeology    │
                    │ reverse-engineering     │
                    │ invariant-hunting       │
                    │ beyond-the-sink         │
                    │ beyond-the-fix          │
                    │ forensic-persistence    │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │   ADVERSARIAL VALIDATION│
                    │                         │
                    │ attack-surface-triage   │
                    │ red-team-auditing       │
                    │ discriminating-proof    │
                    │ authorization-surface   │
                    │ parser-differential     │
                    │ oracle-driven-fuzzing   │
                    │ assume-breach-modeling  │
                    │ purple-team-exercise    │
                    │ detection-engineering   │
                    │ falsifiable-testing     │
                    │ remediation-reporting   │
                    └────────────┬────────────┘
                                 │
             ┌───────────────────┼───────────────────┐
             ▼                   ▼                   ▼
       INTEGRITY            TRUST / DATA          EVIDENCE
       deterministic       validate-boundary      provenance
       audit-chain         honest-degradation     timeline
                           secret lifecycle       logging
                           dependency provenance  decision records
                           resource exhaustion
             │                   │                   │
             └───────────────────┼───────────────────┘
                                 ▼
                       CONSTRUCTION / CHANGE
                                 │
                  secure-by-construction
                  surgical-patcher
                  audit-before-patch
                  git-discipline
                  irreversible-action-gate
