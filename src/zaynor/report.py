"""Human-readable reports over a sealed ZAYNOR result — never a new decision.

Modeled on the section shape of VIGIA's own Daubert-grade PDF reporter
(`vigia/forensics/forensic_reporter.py`: executive summary, findings body,
chain of custody, methodology statement) — confirmed by reading that file in
full — but built against `ZaynorAuthoritativeResult` directly rather than
adapted from it: that reporter is tied to VIGIA's own `ForensicVerdict` type
and Peirce-triad-per-signal fields ZAYNOR's own findings do not carry
(`AuthoritativeFinding` has `finding_id`/`state`/`rationale`/`mitre`/`nist`,
not `firstness`/`secondness`/`thirdness`). Reusing the shape and the library
choice (`reportlab` — pure Python, no external binary) is reuse; copying code
built for a different schema would not be.

`render_html`'s visual language (CSS custom-property palette, a masthead
with a colored seal-line badge, stat tiles, severity/state-tinted finding
cards) is adapted from Anna's own `forge` project's HTML reporter
(`forge/report.py`) — a self-contained, dependency-free single-file HTML
report with the same design goal: evidence-first, no external CSS/JS, a
tone (ok/fail/caution/muted) that reads at a glance. `forge`'s tone comes
from a seal PASS/FAIL; ZAYNOR's comes from the verdict scale
(`_VERDICT_TONE`), since a report here explains a forensic verdict, not a
code-audit seal status.

Every renderer here is read-only over an already-sealed result and its seal.
Nothing here computes a verdict, a score, or a new finding — a report is a
projection, and `result_sha256` is printed on every format precisely so a
reader can independently re-verify the projection did not drift from the
seal (`zaynor audit`).
"""

from __future__ import annotations

import hashlib
from typing import Any
from xml.sax.saxutils import escape

from zaynor.argentina_time import format_argentina
from zaynor.authority_seal import AuthoritySeal
from zaynor.schemas import AuthoritativeFinding, ZaynorAuthoritativeResult


class ReportError(RuntimeError):
    """A report could not be rendered."""


def _custody_rows(result: ZaynorAuthoritativeResult) -> list[tuple[str, str, str]]:
    rows = []
    for finding in result.findings:
        for ref in finding.evidence_refs:
            rows.append((finding.finding_id, ref.artifact, ref.lineage_id))
    return rows


_ENGINE_DISPLAY_NAME = "ZAYNOR deterministic engine (Mode 1)"


def _engine_display(result: ZaynorAuthoritativeResult) -> str:
    """A client-facing report names ZAYNOR, not its vendored internals.

    `result.engine["name"]` is literally the string "vigia_agent" (real
    provenance metadata, correct for an internal audit trail) -- but this
    function's output is what a perito or a court reads, and ZAYNOR is its
    own product (AGENTS.md 2.1 / this session's own "no quiero mezclar a
    VIGIA, ESTE es otro producto" instruction). The version number is real
    and shown; the raw engine name is not.
    """
    version = result.engine.get("version", "")
    return f"{_ENGINE_DISPLAY_NAME} {version}".rstrip()


def _state_tone(state: str) -> str:
    """Same tone vocabulary as `_VERDICT_TONE`, applied to a per-finding
    state. Falls back to "muted" for a state outside that vocabulary
    (e.g. a synthetic test fixture's "CORROBORATED") rather than guessing.
    """
    return _VERDICT_TONE.get(state, "muted")


def _engine_stats(result: ZaynorAuthoritativeResult) -> list[tuple[str, str]]:
    """Stat tiles built only from fields the pipeline actually populates.

    `result.integrity["confidence"]` is part of the schema (some test
    fixtures and future engine paths set it) but the real Mode 1 adapter
    path (`zaynor_mode1_executor.py`) never writes it -- every report from
    a real `zaynor analyze` run would otherwise show a permanent
    "Confidence: UNKNOWN" tile. `iterations_executed` and
    `self_corrections_applied` are what that same path always writes, so
    they anchor the stat row whether or not `confidence` is present.
    """
    stats: list[tuple[str, str]] = []
    if "confidence" in result.integrity:
        stats.append(("Confidence", str(result.integrity["confidence"])))
    stats.append(("Iterations", str(result.integrity.get("iterations_executed", "UNKNOWN"))))
    stats.append(("Self-corrections", str(result.integrity.get("self_corrections_applied", "UNKNOWN"))))
    stats.append(("Engine", _engine_display(result)))
    stats.append(("Findings", str(len(result.findings))))
    return stats


_METHODOLOGY = (
    "The deterministic engine produces and seals the result before any "
    "language model is invoked. The model receives a compressed, read-only "
    "summary and narrates it; it cannot alter a verdict, a finding, or the "
    "seal. Every claim in a narration is checked against this sealed result "
    "before being shown (zaynor chat/serve). result_sha256 is the canonical "
    "SHA-256 seal of the authoritative result: recompute it independently "
    "with `zaynor audit` to confirm this report was not altered after the "
    "fact."
)


def render_markdown(result: ZaynorAuthoritativeResult, seal: AuthoritySeal) -> str:
    generated_at = format_argentina()
    lines = [
        f"# ZAYNOR Forensic Report — {result.case_id}",
        "",
        f"*Generated {generated_at} (Argentina time)*",
        "",
        "## Overview — what kind of incident this is",
        "",
        f"- **Case:** {result.case_id}",
        f"- **Classification:** {_incident_classification(result)}",
        f"- **Result SHA-256:** `{seal.sha256}`",
        *[f"- **{label}:** {value}" for label, value in _engine_stats(result)],
        f"- **Unknowns:** {len(result.unknowns)}",
        "",
        "## Agents in this pipeline",
        "",
        "| Role | Status | What it actually does |",
        "|---|---|---|",
    ]
    lines += [f"| {name} | {status} | {note} |" for name, status, note in _AGENTS]
    lines += [
        "",
        "Findings themselves come from ZAYNOR's own deterministic Mode 1 engine, not "
        "from a named agent above -- no per-finding agent attribution exists in "
        "the sealed contract (`AuthoritativeFinding` has no agent field). This "
        "table names what ZAYNOR's own local, Ollama-driven agent layer does "
        "around that sealed result.",
        "",
        "## Findings",
        "",
    ]
    if not result.findings:
        lines.append("No findings in this result.")
    else:
        lines.append("| Finding | State | MITRE | Detected by | Rationale |")
        lines.append("|---|---|---|---|---|")
        for finding in result.findings:
            technique = (finding.mitre or {}).get("technique", "-") if finding.mitre else "-"
            rationale = finding.rationale.replace("|", "\\|") or "-"
            lines.append(
                f"| {finding.finding_id} | {finding.state} | {technique} "
                f"| {_ENGINE_DISPLAY_NAME} | {rationale} |"
            )
        lines.append("")
        for finding in result.findings:
            if finding.evidence_refs:
                refs = ", ".join(f"`{ref.artifact}` → `{ref.lineage_id}`" for ref in finding.evidence_refs)
                lines.append(f"- **{finding.finding_id} evidence:** {refs}")
    lines += ["", "## Unknowns", ""]
    if result.unknowns:
        lines += [f"- {unknown}" for unknown in result.unknowns]
    else:
        lines.append("None declared.")
    lines += ["", "## Chain of custody", "", "```"]
    lines += [f"{label:<28}: {value}" for label, value in _custody_chain(seal, generated_at=generated_at)]
    lines += ["```", "", "## Methodology", "", _METHODOLOGY, ""]
    return "\n".join(lines)


def _escape_html(text: str) -> str:
    return (
        text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    )


_VERDICT_TONE = {
    "MALICE": "fail",
    "SUSPICION": "caution",
    "INTENT": "caution",
    "BENIGN": "ok",
    "NOISE": "ok",
    "ABSTAIN": "muted",
    "UNKNOWN": "muted",
}


def _finding_card(finding: AuthoritativeFinding) -> str:
    technique = (finding.mitre or {}).get("technique", "-") if finding.mitre else "-"
    tone = _state_tone(finding.state)
    refs = "".join(
        f"<li><code>{_escape_html(ref.artifact)}</code> → <code>{_escape_html(ref.lineage_id)}</code></li>"
        for ref in finding.evidence_refs
    ) or "<li>No evidence references recorded.</li>"
    return f"""<article class="finding-card sev-{tone}">
  <div class="finding-head">
    <span class="badge state sev-{tone}">{_escape_html(finding.state)}</span>
    <span class="ref">{_escape_html(finding.finding_id)}</span>
    {f'<span class="badge mitre">{_escape_html(technique)}</span>' if technique != "-" else ""}
  </div>
  <p><strong>Detected by:</strong> {_ENGINE_DISPLAY_NAME} — no LLM in the decision path.</p>
  <p>{_escape_html(finding.rationale or "No rationale recorded.")}</p>
  <details><summary>Evidence chain</summary><ul>{refs}</ul></details>
</article>"""


# Real status of ZAYNOR's own agent roles -- not per-finding attribution
# (AuthoritativeFinding carries no agent field: findings come from the
# deterministic Mode 1 engine, not a named ZAYNOR sub-agent) but an honest
# account of what actually runs during a normal analyze/report, versus
# code that exists and is tested but has no automatic caller yet, versus
# out of scope. Verified by grepping cli.py/api.py for each tool function
# before writing this table -- "conectado" is reserved for the one role a
# normal run actually invokes; the others are real, tested library code
# waiting on a CLI/API entry point that does not exist yet.
_AGENTS = (
    ("MENTOR", "conectado", "Narrates an already-sealed result via zaynor chat/serve; never re-invokes the engine."),
    ("DISPATCHER", "conectado", "Catalog of evidence types the engine can actually analyze, via zaynor hunts."),
    ("CONSULT", "conectado", "Read-only view of a sealed case (findings, framework context, hunts), via zaynor consult."),
    ("INVESTIGATOR", "implementado, sin invocación automática", "Collects a bounded evidence window and re-verifies custody hashes; real and tested, no CLI/API command calls it yet."),
    ("FLEET_COMMANDER", "implementado, sin invocación automática", "Writes to the investigation log; real and tested, no caller wired yet."),
    ("DETECTION_ENGINEER", "implementado, sin invocación automática", "Drafts a candidate detection rule anchored to a real sealed finding; real and tested, not wired to a command yet."),
    ("ENDPOINT_HUNTER / PERSISTENCE_HUNTER", "out of scope", "Would need a live EDR collection backend this project does not have."),
    ("THREAT_INTEL", "out of scope, for now", "A portable VirusTotal/GTI enrichment exists but is not wired in — external network dependency, pending decision."),
)

_MITRE_TACTIC_HINT = {
    "T1078": "Valid Accounts",
    "T1059": "Command and Scripting Interpreter",
    "T1053": "Scheduled Task/Job",
    "T1071": "Application Layer Protocol",
    "T1070": "Indicator Removal",
}


def _incident_classification(result: ZaynorAuthoritativeResult) -> str:
    """What kind of incident this is, from the only two authoritative
    sources a sealed result actually carries: the verdict itself (VIGIA's
    own classification scale) and the MITRE techniques attached to real
    findings. Never inferred beyond that — an empty findings set means an
    honest "no technique corroborated", not a guess.
    """
    techniques = sorted(
        {(f.mitre or {}).get("technique") for f in result.findings if f.mitre and f.mitre.get("technique")}
    )
    if not techniques:
        return f"{result.verdict} — no ATT&CK technique corroborated"
    labels = []
    for technique in techniques:
        base = technique.split(".")[0]
        hint = _MITRE_TACTIC_HINT.get(base)
        labels.append(f"{technique} ({hint})" if hint else technique)
    return f"{result.verdict} — " + ", ".join(labels)


def _agents_html() -> str:
    rows = "".join(
        f"<tr><td><code>{_escape_html(name)}</code></td><td>{_escape_html(status)}</td><td>{_escape_html(note)}</td></tr>"
        for name, status, note in _AGENTS
    )
    return (
        '<table class="data-table"><tr><th>Role</th><th>Status</th><th>What it actually does</th></tr>'
        f"{rows}</table>"
    )


def _custody_chain(seal: AuthoritySeal, *, generated_at: str) -> list[tuple[str, str]]:
    """Exactly two hashes, not VIGIA's four (manifest/snapshot/engine/seal —
    real, but too many for a reader to hold onto at a glance; each of the
    other two is still independently recomputable via `zaynor audit`, they
    are just not the headline of this report).

    One is bit-for-bit deterministic: `seal.sha256` never changes for the
    same frozen case, reproducible by anyone who reruns `zaynor analyze`.
    The other varies by design: `report_hash` folds in *when this specific
    report was generated* (Argentina time — CLAUDE.md 5.2 keeps that
    timestamp out of the sealed result itself; it only ever touches this
    report-level, non-authoritative hash), so two reports of the identical
    sealed result still produce distinguishable report_hash values.
    """
    report_hash = hashlib.sha256(f"{seal.sha256}:{generated_at}".encode("utf-8")).hexdigest()
    return [
        ("result_sha256 (deterministic)", seal.sha256),
        ("report_hash (timestamped)", report_hash),
    ]


def render_html(result: ZaynorAuthoritativeResult, seal: AuthoritySeal) -> str:
    generated_at = format_argentina()
    tone = _VERDICT_TONE.get(result.verdict, "muted")
    findings_html = "".join(_finding_card(f) for f in result.findings) or (
        '<p class="empty-state">No findings in this result.</p>'
    )
    unknowns_items = "".join(f"<li>{_escape_html(u)}</li>" for u in result.unknowns) or "<li>None declared.</li>"
    chain_block = "\n".join(f"{label:<28}: {value}" for label, value in _custody_chain(seal, generated_at=generated_at))
    stat_tiles = "".join(
        f'<div class="stat-tile"><strong>{_escape_html(label)}</strong><span>{_escape_html(value)}</span></div>'
        for label, value in _engine_stats(result)
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>ZAYNOR Forensic Report — {_escape_html(result.case_id)}</title>
<style>
:root{{
  --bg:#E3B8B8; --bg-elevated:#FFFFFF; --bg-sunken:#E8E9E3;
  --ink:#1C2222; --ink-muted:#5B6460; --ink-faint:#8B9490;
  --rule:#D5D6CE; --rule-strong:#B9BBB0; --accent:#2B5D63; --accent-soft:#DCE7E6;
  --ok:#3C7A52; --ok-bg:#DFEDE2; --ok-ink:#2A5A3C;
  --fail:#A8501C; --fail-bg:#F6E3D5; --fail-ink:#7A3A14;
  --caution-bg:#F4EED8; --caution-ink:#765D1C; --caution-border:#CDBB78;
  --muted-bg:#E8E9E3; --muted-ink:#5B6460;
  --serif: "Iowan Old Style","Palatino Linotype",Palatino,"Book Antiqua",Georgia,"Times New Roman",serif;
  --sans: -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
  --mono: "SF Mono","IBM Plex Mono",Menlo,Consolas,"Liberation Mono",monospace;
  --shadow: 0 1px 2px rgba(28,34,34,.08), 0 4px 14px rgba(28,34,34,.06);
}}
*{{box-sizing:border-box;}}
body{{ margin:0; background:var(--bg); color:var(--ink); font-family:var(--sans); font-size:16px; line-height:1.55; -webkit-font-smoothing:antialiased; }}
::selection{{ background:var(--accent-soft); }}
a{{ color:var(--accent); }}
code{{ font-family:var(--mono); }}
.wrap{{ max-width:1100px; margin:0 auto; padding:0 28px 96px; }}
header.masthead{{ border-bottom:2px solid var(--ink); padding:40px 0 22px; margin-bottom:36px; }}
header.masthead h1{{ font-family:var(--serif); font-weight:600; font-size:clamp(26px,4vw,38px); margin:0 0 14px; letter-spacing:.003em; }}
.seal-line{{ display:inline-block; font-family:var(--mono); font-size:13px; letter-spacing:.03em; padding:6px 12px; border-radius:14px; }}
.seal-line.ok{{ background:var(--ok-bg); color:var(--ok-ink); }}
.seal-line.fail{{ background:var(--fail-bg); color:var(--fail-ink); }}
.seal-line.caution{{ background:var(--caution-bg); color:var(--caution-ink); }}
.seal-line.muted{{ background:var(--muted-bg); color:var(--muted-ink); }}
.generated-at{{ font-family:var(--mono); font-size:11.5px; color:var(--ink-muted); margin:10px 0 0; }}
.summary-grid{{ display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:10px; margin:24px 0 18px; }}
.stat-tile{{ border:1px solid var(--rule); border-radius:3px; padding:13px 15px; background:var(--bg-sunken); }}
.stat-tile strong{{ display:block; color:var(--ink-muted); font:11px var(--mono); text-transform:uppercase; letter-spacing:.04em; }}
.stat-tile span{{ display:block; font:600 18px var(--serif); margin-top:4px; word-break:break-all; }}
section{{ background:var(--bg-elevated); border:1px solid var(--rule); border-radius:3px; margin:1.5rem 0; padding:22px 24px; box-shadow:var(--shadow); }}
section h2{{ font-family:var(--serif); font-size:20px; font-weight:600; margin:0 0 14px; padding-bottom:10px; border-bottom:1px solid var(--rule); }}
#findings h2{{ color:var(--accent); }}
.finding-card{{ border:1px solid var(--rule); border-left:6px solid var(--accent); border-radius:3px; padding:14px 18px; margin:14px 0; background:var(--bg-elevated); }}
.finding-card.sev-fail{{ border-left-color:var(--fail); }}
.finding-card.sev-caution{{ border-left-color:var(--caution-border); }}
.finding-card.sev-ok{{ border-left-color:var(--ok); }}
.finding-card.sev-muted{{ border-left-color:var(--rule-strong); }}
.finding-head{{ display:flex; gap:8px; align-items:center; flex-wrap:wrap; margin-bottom:6px; }}
.badge{{ font-family:var(--mono); font-size:10.5px; letter-spacing:.06em; text-transform:uppercase; background:var(--accent-soft); color:var(--accent); border:1px solid var(--rule-strong); padding:3px 9px; border-radius:11px; }}
.badge.mitre{{ background:var(--caution-bg); color:var(--caution-ink); border-color:var(--caution-border); }}
.badge.state.sev-fail{{ background:var(--fail-bg); color:var(--fail-ink); border-color:var(--fail); }}
.badge.state.sev-caution{{ background:var(--caution-bg); color:var(--caution-ink); border-color:var(--caution-border); }}
.badge.state.sev-ok{{ background:var(--ok-bg); color:var(--ok-ink); border-color:var(--ok); }}
.badge.state.sev-muted{{ background:var(--muted-bg); color:var(--muted-ink); border-color:var(--rule-strong); }}
.ref{{ font-family:var(--mono); font-size:12.5px; color:var(--ink-muted); }}
.finding-card p{{ margin:6px 0; font-size:14px; }}
.finding-card details{{ font-size:13px; color:var(--ink-muted); }}
.finding-card ul{{ margin:6px 0 0; padding-left:18px; }}
.empty-state{{ color:var(--ink-faint); font-style:italic; }}
ul.plain{{ padding-left:18px; }}
.chain-block{{ font-family:var(--mono); font-size:13px; background:var(--bg-sunken); padding:14px 18px; border-radius:3px; white-space:pre-wrap; }}
nav.toc{{ display:flex; flex-wrap:wrap; gap:8px; margin-top:14px; }}
nav.toc a{{ border:1px solid var(--rule-strong); border-radius:14px; padding:4px 10px; background:var(--bg-elevated); color:var(--accent); font:11px var(--mono); text-decoration:none; text-transform:uppercase; letter-spacing:.04em; }}
nav.toc a:hover{{ background:var(--bg-sunken); }}
.overview-grid{{ display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:10px; }}
.overview-card{{ border:1px solid var(--rule); background:var(--bg-sunken); padding:11px 13px; border-radius:3px; }}
.overview-card span{{ display:block; color:var(--ink-muted); font:11px var(--mono); text-transform:uppercase; letter-spacing:.04em; }}
.overview-card strong{{ display:block; margin-top:4px; font-size:15px; overflow-wrap:anywhere; }}
.data-table{{ border-collapse:collapse; width:100%; }}
.data-table td, .data-table th{{ text-align:left; padding:8px 12px; border-bottom:1px solid var(--rule); font-size:13.5px; vertical-align:top; }}
.data-table th{{ font-family:var(--mono); font-size:11px; text-transform:uppercase; letter-spacing:.06em; color:var(--ink-muted); background:var(--bg-sunken); }}
.data-table tr:last-child td{{ border-bottom:none; }}
.engine-note{{ font-family:var(--mono); font-size:11.5px; color:var(--ink-muted); margin-top:8px; }}
.seal-line, .badge, .stat-tile, .finding-card{{ -webkit-print-color-adjust:exact; print-color-adjust:exact; }}
@media print {{
  body{{ background:#fff; }}
  nav.toc{{ display:none; }}
  section{{ box-shadow:none; break-inside:avoid; page-break-inside:avoid; }}
  .finding-card{{ break-inside:avoid; page-break-inside:avoid; }}
  a{{ color:inherit; text-decoration:none; }}
}}
</style>
</head>
<body>
<div class="wrap">
<header class="masthead">
<h1>ZAYNOR Forensic Report — {_escape_html(result.case_id)}</h1>
<span class="seal-line {tone}">verdict: {_escape_html(result.verdict)} — sealed, verify with `zaynor audit`</span>
<p class="generated-at">Generated {_escape_html(generated_at)} (Argentina time)</p>
<div class="summary-grid">{stat_tiles}</div>
<nav class="toc">
<a href="#overview">Overview</a><a href="#agents">Agents</a><a href="#findings">Findings</a>
<a href="#unknowns">Unknowns</a><a href="#chain-of-custody">Chain of custody</a><a href="#methodology">Methodology</a>
</nav>
</header>
<section id="overview"><h2>Overview — what kind of incident this is</h2>
<div class="overview-grid">
<div class="overview-card"><span>Case</span><strong>{_escape_html(result.case_id)}</strong></div>
<div class="overview-card"><span>Classification</span><strong>{_escape_html(_incident_classification(result))}</strong></div>
<div class="overview-card"><span>Findings / Unknowns</span><strong>{len(result.findings)} / {len(result.unknowns)}</strong></div>
</div>
</section>
<section id="agents"><h2>Agents in this pipeline</h2>{_agents_html()}
<p class="engine-note">Findings themselves come from ZAYNOR's own deterministic Mode 1 engine, not from a named agent above — no per-finding agent attribution exists in the sealed contract (AuthoritativeFinding has no agent field). This table names what ZAYNOR's own local, Ollama-driven agent layer does around that sealed result.</p>
</section>
<section id="findings"><h2>Findings</h2>{findings_html}</section>
<section id="unknowns"><h2>Unknowns</h2><ul class="plain">{unknowns_items}</ul></section>
<section id="chain-of-custody"><h2>Chain of custody</h2><div class="chain-block">{_escape_html(chain_block)}</div></section>
<section id="methodology"><h2>Methodology</h2><p>{_escape_html(_METHODOLOGY)}</p></section>
</div>
</body>
</html>
"""


def render_pdf(result: ZaynorAuthoritativeResult, seal: AuthoritySeal) -> bytes:
    """Render a PDF via reportlab — same library VIGIA's own Daubert-grade
    reporter uses, imported lazily so the rest of ZAYNOR has no hard
    dependency on it (mirrors `zaynor serve`'s optional `[api]` extra).
    """
    try:
        from io import BytesIO

        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError as exc:
        raise ReportError("PDF reports require the optional 'report' dependency: pip install -e '.[report]'") from exc

    tone_colors = {
        "ok": (colors.HexColor("#DFEDE2"), colors.HexColor("#2A5A3C")),
        "fail": (colors.HexColor("#F6E3D5"), colors.HexColor("#7A3A14")),
        "caution": (colors.HexColor("#F4EED8"), colors.HexColor("#765D1C")),
        "muted": (colors.HexColor("#E8E9E3"), colors.HexColor("#5B6460")),
    }

    def _footer(canvas, doc_) -> None:
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.grey)
        canvas.drawString(36, 20, f"ZAYNOR sealed forensic report -- result_sha256 {seal.sha256[:16]}... -- verify with `zaynor audit`")
        canvas.drawRightString(A4[0] - 36, 20, f"Page {doc_.page}")
        canvas.restoreState()

    styles = getSampleStyleSheet()
    table_header_style = styles["Normal"].clone("ZaynorTableHeader")
    table_header_style.fontSize = 8
    table_header_style.leading = 10
    table_cell_style = styles["Normal"].clone("ZaynorTableCell")
    table_cell_style.fontSize = 8
    table_cell_style.leading = 10
    table_cell_style.wordWrap = "CJK"

    def _table(rows: list[list[str]], col_widths: list[int] | None = None, row_tones: list[str | None] | None = None) -> Table:
        # Plain strings are not wrappable Table cells in ReportLab.  Long
        # roles and finding rationales consequently run past the page edge.
        wrapped_rows = [
            [
                Paragraph(
                    escape(str(cell)).replace("\n", "<br/>") or "&#160;",
                    table_header_style if row_index == 0 else table_cell_style,
                )
                for cell in row
            ]
            for row_index, row in enumerate(rows)
        ]
        if col_widths is None:
            col_widths = [110, 75, 338] if len(rows[0]) == 3 else [70, 65, 70, 95, 223]
        table = Table(wrapped_rows, repeatRows=1, colWidths=col_widths)
        style_commands = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]
        if row_tones:
            for row_index, tone in enumerate(row_tones, start=1):
                if tone is not None:
                    bg, _ = tone_colors.get(tone, tone_colors["muted"])
                    style_commands.append(("BACKGROUND", (0, row_index), (-1, row_index), bg))
        table.setStyle(TableStyle(style_commands))
        return table

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, title=f"ZAYNOR Forensic Report — {result.case_id}")
    generated_at = format_argentina()
    verdict_tone = _VERDICT_TONE.get(result.verdict, "muted")
    verdict_bg, verdict_ink = tone_colors.get(verdict_tone, tone_colors["muted"])
    verdict_style = styles["Normal"].clone("ZaynorVerdictBanner")
    verdict_style.fontSize = 12
    verdict_style.textColor = verdict_ink
    verdict_banner = Table(
        [[Paragraph(f"VERDICT: {escape(result.verdict)} -- sealed, verify with `zaynor audit`", verdict_style)]],
        colWidths=[523],
    )
    verdict_banner.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), verdict_bg), ("BOX", (0, 0), (-1, -1), 0.5, verdict_ink), ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8), ("LEFTPADDING", (0, 0), (-1, -1), 10)]))
    story: list[Any] = [
        Paragraph(f"ZAYNOR Forensic Report — {escape(result.case_id)}", styles["Title"]),
        Spacer(1, 8),
        verdict_banner,
        Spacer(1, 12),
        Paragraph("Overview — what kind of incident this is", styles["Heading2"]),
        Paragraph(f"Classification: {escape(_incident_classification(result))}", styles["Normal"]),
        Paragraph(f"Result SHA-256: {seal.sha256}", styles["Normal"]),
        *[Paragraph(f"{escape(label)}: {escape(value)}", styles["Normal"]) for label, value in _engine_stats(result)],
        Paragraph(f"Unknowns: {len(result.unknowns)}", styles["Normal"]),
        Spacer(1, 12),
        Paragraph("Agents in this pipeline", styles["Heading2"]),
        _table([["Role", "Status", "What it actually does"], *[[n, s, note] for n, s, note in _AGENTS]]),
        Paragraph(
            "Findings come from ZAYNOR's own deterministic Mode 1 engine, not from a named agent above "
            "-- no per-finding agent attribution exists in the sealed contract.",
            styles["Normal"],
        ),
        Spacer(1, 12),
        Paragraph("Findings", styles["Heading2"]),
    ]
    finding_table = [["Finding", "State", "MITRE", "Detected by", "Rationale"]]
    row_tones: list[str | None] = []
    for finding in result.findings:
        technique = (finding.mitre or {}).get("technique", "-") if finding.mitre else "-"
        finding_table.append(
            [finding.finding_id, finding.state, technique, _ENGINE_DISPLAY_NAME, finding.rationale or "-"]
        )
        row_tones.append(_state_tone(finding.state))
    if len(finding_table) == 1:
        finding_table.append(["-", "-", "-", "-", "No findings in this result."])
        row_tones.append(None)
    story += [_table(finding_table, row_tones=row_tones), Spacer(1, 12), Paragraph("Unknowns", styles["Heading2"])]
    for unknown in result.unknowns or ["None declared."]:
        story.append(Paragraph(f"- {escape(str(unknown))}", styles["Normal"]))
    story += [Spacer(1, 12), Paragraph("Chain of custody", styles["Heading2"])]
    for label, value in _custody_chain(seal, generated_at=generated_at):
        story.append(Paragraph(f"{escape(label)}: {escape(value)}", styles["Code"]))
    story += [Spacer(1, 12), Paragraph("Methodology", styles["Heading2"]), Paragraph(_METHODOLOGY, styles["Normal"])]
    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buffer.getvalue()
