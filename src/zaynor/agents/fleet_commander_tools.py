"""FLEET_COMMANDER role tool handlers — thin, bounded wrappers over
`investigation_log.py`'s journal.

`investigation_log.py` was itself ADAPTED from ANNACONDA's
`agent/mission.py` (hypothesis/open-question/sealed-journal subset only)
— its own docstring documents what was deliberately dropped: the whole
autonomous cron-wakeup loop (`schedule_next_action`/`begin_cycle`/
`is_due`/`acknowledge_escalation`'s escalation-rank machinery), because
ZAYNOR's investigator, if used, runs synchronously within one case's
investigation, not across weeks of asynchronous sweeps. These six tools
honor that same boundary: each is a single, bounded journal write — never
a recurring schedule, never something that itself notifies anyone or
blocks the investigation waiting for a human. A human or external system
observes the journal to act on what's recorded here.

None of these six tools ever produce or read a VIGÍA verdict, or reach
authoritative claim state — `record_hypothesis_proposal`'s hypothesis is
`open`/`supported`/`refuted` (see `investigation_log.HYPOTHESIS_STATES`),
never a `CORROBORATED`/`CONTRADICTED`/`INSUFFICIENT` finding. That
distinction is the entire reason for this tool's `_proposal` name
qualifier — see red-team round 5 (R5-1): a name that implied ZAYNOR's
local agent "registers hypotheses" with authority was exactly the
authority creep AGENTS.md exists to prevent, even when correctly scoped
underneath.
"""

from __future__ import annotations

from typing import Any

from zaynor.investigation_log import InvestigationLogError, add_hypothesis, record, verify_log


class FleetCommanderToolError(ValueError):
    """A FLEET_COMMANDER tool call could not be completed."""


def _required_text(arguments: dict[str, Any], field: str, tool: str) -> str:
    value = arguments.get(field)
    if not isinstance(value, str) or not value.strip():
        raise FleetCommanderToolError(f"{tool} requires a non-empty string {field!r}")
    return value


def read_mission(log: dict, arguments: dict[str, Any]) -> Any:
    """READ:case_memory — a bounded summary of the investigation journal,
    analogous to ANNACONDA `mission.py`'s `brief()`, without the fields
    (escalation rank, next-cycle timing) this repo does not carry.
    """
    verification = verify_log(log)
    return {
        "case_id": log.get("case_id"),
        "journal_entries": verification["journal_entries"],
        "log_ok": verification["log_ok"],
        "hypotheses": list(log.get("hypotheses", [])),
        "open_questions": list(log.get("open_questions", [])),
    }


def record_hypothesis_proposal(log: dict, arguments: dict[str, Any]) -> Any:
    """DERIVE:investigation_plan — proposes a hypothesis for a human (or,
    eventually, the VIGÍA-backed gate AGENTS.md §2.3 describes) to later
    corroborate or refute. Never itself an authoritative claim.
    """
    text = _required_text(arguments, "text", "record_hypothesis_proposal")
    actor = arguments.get("actor", "fleet-commander")
    try:
        return add_hypothesis(log, actor=actor, text=text)
    except InvestigationLogError as exc:
        raise FleetCommanderToolError(str(exc)) from exc


def task_specialist(log: dict, arguments: dict[str, Any]) -> Any:
    """DERIVE:investigation_plan — records that a specialist role was
    assigned a task. Does NOT itself dispatch or run another agent: no
    specialist-invocation runtime exists yet. This is a journal entry
    documenting intent, for a human or a future orchestrator to act on —
    an honest scope limit, not a stub pretending to be the real thing.
    """
    specialist = _required_text(arguments, "specialist", "task_specialist")
    reason = _required_text(arguments, "reason", "task_specialist")
    return record(
        log,
        actor="fleet-commander",
        action="TASK_SPECIALIST",
        detail={"specialist": specialist, "reason": reason},
    )


def schedule_review(log: dict, arguments: dict[str, Any]) -> Any:
    """DERIVE:investigation_plan — records a one-shot request for a later
    review. Never a recurring/cron schedule — that loop is explicitly out
    of scope (see this module's docstring).
    """
    reason = _required_text(arguments, "reason", "schedule_review")
    return record(log, actor="fleet-commander", action="SCHEDULE_REVIEW", detail={"reason": reason})


def escalate_human(log: dict, arguments: dict[str, Any]) -> Any:
    """DERIVE:investigation_plan — records a request for human attention.
    Never itself notifies anyone or blocks the investigation waiting for
    a response; a human or external system must observe the journal.
    """
    why = _required_text(arguments, "why", "escalate_human")
    return record(log, actor="fleet-commander", action="ESCALATE_HUMAN", detail={"why": why})


def stand_down(log: dict, arguments: dict[str, Any]) -> Any:
    """DERIVE:investigation_plan — records that the investigator is
    ending its own turn/session. A bounded terminal entry, not a
    resumable cron state (ANNACONDA's `is_due`/`begin_cycle` are not
    ported — see this module's docstring).
    """
    rationale = _required_text(arguments, "rationale", "stand_down")
    return record(log, actor="fleet-commander", action="STAND_DOWN", detail={"rationale": rationale})


def build_fleet_commander_tools(log: dict) -> dict[str, Any]:
    """The real FLEET_COMMANDER tool set for
    `AgentRuntime.run(AgentRole.FLEET_COMMANDER, tools=build_fleet_commander_tools(log))`.

    `log` is one case's investigation journal
    (`investigation_log.new_investigation_log` or a resumed one) —
    mutated in place by every DERIVE tool here.
    """
    return {
        "read_mission": lambda arguments: read_mission(log, arguments),
        "task_specialist": lambda arguments: task_specialist(log, arguments),
        "record_hypothesis_proposal": lambda arguments: record_hypothesis_proposal(log, arguments),
        "schedule_review": lambda arguments: schedule_review(log, arguments),
        "escalate_human": lambda arguments: escalate_human(log, arguments),
        "stand_down": lambda arguments: stand_down(log, arguments),
    }
