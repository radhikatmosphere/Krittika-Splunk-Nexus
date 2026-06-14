# agent_core/ethics.py — Three-principle decision ethics for Krittika-Splunk Nexus
# RADHIKATMOSPHERE / Krittika-Splunk Nexus
#
# Implements three Sanskrit / Buddhist principles as decision constraints:
#
#   1. Ahimsa (No-violence / Fail-open)
#      The system operates in fail-open mode by default. Block-and-isolate
#      actions require CONSENSUS — multiple independent signals agreeing.
#      When evidence is ambiguous, the system prefers availability over
#      strict-security.
#
#   2. Karma Temporal (Time-to-live blocks)
#      No block is perpetual. Every blocking action has a TTL. The system
#      allows redemption — blocked nodes are re-evaluated at TTL expiry, and
#      the block is lifted if evidence no longer supports it.
#
#   3. Shunyata (Non-punitive neutralization)
#      Threats are deactivated without harming the source. We DROP packets,
#      we don't blast the offender. We QUARANTINE processes, we don't kill
#      the host. The body's immune system metaphor: wall off the infection,
#      not amputate the limb.
#
# These principles are encoded as discrete rules the DecisionEngine queries
# before producing a final action. They are intentionally simple and
# declarative -- easy to test, audit, and override.
from __future__ import annotations
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional


# ---------------------------------------------------------------------------
# TTL table (Karma Temporal)
# ---------------------------------------------------------------------------
# Defines how long each blocking action persists. After TTL expires, the
# node is automatically re-evaluated using the same Ahimsa consensus rule.
DEFAULT_TTL_HOURS = {
    "ISOLATE_NODE":        24,    # isolation is reversible — review in 1 day
    "QUARANTINE_PROCESS":  6,     # tighter — review in 6 hours
    "ACTIVATE_XDP_BLOCK":  12,    # block IP at the kernel — review in 12 hours
    "INVESTIGATE_DEEP":    None,  # no block, no TTL needed
    "DISMISS":             None,  # no block, no TTL needed
    "SKIP":                None,  # no block, no TTL needed
}


# ---------------------------------------------------------------------------
# Consensus requirement (Ahimsa)
# ---------------------------------------------------------------------------
# Each action must clear these minimum-evidence thresholds before the
# agent is permitted to emit it. Evidence counts are integers — typically
# fed from eBPF events, port-scan sources, and alert severity rank.
MIN_CONSENSUS = {
    "ISOLATE_NODE": {
        "min_alert_severity_rank":  3,    # CRITICAL only
        "min_external_threats":     1,    # ≥ 1 anomalous external IP
        "min_internal_correlation": 1,    # ≥ 1 validator target bound
    },
    "QUARANTINE_PROCESS": {
        "min_alert_severity_rank":  2,    # HIGH or CRITICAL
        "min_external_threats":     0,    # internal-only OK (insider scenario)
        "min_internal_correlation": 1,
    },
    "ACTIVATE_XDP_BLOCK": {
        "min_alert_severity_rank":  2,    # HIGH or CRITICAL
        "min_external_threats":     1,
        "min_internal_correlation": 0,
    },
    "INVESTIGATE_DEEP": {
        "min_alert_severity_rank":  1,    # WARN or above
        "min_external_threats":     0,
        "min_internal_correlation": 0,
    },
    "DISMISS": {
        "min_alert_severity_rank":  0,    # anything
        "min_external_threats":     0,
        "min_internal_correlation": 0,
    },
    "SKIP":     {},
}


# Severity-rank map for alerts. Falls back to 1 (INFO/WARN).
SEVERITY_RANK = {"CRITICAL": 3, "HIGH": 2, "WARN": 1, "INFO": 0}


def _alert_rank(text: str) -> int:
    upper = text.upper()
    for tag, rank in SEVERITY_RANK.items():
        if upper.startswith(tag + ":") or f" {tag}:" in upper:
            return max(rank, _alert_rank(other_parts(text, tag)))
    return 1


def other_parts(text: str, tag: str) -> str:
    """Strip leading SEVERITY tag for recursion (helper for compound alerts)."""
    return text.replace(f"{tag}:", "", 1)


# ---------------------------------------------------------------------------
# Decision objects
# ---------------------------------------------------------------------------

@dataclass
class EthicalDecision:
    """Wraps an agent-decision with the three-principle audit."""
    action: str
    severity: str
    target: Optional[str]
    rationale: str
    next_step: str

    # Karma Temporal
    ttl_hours: Optional[int] = None
    ttl_expires_at: Optional[str] = None

    # Ahimsa
    fail_open: bool = True
    consensus_clear: bool = False
    consensus_blockers: list[str] = field(default_factory=list)

    # Shunyata
    non_punitive: bool = True
    punishment_warnings: list[str] = field(default_factory=list)

    def audit_block(self) -> str:
        """One-line audit string for logs."""
        return (
            f"action={self.action} severity={self.severity} "
            f"target={self.target or '-'} "
            f"ttl_hours={self.ttl_hours if self.ttl_hours is not None else '∞'} "
            f"non_punitive={self.non_punitive} "
            f"consensus={'OK' if self.consensus_clear else 'BLOCKED'}"
        )


# ---------------------------------------------------------------------------
# Ahimsa: Fail-open + consensus gate
# ---------------------------------------------------------------------------

def ahimsa_gate(action: str, alert_text: str, evidence: dict) -> tuple[bool, list[str]]:
    """Apply the Ahimsa principle: only block when the evidence consensus
    is unambiguous. Returns (allowed, blockers).

    Evidence dict should contain:
      - alert_severity_rank : int (0..3)
      - external_threats    : int (0+)
      - internal_correlation: int (0+)
      - anomaly_events      : int (0+)
    """
    blockers: list[str] = []
    thresholds = MIN_CONSENSUS.get(action, {})
    if not thresholds:
        return True, []  # DISMISS / SKIP always allowed

    if evidence.get("alert_severity_rank", 0) < thresholds["min_alert_severity_rank"]:
        blockers.append(
            f"alert severity rank {evidence.get('alert_severity_rank',0)} "
            f"< {thresholds['min_alert_severity_rank']} required for {action}"
        )
    if evidence.get("external_threats", 0) < thresholds["min_external_threats"]:
        blockers.append(
            f"external threats {evidence.get('external_threats',0)} "
            f"< {thresholds['min_external_threats']} required for {action}"
        )
    if evidence.get("internal_correlation", 0) < thresholds["min_internal_correlation"]:
        blockers.append(
            f"internal correlation {evidence.get('internal_correlation',0)} "
            f"< {thresholds['min_internal_correlation']} required for {action}"
        )
    return (len(blockers) == 0), blockers


# ---------------------------------------------------------------------------
# Karma Temporal: TTL-based redemption
# ---------------------------------------------------------------------------

def apply_ttl(decision: EthicalDecision, *, now: Optional[datetime] = None) -> EthicalDecision:
    """Attach a TTL to a blocking decision. Non-blocking actions stay unbounded."""
    ttl = DEFAULT_TTL_HOURS.get(decision.action)
    decision.ttl_hours = ttl
    if ttl is not None:
        now = now or datetime.now(timezone.utc)
        decision.ttl_expires_at = (now + timedelta(hours=ttl)).isoformat()
    return decision


# ---------------------------------------------------------------------------
# Shunyata: Non-punitive neutralization
# ---------------------------------------------------------------------------

PUNISHMENT_PATTERNS = (
    "kill_host",
    "destroy_data",
    "revoke_credentials_permanently",
    "blackhole_ip_forever",
    "wipe_disk",
)


def shunyata_check(decision: EthicalDecision) -> EthicalDecision:
    """Reject decisions whose next_step contains a punishment pattern.
    Convert them to their non-punitive equivalents."""

    next_step = decision.next_step or ""
    for pattern in PUNISHMENT_PATTERNS:
        if pattern in next_step.lower():
            decision.punishment_warnings.append(pattern)
            decision.non_punitive = False
            # Auto-correct: if the action is destructive, demote it.
            if decision.action in {"ISOLATE_NODE"}:
                decision.action = "QUARANTINE_PROCESS"
                decision.severity = "medium"
                decision.next_step = (next_step
                                      .replace(pattern, "[removed: non-punitive]"))
            elif decision.action in {"ACTIVATE_XDP_BLOCK"}:
                decision.next_step += " (TTL-bounded; will release in 12h)"
    return decision


# ---------------------------------------------------------------------------
# Three-principle decision wrapper
# ---------------------------------------------------------------------------

def apply_ethics(
    action: str,
    severity: str,
    target: Optional[str],
    rationale: str,
    next_step: str,
    alert_text: str,
    evidence: Optional[dict] = None,
) -> EthicalDecision:
    """Build an EthicalDecision and apply the three principles in order:
      1. Shunyata (non-punitive): reject punishments
      2. Ahimsa (fail-open): block if consensus insufficient
      3. Karma Temporal: attach TTL
    Falls back to DISMISS if Ahimsa gate blocks the requested action.
    """
    evidence = evidence or {}
    decision = EthicalDecision(
        action=action,
        severity=severity,
        target=target,
        rationale=rationale,
        next_step=next_step,
    )

    # Shunyata: reject punitive actions (cannot undo this — punitive is
    # immutable, so do this first)
    decision = shunyata_check(decision)

    # Ahimsa: consensus gate. If failed, demote to INVESTIGATE_DEEP — *not*
    # auto-block.
    allowed, blockers = ahimsa_gate(decision.action, alert_text, evidence)
    if not allowed:
        decision.consensus_blockers = blockers
        decision.consensus_clear = False
        # Fail-open: prefer investigation over risky block.
        decision.action = "INVESTIGATE_DEEP"
        decision.severity = max(severity, "medium", key=lambda s: {"low": 0, "info": 0, "medium": 1, "high": 2}.get(s, 1))
        decision.next_step = (
            f"insufficient consensus for {action}; investigating before escalation. "
            f"blockers={blockers}"
        )
        decision.fail_open = True
    else:
        decision.consensus_clear = True

    # Karma Temporal: TTL
    apply_ttl(decision)
    return decision
