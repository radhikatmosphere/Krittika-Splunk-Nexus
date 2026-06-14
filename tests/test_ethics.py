# tests/test_ethics.py — Tests for Ahimsa / Karma TTL / Shunyata principles
# RADHIKATMOSPHERE / Krittika-Splunk Nexus

import os

os.environ["KRITTIKA_DISABLE_JITTER"] = "1"

from datetime import datetime, timedelta, timezone

import pytest

from agent_core.ethics import (
    DEFAULT_TTL_HOURS,
    EthicalDecision,
    MIN_CONSENSUS,
    SEVERITY_RANK,
    ahimsa_gate,
    apply_ethics,
    apply_ttl,
    shunyata_check,
)


# ---------------------------------------------------------------------------
# Ahimsa — Fail-open + consensus
# ---------------------------------------------------------------------------


class TestAhimsaGate:
    def test_isolate_requires_critical_severity(self):
        allowed, blockers = ahimsa_gate(
            "ISOLATE_NODE",
            "WARN: validator-3 latency spike",
            {"alert_severity_rank": 1, "external_threats": 5, "internal_correlation": 1},
        )
        assert not allowed
        assert any("severity rank" in b for b in blockers)

    def test_isolate_requires_critical_alert_text(self):
        # Severity rank pulled from text
        allowed, blockers = ahimsa_gate(
            "ISOLATE_NODE",
            "CRITICAL: validator-3 anomaly",
            {"alert_severity_rank": 3, "external_threats": 1, "internal_correlation": 1},
        )
        assert allowed
        assert blockers == []

    def test_quarantine_allows_internal_only(self):
        # Insider scenario: no external probes, but internal correlation OK
        allowed, blockers = ahimsa_gate(
            "QUARANTINE_PROCESS",
            "HIGH: insider activity",
            {"alert_severity_rank": 2, "external_threats": 0, "internal_correlation": 1},
        )
        assert allowed

    def test_dismiss_always_allowed(self):
        allowed, _ = ahimsa_gate(
            "DISMISS", "INFO: something", {"alert_severity_rank": 0},
        )
        assert allowed

    def test_skip_always_allowed(self):
        allowed, _ = ahimsa_gate(
            "SKIP", "INFO: baseline noise", {"alert_severity_rank": 0},
        )
        assert allowed


# ---------------------------------------------------------------------------
# Karma Temporal — TTL redemption
# ---------------------------------------------------------------------------


class TestKarmaTemporal:
    def test_ttl_table_is_complete(self):
        for action in {"ISOLATE_NODE", "QUARANTINE_PROCESS", "ACTIVATE_XDP_BLOCK",
                       "INVESTIGATE_DEEP", "DISMISS", "SKIP"}:
            assert action in DEFAULT_TTL_HOURS

    def test_blocking_actions_have_finite_ttl(self):
        assert DEFAULT_TTL_HOURS["ISOLATE_NODE"] == 24
        assert DEFAULT_TTL_HOURS["QUARANTINE_PROCESS"] == 6
        assert DEFAULT_TTL_HOURS["ACTIVATE_XDP_BLOCK"] == 12

    def test_non_blocking_actions_have_null_ttl(self):
        assert DEFAULT_TTL_HOURS["INVESTIGATE_DEEP"] is None
        assert DEFAULT_TTL_HOURS["DISMISS"] is None
        assert DEFAULT_TTL_HOURS["SKIP"] is None

    def test_apply_ttl_sets_expires_at_when_blocking(self):
        decision = EthicalDecision(
            action="ISOLATE_NODE", severity="high", target="v3",
            rationale="x", next_step="y",
        )
        now = datetime(2026, 6, 14, 0, 0, 0, tzinfo=timezone.utc)
        apply_ttl(decision, now=now)
        assert decision.ttl_hours == 24
        expected = (now + timedelta(hours=24)).isoformat()
        assert decision.ttl_expires_at == expected

    def test_no_ttl_when_non_blocking(self):
        decision = EthicalDecision(
            action="DISMISS", severity="info", target=None,
            rationale="x", next_step="y",
        )
        apply_ttl(decision)
        assert decision.ttl_hours is None
        assert decision.ttl_expires_at is None


# ---------------------------------------------------------------------------
# Shunyata — non-punitive neutralization
# ---------------------------------------------------------------------------


class TestShunyata:
    def test_punishment_pattern_triggers_rejection(self):
        d = EthicalDecision(
            action="ISOLATE_NODE", severity="high", target="v3",
            rationale="x", next_step="kill_host immediately",
        )
        d = shunyata_check(d)
        assert d.non_punitive is False
        assert "kill_host" in d.punishment_warnings
        # Action should be demoted to non-destructive
        assert d.action == "QUARANTINE_PROCESS"

    def test_clean_decision_passes_through(self):
        d = EthicalDecision(
            action="ISOLATE_NODE", severity="high", target="v3",
            rationale="x", next_step="activate_xdp + restart validator",
        )
        d = shunyata_check(d)
        assert d.non_punitive is True
        assert d.punishment_warnings == []
        assert d.action == "ISOLATE_NODE"

    def test_xdp_block_can_be_released(self):
        # XDP block must run through the full pipeline (shunyata + ttl)
        # to be properly released at TTL.
        d = EthicalDecision(
            action="ACTIVATE_XDP_BLOCK", severity="high", target="185.220.101.34",
            rationale="port scan", next_step="xdp_loader drop",
        )
        d = shunyata_check(d)        # 1: non-punitive
        d = apply_ttl(d)             # 2: TTL bounce-back
        assert d.non_punitive is True
        assert d.ttl_hours == 12      # TTL is set
        assert d.ttl_expires_at is not None


# ---------------------------------------------------------------------------
# Combined wrapper
# ---------------------------------------------------------------------------


class TestApplyEthics:
    def test_fail_open_demotes_undersupported_isolate(self):
        alert = "WARN: validator-3 noise"
        decision = apply_ethics(
            action="ISOLATE_NODE",
            severity="high",
            target="v3",
            rationale="agent wanted to isolate",
            next_step="isolate validator",
            alert_text=alert,
            evidence={
                "alert_severity_rank": SEVERITY_RANK["WARN"],  # 1, below 3 required
                "external_threats": 0,
                "internal_correlation": 1,
            },
        )
        assert decision.action == "INVESTIGATE_DEEP"   # demoted
        assert decision.consensus_clear is False
        assert decision.fail_open is True
        # TTL of INVESTIGATE_DEEP is null
        assert decision.ttl_hours is None

    def test_strong_evidence_passes_isolate(self):
        alert = "CRITICAL: validator-3 python3 -c execution"
        decision = apply_ethics(
            action="ISOLATE_NODE",
            severity="high",
            target="v3",
            rationale="high consensus",
            next_step="isolate validator",
            alert_text=alert,
            evidence={
                "alert_severity_rank": SEVERITY_RANK["CRITICAL"],  # 3
                "external_threats": 1,
                "internal_correlation": 1,
            },
        )
        assert decision.action == "ISOLATE_NODE"
        assert decision.consensus_clear is True
        assert decision.ttl_hours == 24
        assert decision.ttl_expires_at is not None

    def test_punitive_action_is_demoted(self):
        alert = "CRITICAL: validator-3 anomaly"
        decision = apply_ethics(
            action="ISOLATE_NODE",
            severity="high",
            target="v3",
            rationale="x",
            next_step="isolate validator; kill_host",
            alert_text=alert,
            evidence={
                "alert_severity_rank": SEVERITY_RANK["CRITICAL"],
                "external_threats": 1,
                "internal_correlation": 1,
            },
        )
        # Shunyata demoted the action because of the "kill_host" pattern
        assert decision.action == "QUARANTINE_PROCESS"
        assert "kill_host" in decision.punishment_warnings

    def test_audit_block_emits_canonical_string(self):
        alert = "CRITICAL: validator-3 anomaly"
        decision = apply_ethics(
            action="ISOLATE_NODE", severity="high", target="v3",
            rationale="r", next_step="ns",
            alert_text=alert,
            evidence={
                "alert_severity_rank": SEVERITY_RANK["CRITICAL"],
                "external_threats": 1, "internal_correlation": 1,
            },
        )
        audit = decision.audit_block()
        assert "action=ISOLATE_NODE" in audit
        assert "ttl_hours=24" in audit
        assert "non_punitive=True" in audit
        assert "consensus=OK" in audit
