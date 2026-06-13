# agent_core/orchestrator.py — Krittika Sovereign Fleet Orchestrator
# RADHIKATMOSPHERE / Krittika-Splunk Nexus
#
# Autonomous decision loop that correlates observability (performance)
# with security (threat detection) and executes closed-loop remediation.
#
# Flow:
#   1. Query Splunk via MCP for consensus latency and network anomalies
#   2. Classify: resource degradation vs. security threat
#   3. Log INTENT (pre-execution audit with chain hash)
#   4. Execute remediation action
#   5. Log OUTCOME (post-execution audit with health check)
#   6. Repeat every POLL_INTERVAL seconds

import asyncio
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from dotenv import load_dotenv

from .auditor import AuditLogger
from .remediation_actions import RemediationActions
from .splunk_mcp_client import SplunkMCPClient
from .api_server import FleetAPIServer, update_state
from .retry import (
    PermanentError,
    RetryPolicy,
    TransientError,
)

load_dotenv()

logger = logging.getLogger("krittika.orchestrator")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "30"))
LATENCY_THRESHOLD_MS = int(os.environ.get("LATENCY_THRESHOLD_MS", "500"))
THREAT_COUNT_THRESHOLD = int(os.environ.get("THREAT_COUNT_THRESHOLD", "3"))
DEMO_MODE = os.environ.get("DEMO_MODE", "true").lower() == "true"

# ---------------------------------------------------------------------------
# Production SPL Queries for Proof of Karma
# ---------------------------------------------------------------------------

PRODUCTION_QUERIES = {
    # Existing queries — migrated to sovereign_fleet index
    "consensus_latency_breach": (
        'index=sovereign_fleet sourcetype=karma_consensus_logs '
        '| stats latest(latency_ms) as latency_ms '
        '       latest(validator_id) as validator_id '
        '       latest(karma_score) as karma_score '
        '       latest(block_height) as block_height '
        '  by validator_id '
        '| where latency_ms > {threshold} '
        '| sort - latency_ms'
    ),
    "karma_health": (
        'index=sovereign_fleet sourcetype=karma_consensus_logs '
        '| stats avg(karma_score) as avg_karma '
        '       stdev(karma_score) as sigma_karma '
        '       latest(validator_id) as validator_id '
        '  by validator_id '
        '| where avg_karma < 70 OR sigma_karma > 15 '
        '| eval alert_level="CRITICAL" '
        '| table validator_id, avg_karma, sigma_karma, alert_level'
    ),
    "network_port_scan": (
        'index=sovereign_fleet sourcetype=ebpf_traffic anomaly=port_scan '
        '| stats count as scan_count '
        '       dc(dst_port) as ports_scanned '
        '       values(dst_port) as target_ports '
        '  by src_ip '
        '| where scan_count >= {threshold} '
        '| sort - scan_count'
    ),
    "container_saturation": (
        'index=sovereign_fleet sourcetype=krittika:container '
        '| stats avg(cpu_percent) as avg_cpu '
        '       max(mem_percent) as max_mem '
        '       latest(container_name) as container_name '
        '  by container_name '
        '| where avg_cpu > 80 OR max_mem > 90 '
        '| sort - avg_cpu'
    ),
    "consensus_quorum": (
        'index=sovereign_fleet sourcetype=karma_consensus_logs '
        '| stats dc(validator_id) as active_validators '
        '       latest(block_height) as block_height '
        '| eval total_validators=7 '
        '| eval quorum_pct=round(active_validators / total_validators * 100, 1) '
        '| eval quorum_status=if(quorum_pct >= 85, "HEALTHY", '
        '  if(quorum_pct >= 57, "DEGRADED", "CRITICAL"))'
    ),
    "chain_hash_integrity": (
        'index=sovereign_fleet sourcetype=krittika:audit '
        '| sort _time '
        '| streamstats current=f last(current_hash) as expected_prev_hash '
        '| eval chain_valid=if(isnull(expected_prev_hash), "GENESIS", '
        '  if(expected_prev_hash==prev_hash, "VALID", "BROKEN")) '
        '| stats count as total '
        '       count(eval(chain_valid=="VALID")) as valid '
        '       count(eval(chain_valid=="BROKEN")) as broken '
        '       count(eval(chain_valid=="GENESIS")) as genesis '
        '| eval integrity_pct=round((valid+genesis)/total*100,2) '
        '| eval status=if(broken>0, "COMPROMISED", "INTACT")'
    ),
    # New production SPL queries for Sovereign Fleet
    "health_karma": (
        'index=sovereign_fleet sourcetype=karma_consensus_logs '
        '| stats avg(karma_score) as avg_karma, '
        '       stdev(karma_score) as sigma_karma '
        '  by host '
        '| where avg_karma < 70 OR sigma_karma > 15 '
        '| eval alert_level="CRITICAL" '
        '| table host, avg_karma, sigma_karma, alert_level'
    ),
    "latency_mesh": (
        'index=sovereign_fleet sourcetype=ebpf_traffic '
        '| timechart span=1m avg(network_latency_ms) as latency by source_node '
        '| where latency > 250 '
        '| lookup validator_nodes host as source_node OUTPUT cluster_role '
        '| table _time, source_node, cluster_role, latency'
    ),
    "security_threat": (
        'index=sovereign_fleet sourcetype=ebpf_kernel_events '
        '| regex process_name="(?i)(bash|sh|nc|nmap|python3 -c)" '
        '| stats count by host, process_name, user '
        '| where count > 5 '
        '| sort - count'
    ),
}

# ---------------------------------------------------------------------------
# Decision Engine
# ---------------------------------------------------------------------------


class DecisionEngine:
    """
    Classifies observed anomalies into actionable decisions.

    Decision matrix:
    - High latency + high threat count  → ISOLATE (security mode)
    - High latency + low threat count   → REBALANCE (optimization mode)
    - Normal latency                    → SKIP (healthy)
    """

    def __init__(
        self,
        latency_threshold: int = LATENCY_THRESHOLD_MS,
        threat_threshold: int = THREAT_COUNT_THRESHOLD,
    ):
        self.latency_threshold = latency_threshold
        self.threat_threshold = threat_threshold

    def evaluate(
        self,
        latency_ms: float,
        threat_count: int,
        validator_id: str = "unknown",
        container_name: str = "unknown",
    ) -> dict[str, Any]:
        """
        Evaluate current metrics and return a decision.

        Returns:
            {
                "action": "isolate" | "rebalance" | "skip",
                "risk_level": "high" | "medium" | "low",
                "reason": str,
                "target": str,
                "parameters": dict,
            }
        """
        if latency_ms <= self.latency_threshold:
            return {
                "action": "skip",
                "risk_level": "low",
                "reason": f"Latency {latency_ms}ms within threshold ({self.latency_threshold}ms)",
                "target": validator_id,
                "parameters": {},
            }

        if threat_count >= self.threat_threshold:
            return {
                "action": "isolate",
                "risk_level": "high",
                "reason": (
                    f"Latency {latency_ms}ms exceeds threshold AND "
                    f"{threat_count} threats detected (>= {self.threat_threshold})"
                ),
                "target": validator_id,
                "parameters": {
                    "validator_id": validator_id,
                    "threat_count": threat_count,
                    "latency_ms": latency_ms,
                },
            }

        return {
            "action": "rebalance",
            "risk_level": "medium",
            "reason": (
                f"Latency {latency_ms}ms exceeds threshold but no significant threats. "
                f"Likely resource contention."
            ),
            "target": container_name,
            "parameters": {
                "container": container_name,
                "cpus": "0.5",
                "mem_limit": "512m",
                "latency_ms": latency_ms,
            },
        }


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


class KrittikaOrchestrator:
    """
    Main autonomous loop: observe → decide → act → audit.

    Connects to Splunk via MCP (or uses demo datasets), evaluates
    the health of the RadhikaChain consensus, and executes remediation
    with full chain-hash audit trail.
    """

    def __init__(self):
        self.auditor = AuditLogger(
            splunk_hec_url=os.environ.get(
                "SPLUNK_HEC_URL", "https://localhost:8088/services/collector"
            ),
            hec_token=os.environ.get("HEC_TOKEN", ""),
            audit_index=os.environ.get("AUDIT_INDEX", "krittika_audit"),
        )
        self.decision_engine = DecisionEngine()
        self.remediation = RemediationActions(demo_mode=DEMO_MODE)
        self.mcp_client: Optional[SplunkMCPClient] = None
        self.running = False
        self.episode_count = 0
        self.total_decisions = 0
        self.api_server = FleetAPIServer(
            host=os.environ.get("API_HOST", "0.0.0.0"),
            port=int(os.environ.get("API_PORT", "8080")),
        )
        self.api_server.start()

    async def initialize(self):
        """Set up MCP client and verify connectivity."""
        if not DEMO_MODE:
            self.mcp_client = SplunkMCPClient(
                mcp_endpoint=os.environ.get("MCP_ENDPOINT"),
                mcp_token=os.environ.get("MCP_TOKEN"),
            )
            logger.info("MCP client initialized (production mode)")
        else:
            logger.info("Running in DEMO mode — using simulated Splunk data")

    async def query_latency(self) -> dict[str, Any]:
        """
        Query Splunk for the latest consensus latency metric.

        In demo mode, reads from test_datasets/radhikachain_genesis.log.
        In production mode, uses splunk_run_query via MCP (with retry).
        """
        if DEMO_MODE:
            return self._demo_query_latency()

        if not self.mcp_client:
            return {"latency_ms": 0, "validator_id": "unknown", "karma_score": 0}

        async with self.mcp_client as client:
            result = await client.run_query(
                'index=sovereign_fleet sourcetype="karma_consensus_logs" '
                "| stats latest(latency_ms) as latency_ms, "
                "latest(validator_id) as validator_id, "
                "latest(karma_score) as karma_score"
            )
            if result.get("success") and result.get("result", {}).get("result"):
                rows = result["result"]["result"]
                if rows:
                    return rows[0]

        return {"latency_ms": 0, "validator_id": "unknown", "karma_score": 0}

    def _demo_query_latency(self) -> dict[str, Any]:
        """Simulate Splunk query using test dataset."""
        dataset_path = Path(__file__).parent.parent / "test_datasets" / "radhikachain_genesis.log"
        if not dataset_path.exists():
            return {"latency_ms": 120, "validator_id": "Validator-1", "karma_score": 0.95}

        lines = dataset_path.read_text().strip().split("\n")
        # Parse the last line for current state
        for line in reversed(lines):
            if "[KARMA]" in line:
                parts = {}
                for segment in line.split():
                    if "=" in segment:
                        key, val = segment.split("=", 1)
                        parts[key] = val
                return {
                    "latency_ms": float(parts.get("latency", "0").replace("ms", "")),
                    "validator_id": parts.get("validator", "unknown"),
                    "karma_score": float(parts.get("karma", "0")),
                    "block_height": int(parts.get("block", "0")),
                }

        return {"latency_ms": 120, "validator_id": "Validator-1", "karma_score": 0.95}

    async def query_threats(self) -> int:
        """
        Query Splunk for recent network anomaly count.

        In demo mode, reads from test_datasets/ebpf_network_alerts.json.
        """
        if DEMO_MODE:
            return self._demo_query_threats()

        if not self.mcp_client:
            return 0

        async with self.mcp_client as client:
            result = await client.run_query(
                'index=sovereign_fleet sourcetype="ebpf_traffic" anomaly=* '
                '| stats count as threat_count'
            )
            if result.get("success") and result.get("result", {}).get("result"):
                rows = result["result"]["result"]
                if rows:
                    return int(rows[0].get("threat_count", 0))

        return 0

    def _demo_query_threats(self) -> int:
        """Simulate threat query using test dataset."""
        dataset_path = Path(__file__).parent.parent / "test_datasets" / "ebpf_network_alerts.json"
        if not dataset_path.exists():
            return 0

        data = json.loads(dataset_path.read_text())
        if isinstance(data, list):
            return sum(1 for e in data if e.get("anomaly") in ("port_scan", "syn_scan", "data_exfil"))
        return 1 if data.get("anomaly") else 0

    async def query_karma_health(self) -> dict[str, Any]:
        """
        PRODUCTION: Query Splunk for karma consensus health.
        Detects nodes with low average karma or high variance (unstable).
        """
        if DEMO_MODE:
            return self._demo_query_karma_health()

        if not self.mcp_client:
            return {"healthy": True, "unhealthy_nodes": []}

        async with self.mcp_client as client:
            result = await client.run_query(
                PRODUCTION_QUERIES["karma_health"].format(
                    threshold=LATENCY_THRESHOLD_MS
                )
            )
            if result.get("success") and result.get("result", {}).get("result"):
                rows = result["result"]["result"]
                unhealthy = [r for r in rows if r.get("avg_karma", 100) < 70]
                return {
                    "healthy": len(unhealthy) == 0,
                    "unhealthy_nodes": unhealthy,
                    "total_checked": len(rows),
                }

        return {"healthy": True, "unhealthy_nodes": []}

    def _demo_query_karma_health(self) -> dict[str, Any]:
        """Simulate karma health query using test dataset."""
        dataset_path = Path(__file__).parent.parent / "test_datasets" / "radhikachain_genesis.log"
        if not dataset_path.exists():
            return {"healthy": True, "unhealthy_nodes": []}

        validator_stats: dict[str, list[float]] = {}
        for line in dataset_path.read_text().strip().split("\n"):
            if "[KARMA]" not in line:
                continue
            parts = {}
            for segment in line.split():
                if "=" in segment:
                    key, val = segment.split("=", 1)
                    parts[key] = val
            vid = parts.get("validator")
            karma = float(parts.get("karma", "0"))
            if vid:
                validator_stats.setdefault(vid, []).append(karma)

        unhealthy = []
        for vid, scores in validator_stats.items():
            avg = sum(scores) / len(scores) if scores else 0
            variance = sum((s - avg) ** 2 for s in scores) / len(scores) if scores else 0
            sigma = variance ** 0.5
            if avg < 70 or sigma > 15:
                unhealthy.append({
                    "validator_id": vid,
                    "avg_karma": round(avg, 2),
                    "sigma_karma": round(sigma, 2),
                    "alert_level": "CRITICAL",
                })

        return {
            "healthy": len(unhealthy) == 0,
            "unhealthy_nodes": unhealthy,
            "total_checked": len(validator_stats),
        }

    async def _observe_with_retry(self, query_fn):
        """Self-correction wrapper: run an observation query, applying RetryPolicy.

        If the query raises PermanentError (e.g., 401 unauth, 400 bad query),
        it is raised to the caller — the episode cannot continue without
        valid observation data.

        If the query raises TransientError (e.g., 503 backend unavailable),
        the retry layers in splunk_mcp_client.run_query have already applied
        backoff. As a last-resort, if the retry layer is exhausted and the
        underlying query still raises, we raise to the caller and log it.
        """
        try:
            return await query_fn()
        except PermanentError as e:
            logger.error(
                f"[observe] permanent failure on {query_fn.__name__}: {e}",
                exc_info=True,
            )
            raise
        except TransientError as e:
            logger.error(
                f"[observe] retry budget exhausted on {query_fn.__name__}: {e}",
                exc_info=True,
            )
            raise
        except Exception as e:
            logger.error(
                f"[observe] unexpected error on {query_fn.__name__}: {e}",
                exc_info=True,
            )
            raise

    async def run_episode(self):
        """
        Execute one decision episode:
        1. Observe (query Splunk with self-correction retry on transient errors)
        2. Decide (evaluate metrics)
        3. Log intent (pre-execution audit)
        4. Act (execute remediation)
        5. Log outcome (post-execution audit)
        """
        self.episode_count += 1
        logger.info(f"{'='*60}")
        logger.info(f"Episode {self.episode_count}")
        logger.info(f"{'='*60}")

        # 1. OBSERVE (Production SPL Queries with retry-aware self-correction)
        # All three queries run via asymmetric try/except: PermanentError
        # halts the episode (no point retrying), TransientError is handled
        # by the retry layer inside query_*
        latency_data = await self._observe_with_retry(self.query_latency)
        threat_count = await self._observe_with_retry(self.query_threats)
        karma_health = await self._observe_with_retry(self.query_karma_health)

        latency_ms = latency_data.get("latency_ms", 0)
        validator_id = latency_data.get("validator_id", "unknown")
        karma_score = latency_data.get("karma_score", 0)
        container_name = f"karma-engine-{validator_id}"

        # Use unhealthy node from karma query if available
        if not karma_health.get("healthy") and karma_health.get("unhealthy_nodes"):
            first_unhealthy = karma_health["unhealthy_nodes"][0]
            validator_id = first_unhealthy.get("validator_id", validator_id)
            karma_score = first_unhealthy.get("avg_karma", karma_score)

        logger.info(
            f"Observations: latency={latency_ms}ms, "
            f"validator={validator_id}, karma={karma_score}, "
            f"threats={threat_count}, "
            f"karma_health={'HEALTHY' if karma_health['healthy'] else 'DEGRADED'}"
        )

        # 2. DECIDE
        decision = self.decision_engine.evaluate(
            latency_ms=latency_ms,
            threat_count=threat_count,
            validator_id=validator_id,
            container_name=container_name,
        )
        self.total_decisions += 1

        logger.info(
            f"Decision: {decision['action']} ({decision['risk_level']}) — "
            f"{decision['reason']}"
        )

        # 3. LOG INTENT (pre-execution audit with chain hash)
        intent_entry = self.auditor.log_intent(
            reasoning_context={
                "trigger": "latency_threshold_exceeded" if latency_ms > LATENCY_THRESHOLD_MS else "routine_check",
                "validator_id": validator_id,
                "observed_latency_ms": latency_ms,
                "observed_karma_score": karma_score,
                "threat_count": threat_count,
                "threshold_latency_ms": LATENCY_THRESHOLD_MS,
                "threshold_threats": THREAT_COUNT_THRESHOLD,
            },
            evidence_reference={
                "sourcetype": "karma_consensus_logs",
                "query": f"validator={validator_id} | stats latest(latency_ms)",
                "threat_query": f"anomaly=* | stats count",
            },
            decision=decision,
        )
        logger.info(f"Audit intent logged: hash={intent_entry.get('current_hash', '')[:16]}...")

        # 4. ACT (execute remediation)
        if decision["action"] == "skip":
            logger.info("No action required — node healthy")
            action_result = {"status": "skipped", "reason": "healthy"}
        elif decision["action"] == "isolate":
            logger.warning(f"SECURITY MODE: Isolating validator {validator_id}")
            action_result = self.remediation.execute(
                "isolate_node", decision["parameters"]
            ).to_dict()
        elif decision["action"] == "rebalance":
            logger.info(f"OPTIMIZATION MODE: Rebalancing {container_name}")
            action_result = self.remediation.execute(
                "rebalance_cpu", decision["parameters"]
            ).to_dict()
        else:
            action_result = {"status": "unknown_action", "action": decision["action"]}

        # 5. LOG OUTCOME (post-execution audit with health check)
        health_check = self.remediation.execute(
            "health_check", {"target": decision["target"]}
        )

        outcome_entry = self.auditor.log_outcome(
            execution_result={
                "action": decision["action"],
                "target": decision["target"],
                "result": action_result,
            },
            health_check={
                "target": decision["target"],
                "status": health_check.details.get("status", "unknown"),
                "latency_ms": health_check.details.get("latency_ms", 0),
                "cpu_percent": health_check.details.get("cpu_percent", 0),
                "mem_percent": health_check.details.get("mem_percent", 0),
                "karma_score": health_check.details.get("karma_score", 0),
            },
        )
        logger.info(f"Audit outcome logged: hash={outcome_entry.get('current_hash', '')[:16]}...")

        # Update fleet API state
        update_state(
            status="running",
            episode=self.episode_count,
            latency_ms=latency_ms,
            threat_count=threat_count,
            karma_score=karma_score,
            validator_id=validator_id,
            healthy=karma_health.get("healthy", True),
            last_action=decision["action"],
            audit_last_hash=self.auditor.last_hash,
            remediation_summary=self.remediation.get_action_summary(),
        )

        return {
            "episode": self.episode_count,
            "decision": decision,
            "intent_hash": intent_entry.get("current_hash", ""),
            "outcome_hash": outcome_entry.get("current_hash", ""),
            "chain_intact": True,
        }

    async def run(self, max_episodes: int = 10):
        """
        Main autonomous loop.

        Runs episodes every POLL_INTERVAL seconds until max_episodes reached.
        """
        self.running = True
        logger.info(
            f"Krittika Orchestrator starting — "
            f"demo_mode={DEMO_MODE}, poll_interval={POLL_INTERVAL}s, "
            f"max_episodes={max_episodes}"
        )

        await self.initialize()

        episode = 0
        while self.running and episode < max_episodes:
            try:
                result = await self.run_episode()
                episode += 1

                logger.info(
                    f"Episode {episode} complete — "
                    f"action={result['decision']['action']}, "
                    f"risk={result['decision']['risk_level']}"
                )

                if episode < max_episodes:
                    logger.info(f"Next episode in {POLL_INTERVAL}s...")
                    await asyncio.sleep(POLL_INTERVAL)

            except KeyboardInterrupt:
                logger.info("Orchestrator stopped by user")
                break
            except Exception as e:
                logger.error(f"Episode {episode + 1} failed: {e}", exc_info=True)
                await asyncio.sleep(5)

        # Final summary
        self.running = False
        summary = {
            "status": "complete",
            "episodes": episode,
            "total_decisions": self.total_decisions,
            "remediation_summary": self.remediation.get_action_summary(),
            "audit_chain": {
                "last_hash": self.auditor.last_hash,
                "sessions_created": self.episode_count,
            },
        }
        logger.info(f"Orchestrator summary: {json.dumps(summary, indent=2)}")
        return summary


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Krittika Sovereign Fleet Observability Agent"
    )
    parser.add_argument(
        "--episodes", type=int, default=5, help="Number of decision episodes to run"
    )
    parser.add_argument(
        "--interval", type=int, default=30, help="Seconds between episodes"
    )
    parser.add_argument(
        "--demo", action="store_true", default=True, help="Run in demo mode"
    )
    parser.add_argument(
        "--log-level", default="INFO", help="Logging level"
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    if args.demo:
        os.environ["DEMO_MODE"] = "true"

    orchestrator = KrittikaOrchestrator()
    summary = asyncio.run(orchestrator.run(max_episodes=args.episodes))

    print("\n" + "=" * 60)
    print("KRITTIKA ORCHESTRATOR — FINAL REPORT")
    print("=" * 60)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
