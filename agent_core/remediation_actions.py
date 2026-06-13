# agent_core/remediation_actions.py — Closed-Loop Remediation
# RADHIKATMOSPHERE / Krittika-Splunk Nexus
#
# Executes autonomous remediation actions when the orchestrator detects
# anomalies. Includes pre/post health checks for audit trail completeness.
#
# Actions:
# - Resource rebalancing (CPU/memory limits)
# - Node isolation (network-level containment)
# - XDP filter activation (kernel-level defense)
# - Health verification (post-action validation)

import json
import logging
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger("krittika.remediation")


@dataclass
class ActionResult:
    """Structured result from a remediation action."""
    action: str
    target: str
    success: bool
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    duration_ms: float = 0.0
    timestamp: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = {
            "action": self.action,
            "target": self.target,
            "success": self.success,
            "stdout": self.stdout[:500],
            "stderr": self.stderr[:500],
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
            "timestamp": self.timestamp or datetime.now(timezone.utc).isoformat(),
        }
        d.update(self.details)
        return d


class RemediationActions:
    """
    Autonomous remediation engine with audit-safe execution.

    All actions are simulated in demo mode (no actual Docker/kernel calls)
    but structured to support real execution when deployed with proper permissions.
    """

    def __init__(self, demo_mode: bool = True):
        self.demo_mode = demo_mode
        self.action_history: list[ActionResult] = []

    def execute(self, action_type: str, params: dict) -> ActionResult:
        """
        Dispatch to the appropriate remediation action.

        action_type: 'rebalance_cpu', 'rebalance_mem', 'isolate_node',
                     'activate_xdp', 'restart_service', 'health_check'
        """
        import time
        start = time.time()

        action_map = {
            "rebalance_cpu": self._rebalance_cpu,
            "rebalance_mem": self._rebalance_memory,
            "isolate_node": self._isolate_node,
            "activate_xdp": self._activate_xdp_filter,
            "restart_service": self._restart_service,
            "health_check": self._health_check,
        }

        handler = action_map.get(action_type)
        if not handler:
            result = ActionResult(
                action=action_type,
                target=params.get("target", "unknown"),
                success=False,
                stderr=f"Unknown action type: {action_type}",
            )
        else:
            result = handler(params)

        result.duration_ms = (time.time() - start) * 1000
        result.timestamp = datetime.now(timezone.utc).isoformat()
        self.action_history.append(result)

        logger.info(
            f"Remediation: {action_type} on {result.target} → "
            f"{'SUCCESS' if result.success else 'FAILED'} "
            f"({result.duration_ms:.0f}ms)"
        )
        return result

    def _rebalance_cpu(self, params: dict) -> ActionResult:
        """Limit CPU allocation for a resource-hogging container."""
        target = params.get("container", "unknown")
        cpus = params.get("cpus", "0.5")

        if self.demo_mode:
            return ActionResult(
                action="rebalance_cpu",
                target=target,
                success=True,
                stdout=f"[DEMO] Would execute: docker update --cpus={cpus} {target}",
                details={"cpus_limit": float(cpus), "mode": "demo"},
            )

        try:
            proc = subprocess.run(
                ["docker", "update", f"--cpus={cpus}", target],
                capture_output=True, text=True, timeout=30, shell=False,
            )
            return ActionResult(
                action="rebalance_cpu",
                target=target,
                success=proc.returncode == 0,
                stdout=proc.stdout,
                stderr=proc.stderr,
                exit_code=proc.returncode,
            )
        except Exception as e:
            return ActionResult(
                action="rebalance_cpu",
                target=target,
                success=False,
                stderr=str(e),
            )

    def _rebalance_memory(self, params: dict) -> ActionResult:
        """Limit memory allocation for a container with memory leak."""
        target = params.get("container", "unknown")
        mem_limit = params.get("mem_limit", "512m")

        if self.demo_mode:
            return ActionResult(
                action="rebalance_mem",
                target=target,
                success=True,
                stdout=f"[DEMO] Would execute: docker update --memory={mem_limit} {target}",
                details={"mem_limit": mem_limit, "mode": "demo"},
            )

        try:
            proc = subprocess.run(
                ["docker", "update", f"--memory={mem_limit}", target],
                capture_output=True, text=True, timeout=30, shell=False,
            )
            return ActionResult(
                action="rebalance_mem",
                target=target,
                success=proc.returncode == 0,
                stdout=proc.stdout,
                stderr=proc.stderr,
                exit_code=proc.returncode,
            )
        except Exception as e:
            return ActionResult(
                action="rebalance_mem",
                target=target,
                success=False,
                stderr=str(e),
            )

    def _isolate_node(self, params: dict) -> ActionResult:
        """
        Isolate a compromised validator node from the mesh network.
        In production: iptables rules, network policy updates, or container network disconnect.
        """
        target = params.get("validator_id", params.get("node_ip", "unknown"))

        if self.demo_mode:
            return ActionResult(
                action="isolate_node",
                target=target,
                success=True,
                stdout=f"[DEMO] Would isolate node {target} from mesh network",
                details={"isolation_type": "network", "mode": "demo"},
            )

        try:
            # Block all traffic to/from the compromised node
            proc = subprocess.run(
                ["iptables", "-A", "INPUT", "-s", target, "-j", "DROP"],
                capture_output=True, text=True, timeout=10, shell=False,
            )
            return ActionResult(
                action="isolate_node",
                target=target,
                success=proc.returncode == 0,
                stdout=proc.stdout,
                stderr=proc.stderr,
                exit_code=proc.returncode,
            )
        except Exception as e:
            return ActionResult(
                action="isolate_node",
                target=target,
                success=False,
                stderr=str(e),
            )

    def _activate_xdp_filter(self, params: dict) -> ActionResult:
        """
        Activate XDP/eBPF firewall rules against attacking IPs.
        Requires CAP_NET_ADMIN and kernel support.
        """
        target_ip = params.get("target_ip", "0.0.0.0")
        interface = params.get("interface", "eth0")

        if self.demo_mode:
            return ActionResult(
                action="activate_xdp",
                target=target_ip,
                success=True,
                stdout=f"[DEMO] Would load XDP filter on {interface} blocking {target_ip}",
                details={
                    "filter_type": "xdp_drop",
                    "interface": interface,
                    "blocked_ip": target_ip,
                    "mode": "demo",
                },
            )

        try:
            proc = subprocess.run(
                ["xdp-loader", "load", "--mode", "skb", interface,
                 "--prog-section", "xdp_drop", "--prog-filename",
                 f"/tmp/xdp_block_{target_ip.replace('.', '_')}.o"],
                capture_output=True, text=True, timeout=15, shell=False,
            )
            return ActionResult(
                action="activate_xdp",
                target=target_ip,
                success=proc.returncode == 0,
                stdout=proc.stdout,
                stderr=proc.stderr,
                exit_code=proc.returncode,
            )
        except Exception as e:
            return ActionResult(
                action="activate_xdp",
                target=target_ip,
                success=False,
                stderr=str(e),
            )

    def _restart_service(self, params: dict) -> ActionResult:
        """Restart a degraded service container."""
        target = params.get("container", "unknown")

        if self.demo_mode:
            return ActionResult(
                action="restart_service",
                target=target,
                success=True,
                stdout=f"[DEMO] Would restart container: {target}",
                details={"mode": "demo"},
            )

        try:
            proc = subprocess.run(
                ["docker", "restart", target],
                capture_output=True, text=True, timeout=30, shell=False,
            )
            return ActionResult(
                action="restart_service",
                target=target,
                success=proc.returncode == 0,
                stdout=proc.stdout,
                stderr=proc.stderr,
                exit_code=proc.returncode,
            )
        except Exception as e:
            return ActionResult(
                action="restart_service",
                target=target,
                success=False,
                stderr=str(e),
            )

    def _health_check(self, params: dict) -> ActionResult:
        """
        Post-action health verification.
        Returns current metrics for the target node/container.
        """
        target = params.get("target", "unknown")

        if self.demo_mode:
            import random
            return ActionResult(
                action="health_check",
                target=target,
                success=True,
                stdout=f"[DEMO] Health check for {target}",
                details={
                    "latency_ms": random.randint(100, 400),
                    "cpu_percent": round(random.uniform(20, 60), 1),
                    "mem_percent": round(random.uniform(40, 70), 1),
                    "karma_score": round(random.uniform(0.7, 0.95), 2),
                    "status": "healthy",
                    "mode": "demo",
                },
            )

        try:
            proc = subprocess.run(
                ["docker", "stats", "--no-stream", "--format",
                 "{{.CPUPerc}}\t{{.MemPerc}}\t{{.MemUsage}}", target],
                capture_output=True, text=True, timeout=10, shell=False,
            )
            return ActionResult(
                action="health_check",
                target=target,
                success=proc.returncode == 0,
                stdout=proc.stdout,
                stderr=proc.stderr,
                exit_code=proc.returncode,
            )
        except Exception as e:
            return ActionResult(
                action="health_check",
                target=target,
                success=False,
                stderr=str(e),
            )

    def get_action_summary(self) -> dict:
        """Return a summary of all remediation actions taken."""
        total = len(self.action_history)
        successful = sum(1 for a in self.action_history if a.success)
        failed = total - successful

        return {
            "total_actions": total,
            "successful": successful,
            "failed": failed,
            "success_rate": round(successful / total * 100, 1) if total > 0 else 0,
            "actions_by_type": self._group_by_type(),
            "recent_actions": [a.to_dict() for a in self.action_history[-5:]],
        }

    def _group_by_type(self) -> dict:
        """Group action history by action type."""
        groups: dict[str, int] = {}
        for action in self.action_history:
            groups[action.action] = groups.get(action.action, 0) + 1
        return groups
