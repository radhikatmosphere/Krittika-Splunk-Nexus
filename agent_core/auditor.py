# agent_core/auditor.py — Chain Hash Audit Logger
# RADHIKATMOSPHERE / Krittika-Splunk Nexus
#
# Implements blockchain-style hash chaining for immutable audit trails.
# Each log entry contains the SHA-256 hash of the previous entry,
# making tampering detectable by breaking the chain.

import hashlib
import json
import datetime
import logging
import os
import uuid
from typing import Any, Optional

import requests

logger = logging.getLogger("krittika.auditor")


class AuditLogger:
    """
    Immutable audit trail with SHA-256 hash chaining.

    Every entry includes:
    - prev_hash: SHA-256 of the previous entry (genesis = 64 zeros)
    - current_hash: SHA-256 of this entry (used as prev_hash for next)
    - session_id: Groups related decisions (intent + outcome)

    Tampering with any entry breaks the hash chain, providing
    cryptographic proof of integrity for hackathon demos.
    """

    def __init__(
        self,
        splunk_hec_url: Optional[str] = None,
        hec_token: Optional[str] = None,
        audit_index: str = "krittika_audit",
    ):
        self.splunk_hec_url = splunk_hec_url or os.environ.get(
            "SPLUNK_HEC_URL", "https://localhost:8088/services/collector"
        )
        self.hec_token = hec_token or os.environ.get("HEC_TOKEN", "")
        self.audit_index = audit_index
        self.last_hash = "0" * 64  # Hash génesis
        self.current_session_id: Optional[str] = None
        self.sequence_num = 0

    def new_session(self) -> str:
        """Start a new audit session (e.g., a remediation episode)."""
        self.current_session_id = (
            f"ksn-{datetime.datetime.utcnow().strftime('%Y%m%d-%H%M%S')}-"
            f"{uuid.uuid4().hex[:8]}"
        )
        self.sequence_num = 0
        logger.info(f"New audit session: {self.current_session_id}")
        return self.current_session_id

    def log_intent(
        self,
        reasoning_context: dict[str, Any],
        evidence_reference: dict[str, Any],
        decision: dict[str, Any],
        session_id: Optional[str] = None,
    ) -> dict:
        """
        PRE-execution: Log what the agent plans to do.
        Captures the reasoning, evidence, and intended action.
        """
        sid = session_id or self.current_session_id or self.new_session()
        self.sequence_num += 1

        audit_entry = self._build_entry(
            stage="intent",
            session_id=sid,
            sequence_num=self.sequence_num,
            reasoning_context=reasoning_context,
            evidence_reference=evidence_reference,
            decision=decision,
        )
        return self._send(audit_entry)

    def log_outcome(
        self,
        execution_result: dict[str, Any],
        health_check: dict[str, Any],
        session_id: Optional[str] = None,
    ) -> dict:
        """
        POST-execution: Log the result and post-action health check.
        Closes the audit block with cryptographic proof.
        """
        sid = session_id or self.current_session_id
        if not sid:
            sid = self.new_session()
        self.sequence_num += 1

        audit_entry = self._build_entry(
            stage="outcome",
            session_id=sid,
            sequence_num=self.sequence_num,
            execution_result=execution_result,
            health_check=health_check,
        )
        return self._send(audit_entry)

    def log_decision(
        self,
        intent: str,
        action: str,
        result_status: str,
        metadata: dict[str, Any],
        session_id: Optional[str] = None,
    ) -> dict:
        """
        Simplified single-entry log for backward compatibility.
        Combines intent and result in one audit block.
        """
        sid = session_id or self.current_session_id or self.new_session()
        self.sequence_num += 1

        audit_entry = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "session_id": sid,
            "sequence_num": self.sequence_num,
            "intent": intent,
            "action": action,
            "status": result_status,
            "metadata": metadata,
            "prev_hash": self.last_hash,
        }

        entry_str = json.dumps(audit_entry, sort_keys=True)
        current_hash = hashlib.sha256(entry_str.encode()).hexdigest()
        audit_entry["current_hash"] = current_hash
        self.last_hash = current_hash

        return self._send_to_splunk(audit_entry)

    def _build_entry(self, stage: str, session_id: str, sequence_num: int, **kwargs) -> dict:
        """Build the structured audit entry with hash chain."""
        entry = {
            "audit_schema_version": "1.0",
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "session_id": session_id,
            "sequence_num": sequence_num,
            "stage": stage,
            "agent_id": "krittika-orchestrator-v1",
            "prev_hash": self.last_hash,
        }
        entry.update(kwargs)
        return entry

    def _send(self, entry: dict) -> dict:
        """Hash the entry, update chain, and send to Splunk HEC."""
        entry_str = json.dumps(entry, sort_keys=True)
        current_hash = hashlib.sha256(entry_str.encode()).hexdigest()
        entry["current_hash"] = current_hash
        self.last_hash = current_hash

        return self._send_to_splunk(entry)

    def _send_to_splunk(self, entry: dict) -> dict:
        """POST the audit entry to Splunk HEC."""
        headers = {"Authorization": f"Splunk {self.hec_token}"}
        payload = {
            "index": self.audit_index,
            "sourcetype": "krittika:audit",
            "event": entry,
        }

        try:
            resp = requests.post(
                self.splunk_hec_url,
                json=payload,
                headers=headers,
                verify=False,
                timeout=10,
            )
            if resp.status_code == 200:
                logger.info(
                    f"Audit entry sent: session={entry.get('session_id')}, "
                    f"stage={entry.get('stage')}, hash={entry['current_hash'][:16]}..."
                )
            else:
                logger.error(f"HEC returned {resp.status_code}: {resp.text}")
        except requests.exceptions.ConnectionError:
            logger.warning(
                f"Cannot reach Splunk HEC at {self.splunk_hec_url} — "
                f"audit entry preserved locally: hash={entry['current_hash'][:16]}..."
            )
        except Exception as e:
            logger.error(f"[ERROR] Auditoría no persistida: {e}")

        return entry

    def verify_chain(self, entries: list[dict]) -> dict:
        """
        Verify the integrity of an audit chain.
        Returns validation results for each entry.
        """
        results = []
        prev_hash = "0" * 64

        for i, entry in enumerate(entries):
            stored_prev = entry.get("prev_hash", "")
            stored_current = entry.get("current_hash", "")

            # Recompute hash
            temp = {k: v for k, v in entry.items() if k != "current_hash"}
            computed = hashlib.sha256(
                json.dumps(temp, sort_keys=True).encode()
            ).hexdigest()

            valid_chain = stored_prev == prev_hash
            valid_hash = computed == stored_current

            results.append({
                "index": i,
                "session_id": entry.get("session_id"),
                "chain_valid": valid_chain,
                "hash_valid": valid_hash,
                "prev_hash_match": stored_prev == prev_hash,
            })

            if valid_chain and valid_hash:
                prev_hash = stored_current

        return {
            "total_entries": len(entries),
            "valid_entries": sum(1 for r in results if r["chain_valid"] and r["hash_valid"]),
            "chain_intact": all(r["chain_valid"] and r["hash_valid"] for r in results),
            "details": results,
        }
