# Krittika-Splunk Nexus

**Autonomous Observability & Defense for Sovereign Blockchain Infrastructure**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Splunk Cloud](https://img.shields.io/badge/Platform-Splunk%20Cloud-orange)](https://www.splunk.com)
[![MCP](https://img.shields.io/badge/Protocol-MCP-blue)](https://modelcontextprotocol.io/)

---

## Concept

**Krittika Sovereign Fleet Observability Agent** — a closed-loop autonomous system that bridges Splunk's operational intelligence with AI-driven remediation for the RadhikaChain blockchain fleet.

The agent continuously monitors consensus latency (Proof of Karma), network anomalies (eBPF telemetry), and container resource saturation. When degradation is detected, it autonomously classifies the root cause (security attack vs. resource contention), executes remediation, and records every decision in an **immutable chain-hash audit trail** — making the entire system cryptographically verifiable.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                     RADHIKACHAIN FLEET                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐            │
│  │Validator-1│  │Validator-2│  │Validator-3│  │Validator-7│ ...     │
│  │(healthy)  │  │(healthy)  │  │(healthy)  │  │(degraded) │         │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘            │
│       │              │              │              │                  │
│  ┌────▼──────────────▼──────────────▼──────────────▼─────┐           │
│  │           Splunk Universal Forwarder                   │           │
│  │  (container logs + eBPF events + consensus metrics)    │           │
│  └────────────────────────┬───────────────────────────────┘           │
│                             │ HEC                                     │
└─────────────────────────────┼─────────────────────────────────────────┘
                              │
┌─────────────────────────────▼─────────────────────────────────────────┐
│                      SPLUNK CLOUD PLATFORM                             │
│  ┌──────────────────────────────────────────────────────────────┐     │
│  │  Splunk MCP Server (from Splunkbase)                         │     │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌───────────┐  │     │
│  │  │krittika_   │ │krittika_   │ │krittika_   │ │krittika_  │  │     │
│  │  │consensus   │ │network     │ │metrics     │ │audit      │  │     │
│  │  └────────────┘ └────────────┘ └────────────┘ └───────────┘  │     │
│  └────────────────────────┬─────────────────────────────────────┘     │
│                             │ MCP over HTTP                           │
└─────────────────────────────┼─────────────────────────────────────────┘
                              │
┌─────────────────────────────▼─────────────────────────────────────────┐
│                     KRITTIKA AI AGENT                                  │
│  ┌──────────────────────────────────────────────────────────────┐     │
│  │  Orchestrator (observe → decide → act → audit)               │     │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐    │     │
│  │  │Splunk MCP    │  │Decision      │  │Remediation       │    │     │
│  │  │Client        │→ │Engine        │→ │Actions           │    │     │
│  │  └──────────────┘  └──────────────┘  └──────────────────┘    │     │
│  │         │                    │                    │            │     │
│  │         └────────────────────┴────────────────────┘            │     │
│  │                          │                                     │     │
│  │                   ┌──────▼──────┐                               │     │
│  │                   │AuditLogger  │ ← Chain Hash (SHA-256)        │     │
│  │                   │(immutable)  │ ← HEC → krittika_audit index  │     │
│  │                   └─────────────┘                               │     │
│  └──────────────────────────────────────────────────────────────┘     │
└───────────────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────▼───────────────┐
              │     REMEDIATION ACTIONS        │
              │  ┌──────────────────────────┐  │
              │  │ docker update --cpus     │  │
              │  │ docker update --memory   │  │
              │  │ iptables DROP (isolate)  │  │
              │  │ xdp-loader (eBPF filter) │  │
              │  └──────────────────────────┘  │
              └─────────────────────────────────┘
```

---

## Quick Start

### Prerequisites

- Python 3.10+
- Docker & Docker Compose (optional, for containerized agent)
- Splunk Cloud Platform instance (trial or production)
- Splunk MCP Server app installed from [Splunkbase](https://splunkbase.splunk.com/app/7931)

### 1. Clone & Setup

```bash
git clone https://github.com/radhikatmosphere/Krittika-Splunk-Nexus.git
cd Krittika-Splunk-Nexus

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r agent_core/requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your Splunk Cloud credentials
```

### 2. Run the Agent (Demo Mode)

```bash
# Runs 5 episodes with 30s intervals using test datasets
python -m agent_core.orchestrator --episodes 5 --interval 5 --demo
```

### 3. Run with Docker Compose

```bash
docker-compose up --build
```

---

## Splunk Configuration

### Step 1: Create the Audit Index

1. Log in to Splunk Cloud as `sc_admin`
2. Navigate to **Settings → Indexes → New Index**
3. Create index with these settings:
   - **Name**: `krittika_audit`
   - **Data Type**: Events
   - **Max Size**: 10 GB
   - **Frozen Time Period**: 365 days
   - **Replication Factor**: Auto

Repeat for the other three indexes: `krittika_consensus`, `krittika_network`, `krittika_metrics`.

### Step 2: Generate HEC Token

1. Navigate to **Settings → Data Inputs → HTTP Event Collector → New Token**
2. Configure:
   - **Name**: `agent_audit_token`
   - **Source Type**: `krittika:audit`
   - **Index**: `krittika_audit` (select only this index)
   - **Allow all indexes**: No (restrict to audit index only)
3. Copy the **Token Value** — this is your `HEC_TOKEN` in `.env`

### Step 3: Install Splunk MCP Server

1. Go to [Splunkbase App 7931](https://splunkbase.splunk.com/app/7931)
2. Install the **Splunk MCP Server** app on your Splunk Cloud instance
3. Navigate to the MCP Server app UI
4. Create an **Encrypted Authentication Token** for your agent client
5. Copy the token — this is your `MCP_TOKEN` in `.env`
6. Assign the `mcp_tool_execute` capability to the agent's role

### Step 4: Configure RBAC

1. Navigate to **Settings → Access Controls → Roles**
2. Create or edit the role used by the agent:
   - Add capability: `mcp_tool_execute`
   - Add capability: `edit_tokens_own` (if the agent creates its own tokens)
   - Set index access: `krittika_audit` (write), `krittika_*` (read)

### Step 5: Import Dashboards

1. In Splunk Web, go to **Dashboards → Create New Dashboard**
2. Select **Source** tab and paste the XML from:
   - `splunk_configs/dashboards/sovereign_fleet.xml` (operational view)
   - `splunk_configs/dashboards/ai_autonomy_oversight.xml` (audit view)
3. Save and verify data populates from the test datasets

---

## Production Deployment & Sovereign Fleet Integration

Krittika-Splunk Nexus has been promoted to production and is fully integrated with the **RadhikaChain Sovereign Fleet** architecture via Mega-Compose. The reliance on test datasets has been removed, replaced by an autonomous, real-time data pipeline.

* **Real-Time Data Ingestion:**
  * **Agentic Forwarder:** Every validator node in the *Mega-Compose* network hosts a **Splunk Universal Forwarder** container (`splunk/universalforwarder`).
  * **Telemetry Streams:** High-fidelity logs — **Proof of Karma** consensus heartbeat (`/var/log/radhikachain/proof-of-karma.log`) and **eBPF** kernel-level network events (`/var/log/radhikachain/mesh-network.log`) — are monitored and streamed instantly to the `krittika_consensus`, `krittika_network`, and `krittika_metrics` indexes in Splunk Cloud.
* **Closed-Loop Autonomous Governance:**
  The Autonomous Triage Agent queries the live Splunk MCP Server directly via `splunk_run_query`. Decisions are made on the current operational state of the validator fleet. Mitigation actions (network isolation or resource optimization) execute dynamically within minutes of detection.
* **Auditability and Integrity:**
  Every telemetry point ingested from production nodes, along with the agent's complete **Chain Hash** reasoning loop, is committed to the immutable `krittika_audit` index in Splunk. This creates a provable, unforgeable audit trail of sovereign fleet operations.

---

## Mega-Compose Architecture (Production)

```yaml
services:
  splunk-universal-forwarder:
    image: splunk/universalforwarder:latest
    volumes:
      - /var/log/radhikachain:/var/log/radhikachain:ro
      - ./splunk_configs/forwarder_outputs.conf:/opt/splunk/etc/system/local/outputs.conf:ro
      - ./splunk_configs/forwarder_inputs.conf:/opt/splunk/etc/system/local/inputs.conf:ro
    environment:
      - SPLUNK_FORWARD_SERVER=prd-p-vce8j.splunkcloud.com:9997
      - SPLUNK_FORWARD_SERVER_HEC=https://prd-p-vce8j.splunkcloud.com:8088
    networks:
      - radhikachain-mesh

  krittika-agent:
    build: ./agent_core
    environment:
      - SPLUNK_HOST=https://prd-p-vce8j.splunkcloud.com
      - HEC_TOKEN=${HEC_TOKEN}
      - MCP_ENDPOINT=https://prd-p-vce8j.splunkcloud.com/services/mcp
      - MCP_TOKEN=${MCP_TOKEN}
    depends_on:
      - splunk-universal-forwarder
    networks:
      - radhikachain-mesh

networks:
  radhikachain-mesh:
    driver: bridge
```

## Production SPL Queries

The agent uses these production queries to monitor the Proof of Karma consensus:

```spl
# Detect consensus latency breach
index=krittika_consensus sourcetype=krittika:consensus
| stats latest(latency_ms) as latency_ms, latest(validator_id) as validator_id, latest(karma_score) as karma_score by block_height
| where latency_ms > 500
| sort - latency_ms

# Detect network port scan
index=krittika_network sourcetype=krittika:ebpf anomaly=port_scan
| stats count as scan_count, dc(dst_port) as ports_scanned by src_ip
| where scan_count >= 5

# Detect container resource saturation
index=krittika_metrics sourcetype=krittika:container
| stats avg(cpu_percent) as avg_cpu, max(mem_percent) as max_mem by container_name
| where avg_cpu > 80 OR max_mem > 90

# Chain hash integrity verification
index=krittika_audit sourcetype=krittika:audit
| sort _time
| streamstats current=f last(current_hash) as expected_prev_hash
| eval chain_valid=if(isnull(expected_prev_hash), "GENESIS", if(expected_prev_hash==prev_hash, "VALID", "BROKEN"))
| stats count as total, count(eval(chain_valid="VALID")) as valid, count(eval(chain_valid="BROKEN")) as broken
```

## Evidence Datasets

Three pre-built datasets simulate real-world scenarios for hackathon demos:

### 1. `test_datasets/radhikachain_genesis.log`

**Scenario**: Consensus degradation of Validator-7

| Metric | Start | End |
|--------|-------|-----|
| Latency | 45ms | 1245ms (offline) |
| Karma Score | 0.95 | 0.00 |
| Block Height | 1 | 50 |

The log shows 7 validators mining blocks via Proof of Karma. Validator-7 progressively degrades from 45ms → 1245ms latency, karma drops from 0.95 → 0.00, and eventually goes offline at block 17. This triggers the agent's remediation loop.

### 2. `test_datasets/ebpf_network_alerts.json`

**Scenario**: Persistent port scan from external attacker

| Field | Value |
|-------|-------|
| Attacker IP | `185.220.101.34` |
| Target Ports | 8332 (RPC), 22 (SSH), 3389 (RDP), 3306 (MySQL), 5432 (PostgreSQL), 6379 (Redis), 27017 (MongoDB) |
| Anomaly Type | `port_scan` |
| Total Events | 200+ |

Low-TTL SYN packets from a known malicious IP range, scanning all sensitive ports across the validator mesh. The agent correlates this with latency spikes to classify the event as a security threat (not resource contention).

### 3. `test_datasets/container_metrics.csv`

**Scenario**: Cascading resource saturation

| Container | CPU Start → End | Memory Start → End |
|-----------|----------------|-------------------|
| karma-engine | 32% → 96% | 45% → 92% |
| mesh-router | 18% → 84% | 38% → 98% |
| validator-daemon | 25% → 100% | 42% → 100% |
| consensus-tracker | 15% → 100% | 30% → 100% |
| log-aggregator | 8% → 100% | 22% → 100% |

All containers experience progressive resource exhaustion. The agent's decision engine distinguishes this from a security event and triggers CPU/memory rebalancing instead of node isolation.

---

## Chain Hash Audit Trail

Every agent decision is recorded with cryptographic integrity:

```
Block 1 (Genesis): prev_hash = 0000...0000
Block 2: prev_hash = SHA256(Block 1)
Block 3: prev_hash = SHA256(Block 2)
...
Block N: prev_hash = SHA256(Block N-1)
```

If any audit entry is modified, the hash chain breaks — providing tamper-proof evidence of the agent's decision history. This is verifiable in Splunk via the **AI Autonomy Oversight** dashboard's "Chain Hash Integrity Verification" panel.

### Audit Schema

```json
{
  "audit_schema_version": "1.0",
  "timestamp": "2026-06-12T14:30:00.000Z",
  "session_id": "ksn-20260612-7a3f9b",
  "sequence_num": 1,
  "stage": "intent",
  "agent_id": "krittika-orchestrator-v1",
  "reasoning_context": {
    "trigger": "latency_threshold_exceeded",
    "validator_id": "Validator-7",
    "observed_latency_ms": 523,
    "threshold_latency_ms": 500
  },
  "evidence_reference": {
    "sourcetype": "krittika:consensus",
    "query": "validator=Validator-7 | stats latest(latency_ms)"
  },
  "decision": {
    "action": "rebalance",
    "target": "karma-engine-Validator-7",
    "risk_level": "medium"
  },
  "prev_hash": "a1b2c3...",
  "current_hash": "d4e5f6..."
}
```

---

## Manual Setup

### For Judges / Evaluators

1. **Load Test Data**:
   ```bash
   # Upload datasets to Splunk Cloud via HEC
   curl -k https://prd-p-vce8j.splunkcloud.com:8088/services/collector \
     -H "Authorization: Splunk $HEC_TOKEN" \
     -d '{"sourcetype":"krittika:consensus","event":"'"$(cat test_datasets/radhikachain_genesis.log)"'"}'
   ```

2. **Import Dashboards**:
   - Go to Splunk Web → Dashboards → Create New Dashboard → Source
   - Paste XML from `splunk_configs/dashboards/sovereign_fleet.xml`
   - Repeat for `ai_autonomy_oversight.xml`

3. **Set Environment Variables**:
   ```bash
   export SPLUNK_HOST=https://prd-p-vce8j.splunkcloud.com
   export HEC_TOKEN=your-hec-token
   export MCP_ENDPOINT=https://prd-p-vce8j.splunkcloud.com/services/mcp
   export MCP_TOKEN=your-encrypted-mcp-token
   export AUDIT_INDEX=krittika_audit
   ```

4. **Run Agent**:
   ```bash
   python -m agent_core.orchestrator --episodes 10 --interval 5
   ```

5. **Verify Audit Trail**:
   - Open the **AI Autonomy Oversight** dashboard
   - Check the "Chain Hash Integrity Verification" panel
   - Click any row in the audit table to see full decision context

---

## Demo Script (For Hackathon Presentation)

1. **Show the sovereign_fleet dashboard** — all validators healthy, green status
2. **Load the degradation dataset** — Validator-7 latency climbs past 500ms
3. **Agent detects anomaly** — decision engine classifies as resource contention
4. **Agent executes rebalancing** — `docker update --cpus=0.5 karma-engine`
5. **Show the ai_autonomy_oversight dashboard** — audit trail with chain hash
6. **Load the attack dataset** — port scan from `185.220.101.34`
7. **Agent detects threat** — correlates with latency spike, classifies as security event
8. **Agent isolates node** — `iptables DROP` rule activated
9. **Show chain hash verification** — all entries VALID, integrity 100%
10. **Show failed remediation alert** — if action fails 3x, human escalation triggered

---

## Repository Structure

```
krittika-splunk-nexus/
├── LICENSE
├── README.md                        # This file
├── architecture.md                  # Mermaid architecture diagram
├── docker-compose.yml               # Container orchestration
├── .gitignore
├── .env.example                     # Environment template
├── agent_core/                      # Autonomous agent
│   ├── __init__.py
│   ├── auditor.py                   # Chain Hash audit logger
│   ├── orchestrator.py              # Decision loop engine
│   ├── splunk_mcp_client.py         # MCP protocol client
│   ├── remediation_actions.py       # Closed-loop actions
│   ├── requirements.txt
│   └── Dockerfile
├── splunk_configs/ # Splunk configuration
│   ├── inputs.conf # Data input definitions
│   ├── forwarder_inputs.conf # Universal Forwarder input config (production)
│   ├── forwarder_outputs.conf # Universal Forwarder output config (production)
│   ├── props.conf # Field extraction rules
│   ├── indexes.conf # Index definitions
│   ├── savedsearches.conf # Alert definitions
│   └── dashboards/
│       ├── sovereign_fleet_autonomy.xml # Neon cyberpunk HUD dashboard
│       └── ai_autonomy_oversight.xml # Audit dashboard
└── test_datasets/                   # Frozen telemetry
    ├── radhikachain_genesis.log     # Consensus degradation scenario
    ├── ebpf_network_alerts.json     # Network attack scenario
    └── container_metrics.csv        # Resource saturation scenario
```

---

## License

MIT License. See `LICENSE` for details.
