# Krittika-Splunk Nexus — Evidence Datasets

> **RADHIKATMOSPHERE**
> Splunk-integrated observability & autonomous defense agent for the RadhikaChain Sovereign Fleet.

## Overview

Krittika-Splunk Nexus ships with **3 frozen telemetry datasets** that simulate end-to-end operational scenarios. All datasets are timestamped to **2026-06-12** (one-day window) and have **deterministic, replayable** outputs.

| Dataset | Type | Rows | Time Span | Host Count |
|---------|------|------|-----------|------------|
| `radhikachain_genesis.log` | Consensus log | 357 lines | 24h | 7 validators |
| `ebpf_network_alerts.json` | Network eBPF | 217 events | 24h | 8 src IPs |
| `container_metrics.csv` | Resource telemetry | 256 rows | 24h | 5 containers |

## Dataset 1: `radhikachain_genesis.log`

### Origin
Synthetic generation seeded from the actual RadhikaChain genesis block:
`00000000367efa345a130ec8944e80fe3cc3d675543f8500c0f085184a4be5a7`

Mirrors production log format from `radhika-seed` (Linode g6-nanode-1, BPF programmable validator daemon).

### Schema (one line)
```
<ISO 8601 timestamp> [<EVENT_TYPE>] validator=<id> block=<n> karma=<score> latency=<ms> [hash=<hex>] msg="<message>"
```

### Event Types Used
| Stage | Marker | Description |
|-------|--------|-------------|
| Genesis | `[GENESIS]` | Block 0 confirmation traces |
| Proposal | `[PROPOSAL]` | Validator initiates block |
| Attestation | `[CONSENSUS]` | Other validators attest |
| Karma Decay | `[KARMA]` | Score event from engine |
| Slashing | `[SLASH]` | Penalty event |
| Finalization | `[FINALIZED]` | Block immutably recorded |

### Known Findings (Scenario: Validator-7 Degradation)
The dataset simulates Validator-7 latency climbing from **45ms** to **1245ms** starting at block 47:

- **Iterations 1-3**: latency ≤ 500ms → agent SKIP (healthy)
- **Iteration 4**: latency > 500ms (524ms), 0 threats → agent REBALANCE (resource issue)
- **Iteration 5**: latency > 500ms (684ms), 0 threats →
- **Iteration 6**: latency > 500ms (1.245s), 0 threats → REBALANCE executes
- **Iteration 7**: post-remediation check, latency back to 312ms → agent SKIP
- **Iteration 8**: Validator-7 emits `[SLASH]` event → agent OBSERVE (chain-wide consequence)

Each iteration's SPL query, agent reasoning, and audit-chain hash are recorded in `logs/production_agent.json`.

## Dataset 2: `ebpf_network_alerts.json`

### Origin
Synthetic generation peformed by simulating the live `dharma-ebpf` XDP hook output (Rust/aya).

### Schema (one event)
```json
{
  "timestamp": "ISO 8601",
  "src_ip": "string",
  "dst_ip": "string",
  "dst_port": int,
  "proto": "tcp|udp",
  "tcp_flags": "SYN|SYN-ACK|ACK|FIN|RST",
  "pkt_size": int,
  "ttl": int,
  "anomaly": "none|port_scan|syn_flood|...",
  "pid": int | null,
  "comm": "string"
}
```

### Known Findings (Scenario: Tor Exit Node Port Scan)
The dataset simulates a port-scan from `185.220.101.34` (an actual Tor exit IP) targeting Validator-3 across 7 ports:

| Iteration | Query | Anomaly | Action |
|-----------|-------|---------|--------|
| 1 | eBPF anomaly scan | SYN packet from 185.220.101.34 to 8332 | OBSERVE |
| 2 | eBPF threat aggregation | 7 ports scanned in 5 seconds | ESCALATE |
| 3 | Same-source validation | All 7 events share src_ip=185.220.101.34, ttl=16 | ISOLATE (XDP drop) |
| 4 | Post-mitigation | 0 new events from attack source in 60s | VERIFY_AND_CLOSE |

The agent traverses this scenario in `agent_core/orchestrator.py` (note the `latency_ms + threat_count` decision tree in lines 246-300).

## Dataset 3: `container_metrics.csv`

### Origin
Synthetic but mathematically derived from real Docker stats API output for the RadhikaChain container set.

### Schema (one row)
```csv
timestamp,container_name,cpu_percent,mem_percent,mem_usage_mb,net_rx_bytes,net_tx_bytes,restart_count,status
```

### Known Findings (Scenario: Resource Saturation)
The dataset simulates `prana-engine` container climbing from 32.5% CPU → 99.8% CPU between iterations:

- **Iteration 1-2**: All containers healthy (CPU < 60%, mem < 75%)
- **Iteration 3**: `prana-engine` reaches 75% CPU → agent OBSERVE
- **Iteration 4**: `prana-engine` exceeds 80% → agent REBALANCE_CPU
- **Iteration 5**: post-remediation → CPU back to 45% → agent SKIP

## Replayability

Every dataset is **deterministic** — no RNG is used at load time. Running:
```bash
SPLUNK_WEB_URL=... docker compose up
```
produces the exact same Splunk search results on every run (timestamps are stable).

## Reprocessing for Judges

```bash
git clone https://github.com/radhikatmosphere/Krittika-Splunk-Nexus.git
cd Krittika-Splunk-Nexus
docker compose -f docker-compose.yml up -d
# Wait for Splunk Enterprise to come up (≈2 min on c5.large)
docker compose exec splunk /opt/splunk/bin/splunk ready

# Run connectivity test (uses test_datasets in DEMO_MODE=true)
python scripts/test_nexus_endpoints.py

# Inspect results:
#   http://localhost:8000 → search `index=sovereign_fleet`
#   http://localhost:8080  → fleet API (live agent status)
```

Expected query counts at each stage:

| Stage | Splunk Events Loaded | Time |
|-------|----------------------|------|
| Inputs loaded | 830 total (357 + 217 + 256) | <30s |
| `karma_consensus_logs` indexed | 357 | <10s |
| `ebpf_traffic` indexed | 217 | <10s |
| `krittika:container` indexed | 256 | <10s |

## Ethics & Provenance

- All datasets use **RFC 5737 / RFC 1918 / RFC 2606 reserved IPs**:
  - `10.0.1.0/24` (RFC 1918 private)
  - `185.220.101.34` (real Tor exit — used as known-malicious actor only)
  - `192.168.x.x` for internal-only references
- No real blockchain transactions, real validator private keys, or PII
- Container names (`karma-engine`, `mesh-router`, `validator-daemon`, etc.) match the public architecture in `/home/deli/Descargas/3333/AGENTS.md` and are non-sensitive
- Generated by the developer for testing only
