# Krittika-Splunk Nexus Architecture

## System Overview

```mermaid
graph TB
    subgraph "RadhikaChain Fleet"
        V1[Validator-1]
        V2[Validator-2]
        V3[Validator-3]
        V7[Validator-7]
    end

    subgraph "Data Collection"
        UF[Splunk Universal Forwarder]
        eBPF[eBPF/dharma-sensor]
        Docker[Docker Stats]
    end

    subgraph "Splunk Cloud Platform"
        IDX[(krittika_consensus)]
        IDX2[(krittika_network)]
        IDX3[(krittika_metrics)]
        IDX4[(krittika_audit)]
        MCP[Splunk MCP Server]
        DASH1[sovereign_fleet.xml]
        DASH2[ai_autonomy_oversight.xml]
    end

    subgraph "Krittika AI Agent"
        CLIENT[Splunk MCP Client]
        ENGINE[Decision Engine]
        AUDIT[Chain Hash AuditLogger]
        REMED[Remediation Actions]
    end

    subgraph "Closed-Loop Actions"
        DOCKER_CMD[docker update --cpus]
        IPTABLES[iptables DROP]
        XDP[xdp-loader]
        HEALTH[health_check]
    end

    V1 --> UF
    V2 --> UF
    V3 --> UF
    V7 --> UF
    V1 --> eBPF
    V2 --> eBPF
    V3 --> eBPF
    V7 --> eBPF
    V1 --> Docker
    V2 --> Docker
    V3 --> Docker
    V7 --> Docker

    UF -->|HEC| IDX
    UF -->|HEC| IDX2
    UF -->|HEC| IDX3
    eBPF -->|HEC| IDX2
    Docker -->|HEC| IDX3

    IDX --> MCP
    IDX2 --> MCP
    IDX3 --> MCP
    IDX4 --> MCP

    MCP -->|MCP over HTTP| CLIENT
    CLIENT --> ENGINE
    ENGINE -->|log_intent| AUDIT
    ENGINE -->|execute| REMED
    REMED -->|log_outcome| AUDIT
    AUDIT -->|HEC| IDX4

    ENGINE -->|rebalance| DOCKER_CMD
    ENGINE -->|isolate| IPTABLES
    ENGINE -->|block| XDP
    ENGINE -->|verify| HEALTH

    MCP --> DASH1
    IDX4 --> DASH2
```

## Data Flow

1. **Ingest**: Validators emit consensus logs, eBPF sensors capture network events, Docker reports resource metrics
2. **Index**: Splunk Universal Forwarder sends all data to Splunk Cloud via HEC
3. **Query**: AI Agent queries Splunk via MCP Server (`splunk_run_query`)
4. **Decide**: Decision Engine classifies anomaly (security vs. resource)
5. **Audit**: Chain Hash AuditLogger records intent (pre-execution)
6. **Act**: Remediation Actions execute (docker/iptables/xdp)
7. **Verify**: Post-action health check confirms effectiveness
8. **Audit**: Chain Hash AuditLogger records outcome (post-execution)
9. **Visualize**: Dashboards display operational state and audit trail

## Security Model

- **HEC Token**: Write-only access to `krittika_audit` index
- **MCP Token**: Encrypted, role-based (`mcp_tool_execute` capability)
- **Chain Hash**: SHA-256 linked entries — tampering breaks the chain
- **Session ID**: Groups related decisions for forensic reconstruction
- **RBAC**: Agent cannot delete or modify audit entries
