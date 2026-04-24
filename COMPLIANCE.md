# Compliance Mapping

How federated-agent-audit capabilities map to regulatory frameworks.

## Capability → Regulation Matrix

| Capability | Module | GDPR | SOC 2 | EU AI Act | ISO 27001 | CCPA/PIPL |
|------------|--------|------|-------|-----------|-----------|-----------|
| **Privacy gate** (block/redact sensitive content) | `privacy_gate.py` | Art 25 (Data Protection by Design) | CC6.1 (Logical Access) | Art 15 (Transparency) | A.8.2 (Information Classification) | §1798.100 (Right to Know) |
| **Differential privacy** (noise injection on aggregates) | `dp_mechanism.py` | Art 25, Art 89 (Statistical Purposes) | — | Art 15 (Transparency) | — | §1798.145 (De-identification) |
| **6-layer desensitization** (hash, bucket, pseudonym, k-anon, DP, dummies) | `desensitizer.py` | Art 25, Art 32 (Pseudonymization) | CC6.1 | Art 15 | A.8.11 (Data Masking) | §1798.145 |
| **Audit trail** (hash-chain, Merkle tree) | `integrity.py`, `merkle.py` | Art 30 (Records of Processing) | CC7.2 (System Monitoring) | Art 12 (Record-Keeping) | A.8.15 (Logging) | — |
| **Commit-reveal protocol** | `commit_reveal.py` | Art 30 | CC7.2, CC7.3 | Art 12 | A.8.15 | — |
| **Access control** (Bell-LaPadula MAC) | `access_control.py` | Art 32 (Security of Processing) | CC6.3 (Role-Based Access) | — | A.5.15-A.5.18 (Access Control) | — |
| **Taint tracking** (information flow labels) | `taint_tracker.py` | — | — | Art 14 (Traceability) | — | — |
| **Negative inference detection** | `negative_inference.py` | Art 25 (Inference Prevention) | — | Art 15 | — | — |
| **Compound attack detection** | `compound_attack.py` | — | CC7.2 | Art 9 (Risk Management) | A.5.7 (Threat Intelligence) | — |
| **Injection detection** | `injection_detector.py` | — | CC7.2 | Art 15, Art 9 | A.8.8 (Vulnerability Mgmt) | — |
| **7-channel auditing** (AgentLeak C1-C7) | `channel_auditor.py` | Art 30 | CC7.2 | Art 12, Art 14 | A.8.15, A.8.16 | — |
| **Epoch commitment chain** | `epoch_chain.py` | Art 30 (Temporal Records) | CC7.2 | Art 12 | A.8.15 | — |
| **Cross-container verification** | `cross_container.py` | Art 32 | CC7.3 (Change Detection) | — | A.5.23 (Supplier Relations) | — |
| **Lifecycle state machine** | `lifecycle.py` | Art 30 | CC7.2 | Art 14 | A.8.15 | — |
| **Privacy loss quantification** | `privacy_loss.py` | Art 35 (DPIA) | — | Art 9 | — | — |
| **Risk aggregation + alerting** | `risk_aggregator.py` | — | CC7.2, CC7.4 | Art 9 | A.5.7, A.6.8 | — |
| **SDK auto-instrumentation** | `sdk/` | Art 25 (By Design) | CC7.2 | Art 14 | — | — |
| **Transport layer** (client/server) | `transport/` | Art 32 (Encryption in Transit) | CC6.1, CC6.7 | — | A.8.20-A.8.24 | — |

## Key Regulation Summaries

### GDPR (EU General Data Protection Regulation)
- **Art 25**: Data protection by design and by default
- **Art 30**: Records of processing activities
- **Art 32**: Security of processing (pseudonymization, encryption)
- **Art 35**: Data protection impact assessment
- **Art 89**: Safeguards for statistical/research purposes

### SOC 2 Type II
- **CC6.1-CC6.8**: Logical and physical access controls
- **CC7.2**: System monitoring and anomaly detection
- **CC7.3**: Change detection mechanisms
- **CC7.4**: Incident response and recovery

### EU AI Act
- **Art 9**: Risk management system for high-risk AI
- **Art 12**: Record-keeping obligations
- **Art 14**: Human oversight and traceability
- **Art 15**: Accuracy, robustness, and cybersecurity

### ISO 27001:2022
- **A.5**: Organizational controls (policies, access, threat intel)
- **A.8**: Technology controls (classification, logging, masking)

### CCPA / PIPL
- **§1798.100**: Consumer right to know what data is collected
- **§1798.145**: De-identification and pseudonymization exemptions
