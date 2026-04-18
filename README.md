# Federated Agent Audit

Federated auditing protocols for multi-agent systems. Each agent maintains its own audit log locally and commits Merkle roots as tamper-proof summaries. When disputes arise, a commit-reveal protocol allows selective disclosure of audit entries with cryptographic verification -- without requiring agents to share their full logs.

Built as a research prototype for studying privacy-preserving compliance verification in multi-agent social networks, extending the threat model from [AgentSocialBench](https://arxiv.org/abs/2604.01487).

## Structure

- `src/federated_agent_audit/` -- core library
  - `merkle.py` -- Merkle tree construction and verification
  - `commit_reveal.py` -- commit-reveal audit protocol
  - `privacy_gate.py` -- runtime privacy enforcement (block/redact)
  - `schemas.py` -- data models
- `tests/` -- unit tests
- `experiments/` -- evaluation scripts
- `paper/` -- manuscript materials

## Setup

```bash
pip install -e ".[dev]"
pytest
```
