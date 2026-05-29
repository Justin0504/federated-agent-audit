# Security Policy

## Reporting a vulnerability

Federated Agent Audit is a privacy/security tool, so we take vulnerabilities
seriously — both in the library itself and in its privacy guarantees (e.g. a
way to recover raw content from a desensitized report, or to bypass a detector).

**Please do not open a public issue for security reports.**

Instead, use GitHub's private vulnerability reporting:
**Security → Report a vulnerability** on the repository, or email the maintainer
at `aojieyua@usc.edu` with:

- a description of the issue and its impact,
- steps to reproduce (a minimal scenario is ideal),
- any suggested remediation.

We aim to acknowledge reports within 5 days and to provide a fix or mitigation
timeline after triage. We'll credit reporters in the changelog unless you
prefer to remain anonymous.

## Scope

In-scope examples:
- raw content leaking into a `LocalAuditReport` / central audit,
- de-pseudonymization of `origin_boundary` without the salt,
- detector bypass that hides a real compositional leak,
- tampering with a Merkle/epoch commitment without detection.

## Supported versions

The latest released minor version on `main` receives security fixes.
