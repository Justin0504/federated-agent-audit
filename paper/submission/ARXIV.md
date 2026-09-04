# arXiv upload — turnkey metadata

Upload `arxiv_submission.zip` (built by `make arxiv`; contains `main.tex`,
`references.bib`, `main.bbl` — self-contained, compiles under arXiv's pdfLaTeX, no
bibtex step needed because `main.bbl` is bundled). Then paste the fields below.

## Title
Privacy Typing for Multi-Tenant Agent Interaction: A Federated, Center-Blind Auditor and an A2A Extension

## Authors
Aojie (Justin) Yuan (University of Southern California)

## Primary category
cs.CR  (Cryptography and Security)

## Cross-list
cs.AI  (Artificial Intelligence);  cs.LG  (Machine Learning)

## Comments
11 pages, 4 figures. Code and the A2A-MT benchmark: https://github.com/Justin0504/federated-agent-audit

## License
Recommended: CC BY 4.0 (or arXiv's non-exclusive license if you prefer). CC BY keeps
the option open for the PoPETs artifact (PETS publishes CC BY).

## Abstract (plain text — paste as-is)
Autonomous agents increasingly delegate work to one another across organizational
boundaries, and protocols such as A2A now standardize how. These protocols carry no
notion of whom a datum concerns or who may receive it, so the resulting leakage is
hard to see: it happens on internal agent-to-agent channels and is often
compositional, emerging from messages that are each individually benign. Centralized
observability offers no remedy, because it must read the very content that sensitive,
cross-organizational deployments will not expose.

We present a federated auditor that detects these leaks from desensitized metadata it
can never invert to content, together with a privacy-typing extension to A2A that
makes the leaks expressible in the first place. By separating the data subject, the
owning principal, and the agent principal, the auditor flags cross-tenant disclosure,
purpose violations, over-forwarding, and cross-tenant inference, all without reading a
message. We prove the center-blind guarantee (the center learns O(log) bits per
message) and characterize when inference becomes detectable, then test the system
where it is easiest to fool ourselves: on a benchmark authored by a separate model it
keeps perfect precision, and against a real LLM recipient we confirm that two benign
fragments already expose a withheld attribute, a threat that grows with model
capability. On its single-tenant projection, which is the deployable product, the
auditor catches every internal-channel leak in AgentLeak's 600 scenarios at 0.97
precision with zero content egress.

## Notes
- This is v1. After the open-weight multi-model rows land, upload v2 (arXiv keeps the
  version history and the same identifier).
- PoPETs "discourages but ignores" preprints during review — posting now is safe for a
  later PoPETs 2027.3 / S&P 2027 submission; the PC disregards the arXiv identity.
- Non-anonymous by design (preprint under your name); the double-blind build lives in
  `paper/popets/`.
