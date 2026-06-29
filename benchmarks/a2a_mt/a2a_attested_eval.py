#!/usr/bin/env python3
"""Defense evaluation: forced-embed attestation closes the E4 evasions.

E4 found the inference detector is evaded only by a dishonest *local* labeler
(under-tagging; subject-id forgery). Both require modifying the labeler. With
forced-embed attestation, the auditor+tagger ship as a build-pinned component and
the center accepts a report only from a trusted build. The trusted build's key
lives only in the unmodified binary, so an under-tagged / forged report cannot be
signed by it: the center rejects it. Silent evasion becomes detected
non-compliance.

Run:  python benchmarks/a2a_mt/a2a_attested_eval.py
"""

from __future__ import annotations

from federated_agent_audit.a2a import (
    A2AAttestor,
    A2AAuditor,
    A2AVerifier,
    AgentClearance,
    Message,
    Part,
    PrivacyLabel,
    canonical_subject,
    label_part,
)

BOB = "tenant:bob"
TRUSTED_FP, TRUSTED_KEY = "build:auditor-v1", b"platform-provisioned-key"
CLR = [AgentClearance(agent_id="bob_cal", principal=BOB, purposes=["scheduling"])]


def _frag(j, subject, tag=True):
    lbl = PrivacyLabel(data_subject=subject, owning_principal="tenant:alice",
                       sensitivity=2, category=["schedule"],
                       inferred_categories=["health"] if tag else [],
                       purpose=["scheduling"], allowed_recipients=[BOB])
    return Message(message_id=f"m{j}", from_agent="alice_cal", to_agent="bob_cal",
                   from_principal="tenant:alice", to_principal=BOB,
                   parts=[label_part(Part(text=f"hint {j}"), lbl)])


def main() -> int:
    verifier = A2AVerifier(trusted_builds={TRUSTED_FP: TRUSTED_KEY})
    # the honest, pinned build holds the trusted fingerprint + key
    honest = A2AAttestor("alice", fingerprint=TRUSTED_FP, key=TRUSTED_KEY)
    # any modified build is a *different* binary: different fingerprint, and it
    # does not possess the trusted key
    adversary = A2AAttestor("alice", fingerprint="build:tampered", key=b"attacker-key")

    print("=" * 70)
    print("  Forced-embed attestation vs. the E4 local-labeler evasions")
    print("=" * 70)

    subj = canonical_subject("alice")  # canonical id the attested build derives

    # 1. honest: real tagger emits tags → inference detected → trusted build accepts
    honest_msgs = [_frag(0, subj), _frag(1, subj)]
    r = A2AAuditor(clearances=CLR).audit(honest_msgs)
    att = honest.attest(r)
    v = verifier.verify(r, att)
    print(f"  honest agent          detected={'cross_tenant_inference' in r.types()}"
          f"  accepted={v.ok}")

    # 2. under-tag: to suppress tags the adversary must modify the build → its
    #    report is signed by an untrusted build → rejected
    under = [_frag(0, subj, tag=False), _frag(1, subj, tag=False)]
    r2 = A2AAuditor(clearances=CLR).audit(under)
    v2 = verifier.verify(r2, adversary.attest(r2))
    print(f"  under-tag (mod build) detected={'cross_tenant_inference' in r2.types()}"
          f"  accepted={v2.ok}  reason={v2.reasons}")

    # 3. subject-forgery: aliasing requires bypassing the canonical derivation →
    #    again a modified build → rejected
    forged = [_frag(0, "subject:alice-a"), _frag(1, "subject:alice-b")]
    r3 = A2AAuditor(clearances=CLR).audit(forged)
    v3 = verifier.verify(r3, adversary.attest(r3))
    print(f"  subject-forgery       detected={'cross_tenant_inference' in r3.types()}"
          f"  accepted={v3.ok}  reason={v3.reasons}")

    # 4. report tampering: edit the report but re-sign with the trusted key —
    #    the edges_hash no longer matches
    r4 = A2AAuditor(clearances=CLR).audit(honest_msgs)
    att4 = honest.attest(r4)
    r4.center_view.pop()  # drop an edge after attesting
    v4 = verifier.verify(r4, att4)
    print(f"  tampered report       accepted={v4.ok}  reason={v4.reasons}")

    print("\n  Under-tagging and subject-forgery both require a modified labeler,")
    print("  which lacks the trusted build's key → the center rejects the report")
    print("  (untrusted_or_modified_build). The evasions are converted from silent")
    print("  success into detected non-compliance.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
