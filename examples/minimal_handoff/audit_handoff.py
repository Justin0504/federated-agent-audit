"""Mirror a real handoff into the existing auditor; no model or network calls."""
import json
from federated_agent_audit.a2a import AuditSession


def audit_handoff(text: str, *, recipient: str, sensitivity: int,
                  categories: list[str], allowed_recipients: list[str]) -> dict:
    """Caller supplies policy from trusted configuration, not agent-generated text.

    This observes a handoff. It neither sends the message nor enforces a policy.
    Do not treat an empty finding list as proof of semantic privacy.
    """
    session = AuditSession()
    session.declare('recipient', principal=recipient, purposes=['support'])
    session.send('support', 'recipient', text,
                 from_principal='org:example', to_principal=recipient,
                 data_subject='subject:example', owning_principal='org:example',
                 sensitivity=sensitivity, category=categories, purpose=['support'],
                 allowed_recipients=allowed_recipients)
    result = session.run()
    # Export aggregate findings only; no raw message, hashes or subject IDs.
    return {'finding_types': sorted(result.types()),
            'finding_count': len(result.violations),
            'message_count': len(result.center_view)}


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', help='Local JSON file with function arguments')
    args = parser.parse_args()
    payload = json.load(open(args.input)) if args.input else dict(
        text='Synthetic support record: account balance is 1200.',
        recipient='vendor:external', sensitivity=5, categories=['finance'],
        allowed_recipients=['org:example'])
    print(json.dumps(audit_handoff(**payload), indent=2))
