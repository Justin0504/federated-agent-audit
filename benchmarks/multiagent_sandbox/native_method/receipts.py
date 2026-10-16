"""One-process experimental authorization/action binding; not semantic verification."""

import hashlib
import hmac
import json
import secrets
import threading


def canonical(action):
    return json.dumps(action, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


class ReceiptExecutor:
    """Serialize authority recheck and native mock-tool execution.

    Trusts the supplied authorizer. This does not certify the message body's
    confidentiality, and the in-process lock is not a distributed transaction.
    """

    def __init__(self, authorize, execute):
        self.authorize = authorize
        self.execute = execute
        self.key = secrets.token_bytes(32)
        self.used = set()
        self.lock = threading.Lock()

    def issue(self, action, task_id, epoch):
        verdict = self.authorize(action)
        if verdict["status"] != "allow":
            return None, verdict
        receipt = {
            "task_id": task_id,
            "epoch": epoch,
            "action_sha256": hashlib.sha256(canonical(action)).hexdigest(),
            "nonce": secrets.token_hex(16),
        }
        receipt["mac"] = hmac.new(self.key, canonical(receipt), hashlib.sha256).hexdigest()
        return receipt, verdict

    def consume(self, receipt, action, task_id, epoch):
        with self.lock:
            fields = dict(receipt)
            mac = fields.pop("mac", "")
            valid = hmac.compare_digest(
                mac, hmac.new(self.key, canonical(fields), hashlib.sha256).hexdigest()
            )
            if not valid or fields.get("task_id") != task_id or fields.get("epoch") != epoch:
                return {"executed": False, "receipt_error": "invalid_binding"}
            if fields.get("action_sha256") != hashlib.sha256(canonical(action)).hexdigest():
                return {"executed": False, "receipt_error": "action_substitution"}
            if fields["nonce"] in self.used:
                return {"executed": False, "receipt_error": "replay"}
            verdict = self.authorize(action)
            if verdict["status"] != "allow":
                return {"executed": False, "receipt_error": "authorization_changed"}
            # Consume before invoking: ambiguous tool failures must not be replayed.
            self.used.add(fields["nonce"])
            output, error = self.execute(action)
            return {"executed": True, "output": output, "error": error}
