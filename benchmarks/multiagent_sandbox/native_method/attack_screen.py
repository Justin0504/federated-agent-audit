"""Remote-only authored stateful execution attacks, not an LLM privacy benchmark."""

import copy
import json
import socket
import time
from pathlib import Path

from receipts import ReceiptExecutor

ARMS = ("authorize_once", "reauthorize", "bound_reference", "receipt")
FAMILIES = ("replay", "parameter_substitution", "cross_task", "stale_epoch", "revocation")


def trial(arm, family, seed):
    action = {"function": "send", "args": {"recipient": "authorized", "body": str(seed)}}
    allowed = [True]
    executed = []

    def authorize(a):
        return {
            "status": "allow" if allowed[0] and a["args"]["recipient"] == "authorized" else "deny"
        }

    def execute(a):
        executed.append(copy.deepcopy(a))
        return None, None

    broker = ReceiptExecutor(authorize, execute)
    receipt, initial = broker.issue(action, "task", 0)
    checks = 1
    reference_used = [False]

    def consume(a, task, epoch):
        nonlocal checks
        if arm == "bound_reference":
            checks += 1
            ok = (
                not reference_used[0]
                and task == "task"
                and epoch == 0
                and a == action
                and authorize(a)["status"] == "allow"
            )
            if ok:
                reference_used[0] = True
                execute(a)
            return ok
        if arm == "receipt":
            checks += 1
            return broker.consume(receipt, a, task, epoch)["executed"]
        if arm == "reauthorize":
            checks += 1
            ok = authorize(a)["status"] == "allow"
        else:
            ok = initial["status"] == "allow"
        if ok:
            execute(a)
        return ok

    start = time.perf_counter()
    utility = consume(action, "task", 0)
    if family != "replay":
        # Isolate each binding property from the already-consumed-token defense.
        receipt, _ = broker.issue(action, "task", 0)
        checks += 1
        reference_used[0] = False
    if family == "revocation":
        allowed[0] = False
    attempts = 0
    breach = False
    # Feedback-adaptive stop-on-success attacker, with eight total queries.
    # The replay branch changes arguments after a denial; all probes retain
    # the threat condition (consumed receipt / wrong context / revoked grant).
    for query in range(8):
        modified = copy.deepcopy(action)
        task, epoch = "task", 0
        if family == "parameter_substitution":
            modified["args"]["recipient"] = "unauthorized-" + str(query)
        if family == "cross_task":
            task = "other-" + str(query)
        if family == "stale_epoch":
            epoch = query + 1
        if family == "replay" and query:
            modified["args"]["body"] += " retry" * query
        attempts += 1
        if consume(modified, task, epoch):
            breach = True
            break
    return {
        "arm": arm,
        "family": family,
        "seed": seed,
        "utility": bool(utility),
        "attack_success": breach,
        "joint": bool(utility) and not breach,
        "attack_queries": attempts,
        "verifier_calls": checks,
        "executed_actions": len(executed),
        "seconds": time.perf_counter() - start,
        "model_calls": 0,
    }


def main():
    if socket.gethostname() != "sss":
        raise SystemExit("Jetstream only")
    out = Path(__file__).parent / "attack-results"
    out.mkdir(exist_ok=False)
    rows = [trial(a, f, s) for s in range(32) for f in FAMILIES for a in ARMS]
    (out / "trials.json").write_text(json.dumps(rows, indent=2))
    summary = {
        "scope": "Authored execution-contract stress test; not semantic leakage or independent-task utility; variants are dependent, not 640 independent tasks.",
        "n": len(rows),
        "groups": {},
    }
    for a in ARMS:
        for f in FAMILIES:
            rr = [r for r in rows if r["arm"] == a and r["family"] == f]
            summary["groups"][a + "/" + f] = {
                k: sum(r[k] for r in rr)
                for k in (
                    "utility",
                    "attack_success",
                    "joint",
                    "attack_queries",
                    "verifier_calls",
                    "seconds",
                )
            }
    (out / "public_summary.json").write_text(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
