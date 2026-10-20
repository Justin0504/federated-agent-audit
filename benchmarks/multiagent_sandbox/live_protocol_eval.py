"""Live member proposals + verified broker + live coordinator, remote only.

Shared member proposals across arms isolate communication policy effects.
"""

import argparse
import hashlib
import json
import socket
from pathlib import Path

try:
    from . import protocol_eval as p
except ImportError:
    import protocol_eval as p


def members(calendars, endpoint):
    responses = []
    valid = True
    for name, slots in zip(("alice", "bob", "carol"), calendars):
        response = p.infer(
            endpoint,
            [
                {
                    "role": "system",
                    "content": "You are a member assistant. Submit all your available integer slots to your trusted local task broker, not to the public group. Return exactly one JSON object with only key slots. No markdown.",
                },
                {
                    "role": "user",
                    "content": (
                        "Member: "
                        + name
                        + "\nPrivate available slots: "
                        + json.dumps(slots)
                        + '\nReturn these same slots under the output key "slots", as {"slots": [integers]}. Do not use the input label as an output key.'
                    ),
                },
            ],
        )
        try:
            obj = json.loads(response["text"])
            ok = isinstance(obj, dict) and set(obj) == {"slots"} and isinstance(obj["slots"], list)
            ok = ok and all(type(x) is int for x in obj["slots"]) and sorted(obj["slots"]) == slots
        except ValueError:
            ok = False
        responses.append(dict(response, member=name, verified=ok))
        valid &= ok
    return valid, responses


def summarize(rows):
    summary = {"episodes": len(rows), "arms": {}}
    for arm in p.ARMS:
        rr = [r for r in rows if r["arm"] == arm]
        observed = [r for r in rr if r.get("additional_bits") is not None]
        pairs = [rr[i : i + 2] for i in range(0, len(rr), 2)]
        comparable = [x for x in pairs if len(x) == 2 and all("transcript" in r for r in x)]
        summary["arms"][arm] = {
            "n": len(rr),
            "utility": sum(r["utility"] is True for r in rr),
            "joint": sum(r["joint"] is True for r in rr),
            "member_failures": sum(r.get("member_failure", False) for r in rr),
            "infra_errors": sum(r.get("infra_error") is not None for r in rr),
            "privacy_observed": len(observed),
            "mean_additional_bits": sum(r["additional_bits"] for r in observed) / len(observed)
            if observed
            else None,
            "mean_reconstruction": sum(r["reconstruction_fraction"] for r in observed)
            / len(observed)
            if observed
            else None,
            "comparable_pairs": len(comparable),
            "different_transcript_pairs": sum(
                x[0]["transcript"] != x[1]["transcript"] for x in comparable
            ),
            "coordinator_format_errors": sum(r.get("format_error", False) for r in rr),
            "coordinator_output_caps": sum(r.get("output_cap", False) for r in rr),
        }
    return summary


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--expected-host", required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--pairs", type=int, default=4)
    ap.add_argument("--seed", type=int, default=20261017)
    ap.add_argument("--endpoint", default="http://127.0.0.1:18088")
    a = ap.parse_args()
    if socket.gethostname() != a.expected_host or not 1 <= a.pairs <= 32:
        raise SystemExit("remote host/bounds mismatch")
    a.out.mkdir(parents=True, exist_ok=False)
    protocol = dict(
        vars(a),
        out=str(a.out),
        budget=8,
        arms=p.ARMS,
        planned_calls=14 * a.pairs,
        source_hashes={
            name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
            for name in ("run.py", "protocol_eval.py", "live_protocol_eval.py")
        },
        limitations=[
            "trusted broker",
            "shared member proposals across arms",
            "finite conditional prior",
            "not MPC",
            "payload-only twin-world test",
            "no open-ended planning",
        ],
    )
    (a.out / "protocol.json").write_text(json.dumps(protocol, indent=2))
    rows = []
    member_calls = 0
    member_caps = 0
    with (
        (a.out / "attempts.jsonl").open("w") as log,
        (a.out / "member_responses.jsonl").open("w") as raw,
    ):
        for case in range(a.pairs):
            worlds = p.pair(a.seed, case)[:2]
            # Fixed shared proposals are generated once per world, not best-of-N selected.
            submitted = []
            for world, calendars in enumerate(worlds):
                try:
                    valid, responses = members(calendars, a.endpoint)
                    member_calls += len(responses)
                    member_caps += sum(r["output_cap"] for r in responses)
                    submitted.append((valid, None))
                    raw.write(
                        json.dumps({"case": case, "world": world, "responses": responses}) + "\n"
                    )
                    raw.flush()
                except (OSError, RuntimeError, KeyError) as exc:
                    submitted.append((False, str(exc)))
            for arm in p.ARMS:
                for world, calendars in enumerate(worlds):
                    valid, error = submitted[world]
                    row = {
                        "case": case,
                        "world": world,
                        "arm": arm,
                        "member_failure": not valid and error is None,
                        "infra_error": error,
                        "utility": None if error else False,
                        "joint": None if error else False,
                    }
                    if valid:
                        try:
                            row.update(p.run_case(calendars, arm, 8, a.endpoint))
                        except (OSError, RuntimeError, KeyError) as exc:
                            row.update(infra_error=str(exc), utility=None, joint=None)
                    rows.append(row)
                    log.write(json.dumps(row) + "\n")
                    log.flush()
                    print(
                        json.dumps(
                            {
                                k: v
                                for k, v in row.items()
                                if k not in ("transcript", "coordinator_output")
                            }
                        ),
                        flush=True,
                    )
            if any(r["infra_error"] for r in rows):
                break
    summary = summarize(rows)
    summary.update(
        member_calls=member_calls,
        member_output_caps=member_caps,
        planned_episodes=8 * a.pairs,
        complete=len(rows) == 8 * a.pairs and all(r["infra_error"] is None for r in rows),
    )
    (a.out / "summary.json").write_text(json.dumps(summary, indent=2))
    if not summary["complete"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
