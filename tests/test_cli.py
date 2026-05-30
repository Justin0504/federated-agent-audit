"""Tests for the `federated-audit` CLI (cli.main)."""

from __future__ import annotations

import json

import pytest

from federated_agent_audit.cli import main


def _run(capsys, argv):
    try:
        main(argv)
    except SystemExit as e:  # argparse / explicit exits are fine
        if e.code not in (None, 0):
            raise
    return capsys.readouterr().out


def test_scan_clean_text(capsys):
    out = _run(capsys, ["scan", "the weather is nice today"])
    assert "CLEAN" in out.upper() or "clean" in out.lower()


def test_scan_redacts_pii(capsys):
    out = _run(capsys, ["scan", "my email is john@acme.com"])
    assert "REDACTED" in out.upper()
    assert "john@acme.com" not in out


def test_scan_protect_keyword(capsys):
    out = _run(capsys, ["scan", "her salary is high", "--protect", "salary"])
    assert "salary" not in out.lower().split("detected")[-1] or "REDACTED" in out.upper()


def test_scan_json_output(capsys):
    out = _run(capsys, ["scan", "SSN is 123-45-6789", "--json"])
    payload = json.loads(out)
    assert "clean" in payload
    assert payload["clean"] is False


def test_version(capsys):
    out = _run(capsys, ["version"])
    assert any(ch.isdigit() for ch in out)


def test_demo_runs(capsys):
    out = _run(capsys, ["demo"])
    assert len(out) > 0


def test_validate_policy_file(capsys, tmp_path):
    policy = tmp_path / "p.json"
    policy.write_text(json.dumps({"agent_id": "bot", "must_not_share": ["salary"]}))
    out = _run(capsys, ["validate", str(policy)])
    assert "bot" in out or "valid" in out.lower() or "✓" in out


def test_validate_bad_file(capsys, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{ not valid json")
    # A malformed policy should be reported and exit non-zero (graceful, not a crash).
    with pytest.raises(SystemExit) as exc:
        main(["validate", str(bad)])
    assert exc.value.code not in (None, 0)
    assert "ERROR" in capsys.readouterr().out.upper()
