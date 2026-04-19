"""Tests for hash-chain integrity."""

from federated_agent_audit.schemas import AuditEntry
from federated_agent_audit.integrity import HashChain, GENESIS_HASH


def _make_entry(trace_id: str, text: str) -> AuditEntry:
    return AuditEntry(
        trace_id=trace_id, agent_id="agent_a",
        action="message_send", output_text=text,
    )


def test_append_and_verify():
    chain = HashChain()
    chain.append(_make_entry("t1", "hello"))
    chain.append(_make_entry("t1", "world"))

    valid, idx = chain.verify_chain()
    assert valid
    assert idx == 2


def test_empty_chain_valid():
    chain = HashChain()
    valid, idx = chain.verify_chain()
    assert valid
    assert idx == 0


def test_tamper_detection():
    chain = HashChain()
    chain.append(_make_entry("t1", "original message"))
    chain.append(_make_entry("t1", "second message"))

    # tamper with first entry
    chain._chain[0].entry.output_text = "tampered message"

    valid, broken_at = chain.verify_chain()
    assert not valid
    assert broken_at == 0


def test_tamper_middle_of_chain():
    chain = HashChain()
    for i in range(5):
        chain.append(_make_entry("t1", f"message {i}"))

    # tamper with entry 2
    chain._chain[2].entry.output_text = "tampered"

    valid, broken_at = chain.verify_chain()
    assert not valid
    assert broken_at == 2


def test_chain_links():
    chain = HashChain()
    e1 = chain.append(_make_entry("t1", "first"))
    e2 = chain.append(_make_entry("t1", "second"))

    assert e1.prev_hash == GENESIS_HASH
    assert e2.prev_hash == e1.entry_hash
    assert e2.entry_hash != e1.entry_hash


def test_verify_single_entry():
    chain = HashChain()
    chain.append(_make_entry("t1", "msg"))
    assert chain.verify_entry(0)
    assert not chain.verify_entry(1)  # out of range


def test_snapshot():
    chain = HashChain()
    chain.append(_make_entry("t1", "msg"))
    snap = chain.snapshot()
    assert snap["chain_length"] == 1
    assert snap["head_hash"] == chain.head_hash
    assert snap["genesis_hash"] == GENESIS_HASH


def test_head_hash_changes():
    chain = HashChain()
    h0 = chain.head_hash
    chain.append(_make_entry("t1", "msg1"))
    h1 = chain.head_hash
    chain.append(_make_entry("t1", "msg2"))
    h2 = chain.head_hash

    assert h0 != h1 != h2
