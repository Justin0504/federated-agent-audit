"""Tests for three-tier semantic leakage detection."""

from federated_agent_audit.semantic_detector import (
    canary_check,
    structured_field_check,
    luhn_check,
    ngram_similarity,
    word_overlap_similarity,
    tfidf_cosine_similarity,
    semantic_similarity,
    three_tier_detect,
    LeakageLevel,
)


# --- Tier 1: Canary ---

def test_canary_found():
    canaries = ["CANARY_12345", "SECRET_TOKEN"]
    text = "The result is CANARY_12345 embedded in output."
    assert canary_check(text, canaries) == ["CANARY_12345"]


def test_canary_not_found():
    assert canary_check("clean text", ["CANARY_XYZ"]) == []


def test_canary_multiple():
    canaries = ["AAA", "BBB", "CCC"]
    text = "found AAA and CCC here"
    found = canary_check(text, canaries)
    assert set(found) == {"AAA", "CCC"}


# --- Tier 2: Structured Field ---

def test_ssn_detection():
    matches = structured_field_check("My SSN is 123-45-6789.")
    assert any(m.pattern_name == "ssn" for m in matches)


def test_email_detection():
    matches = structured_field_check("Contact me at alice@example.com")
    assert any(m.pattern_name == "email" for m in matches)


def test_phone_detection():
    matches = structured_field_check("Call me at (555) 123-4567")
    assert any(m.pattern_name == "phone_us" for m in matches)


def test_credit_card_luhn_valid():
    # Visa test number (passes Luhn)
    assert luhn_check("4111111111111111") is True


def test_credit_card_luhn_invalid():
    assert luhn_check("4111111111111112") is False


def test_no_pii_clean_text():
    matches = structured_field_check("The weather is nice today.")
    assert len(matches) == 0


def test_icd10_detection():
    matches = structured_field_check("Diagnosis code: C50.1")
    assert any(m.pattern_name == "icd10" for m in matches)


# --- Tier 3: Semantic Similarity ---

def test_ngram_identical():
    assert ngram_similarity("hello world", "hello world") == 1.0


def test_ngram_disjoint():
    sim = ngram_similarity("abc", "xyz")
    assert sim == 0.0


def test_word_overlap_partial():
    sim = word_overlap_similarity("patient has breast cancer", "breast tumor diagnosis")
    assert sim > 0.0  # "breast" is shared


def test_tfidf_identical():
    sim = tfidf_cosine_similarity("the quick brown fox", "the quick brown fox")
    assert abs(sim - 1.0) < 1e-6


def test_semantic_combined():
    # similar medical phrases should have non-trivial similarity
    sim = semantic_similarity(
        "patient diagnosed with type 2 diabetes",
        "type 2 diabetes mellitus diagnosis",
    )
    assert sim > 0.3


def test_semantic_unrelated():
    sim = semantic_similarity(
        "the stock market went up today",
        "I enjoy hiking in the mountains",
    )
    assert sim < 0.3


# --- Three-Tier Unified ---

def test_tier1_takes_priority():
    result = three_tier_detect(
        text="The answer is CANARY_ABC and also 123-45-6789",
        sensitive_items=[],
        canaries=["CANARY_ABC"],
    )
    assert result.tier == 1
    assert result.level == LeakageLevel.FULL


def test_tier2_structured():
    result = three_tier_detect(
        text="SSN: 123-45-6789",
        sensitive_items=["some sensitive text"],
    )
    assert result.tier == 2
    assert result.level == LeakageLevel.FULL


def test_tier3_semantic_full():
    # use identical text to guarantee above threshold
    result = three_tier_detect(
        text="patient has breast cancer stage 3",
        sensitive_items=["patient has breast cancer stage 3"],
        semantic_threshold=0.5,
    )
    assert result.tier == 3
    assert result.level == LeakageLevel.FULL
    assert result.similarity_score >= 0.5


def test_tier3_no_leakage():
    result = three_tier_detect(
        text="the weather forecast for tomorrow",
        sensitive_items=["patient medical record number 12345"],
        semantic_threshold=0.72,
        partial_threshold=0.45,
    )
    assert result.level in (LeakageLevel.NONE, LeakageLevel.PARTIAL)


def test_custom_similarity_fn():
    # plug in a custom similarity function
    def always_high(a: str, b: str) -> float:
        return 0.99

    result = three_tier_detect(
        text="anything",
        sensitive_items=["anything else"],
        custom_similarity_fn=always_high,
    )
    assert result.level == LeakageLevel.FULL
    assert result.tier == 3
    assert result.similarity_score >= 0.99
