#!/usr/bin/env python3
"""OpenAI + Privacy Firewall — Minimal Working Example

Shows the firewall intercepting real OpenAI API responses.
Run with: OPENAI_API_KEY=sk-... python examples/openai_firewall_demo.py

Two modes demonstrated:
1. Manual check: call firewall.check() on each response
2. Auto-patch: firewall.patch_openai() intercepts ALL calls transparently
"""

from __future__ import annotations

import os
import sys


def main() -> None:
    api_key = os.environ.get("OPENAI_API_KEY", "")
    if not api_key:
        print("Set OPENAI_API_KEY to run with real API calls.")
        print("Running in offline demo mode instead.\n")
        _offline_demo()
        return

    _live_demo(api_key)


def _live_demo(api_key: str) -> None:
    """Demo with real OpenAI API calls."""
    from openai import OpenAI
    from federated_agent_audit import PrivacyPolicy, LLMFirewall

    policy = PrivacyPolicy(
        agent_id="hr_assistant",
        must_not_share=["salary", "SSN", "email", "phone number"],
        acceptable_abstractions={
            "salary": "compensation info",
            "SSN": "government ID",
            "email": "contact info",
            "phone number": "contact info",
        },
    )

    firewall = LLMFirewall(policy, mode="redact")
    client = OpenAI(api_key=api_key)

    prompts = [
        "What is a typical software engineer salary at Google?",
        "Write a sample employee profile with name, email, and salary.",
        "What's the weather like today?",
    ]

    for prompt in prompts:
        print(f"\n{'='*60}")
        print(f"PROMPT: {prompt}")
        print(f"{'='*60}")

        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are an HR assistant with access to employee records."},
                {"role": "user", "content": prompt},
            ],
            max_tokens=200,
        )

        raw_text = response.choices[0].message.content or ""
        print(f"\nRAW RESPONSE:\n  {raw_text[:200]}")

        result = firewall.check(raw_text)
        print(f"\nFIREWALL: {'REDACTED' if result.was_redacted else 'CLEAN'}")
        if result.was_redacted:
            print(f"  Matched: {result.matched_rules}")
            print(f"\nSAFE RESPONSE:\n  {result.final_text[:200]}")

    # Show audit summary
    report = firewall.audit.get_report(apply_dp=False)
    print(f"\n{'='*60}")
    print("AUDIT SUMMARY")
    print(f"{'='*60}")
    print(f"  Total interactions: {report.total_interactions}")
    print(f"  Violations blocked: {report.violations_blocked}")
    print(f"  Leakage rate: {report.leakage_rate:.1%}")


def _offline_demo() -> None:
    """Demo without API keys — uses simulated responses."""
    from federated_agent_audit import PrivacyPolicy, LLMFirewall

    policy = PrivacyPolicy(
        agent_id="hr_assistant",
        must_not_share=["salary", "SSN", "email", "phone number", "credit card"],
        acceptable_abstractions={
            "salary": "compensation info",
            "SSN": "government ID",
            "email": "contact info",
            "phone number": "contact info",
            "credit card": "payment method",
        },
    )

    firewall = LLMFirewall(policy, mode="redact")

    # Simulated LLM responses (what GPT might actually say)
    simulated = [
        ("What is Zhang Wei's salary?",
         "Based on our records, Zhang Wei's current salary is $185,000 annually. "
         "He received a 12% raise in Q4 2025 based on his performance review."),

        ("Give me John's contact info",
         "John Smith can be reached at john.smith@company.com or by phone at "
         "(415) 555-0142. His SSN on file is 123-45-6789."),

        ("How's the team doing?",
         "The engineering team is performing well. Sprint velocity is up 15% "
         "and customer satisfaction scores are above target."),

        ("Show me the new hire's details",
         "New hire: Alice Chen. Starting salary $145,000. "
         "Email: alice.chen@company.com. Credit card ending in 4242-1234-5678-9012 "
         "for corporate expenses."),
    ]

    for prompt, response in simulated:
        print(f"{'='*60}")
        print(f"PROMPT: {prompt}")
        print(f"\nRAW LLM RESPONSE:")
        print(f"  {response}")

        result = firewall.check(response)
        status = "REDACTED" if result.was_redacted else ("BLOCKED" if result.was_blocked else "CLEAN")
        print(f"\nFIREWALL: {status}")
        if result.matched_rules:
            print(f"  Matched keywords: {result.matched_rules}")
        print(f"\nSAFE OUTPUT:")
        print(f"  {result.final_text}")
        print()

    # Audit report
    report = firewall.audit.get_report(apply_dp=False)
    log = firewall.intercept_log
    redacted = sum(1 for r in log if r.was_redacted)

    print(f"{'='*60}")
    print("AUDIT SUMMARY")
    print(f"{'='*60}")
    print(f"  Total interactions: {report.total_interactions}")
    print(f"  Responses redacted: {redacted}/{len(log)}")
    print(f"  Violations blocked: {report.violations_blocked}")
    print(f"  Leakage rate: {report.leakage_rate:.1%}")
    print(f"  Merkle root: {report.merkle_root[:16]}...")
    print()
    print("Run with OPENAI_API_KEY=sk-... to test with real API calls.")


if __name__ == "__main__":
    main()
