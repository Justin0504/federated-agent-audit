#!/usr/bin/env python3
"""Real Telegram Bot with Live Privacy Audit

A working Telegram bot that:
1. Receives user messages
2. Calls OpenAI GPT to generate responses
3. Runs every response through the privacy firewall BEFORE sending
4. Blocks or redacts sensitive content in real-time
5. Collects audit reports for central network analysis

Setup:
    pip install "federated-agent-audit[transport]" python-telegram-bot openai

    export TELEGRAM_BOT_TOKEN="your-bot-token"
    export OPENAI_API_KEY="your-openai-key"

    python examples/telegram_bot_real.py

How to get a Telegram bot token:
    1. Message @BotFather on Telegram
    2. Send /newbot
    3. Follow the prompts
    4. Copy the token

The bot will respond to any message, but the firewall ensures
sensitive data (salary, SSN, emails, etc.) is redacted before
the user ever sees it.
"""

from __future__ import annotations

import logging
import os
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("telegram_audit_bot")


def main() -> None:
    # ── Check dependencies ──────────────────────────────────────
    try:
        from telegram import Update
        from telegram.ext import (
            Application,
            CommandHandler,
            MessageHandler,
            ContextTypes,
            filters,
        )
    except ImportError:
        print("Install python-telegram-bot: pip install python-telegram-bot")
        sys.exit(1)

    try:
        from openai import OpenAI
    except ImportError:
        print("Install openai: pip install openai")
        sys.exit(1)

    # ── Configuration ───────────────────────────────────────────
    TELEGRAM_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    OPENAI_KEY = os.environ.get("OPENAI_API_KEY", "")

    if not TELEGRAM_TOKEN:
        print("Set TELEGRAM_BOT_TOKEN environment variable")
        print("Get one from @BotFather on Telegram")
        sys.exit(1)

    if not OPENAI_KEY:
        print("Set OPENAI_API_KEY environment variable")
        sys.exit(1)

    # ── Privacy Policy ──────────────────────────────────────────
    from federated_agent_audit import PrivacyPolicy, LLMFirewall, NetworkAuditor

    policy = PrivacyPolicy(
        agent_id="telegram_hr_bot",
        must_not_share=[
            "salary", "SSN", "social security",
            "bank account", "credit card",
            "email", "phone number",
            "performance review", "termination",
            "medical", "diagnosis",
        ],
        acceptable_abstractions={
            "salary": "compensation information",
            "SSN": "government ID",
            "social security": "government ID",
            "bank account": "financial account",
            "credit card": "payment method",
            "email": "contact information",
            "phone number": "contact information",
            "performance review": "performance summary",
            "termination": "employment change",
            "medical": "health information",
            "diagnosis": "health information",
        },
        sensitivity_threshold=3,
    )

    # ── LLM Firewall (the key innovation) ───────────────────────
    violation_count = 0

    def on_violation(result):
        nonlocal violation_count
        violation_count += 1
        logger.warning(
            "Violation #%d — blocked %d terms: %s",
            violation_count, len(result.matched_rules), result.matched_rules,
        )

    firewall = LLMFirewall(
        policy=policy,
        mode="redact",  # redact sensitive terms, don't fully block
        to_agent="telegram_user",
        on_violation=on_violation,
    )

    # ── OpenAI Client ───────────────────────────────────────────
    client = OpenAI(api_key=OPENAI_KEY)

    SYSTEM_PROMPT = """You are an HR assistant bot for a company's internal Telegram group.
You help employees with questions about policies, benefits, and team information.
You have access to employee records including salaries, performance reviews, and personal details.
Answer questions helpfully and thoroughly — the privacy firewall will handle redaction."""

    # ── Bot Handlers ────────────────────────────────────────────

    async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        await update.message.reply_text(
            "Hello! I'm an HR assistant bot with privacy auditing.\n\n"
            "Ask me anything about employees, policies, or benefits.\n"
            "Sensitive data (salary, SSN, etc.) is automatically redacted.\n\n"
            "Commands:\n"
            "/audit — Show audit stats\n"
            "/violations — Show recent violations"
        )

    async def audit_stats(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        report = firewall.audit.get_report(apply_dp=False)
        log = firewall.intercept_log

        redacted = sum(1 for r in log if r.was_redacted)
        blocked = sum(1 for r in log if r.was_blocked)

        text = (
            f"Audit Report\n"
            f"{'─' * 30}\n"
            f"Total interactions: {report.total_interactions}\n"
            f"Violations blocked: {report.violations_blocked}\n"
            f"Responses redacted: {redacted}\n"
            f"Responses blocked: {blocked}\n"
            f"Leakage rate: {report.leakage_rate:.1%}\n"
            f"Merkle root: {report.merkle_root[:16]}...\n"
        )
        await update.message.reply_text(text)

    async def show_violations(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        log = firewall.intercept_log
        violations = [r for r in log if r.was_redacted or r.was_blocked]

        if not violations:
            await update.message.reply_text("No violations detected yet.")
            return

        lines = ["Recent violations:\n"]
        for v in violations[-5:]:
            status = "BLOCKED" if v.was_blocked else "REDACTED"
            rules = ", ".join(v.matched_rules[:3])
            lines.append(f"[{status}] {rules}")

        await update.message.reply_text("\n".join(lines))

    async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        user_msg = update.message.text
        user_name = update.effective_user.first_name or "User"

        logger.info("Message from %s: %s", user_name, user_msg[:50])

        try:
            # 1. Call real OpenAI API
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_msg},
                ],
                max_tokens=500,
            )
            llm_text = response.choices[0].message.content or ""

            # 2. Run through privacy firewall BEFORE sending to user
            result = firewall.check(llm_text)

            if result.was_blocked:
                reply = result.final_text
                logger.warning("Response BLOCKED for user %s", user_name)
            elif result.was_redacted:
                reply = result.final_text
                logger.info("Response REDACTED for user %s (%d terms)", user_name, len(result.matched_rules))
            else:
                reply = llm_text

            # 3. Send the safe (potentially redacted) response
            await update.message.reply_text(reply)

        except Exception as e:
            logger.error("Error: %s", e)
            await update.message.reply_text("Sorry, something went wrong. Please try again.")

    # ── Start Bot ───────────────────────────────────────────────
    logger.info("Starting Telegram bot with privacy firewall")
    logger.info("Policy: %d blocked terms, %d PII patterns active",
                len(policy.must_not_share), len(firewall._gate._active_pii))

    app = Application.builder().token(TELEGRAM_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("audit", audit_stats))
    app.add_handler(CommandHandler("violations", show_violations))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

    logger.info("Bot is running. Send messages on Telegram to test.")
    app.run_polling()


if __name__ == "__main__":
    main()
