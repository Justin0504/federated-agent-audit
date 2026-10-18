"""Pinned AgentDojo task-level defense, using the same bounded local model.

The upstream filter and its parser are executed directly, not reimplemented.
No provider API is contacted. All calls, including filtering, consume budget.
"""

import json
import time
from types import SimpleNamespace


class FilterGenerationError(ValueError):
    def __init__(self, reason, records):
        super().__init__(reason)
        self.records = records


class FilterBudgetExceeded(ValueError):
    def __init__(self, reason, records):
        super().__init__(reason)
        self.records = records


def filter_tools(runtime, request, budget, system):
    from agentdojo.agent_pipeline.agent_pipeline import TOOL_FILTER_PROMPT
    from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLMToolFilter
    from agentdojo.types import text_content_block_from_string
    from backend import NativeFormatError, post

    records = []
    history = []

    def create(**kwargs):
        start = time.monotonic()
        messages = kwargs["messages"]
        # llama.cpp uses system rather than the OpenAI developer role.
        messages = [dict(m, role="system") if m["role"] == "developer" else m for m in messages]
        tools = kwargs["tools"]
        prompt = post("/apply-template", {"messages": messages, "tools": tools})["prompt"]
        tokens = post("/tokenize", {"content": prompt, "add_special": True, "parse_special": True})["tokens"]
        if len(tokens) + budget["max_new_tokens"] > budget["max_input_tokens"]:
            raise FilterBudgetExceeded("filter context exceeds matched budget", records)
        record = {"model_call": True, "baseline_setup_call": True, "response": {
            "input_tokens": None, "output_tokens": None, "usage_unknown": True,
            "requested_prompt_tokens": len(tokens)}}
        records.append(record)
        try:
            response = post("/v1/chat/completions", {
                "messages": messages, "tools": tools, "tool_choice": "none",
                "temperature": 0, "seed": 0, "max_tokens": budget["max_new_tokens"],
                "cache_prompt": False, "chat_template_kwargs": {"enable_thinking": False},
            })
        except NativeFormatError as exc:
            record["format_error"] = "backend_tool_syntax"
            raise FilterGenerationError("filter generated invalid syntax", records) from exc
        finally:
            record["response"]["seconds"] = time.monotonic() - start
        choice = response["choices"][0]
        usage = response.get("usage") or {}
        text = choice["message"].get("content") or ""
        record["response"].update(text=json.dumps({"final": text}),
            input_tokens=usage.get("prompt_tokens"), output_tokens=usage.get("completion_tokens"),
            usage_unknown=any(usage.get(k) is None for k in ("prompt_tokens", "completion_tokens")))
        record["cap_hit"] = choice["finish_reason"] == "length"
        if record["cap_hit"]:
            raise FilterBudgetExceeded("filter output cap reached", records)
        history.extend([messages[-1], {"role": "assistant", "content": text}])
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=text, tool_calls=None))])

    client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
    component = OpenAILLMToolFilter(TOOL_FILTER_PROMPT, client, budget.get("served_model", "Qwen2.5-7B"), temperature=0)
    messages = [
        {"role": "system", "content": [text_content_block_from_string(system)]},
        {"role": "user", "content": [text_content_block_from_string(request)]},
    ]
    component.query(request, runtime, messages=messages)
    return records, history
