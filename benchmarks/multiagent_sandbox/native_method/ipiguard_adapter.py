"""Execute pinned official IPIGuard against the shared AgentDojo environment.

Only message-version compatibility and resource accounting are adapted.
Official planning, traversal, whitelist and reflection code remain unchanged.
"""

import importlib.util
import inspect
import os
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

REVISION = "4e686ed2f62c135cb12564a4466daa95f3ace878"


class BudgetExceeded(RuntimeError):
    pass


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def components():
    root = Path(os.environ.get("FAA_IPIGUARD_SOURCE", "/dev/shm/faa-ipiguard"))
    revision = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    if revision != REVISION:
        raise ValueError("IPIGuard source revision mismatch")
    source = root / "agentdojo/src/agentdojo"
    load("agentdojo.default_suites.v1.tools.tool_white_list", source / "default_suites/v1/tools/tool_white_list.py")
    compat = load("_ipiguard_messages", source / "agent_pipeline/llms/openai_llm.py")
    llm = load("_official_ipiguard_llm", source / "agent_pipeline/llms/ipiguard_llm.py")
    llm._message_to_openai = compat._message_to_openai
    execution = load("_official_ipiguard_execution", source / "agent_pipeline/tool_execution.py")
    return llm, execution


def metered_completion(post, kwargs, budget, counts, records, repair):
    """Keep attempted generations observable even when parsing/server calls fail."""
    if counts["model"] >= budget["max_steps"]:
        raise BudgetExceeded("model_call_budget")
    start = time.monotonic()
    messages = kwargs["messages"]
    prompt = post("/apply-template", {"messages": messages})["prompt"]
    tokens = post("/tokenize", {"content": prompt, "add_special": True, "parse_special": True})["tokens"]
    if len(tokens) + budget["max_new_tokens"] > budget["max_input_tokens"]:
        records.append({"model_call": False, "repair_call": False,
                        "context_budget_exhausted": True, "response": {
                            "input_tokens": 0, "output_tokens": 0,
                            "seconds": time.monotonic() - start}})
        raise BudgetExceeded("context_budget")
    body = dict(kwargs, model=budget.get("served_model", "Qwen2.5-7B"), temperature=0, seed=0,
                max_tokens=budget["max_new_tokens"], cache_prompt=False,
                chat_template_kwargs={"enable_thinking": False})
    counts["model"] += 1
    record = {"model_call": True, "repair_call": repair, "response": {
        "input_tokens": None, "output_tokens": None, "usage_unknown": True,
        "requested_prompt_tokens": len(tokens)}}
    records.append(record)
    try:
        response = post("/v1/chat/completions", body)
        usage = response.get("usage") or {}
        record["response"].update(input_tokens=usage.get("prompt_tokens"),
                                  output_tokens=usage.get("completion_tokens"),
                                  usage_unknown=any(usage.get(k) is None for k in
                                                    ("prompt_tokens", "completion_tokens")))
        choice = response["choices"][0]
        record["response"]["text"] = choice["message"].get("content") or ""
        record["cap_hit"] = choice["finish_reason"] == "length"
        if record["cap_hit"]:
            raise BudgetExceeded("output_budget")
        return response
    finally:
        record["response"]["seconds"] = time.monotonic() - start


def run(runtime, env, request, budget, score, calls):
    from agentdojo.functions_runtime import FunctionCall
    from backend import NativeFormatError, post
    from openai.types.chat import ChatCompletion

    llm, execution = components()
    records = []
    counts = {"model": 0, "tools": 0}

    def create(**kwargs):
        repair = any(f.function == "query_reflection" for f in inspect.stack())
        response = metered_completion(post, kwargs, budget, counts, records, repair)
        return ChatCompletion.model_validate(response)

    class MeteredRuntime:
        def __getattr__(self, name):
            return getattr(runtime, name)

        def run_function(self, environment, function, args):
            if counts["tools"] >= budget["max_steps"]:
                raise BudgetExceeded("action_budget")
            counts["tools"] += 1
            call = FunctionCall(function=function, args=args)
            calls.append(call)
            output, error = runtime.run_function(environment, function, args)
            records.append({"model_call": False, "response": {}, "tool_error": error,
                            "tool_function": function, "verdict": {"status": "allow", "reason": "official_ipiguard"}})
            return output, error

    client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
    construct = llm.OpenAIConstructLLM(client, budget.get("served_model", "Qwen2.5-7B"))
    traverse = llm.OpenAITraverseLLM(client, budget.get("served_model", "Qwen2.5-7B"))
    executor = execution.DagToolsExecutionLoop(execution.DagToolsExecutor(traverse))
    messages = [{"role": "system", "content": budget["system"]}, {"role": "user", "content": request}]
    initial = score("")
    final, error, exhausted = "", None, False
    try:
        args = construct.query(request, MeteredRuntime(), env, messages, {})
        _, _, _, messages, _ = executor.query(*args)
        if messages and messages[-1]["role"] == "assistant":
            final = messages[-1].get("content") or ""
    except BudgetExceeded as exc:
        error, exhausted = str(exc), True
    except (ValueError, KeyError, TypeError, NativeFormatError) as exc:
        # Preserve invalid plans; do not retune prompts or manufacture tool success.
        error = type(exc).__name__
        records.append({"model_call": False, "response": {}, "format_error": error})
    return {"initial": initial, "outcome": score(final), "steps": records,
            "final": final, "terminated": error is None, "step_budget_exhausted": exhausted,
            "baseline_failure": error, "baseline_revision": REVISION,
            "model_calls": counts["model"], "action_attempts": counts["tools"]}
