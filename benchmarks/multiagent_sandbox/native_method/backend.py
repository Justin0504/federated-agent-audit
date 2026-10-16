"""Remote-local llama.cpp requests with exact pre-rendered context accounting."""

import json
import time
import urllib.request

ACTION_SCHEMA = {
    "anyOf": [
        {
            "type": "object",
            "properties": {
                "function": {"type": "string"},
                "args": {"type": "object", "additionalProperties": True},
            },
            "required": ["function", "args"],
            "additionalProperties": False,
        },
        {
            "type": "object",
            "properties": {"final": {"type": "string"}},
            "required": ["final"],
            "additionalProperties": False,
        },
    ]
}

ENDPOINT = "http://127.0.0.1:18089"


def post(path, data):
    req = urllib.request.Request(
        ENDPOINT + path,
        data=json.dumps(data).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=600) as response:
        return json.load(response)


def generate(messages, p):
    start = time.monotonic()
    try:
        prompt = post("/apply-template", {"messages": messages})["prompt"]
        tokens = post("/tokenize", {"content": prompt, "add_special": True, "parse_special": True})[
            "tokens"
        ]
        if len(tokens) + p["max_new_tokens"] > p["max_input_tokens"]:
            raise ValueError("Input plus output budget exceeds context; not generated")
        response = post(
            "/completion",
            {
                "prompt": tokens,
                "n_predict": p["max_new_tokens"],
                "temperature": 0,
                "seed": 0,
                "stream": False,
                "cache_prompt": False,
                "repeat_penalty": 1.0,
                "presence_penalty": 0.0,
                "frequency_penalty": 0.0,
                "json_schema": ACTION_SCHEMA,
            },
        )
        if response.get("truncated"):
            raise ValueError("Backend reported context truncation")
        result = {
            "text": response["content"],
            "input_tokens": len(tokens),
            "output_tokens": response.get("tokens_predicted"),
            "truncated": bool(response.get("stopped_limit")),
            "context_truncation_verified": True,
            "cache_prompt": False,
            "action_schema_constrained": True,
        }
    except (OSError, ValueError, KeyError, TypeError) as exc:
        result = {"error": type(exc).__name__ + ": " + str(exc)}
    result["seconds"] = time.monotonic() - start
    return result
