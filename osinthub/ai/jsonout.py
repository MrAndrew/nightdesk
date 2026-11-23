"""JSON replies from a chat model: the instruction to add, pulling the JSON out of the reply, and a small schema check.

Shared by the built-in helper (osinthub/ai/server.py) and the app's client for other OpenAI-compatible servers
(osinthub/ai/client.py), so a reply is checked the same way whichever model wrote it. Imports nothing from the app.
okf/architecture/local-ai.md#json-output
"""
from __future__ import annotations

import json
import re
from typing import Any


def hint(schema: dict | None) -> str:
    """The sentence added to the system prompt when a JSON reply is wanted."""
    h = "Reply with a single JSON value only, no prose and no code fences."
    if schema:
        h += " It must validate against this JSON Schema:\n" + json.dumps(schema)
    return h


def with_hint(messages: list[dict], schema: dict | None) -> list[dict]:
    """The messages with the JSON instruction added to the system message (or a system message holding it)."""
    msgs = [dict(m) for m in messages]
    h = hint(schema)
    if msgs and msgs[0].get("role") == "system":
        msgs[0]["content"] = (msgs[0].get("content") or "") + "\n\n" + h
    else:
        msgs.insert(0, {"role": "system", "content": h})
    return msgs


def problem(text: str, schema: dict | None) -> tuple[Any, str | None]:
    """(the parsed value, None) when the reply is usable JSON that fits the schema, else (None, what is wrong)."""
    try:
        obj = extract(text)
    except ValueError as e:
        return None, str(e)
    errs = check(obj, schema) if schema else []
    return (obj, None) if not errs else (None, "; ".join(errs[:10]))


def extract(text: str) -> Any:
    t = text.strip()
    t = re.sub(r"^```(?:json)?\s*|\s*```$", "", t)
    try:
        return json.loads(t)
    except json.JSONDecodeError:
        pass
    starts = [i for i in (t.find("{"), t.find("[")) if i >= 0]
    if not starts:
        raise ValueError("no JSON object in output")
    s = min(starts)
    dec = json.JSONDecoder()
    obj, _ = dec.raw_decode(t[s:])
    return obj


def check(obj: Any, schema: dict, path: str = "$") -> list[str]:
    """A small JSON Schema subset check (type, required, properties, items, enum)."""
    errs: list[str] = []
    if not isinstance(schema, dict):
        return errs
    types = schema.get("type")
    py = {"object": dict, "array": list, "string": str, "integer": int, "number": (int, float),
          "boolean": bool, "null": type(None)}
    if types:
        tl = types if isinstance(types, list) else [types]
        if not any(isinstance(obj, py.get(t, object)) and not (t in ("integer", "number") and isinstance(obj, bool))
                   for t in tl):
            return [f"{path}: expected {types}"]
    if "enum" in schema and obj not in schema["enum"]:
        errs.append(f"{path}: must be one of {schema['enum']}")
    if isinstance(obj, dict):
        for k in schema.get("required", []):
            if k not in obj:
                errs.append(f"{path}: missing '{k}'")
        for k, sub in (schema.get("properties") or {}).items():
            if k in obj:
                errs += check(obj[k], sub, f"{path}.{k}")
    if isinstance(obj, list) and isinstance(schema.get("items"), dict):
        for i, v in enumerate(obj[:200]):
            errs += check(v, schema["items"], f"{path}[{i}]")
    return errs
