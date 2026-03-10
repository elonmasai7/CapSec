from __future__ import annotations

import json
import os
from typing import Dict

from .prompt import build_prompt


class AnthropicBackend:
    """LLM backend using Anthropic's Python SDK."""

    def __init__(self) -> None:
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY is required.")
        self.api_key = api_key
        self.model = os.environ.get("CAPSEC_LLM_MODEL", "claude-3-5-sonnet-latest")
        self.max_tokens = int(os.environ.get("CAPSEC_LLM_MAX_TOKENS", "1024"))
        self.temperature = float(os.environ.get("CAPSEC_LLM_TEMPERATURE", "0"))

    def analyze(self, pact_code: str) -> Dict:
        prompt = build_prompt(pact_code)
        try:
            from anthropic import Anthropic
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(
                "Anthropic SDK not installed. Install dependencies with: pip install -e ."
            ) from exc

        try:
            client = Anthropic(api_key=self.api_key)
            message = client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                messages=[{"role": "user", "content": prompt}],
            )
            text = message.content[0].text if message.content else ""
            return _parse_json(text)
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(
                "Anthropic request failed. Check API key, model, and network connectivity."
            ) from exc


def _parse_json(text: str) -> Dict:
    text = text.strip()
    if not text:
        return {"contract_name": "snippet", "issues": [], "summary": {"total_issues": 0, "critical_issues": 0, "recommendation_overview": ""}}

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            return json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            pass

    return {
        "contract_name": "snippet",
        "issues": [
            {
                "function_name": "llm_output",
                "severity": "Low",
                "description": "LLM output was not valid JSON. Returned raw text in recommendation.",
                "recommendation": text[:2000],
                "example_fix": "Ensure the LLM returns valid JSON per the CapSec schema.",
            }
        ],
        "summary": {
            "total_issues": 1,
            "critical_issues": 0,
            "recommendation_overview": "LLM output parsing failed.",
        },
    }
