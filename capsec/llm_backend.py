from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, List, Dict

from .prompt import build_prompt

class LLMBackend(Protocol):
    def analyze(self, pact_code: str, deployment_info: Dict | None = None) -> Dict:
        """Return a JSON-compatible dict with contract_name and issues."""


@dataclass
class LLMIssue:
    function_name: str
    severity: str
    description: str
    recommendation: str
    example_fix: str


class StubLLMBackend:
    """Placeholder backend for wiring and tests."""

    def analyze(self, pact_code: str, deployment_info: Dict | None = None) -> Dict:
        _ = build_prompt(pact_code, deployment_info=deployment_info)
        return {
            "contract_name": "snippet",
            "issues": [],
        }
