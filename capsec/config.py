from __future__ import annotations

import os
from typing import Dict, List

import yaml


DEPLOYMENT_FILES = ("deployment.yaml", "deployment.yml", "deployment.json")


def _candidate_files(paths: List[str]) -> List[str]:
    candidates: List[str] = []
    for path in paths:
        if os.path.isdir(path):
            for root, _, filenames in os.walk(path):
                for name in filenames:
                    if name in DEPLOYMENT_FILES:
                        candidates.append(os.path.join(root, name))
        else:
            if os.path.basename(path) in DEPLOYMENT_FILES:
                candidates.append(path)
            else:
                parent = os.path.dirname(path)
                for name in DEPLOYMENT_FILES:
                    candidate = os.path.join(parent, name)
                    if os.path.exists(candidate):
                        candidates.append(candidate)
    return candidates


def find_deployment_manifest(paths: List[str]) -> str | None:
    candidates = _candidate_files(paths)
    return candidates[0] if candidates else None


def load_deployment_info(path: str) -> Dict:
    with open(path, "r", encoding="utf-8") as handle:
        if path.endswith(".json"):
            import json

            return json.load(handle)
        return yaml.safe_load(handle) or {}
