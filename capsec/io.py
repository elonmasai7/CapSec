from __future__ import annotations

import os
from dataclasses import dataclass
from typing import List


PACT_EXTENSIONS = {".pact", ".repl", ".pactcode"}


@dataclass
class PactSource:
    path: str
    content: str


def _is_pact_file(path: str) -> bool:
    _, ext = os.path.splitext(path)
    return ext.lower() in PACT_EXTENSIONS


def collect_pact_files(path: str) -> List[str]:
    files: List[str] = []
    if os.path.isdir(path):
        for root, _, filenames in os.walk(path):
            for name in filenames:
                full_path = os.path.join(root, name)
                if _is_pact_file(full_path):
                    files.append(full_path)
    else:
        files.append(path)
    return files


def load_pact_sources(paths: List[str]) -> List[PactSource]:
    sources: List[PactSource] = []
    for path in paths:
        for file_path in collect_pact_files(path):
            with open(file_path, "r", encoding="utf-8") as handle:
                sources.append(PactSource(path=file_path, content=handle.read()))
    return sources


def combine_sources(sources: List[PactSource]) -> str:
    parts: List[str] = []
    for source in sources:
        parts.append(f";; --- file: {source.path} ---\n{source.content}")
    return "\n\n".join(parts)
