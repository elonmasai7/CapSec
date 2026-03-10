from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List


@dataclass
class PactFunction:
    name: str
    body: str


@dataclass
class PactCapability:
    name: str
    body: str


@dataclass
class PactPact:
    name: str
    body: str


@dataclass
class PactModule:
    name: str
    governance: str | None = None
    functions: List[PactFunction] = field(default_factory=list)
    capabilities: List[PactCapability] = field(default_factory=list)
    pacts: List[PactPact] = field(default_factory=list)
    schemas: List[str] = field(default_factory=list)
    tables: List[str] = field(default_factory=list)
    raw: str = ""


_DEFUN_RE = re.compile(r"^\(defun\s+([^\s\)]+)")
_DEFCAP_RE = re.compile(r"^\(defcap\s+([^\s\)]+)")
_DEFPact_RE = re.compile(r"^\(defpact\s+([^\s\)]+)")
_DEFSCHEMA_RE = re.compile(r"^\(defschema\s+([^\s\)]+)")
_DEFTABLE_RE = re.compile(r"^\(deftable\s+([^\s\)]+)")
_MODULE_RE = re.compile(r"^\(module\s+([^\s\)]+)")
_MODULE_HEADER_RE = re.compile(r"^\(module\s+([^\s\)]+)\s+([^\s\)]+)")


def _extract_top_level_forms(code: str) -> List[str]:
    forms: List[str] = []
    depth = 0
    start = None
    in_string = False
    escape = False

    for idx, ch in enumerate(code):
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue

        if ch == '"':
            in_string = True
            continue

        if ch == "(":
            if depth == 0:
                start = idx
            depth += 1
        elif ch == ")":
            if depth > 0:
                depth -= 1
                if depth == 0 and start is not None:
                    forms.append(code[start : idx + 1])
                    start = None

    return forms


def _parse_module_form(module_form: str) -> PactModule:
    header_match = _MODULE_HEADER_RE.match(module_form)
    module_name = header_match.group(1) if header_match else "snippet"
    governance = header_match.group(2) if header_match else None

    module = PactModule(name=module_name, governance=governance, raw=module_form)
    search_forms = _extract_top_level_forms(module_form)

    for form in search_forms:
        match = _DEFUN_RE.match(form)
        if match:
            module.functions.append(PactFunction(name=match.group(1), body=form))
            continue

        match = _DEFCAP_RE.match(form)
        if match:
            module.capabilities.append(PactCapability(name=match.group(1), body=form))
            continue

        match = _DEFPact_RE.match(form)
        if match:
            module.pacts.append(PactPact(name=match.group(1), body=form))
            continue

        match = _DEFSCHEMA_RE.match(form)
        if match:
            module.schemas.append(match.group(1))
            continue

        match = _DEFTABLE_RE.match(form)
        if match:
            module.tables.append(match.group(1))
            continue

    return module


def parse_pact(code: str) -> PactModule:
    modules = parse_pact_multi(code)
    if not modules:
        return PactModule(name="snippet", raw=code)
    return modules[0]


def parse_pact_multi(code: str) -> List[PactModule]:
    forms = _extract_top_level_forms(code)
    modules: List[PactModule] = []

    for form in forms:
        if _MODULE_RE.match(form):
            modules.append(_parse_module_form(form))

    if not modules:
        snippet_module = PactModule(name="snippet", raw=code)
        search_forms = forms
        for form in search_forms:
            match = _DEFUN_RE.match(form)
            if match:
                snippet_module.functions.append(PactFunction(name=match.group(1), body=form))
                continue
            match = _DEFCAP_RE.match(form)
            if match:
                snippet_module.capabilities.append(PactCapability(name=match.group(1), body=form))
                continue
            match = _DEFPact_RE.match(form)
            if match:
                snippet_module.pacts.append(PactPact(name=match.group(1), body=form))
                continue
            match = _DEFSCHEMA_RE.match(form)
            if match:
                snippet_module.schemas.append(match.group(1))
                continue
            match = _DEFTABLE_RE.match(form)
            if match:
                snippet_module.tables.append(match.group(1))
                continue
        modules.append(snippet_module)

    return modules
