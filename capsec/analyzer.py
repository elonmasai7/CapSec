from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import List, Dict, Iterable

from .parser import (
    PactModule,
    PactFunction,
    PactCapability,
    PactPact,
    parse_pact_multi,
)
from .llm_backend import LLMBackend


STATE_MUTATING_TOKENS = [
    "insert",
    "update",
    "write",
    "remove",
    "delete",
    "create-table",
    "namespace",
    "create-user",
    "define-keyset",
]

AUTH_TOKENS = [
    "with-capability",
    "require-capability",
    "enforce",
    "enforce-one",
    "enforce-keyset",
    "enforce-guard",
    "check-guard",
]

KEY_LITERAL_RE = re.compile(r"\b(k:[A-Za-z0-9_-]{43,}|[A-Fa-f0-9]{64})\b")
WITH_CAP_RE = re.compile(r"\((with-capability|require-capability)\s+\(([^)\s]+)([^)]*)\)")
DEFCAP_ARGS_RE = re.compile(r"^\(defcap\s+([^\s\)]+)\s*\(([^)]*)\)", re.DOTALL)
DEFINE_KEYSET_RE = re.compile(r"\(define-keyset\s+'?([^\s\)]+)")


@dataclass
class Issue:
    function_name: str
    module_name: str
    severity: str
    description: str
    recommendation: str
    example_fix: str


def _has_any_token(body: str, tokens: List[str]) -> bool:
    return any(f"({token}" in body for token in tokens)


def _first_token_index(body: str, tokens: List[str]) -> int:
    indices = [body.find(f"({token}") for token in tokens]
    indices = [idx for idx in indices if idx != -1]
    return min(indices) if indices else -1


def _detect_state_change_without_auth(func: PactFunction) -> Issue | None:
    has_state_change = _has_any_token(func.body, STATE_MUTATING_TOKENS)
    has_auth = _has_any_token(func.body, AUTH_TOKENS)

    if has_state_change and not has_auth:
        return Issue(
            function_name=func.name,
            module_name="",
            severity="High",
            description=(
                "State-changing logic is present without any explicit authorization checks. "
                "Attackers may be able to modify critical state without owning the required capability or guard."
            ),
            recommendation=(
                "Add a capability or guard check (e.g., `with-capability`, `enforce-keyset`, or `enforce-guard`) "
                "before performing state updates."
            ),
            example_fix=(
                "(defun {name} (...)\n"
                "  (with-capability (ADMIN)\n"
                "    (update accounts id {{ balance: (+ balance amount) }})))"
            ).format(name=func.name),
        )
    return None


def _detect_state_change_before_auth(func: PactFunction) -> Issue | None:
    state_index = _first_token_index(func.body, STATE_MUTATING_TOKENS)
    auth_index = _first_token_index(func.body, AUTH_TOKENS)

    if state_index != -1 and auth_index != -1 and state_index < auth_index:
        return Issue(
            function_name=func.name,
            module_name="",
            severity="Medium",
            description=(
                "State updates occur before any authorization checks. If execution fails or guards are bypassed, "
                "state could be altered prematurely."
            ),
            recommendation=(
                "Move capability/guard enforcement to the beginning of the function, before any state mutation."
            ),
            example_fix=(
                "(defun {name} (...)\n"
                "  (with-capability (ADMIN)\n"
                "    (update accounts id {{ balance: (+ balance amount) }})))"
            ).format(name=func.name),
        )
    return None


def _detect_defcap_without_guard(cap: PactCapability) -> Issue | None:
    guard_tokens = ["enforce", "enforce-keyset", "enforce-guard", "check-guard"]
    if not _has_any_token(cap.body, guard_tokens):
        return Issue(
            function_name=cap.name,
            module_name="",
            severity="High",
            description=(
                "Capability definition does not enforce any guard or keyset. "
                "This makes the capability effectively unprotected."
            ),
            recommendation=(
                "Add `enforce-keyset`, `enforce-guard`, or `enforce` inside the capability to bind it to an "
                "authorized signer or guard."
            ),
            example_fix=(
                "(defcap {name} ()\n"
                "  (enforce-keyset 'admin-ks))"
            ).format(name=cap.name),
        )
    return None


def _detect_unused_capabilities(module: PactModule) -> List[Issue]:
    issues: List[Issue] = []
    usage_text = module.raw

    for cap in module.capabilities:
        pattern = re.compile(rf"\((with-capability|require-capability)\s+\({re.escape(cap.name)}\b")
        if not pattern.search(usage_text):
            issues.append(
                Issue(
                    function_name=cap.name,
                    module_name="",
                    severity="Low",
                    description=(
                        "Capability is defined but never used. This may indicate missing authorization checks "
                        "in functions that should require it."
                    ),
                    recommendation=(
                        "Apply the capability with `with-capability` or `require-capability` in functions "
                        "that mutate sensitive state."
                    ),
                    example_fix=(
                        "(with-capability ({name})\n  (update accounts id {{ balance: new-balance }}))"
                    ).format(name=cap.name),
                )
            )
    return issues


def _parse_defcap_args(module: PactModule) -> Dict[str, int]:
    arg_counts: Dict[str, int] = {}
    for cap in module.capabilities:
        match = DEFCAP_ARGS_RE.match(cap.body)
        if not match:
            continue
        args = match.group(2).strip()
        if not args:
            arg_counts[cap.name] = 0
        else:
            arg_counts[cap.name] = len([token for token in re.split(r"\s+", args) if token])
    return arg_counts


def _iter_capability_uses(module: PactModule) -> Iterable[tuple[str, int]]:
    for match in WITH_CAP_RE.finditer(module.raw):
        cap_name = match.group(2)
        arg_str = match.group(3).strip()
        if not arg_str:
            yield cap_name, 0
        else:
            arg_count = len([token for token in re.split(r"\s+", arg_str) if token])
            yield cap_name, arg_count


def _detect_capability_arg_mismatch(module: PactModule) -> List[Issue]:
    issues: List[Issue] = []
    arg_counts = _parse_defcap_args(module)

    for cap_name, used_args in _iter_capability_uses(module):
        if cap_name not in arg_counts:
            continue
        expected = arg_counts[cap_name]
        if expected != used_args:
            issues.append(
                Issue(
                    function_name=cap_name,
                    module_name="",
                    severity="Medium",
                    description=(
                        "Capability is invoked with a different number of arguments than its definition. "
                        "This can cause unintended authorization behavior or runtime failures."
                    ),
                    recommendation=(
                        "Ensure every `with-capability`/`require-capability` call matches the `defcap` "
                        "parameter list."
                    ),
                    example_fix=(
                        "(with-capability ({name} <args...>)\n  (update accounts id {{ balance: new-balance }}))"
                    ).format(name=cap_name),
                )
            )
    return issues


def _detect_undefined_capability_use(module: PactModule) -> List[Issue]:
    defined = {cap.name for cap in module.capabilities}
    issues: List[Issue] = []
    for cap_name, _ in _iter_capability_uses(module):
        if cap_name not in defined:
            issues.append(
                Issue(
                    function_name=cap_name,
                    module_name="",
                    severity="High",
                    description=(
                        "Capability is used but not defined in the module. This indicates a broken or bypassable "
                        "authorization path."
                    ),
                    recommendation=(
                        "Define the capability with `defcap` or update the usage to reference the correct capability."
                    ),
                    example_fix=(
                        "(defcap {name} ()\n  (enforce-keyset 'admin-ks))"
                    ).format(name=cap_name),
                )
            )
    return issues


def _detect_hardcoded_keys(module: PactModule) -> Issue | None:
    if KEY_LITERAL_RE.search(module.raw) and "define-keyset" in module.raw:
        return Issue(
            function_name=module.name,
            module_name=module.name,
            severity="Medium",
            description=(
                "Hard-coded public keys appear in keyset definitions. This makes rotation and governance changes "
                "difficult and can create permanent privileged access."
            ),
            recommendation=(
                "Load keysets via `read-keyset` from transaction data or governance mechanisms instead of hard-coding."
            ),
            example_fix=(
                "(define-keyset 'admin-ks (read-keyset 'admin-ks))"
            ),
        )
    return None


def _detect_weak_enforce_one(module: PactModule) -> Issue | None:
    pattern = re.compile(r"\(enforce-one[\s\S]{0,200}?\btrue\b", re.IGNORECASE)
    if pattern.search(module.raw):
        return Issue(
            function_name=module.name,
            module_name=module.name,
            severity="Medium",
            description=(
                "`enforce-one` contains a trivially true branch, which can bypass all other checks."
            ),
            recommendation=(
                "Remove any unconditional true branch from `enforce-one` and ensure each option performs a real check."
            ),
            example_fix=(
                "(enforce-one \"auth\" [(enforce-keyset 'admin-ks) (enforce-guard g)])"
            ),
        )
    return None


def _extract_balanced_forms(code: str) -> List[str]:
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


def _detect_pact_missing_auth(pact: PactPact) -> Issue | None:
    if "(step" in pact.body and not _has_any_token(pact.body, AUTH_TOKENS):
        return Issue(
            function_name=pact.name,
            module_name="",
            severity="High",
            description=(
                "Multi-step pact does not include any authorization checks. Steps may be executed by unauthorized parties."
            ),
            recommendation=(
                "Add capability or guard checks within each step to ensure only authorized actors can progress the pact."
            ),
            example_fix=(
                "(defpact {name}\n"
                "  (step (with-capability (ADMIN) ...))\n"
                "  (step (with-capability (ADMIN) ...)))"
            ).format(name=pact.name),
        )
    return None


def _detect_pact_step_state_without_auth(pact: PactPact) -> List[Issue]:
    issues: List[Issue] = []
    for form in _extract_balanced_forms(pact.body):
        if not form.startswith("(step"):
            continue
        has_state_change = _has_any_token(form, STATE_MUTATING_TOKENS)
        has_auth = _has_any_token(form, AUTH_TOKENS)
        if has_state_change and not has_auth:
            issues.append(
                Issue(
                    function_name=pact.name,
                    module_name="",
                    severity="High",
                    description=(
                        "A pact step mutates state without authorization checks. Any actor could drive the step "
                        "and modify critical state."
                    ),
                    recommendation=(
                        "Add `with-capability`, `enforce-keyset`, or `enforce-guard` inside each pact step that "
                        "updates state."
                    ),
                    example_fix=(
                        "(defpact {name}\n  (step (with-capability (ADMIN) (update table id {{ field: value }}))))"
                    ).format(name=pact.name),
                )
            )
    return issues


def _detect_module_governance(module: PactModule) -> List[Issue]:
    issues: List[Issue] = []
    if "(module" not in module.raw:
        return issues

    if module.governance is None:
        issues.append(
            Issue(
                function_name=module.name,
                module_name=module.name,
                severity="High",
                description=(
                    "Module governance is missing. This can leave administrative operations unprotected."
                ),
                recommendation=(
                    "Define module governance with a keyset or a governance capability."
                ),
                example_fix="(module my-module 'admin-ks ...)",
            )
        )
        return issues

    governance = module.governance
    if governance.lower() in {"true", "false"}:
        issues.append(
            Issue(
                function_name=module.name,
                module_name=module.name,
                severity="Critical",
                description=(
                    "Module governance is set to a boolean, which effectively disables access control."
                ),
                recommendation=(
                    "Use a keyset or governance capability instead of a boolean."
                ),
                example_fix="(module my-module 'admin-ks ...)",
            )
        )
        return issues

    defined_caps = {cap.name for cap in module.capabilities}
    defined_keysets = set(DEFINE_KEYSET_RE.findall(module.raw))
    if governance not in defined_caps and governance.lstrip(\"'\") not in defined_keysets:
        issues.append(
            Issue(
                function_name=module.name,
                module_name=module.name,
                severity="Medium",
                description=(
                    "Module governance does not map to a defined capability or keyset. Governance checks may fail "
                    "or be unintentionally bypassed."
                ),
                recommendation=(
                    "Ensure the governance reference matches a `defcap` or `define-keyset` identifier."
                ),
                example_fix="(define-keyset 'admin-ks (read-keyset 'admin-ks))",
            )
        )

    return issues


def analyze_module(module: PactModule) -> List[Issue]:
    issues: List[Issue] = []

    for func in module.functions:
        issue = _detect_state_change_without_auth(func)
        if issue:
            if not issue.module_name:
                issue.module_name = module.name
            issues.append(issue)
        issue = _detect_state_change_before_auth(func)
        if issue:
            if not issue.module_name:
                issue.module_name = module.name
            issues.append(issue)

    for cap in module.capabilities:
        issue = _detect_defcap_without_guard(cap)
        if issue:
            if not issue.module_name:
                issue.module_name = module.name
            issues.append(issue)

    for issue in _detect_unused_capabilities(module):
        if not issue.module_name:
            issue.module_name = module.name
        issues.append(issue)
    for issue in _detect_capability_arg_mismatch(module):
        if not issue.module_name:
            issue.module_name = module.name
        issues.append(issue)
    for issue in _detect_undefined_capability_use(module):
        if not issue.module_name:
            issue.module_name = module.name
        issues.append(issue)
    for issue in _detect_module_governance(module):
        if not issue.module_name:
            issue.module_name = module.name
        issues.append(issue)

    for pact in module.pacts:
        issue = _detect_pact_missing_auth(pact)
        if issue:
            if not issue.module_name:
                issue.module_name = module.name
            issues.append(issue)
        for step_issue in _detect_pact_step_state_without_auth(pact):
            if not step_issue.module_name:
                step_issue.module_name = module.name
            issues.append(step_issue)

    module_issue = _detect_hardcoded_keys(module)
    if module_issue:
        if not module_issue.module_name:
            module_issue.module_name = module.name
        issues.append(module_issue)

    weak_issue = _detect_weak_enforce_one(module)
    if weak_issue:
        if not weak_issue.module_name:
            weak_issue.module_name = module.name
        issues.append(weak_issue)

    return issues


def _merge_issues(primary: List[Issue], secondary: List[Issue]) -> List[Issue]:
    seen = {(issue.function_name, issue.description) for issue in primary}
    merged = list(primary)
    for issue in secondary:
        key = (issue.function_name, issue.description)
        if key not in seen:
            merged.append(issue)
            seen.add(key)
    return merged


def _summarize(issues: List[Issue]) -> Dict:
    critical = sum(1 for issue in issues if issue.severity.lower() == "critical")
    overview = "Review critical and high findings first, then address authorization and governance gaps."
    return {
        "total_issues": len(issues),
        "critical_issues": critical,
        "recommendation_overview": overview,
    }


def _normalize_deployment_info(deployment_info: Dict | None, modules: List[PactModule]) -> Dict:
    info = deployment_info.copy() if deployment_info else {}
    info.setdefault("addresses", [])
    info.setdefault("network", "")
    info.setdefault("modules", [module.name for module in modules])
    return info


def _severity_rank(severity: str) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return order.get(severity.lower(), 4)


def _detect_cross_module_table_governance(modules: List[PactModule]) -> List[Issue]:
    table_map: Dict[str, List[PactModule]] = {}
    for module in modules:
        for table in module.tables:
            table_map.setdefault(table, []).append(module)

    issues: List[Issue] = []
    for table, owners in table_map.items():
        if len(owners) <= 1:
            continue
        governance_set = {owner.governance for owner in owners}
        if len(governance_set) > 1:
            issues.append(
                Issue(
                    function_name=f"cross-module:{table}",
                    module_name="cross-module",
                    severity="Medium",
                    description=(
                        "The same table name is defined in multiple modules with different governance settings. "
                        "This can create inconsistent access control across modules."
                    ),
                    recommendation=(
                        "Align governance for shared tables or rename tables to avoid cross-module ambiguity."
                    ),
                    example_fix="(module finance 'admin-ks ... (deftable accounts:account))",
                )
            )
    return issues


def _detect_cross_module_capability_reuse(modules: List[PactModule]) -> List[Issue]:
    issues: List[Issue] = []
    cap_defs: Dict[str, Dict[str, int]] = {}

    for module in modules:
        arg_counts = _parse_defcap_args(module)
        for cap_name, arg_count in arg_counts.items():
            cap_defs.setdefault(cap_name, {})[module.name] = arg_count

    for cap_name, owners in cap_defs.items():
        if len(owners) > 1:
            issues.append(
                Issue(
                    function_name=f"cross-module:{cap_name}",
                    module_name="cross-module",
                    severity="Low",
                    description=(
                        "Capability name is defined in multiple modules. This can lead to confusion or "
                        "incorrect references when calling capabilities."
                    ),
                    recommendation=(
                        "Use module-qualified capability names and avoid reusing names across modules."
                    ),
                    example_fix="(with-capability (module-name.CAP ...) ...)",
                )
            )

    for module in modules:
        for cap_name, _ in _iter_capability_uses(module):
            if "." in cap_name:
                module_ref, cap_ref = cap_name.split(".", 1)
                target_module = next((m for m in modules if m.name == module_ref), None)
                if not target_module:
                    issues.append(
                        Issue(
                            function_name=f"{module.name}:{cap_name}",
                            module_name=module.name,
                            severity="High",
                            description=(
                                "A module-qualified capability is referenced, but the referenced module "
                                "does not exist in the input set."
                            ),
                            recommendation=(
                                "Ensure the referenced module is present and the capability name is correct."
                            ),
                            example_fix="(with-capability (module-name.CAP ...) ...)",
                        )
                    )
                elif cap_ref not in {cap.name for cap in target_module.capabilities}:
                    issues.append(
                        Issue(
                            function_name=f"{module.name}:{cap_name}",
                            module_name=module.name,
                            severity="High",
                            description=(
                                "A module-qualified capability is referenced, but the target module does not "
                                "define that capability."
                            ),
                            recommendation=(
                                "Define the referenced capability in the target module or correct the name."
                            ),
                            example_fix=f\"(defcap {cap_ref} () (enforce-keyset 'admin-ks))\",
                        )
                    )

    return issues


def analyze_pact(
    code: str,
    llm_backend: LLMBackend | None = None,
    mode: str = "heuristic",
    deployment_info: Dict | None = None,
) -> dict:
    modules = parse_pact_multi(code)
    all_issues: List[Issue] = []
    deployment_info = _normalize_deployment_info(deployment_info, modules)

    for module in modules:
        heuristic_issues = analyze_module(module)
        llm_issues: List[Issue] = []

        if llm_backend and mode in {"llm", "hybrid"}:
            llm_result = llm_backend.analyze(module.raw, deployment_info=deployment_info)
            for issue in llm_result.get("issues", []):
                llm_issues.append(
                    Issue(
                        function_name=issue.get("function_name", "unknown"),
                        module_name=issue.get("module_name", ""),
                        severity=issue.get("severity", "Medium"),
                        description=issue.get("description", ""),
                        recommendation=issue.get("recommendation", ""),
                        example_fix=issue.get("example_fix", ""),
                    )
                )

        if mode == "llm":
            issues = llm_issues
        elif mode == "hybrid":
            issues = _merge_issues(heuristic_issues, llm_issues)
        else:
            issues = heuristic_issues

        all_issues.extend(issues)

    if len(modules) > 1:
        all_issues.extend(_detect_cross_module_table_governance(modules))
        all_issues.extend(_detect_cross_module_capability_reuse(modules))

    all_issues.sort(key=lambda issue: (_severity_rank(issue.severity), issue.function_name))

    contract_name = (
        modules[0].name if len(modules) == 1 else "multi-module"
    ) if modules else "snippet"

    return {
        "contract_name": contract_name,
        "deployment_info": deployment_info,
        "issues": [
            {
                "function_name": issue.function_name,
                "module_name": issue.module_name,
                "severity": issue.severity,
                "description": issue.description,
                "recommendation": issue.recommendation,
                "example_fix": issue.example_fix,
            }
            for issue in all_issues
        ],
        "summary": _summarize(all_issues),
    }


def analyze_pact_json(
    code: str,
    llm_backend: LLMBackend | None = None,
    mode: str = "heuristic",
    deployment_info: Dict | None = None,
) -> str:
    return json.dumps(
        analyze_pact(code, llm_backend=llm_backend, mode=mode, deployment_info=deployment_info),
        indent=2,
    )
