from __future__ import annotations

import argparse
import importlib
import os
import sys

from .analyzer import analyze_pact, analyze_pact_json
from .config import find_deployment_manifest, load_deployment_info
from .io import combine_sources, load_pact_sources
from .llm_backend import LLMBackend
from .reporting import format_human


def _read_input_from_stdin() -> str:
    return sys.stdin.read()


def _load_backend() -> LLMBackend | None:
    backend_spec = os.environ.get("CAPSEC_LLM_BACKEND")
    if not backend_spec:
        return None
    if ":" not in backend_spec:
        raise ValueError("CAPSEC_LLM_BACKEND must be in module:Class format.")
    module_name, class_name = backend_spec.split(":", 1)
    module = importlib.import_module(module_name)
    backend_class = getattr(module, class_name)
    return backend_class()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="CapSec: Pact security analyzer (heuristic mode)."
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help="Path(s) to Pact file(s) or folder(s). Use '-' or omit to read from stdin.",
    )
    parser.add_argument(
        "--mode",
        choices=["heuristic", "llm", "hybrid"],
        default="heuristic",
        help="Analysis mode: heuristic (default), llm, or hybrid.",
    )
    parser.add_argument(
        "--format",
        choices=["json", "text"],
        default="json",
        help="Output format: json (default) or text.",
    )
    parser.add_argument(
        "--deployment",
        help="Path to a JSON file containing deployment_info (addresses, network, modules).",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors for text output.",
    )

    args = parser.parse_args(argv)
    if not args.paths or args.paths == ["-"]:
        code = _read_input_from_stdin()
    else:
        sources = load_pact_sources(args.paths)
        code = combine_sources(sources)

    if not code.strip():
        sys.stderr.write("No Pact code provided.\n")
        return 1

    backend = None
    if args.mode in {"llm", "hybrid"}:
        try:
            backend = _load_backend()
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"Failed to load LLM backend: {exc}\n")
            return 2
        if backend is None:
            sys.stderr.write("CAPSEC_LLM_BACKEND is required for llm/hybrid mode.\n")
            return 2

    deployment_info = None
    deployment_path = args.deployment
    if deployment_path is None and args.paths and args.paths != ["-"]:
        deployment_path = find_deployment_manifest(args.paths)

    if deployment_path:
        try:
            deployment_info = load_deployment_info(deployment_path)
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"Failed to load deployment info: {exc}\n")
            return 2

    if args.format == "text":
        report = analyze_pact(code, llm_backend=backend, mode=args.mode, deployment_info=deployment_info)
        sys.stdout.write(format_human(report, color=not args.no_color))
    else:
        sys.stdout.write(
            analyze_pact_json(code, llm_backend=backend, mode=args.mode, deployment_info=deployment_info)
        )
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
