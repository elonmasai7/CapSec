from __future__ import annotations

import argparse
import sys

from .analyzer import analyze_pact
from .io import combine_sources, load_pact_sources


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CapSec CI runner")
    parser.add_argument("paths", nargs="*", help="Pact files or directories")
    parser.add_argument("--fail-on", default="high", choices=["low", "medium", "high", "critical"])
    args = parser.parse_args(argv)

    if not args.paths:
        sys.stderr.write("Provide at least one path for CI checks.\n")
        return 2

    sources = load_pact_sources(args.paths)
    code = combine_sources(sources)
    report = analyze_pact(code)

    threshold = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    fail_rank = threshold[args.fail_on]

    issues = report.get("issues", [])
    max_rank = max((threshold.get(issue.get("severity", "low").lower(), 3) for issue in issues), default=3)

    if max_rank <= fail_rank:
        sys.stderr.write("CapSec found issues at or above the fail threshold.\n")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
