"""Command-line interface for ComposeExposure."""

from __future__ import annotations

import argparse
import json
import sys

from .audit import ComposeError, Exposure, compare, inspect, risky


def _describe(record: Exposure) -> str:
    if record.kind == "host-network":
        return f"{record.service}: host network (scope: host)"
    return (
        f"{record.service}: {record.bind}:{record.published} -> "
        f"{record.target}/{record.protocol} (scope: {record.scope})"
    )


def _show(records: list[Exposure]) -> None:
    if not records:
        print("No published ports or host-network services found.")
    for record in records:
        print(_describe(record))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="compose-exposure",
        description="Inspect published ports and host networking in Docker Compose YAML files.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="Inspect one Compose file")
    scan.add_argument("file", help="Path to a Compose YAML file")
    scan.add_argument("--format", choices=("text", "json"), default="text")
    scan.add_argument("--fail-on", choices=("all", "nonlocal"), help="Exit 1 if matching exposure exists")
    diff = commands.add_parser("compare", help="Compare published ports in two Compose files")
    diff.add_argument("baseline", help="Baseline Compose YAML")
    diff.add_argument("candidate", help="Candidate Compose YAML")
    diff.add_argument("--format", choices=("text", "json"), default="text")
    diff.add_argument("--fail-on", choices=("all", "nonlocal"), help="Exit 1 if added exposure matches")
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            records = inspect(args.file)
            if args.format == "json":
                print(json.dumps({"file": args.file, "exposures": [x.to_dict() for x in records]}, indent=2))
            else:
                _show(records)
            return 1 if args.fail_on and risky(records, args.fail_on) else 0
        baseline = inspect(args.baseline)
        candidate = inspect(args.candidate)
        delta = compare(baseline, candidate)
        if args.format == "json":
            print(json.dumps({
                "baseline": args.baseline,
                "candidate": args.candidate,
                "added": [x.to_dict() for x in delta["added"]],
                "removed": [x.to_dict() for x in delta["removed"]],
            }, indent=2))
        else:
            print("Added exposures:")
            _show(delta["added"])
            print("Removed exposures:")
            _show(delta["removed"])
        return 1 if args.fail_on and risky(delta["added"], args.fail_on) else 0
    except ComposeError as exc:
        print(f"compose-exposure: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
