import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .api import (
    clean_file,
    discover_files,
    result_as_dict,
    scan_file,
    write_manifest,
)


RISK_LABELS = {
    "none": "CLEAN",
    "low": "LOW",
    "medium": "MEDIUM",
    "high": "HIGH",
}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fileveil",
        description="Find and remove hidden metadata before sharing files.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="Inspect files without changing them")
    scan.add_argument("paths", nargs="+", type=Path)
    scan.add_argument("--json", action="store_true", help="Print JSON")
    scan.add_argument(
        "--fail-on",
        choices=("medium", "high"),
        help="Exit with status 2 at this risk level or above",
    )

    clean = commands.add_parser("clean", help="Write metadata-free copies")
    clean.add_argument("paths", nargs="+", type=Path)
    clean.add_argument("-o", "--output", required=True, type=Path)
    clean.add_argument("--force", action="store_true", help="Replace existing outputs")
    clean.add_argument("--manifest", type=Path, help="Write a JSON audit manifest")
    return parser


def _print_result(result, as_json=False):
    if as_json:
        print(json.dumps(result_as_dict(result), ensure_ascii=False))
        return
    risk = RISK_LABELS[result.highest_risk]
    print(f"[{risk}] {result.path}")
    if result.error:
        print(f"  ! {result.error}")
        return
    for item in result.findings:
        detail = f" ({item.detail})" if item.detail else ""
        print(f"  - {item.label} [{RISK_LABELS[item.risk]}]{detail}")
    if not result.findings:
        print("  No supported metadata found.")


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    files = discover_files(args.paths)
    if not files:
        print("No supported files found.", file=sys.stderr)
        return 1

    if args.command == "scan":
        results = [scan_file(path) for path in files]
        for result in results:
            _print_result(result, args.json)
        errors = any(result.error for result in results)
        if errors:
            return 1
        if args.fail_on:
            threshold = {"medium": 2, "high": 3}[args.fail_on]
            ranks = {"none": 0, "low": 1, "medium": 2, "high": 3}
            return 2 if any(ranks[item.highest_risk] >= threshold for item in results) else 0
        return 0

    destinations = {}
    for source in files:
        destination = args.output / source.name
        if destination in destinations.values():
            print(f"Name collision in output directory: {source.name}", file=sys.stderr)
            return 1
        destinations[source] = destination

    results = []
    for source, destination in destinations.items():
        try:
            result = clean_file(source, destination, force=args.force)
        except (OSError, ValueError) as error:
            print(f"[ERROR] {source}: {error}", file=sys.stderr)
            return 1
        results.append(result)
        print(f"[CLEAN] {source} -> {destination}")

    if args.manifest:
        write_manifest(args.manifest, results)
        print(f"Manifest: {args.manifest}")
    return 0

