"""Command line entry: python -m ble_agent <scan|audit> ..."""
import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from . import rules
from .models import Characteristic, Device, Service


def _load(path: str) -> list[Device]:
    out = []
    for raw in json.loads(Path(path).read_text()):
        svcs = [Service(s["uuid"], s.get("description", ""),
                        [Characteristic(**c) for c in s.get("characteristics", [])]) for s in raw.pop("services", [])]
        raw["manufacturer_data"] = {int(k): v for k, v in raw.get("manufacturer_data", {}).items()}
        out.append(Device(**raw, services=svcs))
    return out


def _print_findings(findings):
    if not findings:
        print("No findings.")
    for f in sorted(findings, key=lambda f: ["high", "medium", "low", "info"].index(f.severity)):
        print(f"[{f.severity.upper():6}] {f.device}  {f.rule_id:12} {f.title}")


def main(argv=None):
    p = argparse.ArgumentParser(prog="ble_agent", description="Defensive BLE discovery & audit agent")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="Passive advertisement scan")
    s.add_argument("-t", "--timeout", type=float, default=10.0)
    s.add_argument("-o", "--out", default="scan.json")

    a = sub.add_parser("audit", help="Run rules (+ optional GATT + LLM) on scan results")
    a.add_argument("-i", "--input", default="scan.json")
    a.add_argument("--gatt", nargs="*", default=[], metavar="ADDR",
                   help="Addresses YOU OWN/ARE AUTHORISED to connect to for read-only GATT enumeration")
    a.add_argument("--llm", action="store_true", help="Generate AI report (needs ANTHROPIC_API_KEY)")
    a.add_argument("--lang", default="zh", choices=["zh", "en"])
    a.add_argument("-r", "--report", default="report.md")
    args = p.parse_args(argv)

    if args.cmd == "scan":
        from .scanner import scan_sync
        devices = scan_sync(args.timeout)
        Path(args.out).write_text(json.dumps([asdict(d) for d in devices], indent=2, ensure_ascii=False))
        for d in devices:
            print(f"{d.rssi:>4} dBm  {d.address}  {d.name or '-'}")
        print(f"\n{len(devices)} devices -> {args.out}")
        return 0

    devices = _load(args.input)
    if args.gatt:
        from .gatt import enumerate_sync
        for d in devices:
            if d.address in args.gatt:
                try:
                    enumerate_sync(d)
                    print(f"GATT: {d.address} -> {len(d.services)} services")
                except Exception as e:  # noqa: BLE001
                    print(f"GATT failed for {d.address}: {e}", file=sys.stderr)

    findings = rules.audit(devices)
    _print_findings(findings)

    if args.llm:
        from .llm import analyze
        md = analyze([asdict(d) for d in devices], [f.to_dict() for f in findings], lang=args.lang)
    else:
        md = "# BLE Audit Report\n\n" + "\n".join(
            f"- **{f.severity}** `{f.device}` {f.title} — {f.detail}" for f in findings)
    Path(args.report).write_text(md)
    print(f"\nReport -> {args.report}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
