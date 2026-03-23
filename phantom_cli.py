#!/usr/bin/env python3
import sys, os, argparse, json, logging
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from phantom import PhantomEngine
from phantom.engine import PhantomReport

LOGO = """
██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
  Deception Intelligence Layer for Decoy-Hunter
  badBANANA // LANimals collective // GnomeMan4201
"""
DIV = "─" * 72

def setup_logging(v):
    logging.basicConfig(level=logging.DEBUG if v else logging.WARNING,
                        format="%(name)s: %(message)s", stream=sys.stderr)

def print_report(report, color=True):
    C = {"r":"[91m","g":"[92m","y":"[93m","c":"[96m",
         "b":"[1m","d":"[2m","x":"[0m"} if color else         {k:"" for k in ["r","g","y","c","b","d","x"]}

    print(LOGO)
    print(DIV)
    print(f"{C['b']}  TARGET: {report.host}{C['x']}")
    print(DIV)
    t = report.topology
    print(f"\n{C['b']}[ TOPOLOGY ]{C['x']}")
    print(f"  Strategy     : {C['c']}{t.strategy.value}{C['x']}")
    print(f"  Threat Level : {C['y']}{t.threat_level}{C['x']}")
    print(f"  Real / Fake  : {C['g']}{t.real_count}{C['x']} / {C['r']}{t.fake_count}{C['x']} ({t.fake_ratio:.0%} fake)")
    if t.avg_response_ms:
        tp = f" {C['r']}[TARPIT]{C['x']}" if t.tarpit_suspected else ""
        print(f"  Avg Response : {t.avg_response_ms:.0f}ms{tp}")
    if t.notes:
        for n in t.notes: print(f"  · {n}")

    print(f"\n{DIV}\n{C['b']}[ CLASSIFICATIONS ]{C['x']}")
    by_plat = {}
    for c in report.classifications:
        by_plat.setdefault(c.platform.value, []).append(c)
    for plat, entries in sorted(by_plat.items()):
        avg = sum(e.confidence for e in entries)/len(entries)
        col = C['r'] if avg >= 0.70 else C['y']
        print(f"\n  {col}{plat}{C['x']} — {len(entries)} port(s), avg conf {avg:.0%}")
        for e in sorted(entries, key=lambda x: x.port):
            print(f"    [{e.risk_label}] port {e.port} — {e.matched_signature} ({e.confidence:.2f})")

    p = report.playbook
    print(f"\n{DIV}\n{C['b']}[ PLAYBOOK ]{C['x']}")
    print(f"  {C['b']}Approach:{C['x']} {p.approach}")
    print(f"  {C['g']}Prioritize :{C['x']} {p.prioritize_ports or 'none confirmed'}")
    print(f"  {C['r']}Avoid      :{C['x']} {p.avoid_ports[:15]}{'...' if len(p.avoid_ports)>15 else ''}")
    print(f"  {C['y']}Canary Risk:{C['x']} {p.canary_risk_ports or 'none'}")
    print(f"  LANimals Risk : {C['b']}{p.lanimals_risk_score:.2f}{C['x']}")
    print(f"  Tags          : {', '.join(p.lanimals_tags)}")
    for n in p.operator_notes: print(f"  ⚠  {n}")
    print(f"\n{DIV}  [{report.scan_time_s:.2f}s]\n")

def main():
    p = argparse.ArgumentParser(description="PHANTOM — Deception Intelligence for Decoy-Hunter")
    p.add_argument("--host", required=True)
    p.add_argument("--input", "-i")
    p.add_argument("--json", action="store_true")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--output", "-o")
    p.add_argument("--verbose", "-v", action="store_true")
    args = p.parse_args()
    setup_logging(args.verbose)

    if args.input:
        raw = Path(args.input).read_text()
    elif not sys.stdin.isatty():
        raw = sys.stdin.read()
    else:
        print("[!] Pipe Decoy-Hunter output or use --input", file=sys.stderr)
        sys.exit(1)

    engine = PhantomEngine()
    results = PhantomEngine.parse_decoy_hunter_output(raw, args.host)
    if not results:
        print("[!] No [REAL]/[FAKE] lines found in input.", file=sys.stderr)
        sys.exit(1)

    report = engine.analyze(args.host, results)

    if args.json or args.output:
        out = json.dumps(report.to_dict(), indent=2)
        if args.output: Path(args.output).write_text(out)
        if args.json:   print(out)
    else:
        print_report(report, color=not args.no_color)

if __name__ == "__main__":
    main()
