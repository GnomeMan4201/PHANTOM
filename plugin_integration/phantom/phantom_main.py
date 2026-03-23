import sys, os, logging
logger = logging.getLogger("phantom-plugin")

def _find_phantom():
    for p in [
        os.path.join(os.path.dirname(__file__), "..", "..", ".."),
        os.path.expanduser("~/repos/PHANTOM"),
        os.path.expanduser("~/PHANTOM"),
    ]:
        if os.path.isdir(p) and os.path.exists(os.path.join(p, "phantom", "__init__.py")):
            return os.path.abspath(p)
    return None

_path = _find_phantom()
if _path: sys.path.insert(0, _path); _available = True
else: _available = False; logger.warning("PHANTOM not found.")

def run_phantom(targets, scan_output=""):
    if not _available:
        print("[phantom] Not installed — skipping.", file=sys.stderr); return
    try:
        from phantom import PhantomEngine
        from phantom_cli import print_report
    except ImportError as e:
        print(f"[phantom] Import failed: {e}", file=sys.stderr); return
    engine = PhantomEngine()
    for host in targets:
        if not host: continue
        try:
            r = PhantomEngine.parse_decoy_hunter_output(scan_output, host)
            if r: print_report(engine.analyze(host, r))
        except Exception as e:
            print(f"[phantom] Failed for {host}: {e}", file=sys.stderr)
