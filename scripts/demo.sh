#!/usr/bin/env bash
set -euo pipefail
export PYTHONWARNINGS=ignore

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

GRN='\033[0;32m'; YEL='\033[1;33m'; RED='\033[0;31m'
CYN='\033[0;36m'; DIM='\033[2m'; BLD='\033[1m'; RST='\033[0m'

sep() { echo -e "${DIM}────────────────────────────────────────${RST}"; }

sep
echo -e "  ${BLD}PHANTOM${RST} — Deception Intelligence Layer"
sep
echo ""

python3 -c "from phantom.engine import PhantomEngine" 2>/dev/null || {
  echo -e "  ${RED}✗${RST}  missing deps — run: pip install -r requirements.txt"
  exit 1
}
echo -e "  ${GRN}✓${RST}  engine loaded"
echo -e "  ${CYN}→${RST}  target: 192.168.1.10  ports: 22 23 80 443 2222 8080"
echo ""

python3 - << 'PYEOF'
import sys, os, time
sys.path.insert(0, '.')
from phantom.engine import PhantomEngine

GRN='\033[0;32m'; YEL='\033[1;33m'; RED='\033[0;31m'
CYN='\033[0;36m'; DIM='\033[2m'; BLD='\033[1m'; RST='\033[0m'

scan_results = [
    (False, 22,   'tcp', b"SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2\r\n", 12),
    (False, 23,   'tcp', b"SSH-2.0-OpenSSH_5.1p1 Debian-5\r\n",          8),
    (False, 80,   'tcp', b"<script src='https://canarytokens.com/x'>",    5),
    (True,  443,  'tcp', b"HTTP/1.1 200 OK\r\n",                         45),
    (False, 2222, 'tcp', b"SSH-2.0-OpenSSH_5.9p1 Debian-5ubuntu1.1\r\n", 9),
    (True,  8080, 'tcp', b"HTTP/1.1 302 Found\r\n",                      38),
]

print(f"  {DIM}classifying ports...{RST}")
time.sleep(0.4)

engine = PhantomEngine()
report = engine.analyze('192.168.1.10', scan_results)
topo = report.topology
play = report.playbook

print()
print(f"  {BLD}TOPOLOGY{RST}")
print(f"  strategy   : {CYN}{topo.strategy.value}{RST}")
print(f"  real ports : {GRN}{topo.real_count}{RST}  fake ports: {RED}{topo.fake_count}{RST}  fake ratio: {topo.fake_ratio:.0%}")
print(f"  dominant   : {topo.dominant_platform.value}")
print(f"  platform mix: {', '.join(topo.platform_distribution.keys())}")
print()

time.sleep(0.3)
print(f"  {BLD}CLASSIFICATIONS{RST}")
disp_color = {
    'AVOID':       RED,
    'CANARY_RISK': YEL,
    'PRIORITIZE':  GRN,
}
for c in report.classifications:
    print(f"  port {c.port:<5} {RED}FAKE{RST}  {c.platform.value:<16} conf={c.confidence:.2f}  {DIM}{c.notes}{RST}")

time.sleep(0.3)
print()
print(f"  {BLD}PLAYBOOK{RST}  [{play.threat_level}]")
for rec in play.port_recommendations:
    col = disp_color.get(rec.disposition.name, RST)
    print(f"  port {rec.port:<5} {col}{rec.disposition.value:<12}{RST}  {DIM}{rec.reason}{RST}")

print()
print(f"  LANimals risk score : {play.lanimals_risk_score}")
print(f"  tags : {' '.join(play.lanimals_tags)}")
PYEOF

echo ""
sep
echo -e "  ${GRN}✓${RST}  analysis complete"
echo -e "  ${CYN}→${RST}  4 honeypots detected — ports 443 8080 confirmed real"
echo -e "  ${CYN}→${RST}  Thinkst Canary on 80 — interaction already logged upstream"
sep
echo ""
