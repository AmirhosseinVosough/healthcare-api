"""Turn Locust's CSVs into one table."""

import csv
import sys
from pathlib import Path

label = sys.argv[1] if len(sys.argv) > 1 else "baseline"
root = Path("loadtest") / label

print(f"\n  {label}")
header = f"{'users':>6} {'req/s':>8} {'p50':>7} {'p95':>7} {'p99':>7}"
print(f"  {header} {'max':>8} {'fails':>7}")
print(f"  {'-' * 54}")

for users in (10, 25, 50, 100, 200, 400):
    stats = root / f"u{users}_stats.csv"
    if not stats.exists():
        continue
    with stats.open() as fh:
        rows = {r["Name"]: r for r in csv.DictReader(fh)}
    total = rows.get("Aggregated")
    if not total:
        continue
    fails = int(float(total["Failure Count"]))
    reqs = int(float(total["Request Count"]))
    pct = (fails / reqs * 100) if reqs else 0
    print(
        f"  {users:>6} {float(total['Requests/s']):>8.1f} "
        f"{float(total['50%']):>7.0f} {float(total['95%']):>7.0f} "
        f"{float(total['99%']):>7.0f} {float(total['Max Response Time']):>8.0f} "
        f"{pct:>6.1f}%"
    )
print("\n  latency in milliseconds\n")
