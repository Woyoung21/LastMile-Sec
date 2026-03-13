"""Quick review script for mapped output files."""
import json
import sys
from collections import Counter

path = sys.argv[1] if len(sys.argv) > 1 else r"data\mapped\Vulnerability Scan Report (By Issue)_mapped_20260313_140821.json"

with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)

findings = data.get("findings", [])
print(f"Total findings: {len(findings)}\n")

id_counter: Counter = Counter()
valid_count = 0
fail_count = 0
empty_count = 0

for i, f in enumerate(findings):
    meta = f.get("metadata", {})
    mapping = meta.get("mitre_mapping", {})
    mitre_ids = mapping.get("mitre_ids", [])
    raw = mapping.get("raw_model_output", "")[:150].replace("\n", " ")
    valid = mapping.get("validation_passed", None)
    summary = meta.get("technical_summary", "")[:110]
    title = f.get("title", "")[:60]
    severity = f.get("severity", "")

    map_meta = mapping.get("metadata", {})
    val_issues = map_meta.get("validation_issues", [])
    rejected = map_meta.get("rejected_ids", [])
    gates = map_meta.get("validation_gates", {})

    if valid:
        valid_count += 1
    else:
        fail_count += 1

    if not mitre_ids:
        empty_count += 1

    for tid in mitre_ids:
        id_counter[tid] += 1

    status = "OK" if valid else "FAIL"
    ids_str = ", ".join(mitre_ids) if mitre_ids else "(none)"

    print(f"{i+1:2}. [{severity:8}] {status:4} | IDs: {ids_str:30} | {title}")
    if not valid or rejected:
        print(f"     Raw: {raw}")
        for vi in val_issues:
            gate = vi.get("gate", "")
            msg = vi.get("message", "")
            print(f"     Issue: [{gate}] {msg}")
        if rejected:
            print(f"     Rejected: {rejected}")
    print(f"     Summary: {summary}")
    print()

print("=" * 80)
print(f"SUMMARY: {valid_count} valid, {fail_count} failed, {empty_count} with no IDs")
print(f"Unique MITRE IDs assigned: {len(id_counter)}")
print(f"\nID frequency:")
for tid, count in id_counter.most_common():
    print(f"  {tid:15} x{count}")
