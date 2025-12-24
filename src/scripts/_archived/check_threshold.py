#!/usr/bin/env python3
"""Check results by different thresholds."""
import json
from pathlib import Path

results_file = Path('submission/data/analysis/experiment/multiagent_results.jsonl')
if not results_file.exists():
    print('Results file not found')
    exit()

# Load all results
results = []
with open(results_file, encoding='utf-8') as f:
    for line in f:
        if line.strip():
            results.append(json.loads(line))

print(f'Total commits analyzed: {len(results)}')
print()

# Count by threshold
for threshold in [0.5, 0.6, 0.7, 0.8, 0.9]:
    flagged = []
    for r in results:
        analysis = r.get('analysis', {})
        vulns = analysis.get('vulnerabilities_found', [])
        for v in vulns:
            if v.get('confidence', 0) >= threshold:
                flagged.append(r)
                break
    print(f'Threshold {threshold}: {len(flagged)} commits flagged')

print()
print('=== Threshold 0.7 Details ===')
for r in results:
    analysis = r.get('analysis', {})
    vulns = analysis.get('vulnerabilities_found', [])
    high_conf = [v for v in vulns if v.get('confidence', 0) >= 0.7]
    if high_conf:
        print(f"  {r['sha'][:8]} - {r.get('filename', 'N/A')}")
        for v in high_conf:
            print(f"    [{v.get('agent_id')}] conf={v.get('confidence'):.2f} - {v.get('cwe', 'N/A')}")
