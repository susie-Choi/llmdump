#!/usr/bin/env python3
"""Check executor analysis results."""
import json
from pathlib import Path

results_file = Path('submission/data/analysis/experiment/executor_results.jsonl')

results = []
with open(results_file, encoding='utf-8') as f:
    for line in f:
        if line.strip():
            results.append(json.loads(line))

print(f"Analyzed: {len(results)}/90")
print()

vulnerable = []
for r in results:
    summary = r['analysis']['summary']
    sha = r['sha'][:8]
    msg = r['message'][:50]
    
    if summary['is_vulnerable']:
        vulnerable.append(r)
        print(f"⚠️  {sha} - {summary['detected_by']} - {msg}...")
    else:
        print(f"✓  {sha} - safe - {msg}...")

print()
print(f"Vulnerable: {len(vulnerable)}/{len(results)}")
