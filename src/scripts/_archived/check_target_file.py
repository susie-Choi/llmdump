#!/usr/bin/env python3
"""Check if target CVE file was detected."""
import json
from pathlib import Path

results_file = Path('submission/data/analysis/experiment/multiagent_results.jsonl')

# Load all results
results = []
with open(results_file, encoding='utf-8') as f:
    for line in f:
        if line.strip():
            results.append(json.loads(line))

print(f'Total commits analyzed: {len(results)}')
print()

# Find local_python_executor.py results
target_results = [r for r in results if 'local_python_executor' in r.get('filename', '')]

print(f'=== local_python_executor.py Results ({len(target_results)} commits) ===')
for r in target_results:
    analysis = r.get('analysis', {})
    vulns = analysis.get('vulnerabilities_found', [])
    summary = analysis.get('summary', {})
    
    print(f"\n{r['sha'][:8]} - {r.get('filename')}")
    print(f"  Message: {r.get('message', '')[:60]}...")
    print(f"  Is Vulnerable: {summary.get('is_vulnerable')}")
    print(f"  Max Confidence: {summary.get('max_confidence')}")
    print(f"  Detected by: {summary.get('detected_by')}")
    print(f"  CWEs: {summary.get('cwes')}")
    
    if vulns:
        print(f"  Vulnerabilities:")
        for v in vulns:
            print(f"    - [{v.get('agent_id')}] conf={v.get('confidence'):.2f}")
