#!/usr/bin/env python3
"""Check results excluding Code Injection (eval/exec is intended feature)."""
import json
from pathlib import Path

results_file = Path('submission/data/analysis/experiment/multiagent_results.jsonl')

results = []
with open(results_file, encoding='utf-8') as f:
    for line in f:
        if line.strip():
            results.append(json.loads(line))

print(f'Total commits analyzed: {len(results)}')
print()

# Count by threshold, excluding code_injection
for threshold in [0.5, 0.6, 0.7, 0.8, 0.9]:
    flagged = []
    for r in results:
        analysis = r.get('analysis', {})
        vulns = analysis.get('vulnerabilities_found', [])
        # Exclude code_injection
        non_ci_vulns = [v for v in vulns if v.get('agent_id') != 'code_injection']
        for v in non_ci_vulns:
            if v.get('confidence', 0) >= threshold:
                flagged.append(r)
                break
    print(f'Threshold {threshold}: {len(flagged)} commits (excluding Code Injection)')

print()
print('=== Threshold 0.7 (Excluding Code Injection) ===')
for r in results:
    analysis = r.get('analysis', {})
    vulns = analysis.get('vulnerabilities_found', [])
    # Exclude code_injection
    high_conf = [v for v in vulns 
                 if v.get('agent_id') != 'code_injection' 
                 and v.get('confidence', 0) >= 0.7]
    if high_conf:
        print(f"  {r['sha'][:8]} - {r.get('filename', 'N/A')}")
        for v in high_conf:
            print(f"    [{v.get('agent_id')}] conf={v.get('confidence'):.2f} - {v.get('cwe')}")

print()
print('=== By Agent Type (threshold 0.7) ===')
agent_counts = {}
for r in results:
    analysis = r.get('analysis', {})
    vulns = analysis.get('vulnerabilities_found', [])
    for v in vulns:
        if v.get('confidence', 0) >= 0.7:
            agent = v.get('agent_id', 'unknown')
            agent_counts[agent] = agent_counts.get(agent, 0) + 1

for agent, count in sorted(agent_counts.items(), key=lambda x: -x[1]):
    print(f"  {agent}: {count}")
