#!/usr/bin/env python3
"""
Analyze detected commits - check if they were later patched.
This could indicate:
1. Potential CVE (not yet discovered)
2. Pre-emptively patched before CVE registration
"""
import json
from pathlib import Path
from collections import defaultdict

results_file = Path('submission/data/analysis/experiment/multiagent_results.jsonl')

results = []
with open(results_file, encoding='utf-8') as f:
    for line in f:
        if line.strip():
            results.append(json.loads(line))

print(f'Total commits analyzed: {len(results)}')
print()

# Group by file
file_vulns = defaultdict(list)
for r in results:
    analysis = r.get('analysis', {})
    vulns = analysis.get('vulnerabilities_found', [])
    high_conf = [v for v in vulns if v.get('confidence', 0) >= 0.7]
    if high_conf:
        filename = r.get('filename', 'N/A')
        file_vulns[filename].append({
            'sha': r['sha'][:8],
            'date': r.get('date', 'N/A'),
            'message': r.get('message', '')[:80],
            'vulns': [(v.get('agent_id'), v.get('confidence'), v.get('cwe')) for v in high_conf]
        })

print('=== Files with Detected Vulnerabilities (threshold 0.7) ===')
print()

for filename, commits in sorted(file_vulns.items(), key=lambda x: -len(x[1])):
    print(f'📁 {filename} ({len(commits)} commits)')
    for c in sorted(commits, key=lambda x: x['date'], reverse=True)[:5]:  # Show latest 5
        agents = ', '.join([f"{a[0]}({a[1]:.1f})" for a in c['vulns']])
        print(f"   {c['date'][:10]} {c['sha']} - {agents}")
        print(f"      {c['message'][:60]}...")
    if len(commits) > 5:
        print(f"   ... and {len(commits) - 5} more commits")
    print()

# Summary by CWE
print('=== Summary by CWE ===')
cwe_counts = defaultdict(int)
cwe_files = defaultdict(set)
for r in results:
    analysis = r.get('analysis', {})
    vulns = analysis.get('vulnerabilities_found', [])
    for v in vulns:
        if v.get('confidence', 0) >= 0.7:
            cwe = v.get('cwe', 'Unknown')
            cwe_counts[cwe] += 1
            cwe_files[cwe].add(r.get('filename', 'N/A'))

for cwe, count in sorted(cwe_counts.items(), key=lambda x: -x[1]):
    files = cwe_files[cwe]
    print(f'{cwe}: {count} detections in {len(files)} files')
    for f in list(files)[:3]:
        print(f'   - {f}')
    if len(files) > 3:
        print(f'   ... and {len(files) - 3} more files')

print()
print('=== Interpretation ===')
print('''
These detections could represent:
1. TRUE POSITIVES - Actual vulnerabilities (known CVE or undiscovered)
2. POTENTIAL CVEs - Not yet exploited/reported but risky code
3. PRE-EMPTIVE PATCHES - Fixed before becoming CVE
4. FALSE POSITIVES - Intended functionality flagged as risky

For AI Agent frameworks like smolagents:
- Code execution (eval/exec) is INTENDED functionality
- But improper sandboxing can lead to CVEs like CVE-2025-5120
- LLM detection helps identify WHERE to focus security review
''')
