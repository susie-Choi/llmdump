#!/usr/bin/env python3
"""
Find commits that are likely security patches among detected vulnerabilities.
Check if detected commits were actually fixing security issues.
"""
import json
from pathlib import Path
import re

results_file = Path('submission/data/analysis/experiment/multiagent_results.jsonl')

results = []
with open(results_file, encoding='utf-8') as f:
    for line in f:
        if line.strip():
            results.append(json.loads(line))

print(f'Total commits analyzed: {len(results)}')
print()

# Security-related keywords in commit messages
SECURITY_KEYWORDS = [
    'fix', 'security', 'vulnerability', 'vuln', 'injection', 'xss', 
    'sanitize', 'escape', 'validate', 'patch', 'cve', 'safe', 'unsafe',
    'exploit', 'attack', 'malicious', 'traversal', 'deserialize'
]

# Find detected commits with security-related messages
print('=== Detected Commits with Security-Related Messages ===')
print()

security_patches = []
for r in results:
    analysis = r.get('analysis', {})
    vulns = analysis.get('vulnerabilities_found', [])
    high_conf = [v for v in vulns if v.get('confidence', 0) >= 0.7]
    
    if high_conf:
        message = r.get('message', '').lower()
        matched_keywords = [kw for kw in SECURITY_KEYWORDS if kw in message]
        
        if matched_keywords:
            security_patches.append({
                'sha': r['sha'][:8],
                'date': r.get('date', 'N/A')[:10],
                'filename': r.get('filename', 'N/A'),
                'message': r.get('message', '')[:100],
                'keywords': matched_keywords,
                'vulns': [(v.get('agent_id'), v.get('cwe')) for v in high_conf]
            })

print(f'Found {len(security_patches)} commits with security-related keywords')
print()

for p in sorted(security_patches, key=lambda x: x['date'], reverse=True):
    print(f"📌 {p['sha']} ({p['date']})")
    print(f"   File: {p['filename']}")
    print(f"   Message: {p['message']}...")
    print(f"   Keywords: {p['keywords']}")
    print(f"   Detected: {p['vulns']}")
    print()

# Summary
print('=== Summary ===')
print(f'Total detected commits (conf >= 0.7): {sum(1 for r in results if any(v.get("confidence", 0) >= 0.7 for v in r.get("analysis", {}).get("vulnerabilities_found", [])))}')
print(f'Security-related commits: {len(security_patches)}')
print()

# Check for actual CVE mentions
print('=== Commits mentioning CVE ===')
for r in results:
    message = r.get('message', '')
    if 'cve' in message.lower():
        print(f"  {r['sha'][:8]}: {message[:80]}...")
