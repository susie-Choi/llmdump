#!/usr/bin/env python3
"""Check for local_python_executor.py in results."""
import json
from pathlib import Path

# Check original data
commits_file = Path('submission/data/analysis/smolagents/commits_with_code.jsonl')
results_file = Path('submission/data/analysis/experiment/multiagent_results.jsonl')

print("=== Original Data ===")
executor_commits = []
with open(commits_file, encoding='utf-8') as f:
    for line in f:
        if line.strip():
            data = json.loads(line)
            files = data.get('files', [])
            for file in files:
                if 'local_python_executor' in file.get('filename', ''):
                    executor_commits.append({
                        'sha': data['sha'][:8],
                        'filename': file['filename'],
                        'date': data.get('date', 'N/A')
                    })

print(f"Commits with local_python_executor.py: {len(executor_commits)}")
for c in executor_commits[:5]:
    print(f"  {c['sha']} - {c['filename']}")
if len(executor_commits) > 5:
    print(f"  ... and {len(executor_commits) - 5} more")

print()
print("=== Analysis Results ===")
results = []
with open(results_file, encoding='utf-8') as f:
    for line in f:
        if line.strip():
            results.append(json.loads(line))

print(f"Total analyzed: {len(results)}")

# Check unique filenames
filenames = set(r.get('filename', '') for r in results)
executor_results = [f for f in filenames if 'executor' in f.lower()]
print(f"Files with 'executor' in name: {executor_results}")

# Check if local_python_executor was analyzed
local_executor = [r for r in results if 'local_python_executor' in r.get('filename', '')]
print(f"local_python_executor.py results: {len(local_executor)}")

# Check what files WERE analyzed
print()
print("=== Sample of analyzed files ===")
sample_files = list(filenames)[:20]
for f in sorted(sample_files):
    print(f"  {f}")
