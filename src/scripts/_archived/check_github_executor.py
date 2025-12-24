#!/usr/bin/env python3
"""Check if local_python_executor.py exists in smolagents repo."""
import requests
import os
from dotenv import load_dotenv
load_dotenv()

token = os.getenv('GITHUB_TOKEN')
headers = {'Authorization': f'token {token}'}

# Get commits that touched local_python_executor.py
url = 'https://api.github.com/repos/huggingface/smolagents/commits'
params = {'path': 'src/smolagents/local_python_executor.py', 'per_page': 100}

r = requests.get(url, headers=headers, params=params)
if r.ok:
    commits = r.json()
    print(f'Commits touching local_python_executor.py: {len(commits)}')
    for c in commits[:10]:
        print(f"  {c['sha'][:8]} - {c['commit']['message'][:60]}...")
else:
    print(f'Error: {r.status_code} - {r.text}')
