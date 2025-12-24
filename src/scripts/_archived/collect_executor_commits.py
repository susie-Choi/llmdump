#!/usr/bin/env python3
"""
Collect local_python_executor.py commits and analyze them.
"""
import sys
from pathlib import Path
import json
import os
import time
import requests
from dotenv import load_dotenv
import base64

load_dotenv()

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
HEADERS = {"Authorization": f"token {GITHUB_TOKEN}"}

OUTPUT_DIR = Path("submission/data/analysis/smolagents")
OUTPUT_FILE = OUTPUT_DIR / "executor_commits.jsonl"


def get_executor_commits():
    """Get all commits touching local_python_executor.py"""
    url = 'https://api.github.com/repos/huggingface/smolagents/commits'
    params = {'path': 'src/smolagents/local_python_executor.py', 'per_page': 100}
    
    all_commits = []
    page = 1
    
    while True:
        params['page'] = page
        r = requests.get(url, headers=HEADERS, params=params, timeout=60)
        if not r.ok:
            print(f"Error: {r.status_code}")
            break
        
        commits = r.json()
        if not commits:
            break
        
        all_commits.extend(commits)
        print(f"  Page {page}: {len(all_commits)} commits")
        
        if len(commits) < 100:
            break
        page += 1
        time.sleep(0.3)
    
    return all_commits


def get_file_content(sha, filepath):
    """Get file content at specific commit."""
    url = f"https://api.github.com/repos/huggingface/smolagents/contents/{filepath}"
    r = requests.get(url, headers=HEADERS, params={"ref": sha}, timeout=60)
    if r.ok:
        data = r.json()
        if data.get("encoding") == "base64":
            return base64.b64decode(data.get("content", "")).decode('utf-8', errors='ignore')
    return None


def main():
    print("=== Collecting local_python_executor.py commits ===")
    
    commits = get_executor_commits()
    print(f"\nTotal commits: {len(commits)}")
    
    # Save with code content
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        for i, commit in enumerate(commits):
            sha = commit['sha']
            message = commit['commit']['message']
            date = commit['commit']['author']['date']
            
            print(f"[{i+1}/{len(commits)}] {sha[:8]} - {message[:50]}...")
            
            # Get file content
            code = get_file_content(sha, 'src/smolagents/local_python_executor.py')
            
            if code:
                record = {
                    'sha': sha,
                    'message': message,
                    'date': date,
                    'filename': 'src/smolagents/local_python_executor.py',
                    'code': code
                }
                f.write(json.dumps(record, ensure_ascii=False) + '\n')
                print(f"    ✓ Code collected ({len(code)} chars)")
            else:
                print(f"    ✗ No code")
            
            time.sleep(0.5)
    
    print(f"\n✅ Saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
