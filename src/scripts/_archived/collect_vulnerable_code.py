#!/usr/bin/env python3
"""
Collect smolagents commits - with incremental save.
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
if not GITHUB_TOKEN:
    print("ERROR: GITHUB_TOKEN not set")
    sys.exit(1)

HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github+json"
}

TARGET = "huggingface/smolagents"
OWNER, REPO = TARGET.split("/")
OUTPUT_DIR = Path("submission/data/analysis/smolagents")


def get_all_commits():
    """Get all commits."""
    url = f"https://api.github.com/repos/{OWNER}/{REPO}/commits"
    params = {"per_page": 100}
    
    all_commits = []
    page = 1
    
    while True:
        params["page"] = page
        r = requests.get(url, headers=HEADERS, params=params, timeout=60)
        if not r.ok:
            break
        
        commits = r.json()
        if not commits:
            break
        
        all_commits.extend(commits)
        print(f"  Page {page}: {len(all_commits)} total")
        
        if len(commits) < 100:
            break
        page += 1
        time.sleep(0.3)
    
    return all_commits


def get_commit_files(sha):
    """Get files in commit."""
    url = f"https://api.github.com/repos/{OWNER}/{REPO}/commits/{sha}"
    r = requests.get(url, headers=HEADERS, timeout=60)
    if r.ok:
        return r.json().get("files", [])
    return []


def get_file_content(sha, filepath):
    """Get file content."""
    url = f"https://api.github.com/repos/{OWNER}/{REPO}/contents/{filepath}"
    r = requests.get(url, headers=HEADERS, params={"ref": sha}, timeout=60)
    if r.ok:
        data = r.json()
        if data.get("encoding") == "base64":
            return base64.b64decode(data.get("content", "")).decode('utf-8', errors='ignore')
    return None


def load_progress():
    """Load already processed commits."""
    progress_file = OUTPUT_DIR / "commits_with_code.jsonl"
    processed = set()
    if progress_file.exists():
        with open(progress_file, 'r', encoding='utf-8') as f:
            for line in f:
                data = json.loads(line)
                processed.add(data.get("sha"))
    return processed


def save_commit(commit_data):
    """Append single commit to file (incremental save)."""
    progress_file = OUTPUT_DIR / "commits_with_code.jsonl"
    with open(progress_file, 'a', encoding='utf-8') as f:
        f.write(json.dumps(commit_data, ensure_ascii=False) + '\n')


def main():
    print("=" * 60)
    print("Collecting smolagents commits (incremental)")
    print("=" * 60)
    
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    # Load progress
    processed = load_progress()
    print(f"\nAlready processed: {len(processed)} commits")
    
    # Get all commits
    print("\n[1/2] Fetching commit list...")
    raw_commits = get_all_commits()
    print(f"  Total: {len(raw_commits)}")
    
    # Save commit list
    commits = []
    for c in raw_commits:
        commits.append({
            "sha": c.get("sha"),
            "message": c.get("commit", {}).get("message", "")[:500],
            "date": c.get("commit", {}).get("committer", {}).get("date", ""),
        })
    
    with open(OUTPUT_DIR / "commits.json", 'w', encoding='utf-8') as f:
        json.dump(commits, f, indent=2, ensure_ascii=False)
    
    # Process each commit
    print("\n[2/2] Fetching code (incremental save)...")
    
    collected = len(processed)
    
    for i, commit in enumerate(commits):
        sha = commit["sha"]
        
        # Skip if already processed
        if sha in processed:
            continue
        
        # Get files
        files = get_commit_files(sha)
        
        # Filter Python (not test)
        py_files = [f for f in files 
                    if f.get("filename", "").endswith('.py')
                    and 'test' not in f.get("filename", "").lower()]
        
        if py_files:
            file_data = []
            for f in py_files[:3]:
                filename = f.get("filename", "")
                content = get_file_content(sha, filename)
                if content and len(content) < 30000:
                    file_data.append({"filename": filename, "content": content})
                time.sleep(0.15)
            
            if file_data:
                # Save immediately
                save_commit({**commit, "files": file_data})
                collected += 1
        
        if (i + 1) % 50 == 0:
            print(f"    {i+1}/{len(commits)} done, {collected} with code")
        
        time.sleep(0.2)
    
    # Save ground truth
    ground_truth = {
        "cve_id": "CVE-2025-5120",
        "cvss_score": 10.0,
        "published": "2025-07-27",
        "vulnerable_file": "local_python_executor.py",
        "vulnerability_type": "Sandbox Escape → RCE",
        "cwe": "CWE-94",
    }
    with open(OUTPUT_DIR / "ground_truth.json", 'w', encoding='utf-8') as f:
        json.dump(ground_truth, f, indent=2)
    
    print("\n" + "=" * 60)
    print(f"DONE: {collected} commits with code saved")
    print(f"Output: {OUTPUT_DIR}")


if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()
    main()
