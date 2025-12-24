#!/usr/bin/env python3
"""
GitHub Commit Collector.

특정 저장소에서 커밋을 수집하고, 파일 내용과 함께 저장한다.
"""
import json
import os
import time
from pathlib import Path
from typing import Optional
from datetime import datetime

import requests
from dotenv import load_dotenv

load_dotenv()


class GitHubCommitCollector:
    """GitHub 커밋 수집기."""
    
    def __init__(self):
        self.token = os.getenv("GITHUB_TOKEN")
        self.headers = {
            "Accept": "application/vnd.github.v3+json"
        }
        if self.token:
            self.headers["Authorization"] = f"token {self.token}"
    
    def _get_commits(self, repo: str, file_filter: Optional[str] = None, 
                     per_page: int = 100) -> list:
        """저장소의 커밋 목록 조회."""
        commits = []
        page = 1
        
        while True:
            url = f"https://api.github.com/repos/{repo}/commits"
            params = {"per_page": per_page, "page": page}
            if file_filter:
                params["path"] = file_filter
            
            response = requests.get(url, headers=self.headers, params=params)
            
            if response.status_code == 403:
                print("Rate limit exceeded. Waiting 60 seconds...")
                time.sleep(60)
                continue
            
            if response.status_code != 200:
                print(f"Error fetching commits: {response.status_code}")
                break
            
            data = response.json()
            if not data:
                break
            
            commits.extend(data)
            print(f"  Fetched page {page}: {len(data)} commits (total: {len(commits)})")
            
            if len(data) < per_page:
                break
            
            page += 1
            time.sleep(0.5)  # Rate limiting
        
        return commits
    
    def _get_file_content(self, repo: str, sha: str, filepath: str) -> Optional[str]:
        """특정 커밋 시점의 파일 내용 조회."""
        url = f"https://api.github.com/repos/{repo}/contents/{filepath}"
        params = {"ref": sha}
        
        response = requests.get(url, headers=self.headers, params=params)
        
        if response.status_code == 403:
            time.sleep(60)
            response = requests.get(url, headers=self.headers, params=params)
        
        if response.status_code != 200:
            return None
        
        data = response.json()
        
        if data.get("encoding") == "base64":
            import base64
            try:
                return base64.b64decode(data["content"]).decode("utf-8")
            except:
                return None
        
        return None
    
    def _get_commit_files(self, repo: str, sha: str) -> list:
        """커밋에서 변경된 파일 목록 조회."""
        url = f"https://api.github.com/repos/{repo}/commits/{sha}"
        response = requests.get(url, headers=self.headers)
        
        if response.status_code != 200:
            return []
        
        data = response.json()
        return data.get("files", [])
    
    def collect(self, repo: str, file_filter: Optional[str] = None,
                output: Optional[str] = None, include_code: bool = True) -> dict:
        """커밋 수집 및 저장."""
        print(f"Collecting commits from {repo}...")
        if file_filter:
            print(f"  Filtering by: {file_filter}")
        
        # 커밋 목록 조회
        commits = self._get_commits(repo, file_filter)
        print(f"Found {len(commits)} commits")
        
        # 출력 파일 설정
        if output:
            output_path = Path(output)
        else:
            safe_repo = repo.replace("/", "_")
            output_path = Path(f"data/input/{safe_repo}_commits.jsonl")
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # 커밋 처리
        records = []
        for i, commit in enumerate(commits):
            sha = commit["sha"]
            message = commit["commit"]["message"]
            date = commit["commit"]["committer"]["date"]
            
            print(f"[{i+1}/{len(commits)}] {sha[:8]} - {message[:50]}...")
            
            record = {
                "sha": sha,
                "message": message,
                "date": date,
                "author": commit["commit"]["author"]["name"],
                "repo": repo
            }
            
            # 파일 내용 수집
            if include_code:
                if file_filter:
                    # 특정 파일만 수집
                    code = self._get_file_content(repo, sha, file_filter)
                    if code:
                        record["filename"] = file_filter
                        record["code"] = code
                else:
                    # 변경된 Python 파일들 수집
                    files = self._get_commit_files(repo, sha)
                    py_files = [f for f in files if f["filename"].endswith(".py")]
                    
                    if py_files:
                        # 첫 번째 Python 파일만 (간단화)
                        f = py_files[0]
                        code = self._get_file_content(repo, sha, f["filename"])
                        if code:
                            record["filename"] = f["filename"]
                            record["code"] = code
            
            records.append(record)
            time.sleep(0.3)  # Rate limiting
        
        # 저장
        with open(output_path, 'w', encoding='utf-8') as f:
            for record in records:
                f.write(json.dumps(record, ensure_ascii=False) + '\n')
        
        print(f"\n✅ Saved {len(records)} commits to {output_path}")
        
        return {
            "total": len(records),
            "output": str(output_path)
        }
