#!/usr/bin/env python3
"""
Analyze local_python_executor.py commits with Multi-Agent.
"""
import sys
from pathlib import Path
import json
import os
import time
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

import google.generativeai as genai

DATA_FILE = Path("submission/data/analysis/smolagents/executor_commits.jsonl")
OUTPUT_FILE = Path("submission/data/analysis/experiment/executor_results.jsonl")
MODEL = "gemini-2.5-flash"

# Same agents as main experiment
AGENTS = {
    "code_injection": {
        "name": "Code Injection Agent",
        "cwe": "CWE-94",
        "description": "Detects arbitrary code execution via eval/exec/compile",
        "keywords": ["eval", "exec", "compile", "subprocess", "os.system", "pickle.loads"],
    },
    "deserialization": {
        "name": "Deserialization Agent",
        "cwe": "CWE-502",
        "description": "Detects unsafe deserialization",
        "keywords": ["pickle", "yaml.load", "json.loads", "marshal", "shelve"],
    },
}

PROMPT_TEMPLATE = """You are a security specialist focusing ONLY on {cwe_name} ({cwe_id}).

Your task: Determine if this Python code contains a {cwe_name} vulnerability.

VULNERABILITY DEFINITION:
{description}

RELEVANT PATTERNS TO CHECK:
{keywords}

FILE: {filename}
COMMIT MESSAGE: {message}

```python
{code}
```

ANALYSIS INSTRUCTIONS:
1. Look ONLY for {cwe_name} patterns
2. Check if user input can reach dangerous functions
3. Assess if there are proper sanitization/validation
4. Be conservative - only flag CLEAR vulnerabilities

IMPORTANT: This is a Python code executor. eval/exec usage is EXPECTED.
Flag as vulnerable ONLY if:
- User input can bypass sandbox restrictions
- There's a way to escape the intended execution environment
- Security checks can be circumvented

Respond with JSON only:
{{
  "is_vulnerable": true/false,
  "confidence": 0.0-1.0,
  "evidence": "specific code pattern or null",
  "reasoning": "brief explanation"
}}
"""


def analyze_with_agent(agent_id, agent_info, filename, message, code):
    """Analyze code with specific agent."""
    prompt = PROMPT_TEMPLATE.format(
        cwe_name=agent_info["name"],
        cwe_id=agent_info["cwe"],
        description=agent_info["description"],
        keywords=", ".join(agent_info["keywords"]),
        filename=filename,
        message=message[:500],
        code=code[:15000]  # Limit code size
    )
    
    try:
        model = genai.GenerativeModel(MODEL)
        response = model.generate_content(prompt)
        text = response.text.strip()
        
        # Parse JSON
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0]
        elif "```" in text:
            text = text.split("```")[1].split("```")[0]
        
        result = json.loads(text)
        result["agent_id"] = agent_id
        result["cwe"] = agent_info["cwe"]
        return result
    except Exception as e:
        return {
            "agent_id": agent_id,
            "cwe": agent_info["cwe"],
            "error": str(e)
        }


def main():
    genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
    
    # Load data
    commits = []
    with open(DATA_FILE, encoding='utf-8') as f:
        for line in f:
            if line.strip():
                commits.append(json.loads(line))
    
    print(f"Loaded {len(commits)} commits")
    print(f"Output: {OUTPUT_FILE}")
    print()
    
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as out:
        for i, commit in enumerate(commits):
            sha = commit['sha']
            filename = commit['filename']
            message = commit['message']
            code = commit['code']
            date = commit.get('date', '')
            
            print(f"[{i+1}/{len(commits)}] {sha[:8]} - {message[:50]}...")
            
            # Run agents
            results = []
            for agent_id, agent_info in AGENTS.items():
                print(f"    Running {agent_info['name']}...")
                result = analyze_with_agent(agent_id, agent_info, filename, message, code)
                results.append(result)
                time.sleep(1)
            
            # Find vulnerabilities
            vulns = [r for r in results if r.get('is_vulnerable') and r.get('confidence', 0) >= 0.6]
            
            record = {
                'sha': sha,
                'filename': filename,
                'message': message,
                'date': date,
                'analysis': {
                    'agents_run': results,
                    'vulnerabilities_found': vulns,
                    'highest_confidence': max((r.get('confidence', 0) for r in results), default=0),
                    'summary': {
                        'is_vulnerable': len(vulns) > 0,
                        'detected_by': [v['agent_id'] for v in vulns],
                        'cwes': [v['cwe'] for v in vulns],
                        'max_confidence': max((v.get('confidence', 0) for v in vulns), default=0)
                    }
                }
            }
            
            out.write(json.dumps(record, ensure_ascii=False) + '\n')
            out.flush()
            
            if vulns:
                agents = ', '.join([v['agent_id'] for v in vulns])
                print(f"    ⚠️  DETECTED by [{agents}]")
            
            print()
    
    print(f"✅ Analysis complete! Results saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
