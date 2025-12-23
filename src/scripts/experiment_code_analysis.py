#!/usr/bin/env python3
"""
LLM Zero-Day Detection Experiment on smolagents.

Goal: Can LLM find CVE-2025-5120 (Sandbox Escape) by analyzing code?

Process:
1. Load all 390 commits with code
2. LLM analyzes each commit blindly (no CVE info)
3. Record all findings
4. Check if LLM found the actual vulnerability (local_python_executor.py)
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

# Config
DATA_DIR = Path("submission/data/analysis/smolagents")
OUTPUT_DIR = Path("submission/data/analysis/experiment")
MODEL = "gemini-2.5-flash"

# =============================================================================
# MULTI-AGENT VULNERABILITY DETECTION (Based on 2024-2025 Research)
# =============================================================================
# References:
# - iAudit (ICSE 2025): Two-stage approach, Agent ensemble
# - To Err is Machine (2024): SOTA models achieve only 54.5% balanced accuracy
# - Vul-RAG (2024): LLMs struggle with vulnerable vs patched code (6-14%)
# - CoCoNUT (2025): LLMs limited in code execution flow understanding
#
# Approach: Multi-Agent Ensemble
# - Each agent specializes in a specific vulnerability type (CWE)
# - Run all agents on code, aggregate results
# - This is NOT post-hoc targeting - agents are pre-defined specialists
# =============================================================================

# Agent definitions - each specializes in a CWE category
AGENTS = {
    "code_injection": {
        "name": "Code Injection Agent",
        "cwe": "CWE-94",
        "description": "Detects arbitrary code execution via eval/exec/compile",
        "keywords": ["eval", "exec", "compile", "subprocess", "os.system", "pickle.loads"],
    },
    "sql_injection": {
        "name": "SQL Injection Agent",
        "cwe": "CWE-89",
        "description": "Detects SQL injection vulnerabilities",
        "keywords": ["execute", "cursor", "query", "SELECT", "INSERT", "UPDATE", "DELETE"],
    },
    "xss": {
        "name": "XSS Agent",
        "cwe": "CWE-79",
        "description": "Detects cross-site scripting vulnerabilities",
        "keywords": ["innerHTML", "document.write", "render", "template", "html"],
    },
    "path_traversal": {
        "name": "Path Traversal Agent",
        "cwe": "CWE-22",
        "description": "Detects path traversal vulnerabilities",
        "keywords": ["open", "read", "write", "path", "file", "os.path", "../"],
    },
    "deserialization": {
        "name": "Deserialization Agent",
        "cwe": "CWE-502",
        "description": "Detects unsafe deserialization",
        "keywords": ["pickle", "yaml.load", "json.loads", "marshal", "shelve"],
    },
}

# Agent-specific prompt template
AGENT_PROMPT = '''You are a security specialist focusing ONLY on {cwe_name} ({cwe_id}).

Your task: Determine if this Python code contains a {cwe_name} vulnerability.

VULNERABILITY DEFINITION:
{cwe_description}

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

IMPORTANT: Most code is NOT vulnerable. Only flag if you find CLEAR evidence.

Respond with JSON only:
{{
    "is_vulnerable": true/false,
    "confidence": 0.0-1.0,
    "evidence": "specific code pattern found (or null)",
    "reasoning": "brief explanation"
}}
'''


def load_commits():
    """Load commits with code."""
    commits = []
    with open(DATA_DIR / "commits_with_code.jsonl", 'r', encoding='utf-8') as f:
        for line in f:
            commits.append(json.loads(line))
    return commits


def load_ground_truth():
    """Load CVE ground truth."""
    with open(DATA_DIR / "ground_truth.json", 'r', encoding='utf-8') as f:
        return json.load(f)


def load_progress():
    """Load already analyzed files (sha + filename)."""
    progress_file = OUTPUT_DIR / "multiagent_results.jsonl"
    analyzed = set()
    if progress_file.exists():
        with open(progress_file, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    data = json.loads(line)
                    # Use sha + filename as unique key
                    key = f"{data.get('sha')}:{data.get('filename')}"
                    analyzed.add(key)
                except:
                    continue
    return analyzed


def save_result(result):
    """Save single result (incremental)."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_DIR / "analysis_results.jsonl", 'a', encoding='utf-8') as f:
        f.write(json.dumps(result, ensure_ascii=False) + '\n')


def parse_json_response(text):
    """Parse JSON from LLM response."""
    json_start = text.find('{')
    json_end = text.rfind('}') + 1
    if json_start >= 0 and json_end > json_start:
        try:
            return json.loads(text[json_start:json_end])
        except:
            return None
    return None


def run_agent(model, agent_id, agent_config, filename, message, code):
    """Run a single specialized agent on code."""
    prompt = AGENT_PROMPT.format(
        cwe_name=agent_config["description"].split(" - ")[0] if " - " in agent_config["description"] else agent_config["name"],
        cwe_id=agent_config["cwe"],
        cwe_description=agent_config["description"],
        keywords=", ".join(agent_config["keywords"]),
        filename=filename,
        message=message[:200],
        code=code[:10000]
    )
    
    try:
        response = model.generate_content(prompt)
        result = parse_json_response(response.text)
        if result:
            result["agent_id"] = agent_id
            result["cwe"] = agent_config["cwe"]
            return result
    except Exception as e:
        print(f"        {agent_id} Error: {e}")
    
    return {
        "agent_id": agent_id,
        "cwe": agent_config["cwe"],
        "is_vulnerable": False,
        "confidence": 0.0,
        "evidence": None,
        "reasoning": "Error in analysis"
    }


def analyze_with_agents(model, sha, message, filename, code):
    """Run all agents on code and aggregate results."""
    results = {
        "agents_run": [],
        "vulnerabilities_found": [],
        "highest_confidence": 0.0,
        "summary": None
    }
    
    for agent_id, agent_config in AGENTS.items():
        # Quick pre-filter: check if any keywords exist in code
        code_lower = code.lower()
        has_relevant_pattern = any(kw.lower() in code_lower for kw in agent_config["keywords"])
        
        if not has_relevant_pattern:
            results["agents_run"].append({
                "agent_id": agent_id,
                "cwe": agent_config["cwe"],
                "skipped": True,
                "reason": "No relevant patterns"
            })
            continue
        
        # Run agent
        print(f"        Running {agent_config['name']}...", flush=True)
        agent_result = run_agent(model, agent_id, agent_config, filename, message, code)
        results["agents_run"].append(agent_result)
        
        # Track vulnerabilities
        if agent_result.get("is_vulnerable") and agent_result.get("confidence", 0) >= 0.6:
            results["vulnerabilities_found"].append(agent_result)
            if agent_result.get("confidence", 0) > results["highest_confidence"]:
                results["highest_confidence"] = agent_result["confidence"]
        
        time.sleep(0.5)  # Rate limiting between agents
    
    # Summary
    if results["vulnerabilities_found"]:
        results["summary"] = {
            "is_vulnerable": True,
            "detected_by": [v["agent_id"] for v in results["vulnerabilities_found"]],
            "cwes": [v["cwe"] for v in results["vulnerabilities_found"]],
            "max_confidence": results["highest_confidence"]
        }
    else:
        results["summary"] = {
            "is_vulnerable": False,
            "detected_by": [],
            "cwes": [],
            "max_confidence": 0.0
        }
    
    return results


def main():
    print("=" * 70)
    print("LLM Zero-Day Detection: Multi-Agent Ensemble")
    print("=" * 70)
    print("Target: huggingface/smolagents (CVE-2025-5120)")
    print("Approach: Specialized agents for each CWE category")
    print(f"Agents: {', '.join(AGENTS.keys())}")
    
    # Check API key
    api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    if not api_key:
        print("ERROR: GEMINI_API_KEY not set")
        return
    
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel(MODEL)
    
    # Load data
    print("\n[1/3] Loading data...")
    commits = load_commits()
    ground_truth = load_ground_truth()
    analyzed = load_progress()  # Load already analyzed files
    
    print(f"  Total commits: {len(commits)}")
    print(f"  Already analyzed: {len(analyzed)} files")
    print(f"  Ground truth: {ground_truth['cve_id']} ({ground_truth['cwe']})")
    print(f"  Vulnerable file: {ground_truth['vulnerable_file']}")
    
    # Results file
    results_file = OUTPUT_DIR / "multiagent_results.jsonl"
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    # Analyze each commit
    print(f"\n[2/3] Running Multi-Agent analysis with {MODEL}...")
    
    total_files = 0
    skipped_files = 0
    vuln_detected = 0
    target_detections = []
    
    for i, commit in enumerate(commits):
        sha = commit["sha"]
        message = commit.get("message", "")
        files = commit.get("files", [])
        
        print(f"\n  [{i+1}/{len(commits)}] {sha[:8]} - {len(files)} files")
        
        for file_data in files:
            filename = file_data.get("filename", "")
            code = file_data.get("content", "")
            
            if not code:
                continue
            
            total_files += 1
            
            # Skip if already analyzed
            file_key = f"{sha}:{filename}"
            if file_key in analyzed:
                print(f"    [SKIP] {filename} (already analyzed)")
                skipped_files += 1
                continue
            
            print(f"    Analyzing {filename}...")
            
            # Run multi-agent analysis
            result = analyze_with_agents(model, sha, message, filename, code)
            
            # Save result
            with open(results_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps({
                    "sha": sha,
                    "filename": filename,
                    "message": message[:200],
                    "date": commit.get("date", ""),
                    "analysis": result,
                }, ensure_ascii=False) + '\n')
            
            # Track detections
            if result["summary"]["is_vulnerable"]:
                vuln_detected += 1
                agents = result["summary"]["detected_by"]
                cwes = result["summary"]["cwes"]
                print(f"      ⚠️  DETECTED by {agents} ({cwes})")
                
                # Check if target file
                if ground_truth["vulnerable_file"] in filename:
                    target_detections.append({
                        "sha": sha,
                        "filename": filename,
                        "detected_by": agents,
                        "cwes": cwes,
                        "confidence": result["summary"]["max_confidence"],
                        "details": result["vulnerabilities_found"]
                    })
            
            time.sleep(1)  # Rate limiting
        
        # Progress update
        if (i + 1) % 10 == 0:
            analyzed_now = total_files - skipped_files
            print(f"\n    Progress: {i+1}/{len(commits)} commits, {analyzed_now} new files, {vuln_detected} flagged")
    
    # Summary - reload all results including previous runs
    print("\n[3/3] Generating summary...")
    
    all_results = []
    all_vuln = 0
    all_target_detections = []
    
    if results_file.exists():
        with open(results_file, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    data = json.loads(line)
                    all_results.append(data)
                    if data.get("analysis", {}).get("summary", {}).get("is_vulnerable"):
                        all_vuln += 1
                        # Check target
                        if ground_truth["vulnerable_file"] in data.get("filename", ""):
                            all_target_detections.append({
                                "sha": data["sha"],
                                "filename": data["filename"],
                                "detected_by": data["analysis"]["summary"]["detected_by"],
                                "cwes": data["analysis"]["summary"]["cwes"],
                                "confidence": data["analysis"]["summary"]["max_confidence"],
                            })
                except:
                    continue
    
    total_analyzed = len(all_results)
    fp_rate = (all_vuln / total_analyzed * 100) if total_analyzed > 0 else 0
    
    # Check which agent detected the ground truth
    gt_detected = len(all_target_detections) > 0
    gt_agents = list(set(a for td in all_target_detections for a in td["detected_by"])) if gt_detected else []
    
    summary = {
        "experiment_date": datetime.now().isoformat(),
        "model": MODEL,
        "approach": "multi_agent_ensemble",
        "agents": list(AGENTS.keys()),
        "target": "huggingface/smolagents",
        "ground_truth": ground_truth,
        "metrics": {
            "total_commits": len(commits),
            "total_files_analyzed": total_analyzed,
            "files_flagged": all_vuln,
            "false_positive_rate": f"{fp_rate:.1f}%",
            "target_detected": gt_detected,
            "target_detected_by": gt_agents,
            "target_detections": all_target_detections,
        },
    }
    
    with open(OUTPUT_DIR / "multiagent_summary.json", 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    
    print("\n" + "=" * 70)
    print("MULTI-AGENT EXPERIMENT RESULTS")
    print("=" * 70)
    print(f"""
  Model: {MODEL}
  Agents: {len(AGENTS)} specialized detectors
  
  Total commits: {len(commits)}
  Total files analyzed: {total_analyzed}
  Files flagged: {all_vuln}
  False Positive Rate: {fp_rate:.1f}%
  
  GROUND TRUTH VALIDATION
  -----------------------
  CVE: {ground_truth['cve_id']} ({ground_truth['cwe']})
  Target file: {ground_truth['vulnerable_file']}
  Detected: {'✅ YES' if gt_detected else '❌ NO'}
  Detected by: {gt_agents if gt_agents else 'N/A'}
""")
    
    if all_target_detections:
        print("  TARGET FILE DETECTIONS:")
        for td in all_target_detections:
            print(f"    - {td['filename']}")
            print(f"      Agents: {td['detected_by']}")
            print(f"      CWEs: {td['cwes']}")
            print(f"      Confidence: {td['confidence']:.2f}")
    
    print(f"\n  Results saved to: {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
