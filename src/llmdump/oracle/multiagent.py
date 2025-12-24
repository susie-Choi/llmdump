#!/usr/bin/env python3
import json
import time
from pathlib import Path
from typing import Optional
import os
from dotenv import load_dotenv
load_dotenv()

try:
    import google.generativeai as genai
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False

AGENTS = {
    "code_injection": {
        "name": "Code Injection", "cwe": "CWE-94",
        "description": "Arbitrary code execution via eval/exec/compile or sandbox escape",
        "keywords": ["eval", "exec", "compile", "subprocess", "os.system", "pickle", "__class__"],
        "attack_patterns": ["Subclass walking", "Whitelisted module chaining", "Builtin recovery"],
    },
    "deserialization": {
        "name": "Deserialization", "cwe": "CWE-502",
        "description": "Unsafe deserialization leading to code execution",
        "keywords": ["pickle", "yaml.load", "marshal", "shelve"],
        "attack_patterns": ["Pickle __reduce__", "YAML unsafe_load"],
    },
}

PROMPT = '''You are a RED TEAM security researcher analyzing code for {cwe_name} ({cwe_id}).
Defense EXISTING != Defense being COMPLETE. Check for gaps.
FILE: {filename}
COMMIT: {message}
`python
{code}
`
Respond JSON only: {{"is_vulnerable": true/false, "confidence": 0.0-1.0, "evidence": "...", "reasoning": "..."}}
'''

class MultiAgentAnalyzer:
    def __init__(self, model="gemini-2.5-flash"):
        self.model = None
        if GENAI_AVAILABLE and os.getenv("GEMINI_API_KEY"):
            genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
            self.model = genai.GenerativeModel(model)

    def analyze_commit(self, filename, message, code, threshold=0.7):
        results = []
        for aid, info in AGENTS.items():
            if not any(k.lower() in code.lower() for k in info["keywords"]):
                results.append({"agent_id": aid, "cwe": info["cwe"], "is_vulnerable": False, "skipped": True})
                continue
            if not self.model:
                results.append({"agent_id": aid, "error": "No model"})
                continue
            try:
                resp = self.model.generate_content(PROMPT.format(
                    cwe_name=info["name"], cwe_id=info["cwe"],
                    filename=filename, message=message[:500], code=code[:15000]))
                text = resp.text.strip()
                if "`json" in text: text = text.split("`json")[1].split("`")[0]
                elif "`" in text: text = text.split("`")[1].split("`")[0]
                r = json.loads(text)
                r["agent_id"], r["cwe"] = aid, info["cwe"]
                results.append(r)
            except Exception as e:
                results.append({"agent_id": aid, "error": str(e)})
            time.sleep(0.5)
        vulns = [r for r in results if r.get("is_vulnerable") and r.get("confidence", 0) >= threshold]
        return {"agents_run": results, "vulnerabilities_found": vulns,
                "summary": {"is_vulnerable": len(vulns) > 0, "detected_by": [v["agent_id"] for v in vulns]}}

    def analyze_file(self, input_file, output_file=None, threshold=0.7):
        inp = Path(input_file)
        out = Path(output_file) if output_file else inp.parent / f"{inp.stem}_analysis.jsonl"
        out.parent.mkdir(parents=True, exist_ok=True)
        commits = [json.loads(l) for l in open(inp, encoding='utf-8') if l.strip()]
        print(f"Loaded {len(commits)} commits")
        stats = {"total": 0, "detected": 0}
        with open(out, 'w', encoding='utf-8') as f:
            for i, c in enumerate(commits):
                print(f"[{i+1}/{len(commits)}] {c.get('sha','?')[:8]}")
                a = self.analyze_commit(c.get('filename',''), c.get('message',''), c.get('code',''), threshold)
                f.write(json.dumps({"sha": c.get('sha'), "analysis": a}, ensure_ascii=False) + '\n')
                stats["total"] += 1
                if a["summary"]["is_vulnerable"]: stats["detected"] += 1
        print(f"Done: {stats}")
        return stats
