#!/usr/bin/env python3
"""
Adversarial Thinking 기반 취약점 탐지 실험.

기존 프롬프트 vs Adversarial Thinking 프롬프트 비교.
CVE-2025-5120 패치 커밋(33a942e6)을 대상으로 테스트.
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
OUTPUT_FILE = Path("submission/data/analysis/experiment/adversarial_results.jsonl")
MODEL = "gemini-2.5-flash"

# CVE-2025-5120 패치 커밋 SHA
CVE_PATCH_SHA = "33a942e62b6fbf6a35d41f1c735bda2d64c163d0"

# ============================================================
# 기존 프롬프트 (Baseline)
# ============================================================
BASELINE_PROMPT = """You are a security specialist focusing ONLY on Code Injection (CWE-94).

Your task: Determine if this Python code contains a Code Injection vulnerability.

VULNERABILITY DEFINITION:
Detects arbitrary code execution via eval/exec/compile

RELEVANT PATTERNS TO CHECK:
eval, exec, compile, subprocess, os.system, pickle.loads

FILE: {filename}
COMMIT MESSAGE: {message}

```python
{code}
```

ANALYSIS INSTRUCTIONS:
1. Look ONLY for Code Injection patterns
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

# ============================================================
# Adversarial Thinking 프롬프트 (개선된 버전)
# ============================================================
ADVERSARIAL_PROMPT = """You are a RED TEAM security researcher with expertise in Python sandbox escapes.

Your mission: Think like an ATTACKER trying to bypass this code's security measures.

## ADVERSARIAL THINKING PRINCIPLES
1. **Assume defenses can be bypassed**: Every security check has potential weaknesses
2. **Chain multiple techniques**: Combine small weaknesses into full exploits
3. **Abuse whitelisted features**: Allowed functions/modules can be stepping stones
4. **Think beyond obvious patterns**: Creative attackers find unexpected paths

## PYTHON SANDBOX ESCAPE TECHNIQUES TO CONSIDER
1. **Dunder method chaining**: `obj.__class__.__bases__[0].__subclasses__()` to access dangerous classes
2. **Attribute access via whitelisted objects**: `allowed_module.submodule.os.system`
3. **Indirect imports**: Getting modules through object attributes instead of direct import
4. **Type confusion**: Using allowed types to reach forbidden functionality
5. **Closure/frame inspection**: `func.__globals__`, `frame.f_locals`
6. **Metaclass abuse**: Custom `__getattr__`, `__getattribute__` to bypass checks

## CRITICAL QUESTIONS TO ASK
- Can I reach `os`, `subprocess`, `builtins` through ANY whitelisted object?
- Are there objects whose attributes lead to dangerous modules?
- Can I construct forbidden strings/calls indirectly?
- Does the blacklist cover ALL paths to dangerous functionality?
- Can I abuse the interpreter's own internals?

FILE: {filename}
COMMIT MESSAGE: {message}

```python
{code}
```

## YOUR TASK
Analyze this code AS AN ATTACKER would:
1. Identify ALL security mechanisms (blacklists, whitelists, checks)
2. For EACH mechanism, brainstorm potential bypasses
3. Consider if whitelisted modules/functions can chain to dangerous ones
4. Check if attribute access restrictions cover indirect paths
5. Evaluate if the defense is COMPLETE or has gaps

## IMPORTANT
- Defense code EXISTING doesn't mean it's EFFECTIVE
- A blacklist is only as good as its completeness
- Whitelisted objects may have dangerous attributes
- Even "safe" functions can be abused in creative ways

Respond with JSON only:
{{
  "is_vulnerable": true/false,
  "confidence": 0.0-1.0,
  "bypass_vectors": ["list of potential bypass techniques"],
  "defense_gaps": ["identified weaknesses in security measures"],
  "evidence": "specific code pattern showing vulnerability or defense gap",
  "reasoning": "detailed explanation of attack path or why defenses are sufficient"
}}
"""

# ============================================================
# Adversarial Thinking v2 - 더 구체적인 공격 시나리오
# ============================================================
ADVERSARIAL_V2_PROMPT = """You are an ATTACKER trying to escape this Python sandbox.

## KNOWN ESCAPE TECHNIQUES
1. Subclass walking: `().__class__.__bases__[0].__subclasses__()` → find dangerous classes
2. Whitelisted module chaining: `allowed_module.internal.os.system` (like Pandas CVE)
3. Builtin recovery: `obj.__init__.__globals__['__builtins__']`
4. Indirect attribute access: reach forbidden modules through allowed objects

## KEY INSIGHT
Even if direct dunder access is blocked, WHITELISTED MODULES may internally import dangerous modules. An attacker can chain: `whitelisted_obj.some_attr.another_attr.os.system()`

FILE: {filename}
COMMIT MESSAGE: {message}

```python
{code}
```

## ANALYSIS
1. What security measures exist?
2. What modules/objects are WHITELISTED?
3. Can whitelisted objects lead to dangerous modules INDIRECTLY?
4. Is there ANY path to os/subprocess/builtins through allowed objects?

CRITICAL: Defense code EXISTING ≠ Defense being COMPLETE. Check for GAPS.

Respond with JSON only:
{{
  "is_vulnerable": true/false,
  "confidence": 0.0-1.0,
  "potential_bypasses": ["bypass ideas"],
  "evidence": "specific weakness or null",
  "reasoning": "analysis"
}}
"""


def analyze_with_prompt(prompt_template, prompt_name, filename, message, code):
    """Analyze code with given prompt."""
    prompt = prompt_template.format(
        filename=filename,
        message=message[:500],
        code=code[:20000]
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
        result["prompt_type"] = prompt_name
        return result
    except Exception as e:
        return {
            "prompt_type": prompt_name,
            "error": str(e),
            "raw_response": text if 'text' in dir() else None
        }


def main():
    genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
    
    # Load CVE patch commit
    target_commit = None
    with open(DATA_FILE, encoding='utf-8') as f:
        for line in f:
            if line.strip():
                commit = json.loads(line)
                if commit['sha'].startswith(CVE_PATCH_SHA[:8]):
                    target_commit = commit
                    break
    
    if not target_commit:
        print(f"❌ CVE patch commit {CVE_PATCH_SHA[:8]} not found!")
        print("Searching in all commits...")
        
        # Try to find it
        with open(DATA_FILE, encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    commit = json.loads(line)
                    if "indirect" in commit['message'].lower() or "submodule" in commit['message'].lower():
                        print(f"  Found candidate: {commit['sha'][:8]} - {commit['message'][:60]}")
                        target_commit = commit
                        break
    
    if not target_commit:
        print("❌ Could not find CVE patch commit!")
        return
    
    print("=" * 70)
    print("ADVERSARIAL THINKING EXPERIMENT")
    print("=" * 70)
    print(f"Target: CVE-2025-5120 Patch Commit")
    print(f"SHA: {target_commit['sha']}")
    print(f"Message: {target_commit['message']}")
    print(f"Date: {target_commit.get('date', 'N/A')}")
    print("=" * 70)
    print()
    
    filename = target_commit['filename']
    message = target_commit['message']
    code = target_commit['code']
    
    results = []
    
    # Test 1: Baseline prompt
    print("[1/3] Testing BASELINE prompt...")
    baseline_result = analyze_with_prompt(
        BASELINE_PROMPT, "baseline", filename, message, code
    )
    results.append(baseline_result)
    print(f"      Result: is_vulnerable={baseline_result.get('is_vulnerable')}, "
          f"confidence={baseline_result.get('confidence')}")
    time.sleep(2)
    
    # Test 2: Adversarial v1 prompt
    print("[2/3] Testing ADVERSARIAL v1 prompt...")
    adv1_result = analyze_with_prompt(
        ADVERSARIAL_PROMPT, "adversarial_v1", filename, message, code
    )
    results.append(adv1_result)
    print(f"      Result: is_vulnerable={adv1_result.get('is_vulnerable')}, "
          f"confidence={adv1_result.get('confidence')}")
    time.sleep(2)
    
    # Test 3: Adversarial v2 prompt
    print("[3/3] Testing ADVERSARIAL v2 prompt...")
    adv2_result = analyze_with_prompt(
        ADVERSARIAL_V2_PROMPT, "adversarial_v2", filename, message, code
    )
    results.append(adv2_result)
    print(f"      Result: is_vulnerable={adv2_result.get('is_vulnerable')}, "
          f"confidence={adv2_result.get('confidence')}")
    
    print()
    print("=" * 70)
    print("RESULTS COMPARISON")
    print("=" * 70)
    
    for r in results:
        prompt_type = r.get('prompt_type', 'unknown')
        is_vuln = r.get('is_vulnerable', 'error')
        conf = r.get('confidence', 'N/A')
        
        status = "✅ DETECTED" if is_vuln else "❌ MISSED"
        print(f"\n[{prompt_type.upper()}] {status}")
        print(f"  Confidence: {conf}")
        
        if 'reasoning' in r:
            reasoning = r['reasoning'][:300] + "..." if len(r.get('reasoning', '')) > 300 else r.get('reasoning', '')
            print(f"  Reasoning: {reasoning}")
        
        if 'bypass_vectors' in r and r['bypass_vectors']:
            print(f"  Bypass vectors: {r['bypass_vectors'][:3]}")
        
        if 'potential_bypasses' in r and r['potential_bypasses']:
            print(f"  Potential bypasses: {r['potential_bypasses'][:3]}")
        
        if 'attack_scenario' in r and r['attack_scenario']:
            scenario = r['attack_scenario'][:200] + "..." if len(str(r.get('attack_scenario', ''))) > 200 else r.get('attack_scenario', '')
            print(f"  Attack scenario: {scenario}")
    
    # Save results
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    
    output_record = {
        'commit': {
            'sha': target_commit['sha'],
            'message': target_commit['message'],
            'date': target_commit.get('date'),
            'filename': target_commit['filename']
        },
        'experiment': {
            'timestamp': datetime.now().isoformat(),
            'model': MODEL,
            'target': 'CVE-2025-5120 patch commit'
        },
        'results': results,
        'summary': {
            'baseline_detected': results[0].get('is_vulnerable', False),
            'adversarial_v1_detected': results[1].get('is_vulnerable', False),
            'adversarial_v2_detected': results[2].get('is_vulnerable', False),
        }
    }
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(output_record, f, indent=2, ensure_ascii=False)
    
    print()
    print("=" * 70)
    print(f"Results saved to: {OUTPUT_FILE}")
    print("=" * 70)
    
    # Summary
    print()
    print("EXPERIMENT SUMMARY:")
    print(f"  - Baseline prompt: {'DETECTED' if output_record['summary']['baseline_detected'] else 'MISSED'}")
    print(f"  - Adversarial v1:  {'DETECTED' if output_record['summary']['adversarial_v1_detected'] else 'MISSED'}")
    print(f"  - Adversarial v2:  {'DETECTED' if output_record['summary']['adversarial_v2_detected'] else 'MISSED'}")


if __name__ == "__main__":
    main()
