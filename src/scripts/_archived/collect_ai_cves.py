#!/usr/bin/env python3
"""
CVE Data Analysis for AI-Era Vulnerability Research (2024-2025).

Collects and analyzes CVE data for paper:
- Total CVE counts by year
- Severity distribution (CVSS HIGH+)
- AI-related CVE proportion
- Trend analysis
"""

import sys
from pathlib import Path
from datetime import datetime
import json
import time
import requests

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# AI/LLM Attack Techniques - based on OWASP LLM Top 10 + NVD CVE data
# Focused on ATTACK METHODS, not just product names
# Reference: https://genai.owasp.org/llm-top-10/

AI_ATTACK_KEYWORDS = {
    # Prompt-based attacks (OWASP LLM01, LLM07)
    "prompt_attacks": [
        "prompt injection",           # 84 CVEs
        "indirect prompt injection",  # 9 CVEs
        "jailbreak",                  # 13 CVEs
        "prompt manipulation",
        "prompt leaking",
        "system prompt leak",
        "instruction injection",
    ],
    # Data/Model poisoning (OWASP LLM04)
    "poisoning_attacks": [
        "data poisoning",             # 30 CVEs
        "model poisoning",
        "training data poisoning",
        "backdoor attack",
        "trojan model",               # AI-specific, not general trojan
    ],
    # Model theft/extraction (OWASP LLM10)
    "model_theft": [
        "model extraction",           # 3 CVEs
        "model stealing",
        "model inversion",
        "membership inference",
        "training data extraction",
    ],
    # Adversarial attacks
    "adversarial": [
        "adversarial attack",
        "adversarial example",
        "evasion attack",             # 8 CVEs
        "perturbation attack",
    ],
    # Agent/Tool abuse (OWASP LLM06)
    "agent_abuse": [
        "tool poisoning",
        "function call injection",
        "agent hijacking",
        "excessive agency",
        "unauthorized tool",
    ],
    # RAG/Embedding attacks (OWASP LLM08)
    "rag_attacks": [
        "embedding injection",
        "vector injection",
        "rag poisoning",
        "context poisoning",
        "retrieval attack",
    ],
}

# AI Product keywords (for product-based filtering)
AI_PRODUCT_KEYWORDS = {
    "llm_frameworks": [
        "langchain", "llamaindex", "llama", "ollama", "vllm",
        "autogpt", "babyagi", "langflow", "flowise",
    ],
    "ml_platforms": [
        "tensorflow", "pytorch", "mlflow", "gradio", "huggingface",
        "keras", "onnx", "triton", "kubeflow",
    ],
    "ai_services": [
        "openai", "chatgpt", "gpt-4", "gpt-3",
        "claude", "anthropic", "gemini", "copilot", "bard",
    ],
    "vector_db": [
        "pinecone", "weaviate", "chroma", "milvus", "qdrant", "faiss",
    ],
}

# Combine all for matching
AI_KEYWORDS = {**AI_ATTACK_KEYWORDS, **AI_PRODUCT_KEYWORDS}

# Flatten for simple matching
AI_KEYWORDS_FLAT = []
for category, keywords in AI_KEYWORDS.items():
    AI_KEYWORDS_FLAT.extend(keywords)


def fetch_cves_batch(start_date: str, end_date: str, start_index: int = 0, results_per_page: int = 2000):
    """Fetch CVEs from NVD API."""
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "pubStartDate": f"{start_date}T00:00:00.000",
        "pubEndDate": f"{end_date}T23:59:59.999",
        "resultsPerPage": results_per_page,
        "startIndex": start_index,
    }
    
    r = requests.get(url, params=params, verify=False, timeout=60)
    if r.ok:
        return r.json()
    return None


def is_ai_related(description: str) -> tuple[bool, list[str]]:
    """Check if CVE description contains AI-related keywords.
    
    Returns:
        (is_ai_related, matched_categories)
    """
    desc_lower = description.lower()
    matched_categories = []
    
    for category, keywords in AI_KEYWORDS.items():
        for kw in keywords:
            if kw in desc_lower:
                matched_categories.append(category)
                break
    
    return len(matched_categories) > 0, matched_categories


def extract_cve_info(vuln: dict) -> dict:
    """Extract relevant info from NVD vulnerability record."""
    cve = vuln.get("cve", {})
    cve_id = cve.get("id", "")
    
    # Description
    desc = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break
    
    # CVSS score and severity
    metrics = cve.get("metrics", {})
    cvss_score = None
    cvss_severity = None
    
    # Try CVSS 3.1 first, then 3.0, then 2.0
    for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if metric_key in metrics and metrics[metric_key]:
            metric = metrics[metric_key][0]
            cvss_data = metric.get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_severity = cvss_data.get("baseSeverity") or metric.get("baseSeverity")
            break
    
    # CWE
    cwe_ids = []
    for weakness in cve.get("weaknesses", []):
        for d in weakness.get("description", []):
            if d.get("lang") == "en" and d.get("value", "").startswith("CWE-"):
                cwe_ids.append(d.get("value"))
    
    return {
        "cve_id": cve_id,
        "published": cve.get("published", ""),
        "description": desc,
        "cvss_score": cvss_score,
        "cvss_severity": cvss_severity,
        "cwe_ids": cwe_ids,
        "is_ai_related": is_ai_related(desc)[0],
        "ai_categories": is_ai_related(desc)[1],
    }


def collect_and_analyze(year: int, sample_size: int = 2000):
    """Collect CVEs for a year and analyze."""
    print(f"\n{'='*60}")
    print(f"Analyzing {year} CVEs (sample: {sample_size})")
    print("="*60)
    
    # Fetch by month to avoid API limits
    vulns = []
    total_available = 0
    per_month = max(sample_size // 12, 100)
    
    print(f"Fetching from NVD API (by month, {per_month} per month)...")
    
    for month in range(1, 13):
        # Calculate month end
        if month == 12:
            end_day = 31
        elif month in [4, 6, 9, 11]:
            end_day = 30
        elif month == 2:
            end_day = 29 if year % 4 == 0 else 28
        else:
            end_day = 31
        
        start_date = f"{year}-{month:02d}-01"
        end_date = f"{year}-{month:02d}-{end_day:02d}"
        
        data = fetch_cves_batch(start_date, end_date, 0, per_month)
        
        if data:
            month_total = data.get("totalResults", 0)
            month_vulns = data.get("vulnerabilities", [])
            total_available += month_total
            vulns.extend(month_vulns)
            print(f"  {year}-{month:02d}: {len(month_vulns)} fetched (total: {month_total})")
            time.sleep(1)  # Rate limit
        else:
            print(f"  {year}-{month:02d}: Failed")
        
        if len(vulns) >= sample_size:
            break
    
    if not vulns:
        print("Failed to fetch data")
        return None
    
    print(f"\nTotal CVEs in {year}: {total_available:,}")
    print(f"Sample size: {len(vulns):,}")
    
    # Parse CVEs
    cves = [extract_cve_info(v) for v in vulns]
    
    # Analysis
    results = {
        "year": year,
        "total_available": total_available,
        "sample_size": len(cves),
        "severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0},
        "ai_related": {"total": 0, "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}},
        "top_cwes": {},
    }
    
    for cve in cves:
        sev = (cve["cvss_severity"] or "UNKNOWN").upper()
        if sev not in results["severity"]:
            sev = "UNKNOWN"
        results["severity"][sev] += 1
        
        # AI-related
        if cve["is_ai_related"]:
            results["ai_related"]["total"] += 1
            if sev in results["ai_related"]["by_severity"]:
                results["ai_related"]["by_severity"][sev] += 1
            # Track categories
            for cat in cve.get("ai_categories", []):
                if "by_category" not in results["ai_related"]:
                    results["ai_related"]["by_category"] = {}
                results["ai_related"]["by_category"][cat] = results["ai_related"]["by_category"].get(cat, 0) + 1
        
        # CWE tracking
        for cwe in cve["cwe_ids"]:
            results["top_cwes"][cwe] = results["top_cwes"].get(cwe, 0) + 1
    
    # Print results
    print(f"\n📊 Severity Distribution:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        count = results["severity"][sev]
        pct = count / len(cves) * 100 if cves else 0
        bar = "█" * int(pct / 2)
        print(f"  {sev:10} {count:5} ({pct:5.1f}%) {bar}")
    
    high_plus = results["severity"]["CRITICAL"] + results["severity"]["HIGH"]
    high_plus_pct = high_plus / len(cves) * 100 if cves else 0
    print(f"\n  HIGH+ Total: {high_plus:,} ({high_plus_pct:.1f}%)")
    
    print(f"\n🤖 AI-Related CVEs (OWASP LLM Top 10 based):")
    ai_total = results["ai_related"]["total"]
    ai_pct = ai_total / len(cves) * 100 if cves else 0
    print(f"  Total: {ai_total} ({ai_pct:.2f}%)")
    
    ai_high_plus = results["ai_related"]["by_severity"]["CRITICAL"] + results["ai_related"]["by_severity"]["HIGH"]
    if high_plus > 0:
        ai_in_high_pct = ai_high_plus / high_plus * 100
        print(f"  In HIGH+ CVEs: {ai_high_plus} ({ai_in_high_pct:.2f}%)")
    
    # Show by category
    if "by_category" in results["ai_related"]:
        print(f"\n  By OWASP Category:")
        for cat, count in sorted(results["ai_related"]["by_category"].items(), key=lambda x: -x[1]):
            print(f"    {cat}: {count}")
    
    print(f"\n📋 Top 10 CWEs:")
    sorted_cwes = sorted(results["top_cwes"].items(), key=lambda x: -x[1])[:10]
    for cwe, count in sorted_cwes:
        print(f"  {cwe}: {count}")
    
    return results, cves


def save_results(all_results: dict, all_cves: list, output_dir: Path):
    """Save analysis results."""
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Save summary as JSON
    summary_file = output_dir / "cve_analysis_summary.json"
    with open(summary_file, 'w') as f:
        json.dump(all_results, f, indent=2)
    print(f"\n💾 Summary saved to {summary_file}")
    
    # Save CVE data as JSONL
    cve_file = output_dir / "cves_2024_2025.jsonl"
    with open(cve_file, 'w', encoding='utf-8') as f:
        for cve in all_cves:
            f.write(json.dumps(cve, ensure_ascii=False) + "\n")
    print(f"💾 CVE data saved to {cve_file}")
    
    # Save AI-related CVEs separately
    ai_cves = [c for c in all_cves if c["is_ai_related"]]
    ai_file = output_dir / "ai_related_cves.jsonl"
    with open(ai_file, 'w', encoding='utf-8') as f:
        for cve in ai_cves:
            f.write(json.dumps(cve, ensure_ascii=False) + "\n")
    print(f"💾 AI-related CVEs saved to {ai_file} ({len(ai_cves)} records)")
    
    # Save as CSV for easy viewing
    csv_file = output_dir / "cves_2024_2025.csv"
    with open(csv_file, 'w', encoding='utf-8') as f:
        f.write("cve_id,published,cvss_score,cvss_severity,is_ai_related,cwe_ids,description\n")
        for cve in all_cves:
            desc = cve["description"].replace('"', '""')[:200]
            cwes = ";".join(cve["cwe_ids"])
            f.write(f'"{cve["cve_id"]}","{cve["published"]}",{cve["cvss_score"] or ""},"{cve["cvss_severity"] or ""}",{cve["is_ai_related"]},"{cwes}","{desc}"\n')
    print(f"💾 CSV saved to {csv_file}")
    
    # Also copy to submission folder
    submission_dir = Path("submission/data/analysis")
    submission_dir.mkdir(parents=True, exist_ok=True)
    
    import shutil
    shutil.copy(summary_file, submission_dir / "cve_analysis_summary.json")
    shutil.copy(csv_file, submission_dir / "cves_2024_2025.csv")
    shutil.copy(ai_file, submission_dir / "ai_related_cves.jsonl")
    print(f"💾 Copied to submission/data/analysis/")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="CVE Analysis for AI-Era Research")
    parser.add_argument("--sample", type=int, default=2000, help="Sample size per year")
    parser.add_argument("--output", type=str, default="data/output/analysis", help="Output directory")
    
    args = parser.parse_args()
    
    print("="*60)
    print("CVE Analysis for AI-Era Vulnerability Research")
    print("="*60)
    print(f"Sample size: {args.sample} per year")
    print(f"Output: {args.output}")
    
    all_results = {}
    all_cves = []
    
    # Analyze 2024
    results_2024, cves_2024 = collect_and_analyze(2024, args.sample)
    if results_2024:
        all_results["2024"] = results_2024
        all_cves.extend(cves_2024)
    
    time.sleep(6)  # NVD rate limit
    
    # Analyze 2025
    results_2025, cves_2025 = collect_and_analyze(2025, args.sample)
    if results_2025:
        all_results["2025"] = results_2025
        all_cves.extend(cves_2025)
    
    # Combined summary
    print("\n" + "="*60)
    print("COMBINED SUMMARY (2024-2025)")
    print("="*60)
    
    total_available = sum(r["total_available"] for r in all_results.values())
    total_sample = len(all_cves)
    total_ai = sum(r["ai_related"]["total"] for r in all_results.values())
    
    print(f"Total CVEs available: {total_available:,}")
    print(f"Sample analyzed: {total_sample:,}")
    print(f"AI-related in sample: {total_ai} ({total_ai/total_sample*100:.2f}%)")
    
    # Save
    save_results(all_results, all_cves, Path(args.output))
    
    print("\n✅ Analysis complete!")


if __name__ == "__main__":
    main()
