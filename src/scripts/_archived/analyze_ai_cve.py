#!/usr/bin/env python3
"""
CVE Analysis for Paper.

Analyzes:
1. Total CVE statistics (10-year trend: 2015-2025)
2. AI-related CVE trend (2023-2025, post-ChatGPT era)
3. Severity distribution
4. Critical vulnerability analysis

Output: submission/data/analysis/
"""

import sys
from pathlib import Path
from datetime import datetime
import json
import time
import requests

sys.path.insert(0, str(Path(__file__).parent.parent))

# Suppress SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# =============================================================================
# AI Keywords (OWASP LLM Top 10 based + NVD verified)
# =============================================================================
AI_SEARCH_KEYWORDS = [
    # Attack techniques
    ("prompt injection", "attack_prompt"),
    ("jailbreak", "attack_prompt"),
    ("data poisoning", "attack_poisoning"),
    ("adversarial", "attack_adversarial"),
    # LLM Frameworks
    ("langchain", "framework_llm"),
    ("llama", "framework_llm"),
    ("ollama", "framework_llm"),
    # AI Services
    ("openai", "service_ai"),
    ("chatgpt", "service_ai"),
    ("large language model", "service_ai"),
    # ML Platforms
    ("huggingface", "platform_ml"),
    ("pytorch", "platform_ml"),
    ("mlflow", "platform_ml"),
    ("gradio", "platform_ml"),
]


def get_cve_stats_by_period(year: int) -> dict:
    """Get CVE statistics for a year (by quarters to avoid API limits)."""
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    total = 0
    
    # Fetch by quarters to avoid API timeout
    quarters = [
        (f"{year}-01-01", f"{year}-03-31", "Q1"),
        (f"{year}-04-01", f"{year}-06-30", "Q2"),
        (f"{year}-07-01", f"{year}-09-30", "Q3"),
        (f"{year}-10-01", f"{year}-12-31", "Q4"),
    ]
    
    for start, end, qname in quarters:
        params = {
            "pubStartDate": f"{start}T00:00:00.000",
            "pubEndDate": f"{end}T23:59:59.999",
            "resultsPerPage": 1,
        }
        
        # Retry up to 3 times
        for attempt in range(3):
            try:
                r = requests.get(url, params=params, verify=False, timeout=60)
                if r.ok:
                    count = r.json().get("totalResults", 0)
                    total += count
                    break
                else:
                    print(f"    [WARN] {year} {qname}: HTTP {r.status_code}, retry {attempt+1}/3")
                    time.sleep(2)
            except Exception as e:
                print(f"    [WARN] {year} {qname}: {e}, retry {attempt+1}/3")
                time.sleep(2)
        else:
            print(f"    [FAIL] {year} {qname}: All retries failed!")
        
        time.sleep(0.5)
    
    return {"total": total, "year": year}


def collect_ai_cves(start_year: int = 2023) -> list:
    """Collect all AI-related CVEs from start_year onwards."""
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    all_cves = {}
    
    for keyword, category in AI_SEARCH_KEYWORDS:
        # Retry up to 3 times
        data = None
        for attempt in range(3):
            try:
                r = requests.get(url, params={"keywordSearch": keyword, "resultsPerPage": 200}, 
                               verify=False, timeout=60)
                if r.ok:
                    data = r.json()
                    break
                else:
                    print(f"    [WARN] '{keyword}': HTTP {r.status_code}, retry {attempt+1}/3")
                    time.sleep(2)
            except Exception as e:
                print(f"    [WARN] '{keyword}': {e}, retry {attempt+1}/3")
                time.sleep(2)
        
        if not data:
            print(f"    [FAIL] '{keyword}': All retries failed!")
            continue
        
        found = 0
        for v in data.get("vulnerabilities", []):
            cve = v.get("cve", {})
            cve_id = cve.get("id", "")
            published = cve.get("published", "")
            
            # Filter by start_year
            try:
                pub_year = int(published[:4])
                if pub_year < start_year:
                    continue
            except:
                continue
            
            if cve_id in all_cves:
                continue
            
            # Extract info
            desc = next((d["value"] for d in cve.get("descriptions", []) 
                       if d.get("lang") == "en"), "")
            
            metrics = cve.get("metrics", {})
            cvss_score, cvss_severity = None, None
            for mk in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if mk in metrics and metrics[mk]:
                    m = metrics[mk][0]
                    cvss_score = m.get("cvssData", {}).get("baseScore")
                    cvss_severity = m.get("cvssData", {}).get("baseSeverity") or m.get("baseSeverity")
                    break
            
            cwes = [d["value"] for w in cve.get("weaknesses", []) 
                   for d in w.get("description", []) 
                   if d.get("lang") == "en" and d.get("value", "").startswith("CWE-")]
            
            all_cves[cve_id] = {
                "cve_id": cve_id,
                "published": published,
                "year": published[:4],
                "description": desc,
                "cvss_score": cvss_score,
                "cvss_severity": cvss_severity,
                "cwe_ids": cwes,
                "keyword": keyword,
                "category": category,
            }
            found += 1
        
        print(f"    '{keyword}': {found} CVEs (2023+)")
        time.sleep(0.5)
    
    return list(all_cves.values())


def analyze_severity(cves: list) -> dict:
    """Analyze severity distribution."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for cve in cves:
        sev = (cve.get("cvss_severity") or "UNKNOWN").upper()
        if sev not in counts:
            sev = "UNKNOWN"
        counts[sev] += 1
    return counts


def generate_figures(results: dict, output_dir: Path):
    """Generate publication-ready figures."""
    import matplotlib.pyplot as plt
    import matplotlib
    matplotlib.use('Agg')
    
    plt.rcParams['font.size'] = 11
    plt.rcParams['axes.titlesize'] = 12
    plt.rcParams['axes.labelsize'] = 11
    
    fig_dir = output_dir / "figures"
    fig_dir.mkdir(exist_ok=True)
    
    # Unified color palette
    COLOR_PRIMARY = '#2c3e50'      # Dark blue-gray (main)
    COLOR_ACCENT = '#e74c3c'       # Red (highlight/AI era)
    COLOR_SECONDARY = '#3498db'    # Blue
    COLOR_TERTIARY = '#1abc9c'     # Teal
    # CVSS severity colors (standard)
    CVSS_CRITICAL = '#7b241c'      # Dark red
    CVSS_HIGH = '#e74c3c'          # Red
    CVSS_MEDIUM = '#f39c12'        # Orange/Yellow
    CVSS_LOW = '#27ae60'           # Green
    
    # Figure 1: 10-Year CVE Trend
    years = list(range(2015, 2026))
    counts = [results["total_cves_10year"].get(str(y), 0) for y in years]
    
    fig, ax = plt.subplots(figsize=(10, 5))
    bars = ax.bar(years, counts, color=COLOR_PRIMARY, edgecolor='black', linewidth=0.5)
    
    # Highlight 2023-2025 (AI era)
    for i, year in enumerate(years):
        if year >= 2023:
            bars[i].set_color(COLOR_ACCENT)
    
    ax.set_xlabel('Year')
    ax.set_ylabel('Number of CVEs')
    ax.set_title('CVE Publications Over 10 Years (2015-2025)')
    ax.set_xticks(years)
    ax.set_xticklabels(years, rotation=45)
    
    for i, (year, count) in enumerate(zip(years, counts)):
        ax.text(year, count + 500, f'{count:,}', ha='center', va='bottom', fontsize=8)
    
    ax.legend([bars[0], bars[-1]], ['Pre-ChatGPT', 'Post-ChatGPT (2023+)'], loc='upper left')
    plt.tight_layout()
    plt.savefig(fig_dir / 'fig1_cve_trend_10year.jpg', dpi=300, bbox_inches='tight', format='jpeg')
    plt.close()
    print(f"  [Figure 1] 10-Year CVE Trend saved")
    
    # Figure 2: AI-Related CVE Growth (2023-2025)
    ai_years = ['2023', '2024', '2025']
    ai_counts = [results["ai_cves"]["by_year"].get(y, 0) for y in ai_years]
    
    fig, ax = plt.subplots(figsize=(7, 5))
    # Gradient effect using different shades of accent color
    bar_colors = ['#f1948a', '#e74c3c', '#b03a2e']  # Light to dark red
    bars = ax.bar(ai_years, ai_counts, color=bar_colors, edgecolor='black')
    
    ax.set_xlabel('Year')
    ax.set_ylabel('Number of AI-Related CVEs')
    ax.set_title('AI-Related CVE Growth (Post-ChatGPT Era)')
    
    for i, (year, count) in enumerate(zip(ai_years, ai_counts)):
        ax.text(i, count + 5, f'{count}', ha='center', va='bottom', fontsize=12, fontweight='bold')
        if i > 0:
            growth = (ai_counts[i] - ai_counts[i-1]) / ai_counts[i-1] * 100
            ax.annotate(f'+{growth:.0f}%', xy=(i-0.5, (ai_counts[i] + ai_counts[i-1])/2),
                       fontsize=10, color=COLOR_PRIMARY, fontweight='bold')
    
    plt.tight_layout()
    plt.savefig(fig_dir / 'fig2_ai_cve_growth.jpg', dpi=300, bbox_inches='tight', format='jpeg')
    plt.close()
    print(f"  [Figure 2] AI CVE Growth saved")
    
    # Figure 3: AI CVE Severity Distribution (CVSS colors)
    severity = results["ai_cves"]["severity"]
    labels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
    sizes = [severity.get(s, 0) for s in labels]
    colors = [CVSS_CRITICAL, CVSS_HIGH, CVSS_MEDIUM, CVSS_LOW]
    
    fig, ax = plt.subplots(figsize=(7, 7))
    wedges, texts, autotexts = ax.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%',
                                       startangle=90, explode=(0.05, 0.02, 0, 0),
                                       textprops={'fontsize': 11})
    autotexts[0].set_color('white')
    ax.set_title('AI-Related CVE Severity Distribution (2023-2025)')
    
    plt.tight_layout()
    plt.savefig(fig_dir / 'fig3_ai_severity_dist.jpg', dpi=300, bbox_inches='tight', format='jpeg')
    plt.close()
    print(f"  [Figure 3] Severity Distribution saved")
    
    # Figure 4: AI CVE Categories
    categories = results["ai_cves"]["by_category"]
    cat_labels = {
        'attack_prompt': 'Prompt Injection',
        'attack_poisoning': 'Data Poisoning', 
        'attack_adversarial': 'Adversarial',
        'framework_llm': 'LLM Frameworks',
        'service_ai': 'AI Services',
        'platform_ml': 'ML Platforms',
    }
    
    sorted_cats = sorted(categories.items(), key=lambda x: -x[1])
    cat_names = [cat_labels.get(c, c) for c, _ in sorted_cats]
    cat_counts = [v for _, v in sorted_cats]
    
    fig, ax = plt.subplots(figsize=(9, 5))
    bars = ax.barh(cat_names, cat_counts, color=COLOR_TERTIARY, edgecolor='black')
    ax.set_xlabel('Number of CVEs')
    ax.set_title('AI-Related CVE Categories (2023-2025)')
    ax.invert_yaxis()
    
    for i, v in enumerate(cat_counts):
        ax.text(v + 2, i, str(v), va='center', fontsize=10)
    
    plt.tight_layout()
    plt.savefig(fig_dir / 'fig4_ai_categories.jpg', dpi=300, bbox_inches='tight', format='jpeg')
    plt.close()
    print(f"  [Figure 4] AI Categories saved")
    
    print(f"\n  All figures saved to: {fig_dir}")


def main():
    print("=" * 70)
    print("CVE Analysis for Paper (10-Year Trend + AI Focus)")
    print("=" * 70)
    
    output_dir = Path("submission/data/analysis")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    results = {
        "generated_at": datetime.now().isoformat(),
        "total_cves_10year": {},
        "ai_cves": {},
    }
    
    # ==========================================================================
    # 1. 10-Year CVE Trend (2015-2025)
    # ==========================================================================
    print("\n[1/3] Collecting 10-year CVE trend (2015-2025)...")
    
    for year in range(2015, 2026):
        stats = get_cve_stats_by_period(year)
        results["total_cves_10year"][str(year)] = stats["total"]
        print(f"  {year}: {stats['total']:,}")
        time.sleep(0.5)
    
    # ==========================================================================
    # 2. AI-related CVE Collection (2023-2025, post-ChatGPT era)
    # ==========================================================================
    print("\n[2/3] Collecting AI-related CVEs (2023-2025)...")
    
    ai_cves = collect_ai_cves(start_year=2023)
    print(f"\n  Total AI CVEs (2023-2025): {len(ai_cves)}")
    
    # Analyze by year
    ai_by_year = {"2023": [], "2024": [], "2025": []}
    ai_by_category = {}
    
    for cve in ai_cves:
        year = cve.get("year", "")
        if year in ai_by_year:
            ai_by_year[year].append(cve)
        
        cat = cve.get("category", "unknown")
        ai_by_category[cat] = ai_by_category.get(cat, 0) + 1
    
    results["ai_cves"] = {
        "total": len(ai_cves),
        "by_year": {y: len(v) for y, v in ai_by_year.items()},
        "by_category": ai_by_category,
        "severity": analyze_severity(ai_cves),
    }
    
    for year in ["2023", "2024", "2025"]:
        print(f"    {year}: {len(ai_by_year[year])}")
    
    # ==========================================================================
    # 3. Analysis Summary
    # ==========================================================================
    print("\n[3/3] Generating analysis summary...")
    
    total_10year = sum(results["total_cves_10year"].values())
    total_2023_2025 = sum(results["total_cves_10year"].get(str(y), 0) for y in [2023, 2024, 2025])
    
    ai_total = results["ai_cves"]["total"]
    ai_severity = results["ai_cves"]["severity"]
    ai_high_plus = ai_severity["CRITICAL"] + ai_severity["HIGH"]
    
    # Growth calculations
    ai_2023 = len(ai_by_year["2023"])
    ai_2024 = len(ai_by_year["2024"])
    ai_2025 = len(ai_by_year["2025"])
    
    growth_2023_2024 = ((ai_2024 - ai_2023) / ai_2023 * 100) if ai_2023 > 0 else 0
    growth_2024_2025 = ((ai_2025 - ai_2024) / ai_2024 * 100) if ai_2024 > 0 else 0
    
    summary = {
        "analysis_period": {
            "total_cves": "2015-2025 (10 years)",
            "ai_cves": "2023-2025 (post-ChatGPT era)",
        },
        "total_cves_10year": total_10year,
        "total_cves_2023_2025": total_2023_2025,
        "ai_cves_total": ai_total,
        "ai_cves_ratio": f"{ai_total / total_2023_2025 * 100:.2f}%" if total_2023_2025 > 0 else "N/A",
        "ai_by_year": {"2023": ai_2023, "2024": ai_2024, "2025": ai_2025},
        "ai_growth": {
            "2023_to_2024": f"+{growth_2023_2024:.1f}%",
            "2024_to_2025": f"+{growth_2024_2025:.1f}%",
        },
        "ai_severity": {
            "critical": ai_severity["CRITICAL"],
            "high": ai_severity["HIGH"],
            "high_plus_ratio": f"{ai_high_plus / ai_total * 100:.1f}%" if ai_total > 0 else "N/A",
        },
    }
    
    results["summary"] = summary
    
    # ==========================================================================
    # Save Results
    # ==========================================================================
    
    with open(output_dir / "cve_analysis_full.json", 'w') as f:
        json.dump(results, f, indent=2)
    
    with open(output_dir / "ai_cves.jsonl", 'w', encoding='utf-8') as f:
        for cve in ai_cves:
            f.write(json.dumps(cve, ensure_ascii=False) + "\n")
    
    with open(output_dir / "summary.json", 'w') as f:
        json.dump(summary, f, indent=2)
    
    # ==========================================================================
    # Print Summary
    # ==========================================================================
    print("\n" + "=" * 70)
    print("ANALYSIS SUMMARY")
    print("=" * 70)
    
    print("\n📊 10-YEAR CVE TREND (2015-2025):")
    for year in range(2015, 2026):
        count = results["total_cves_10year"].get(str(year), 0)
        bar = "█" * (count // 5000)
        print(f"  {year}: {count:>6,} {bar}")
    print(f"  Total: {total_10year:,}")
    
    print(f"""
🤖 AI-RELATED CVEs (2023-2025, post-ChatGPT):
  Total: {ai_total} ({summary['ai_cves_ratio']} of 2023-2025 CVEs)
  
  By Year:
    2023: {ai_2023:>4} (ChatGPT launched Nov 2022)
    2024: {ai_2024:>4} ({summary['ai_growth']['2023_to_2024']} growth)
    2025: {ai_2025:>4} ({summary['ai_growth']['2024_to_2025']} growth)
  
  Severity:
    CRITICAL: {ai_severity['CRITICAL']} ({ai_severity['CRITICAL']/ai_total*100:.1f}%)
    HIGH: {ai_severity['HIGH']} ({ai_severity['HIGH']/ai_total*100:.1f}%)
    HIGH+: {ai_high_plus} ({summary['ai_severity']['high_plus_ratio']})

📂 AI CVE CATEGORIES:
""")
    for cat, count in sorted(ai_by_category.items(), key=lambda x: -x[1]):
        print(f"  {cat}: {count}")
    
    print(f"""
💾 OUTPUT FILES:
  {output_dir / 'cve_analysis_full.json'}
  {output_dir / 'ai_cves.jsonl'}
  {output_dir / 'summary.json'}
""")
    
    # ==========================================================================
    # 4. Generate Figures
    # ==========================================================================
    print("[4/4] Generating publication figures...")
    generate_figures(results, output_dir)
    
    print("\n✅ Analysis complete!")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--figures-only', action='store_true', help='Generate figures from existing data')
    args = parser.parse_args()
    
    if args.figures_only:
        # Load existing data and generate figures only
        output_dir = Path("submission/data/analysis")
        with open(output_dir / "cve_analysis_full.json") as f:
            results = json.load(f)
        print("Generating figures from existing data...")
        generate_figures(results, output_dir)
        print("✅ Figures generated!")
    else:
        main()
