#!/usr/bin/env python3
"""
Create curated core dataset for LLM code generation research.

This script filters CVEs to create a focused dataset:
- KEV-listed CVEs (confirmed exploits)
- Top CWE representatives
- High EPSS scores
- Famous CVEs
"""

import json
import sys
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Set

sys.path.insert(0, str(Path(__file__).parent.parent))

from llmdump.hub import Neo4jConnection, Neo4jQuery


def load_jsonl(file_path: Path) -> List[Dict]:
    """Load JSONL file."""
    data = []
    if not file_path.exists():
        return data
    
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                data.append(json.loads(line))
    return data


def save_jsonl(data: List[Dict], file_path: Path):
    """Save data to JSONL file."""
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with open(file_path, 'w', encoding='utf-8') as f:
        for item in data:
            f.write(json.dumps(item, ensure_ascii=False) + '\n')


def get_kev_cves(kev_data: List[Dict]) -> Set[str]:
    """Extract CVE IDs from KEV data."""
    cve_ids = set()
    for entry in kev_data:
        cve_id = entry.get('cve_id') or entry.get('cveID')
        if cve_id:
            cve_ids.add(cve_id)
    return cve_ids


def get_top_cwe_cves(cve_data: List[Dict], top_n: int = 10) -> Set[str]:
    """Get top N CVEs per CWE type."""
    cwe_to_cves = defaultdict(list)
    
    for cve in cve_data:
        cve_id = cve.get('cve_id') or cve.get('id')
        cwe_ids = cve.get('cwe_ids', [])
        
        if not cve_id or not cwe_ids:
            continue
        
        for cwe_id in cwe_ids:
            if isinstance(cwe_id, dict):
                cwe_id = cwe_id.get('id') or cwe_id.get('cwe_id')
            if cwe_id:
                cwe_to_cves[cwe_id].append(cve_id)
    
    selected_cves = set()
    for cwe_id, cves in sorted(cwe_to_cves.items(), key=lambda x: len(x[1]), reverse=True)[:top_n]:
        selected_cves.update(cves[:5])
    
    return selected_cves


def get_high_epss_cves(epss_data: List[Dict], threshold: float = 0.5) -> Set[str]:
    """Get CVEs with high EPSS scores."""
    high_epss_cves = set()
    
    for entry in epss_data:
        cve_id = entry.get('cve') or entry.get('cve_id')
        epss_score = entry.get('epss') or entry.get('score', 0)
        
        if cve_id and isinstance(epss_score, (int, float)) and epss_score >= threshold:
            high_epss_cves.add(cve_id)
    
    return high_epss_cves


def get_famous_cves() -> Set[str]:
    """Get famous CVEs for research."""
    return {
        'CVE-2021-44228',  # Log4Shell
        'CVE-2021-45046',  # Log4j2 DoS
        'CVE-2021-45105',  # Log4j2 DoS
        'CVE-2021-3156',   # Sudo Baron Samedit
        'CVE-2021-26855',  # Exchange ProxyLogon
        'CVE-2020-0601',   # Windows CurveBall
        'CVE-2017-5638',   # Struts2 Equifax
        'CVE-2014-0160',   # OpenSSL Heartbleed
        'CVE-2017-0144',   # EternalBlue
        'CVE-2014-6271',   # Shellshock
    }


def create_core_dataset(
    cve_file: Path,
    kev_file: Path,
    epss_file: Path,
    output_file: Path,
    max_cves: int = 1000
):
    """Create curated core dataset."""
    print("📊 Creating core dataset for LLM research...")
    print("=" * 60)
    
    # Load data
    print("\n📥 Loading data files...")
    cve_data = load_jsonl(cve_file)
    kev_data = load_jsonl(kev_file)
    epss_data = load_jsonl(epss_file)
    
    print(f"  - CVEs: {len(cve_data)}")
    print(f"  - KEV entries: {len(kev_data)}")
    print(f"  - EPSS scores: {len(epss_data)}")
    
    # Select CVEs
    print("\n🎯 Selecting CVEs...")
    
    selected_cves = set()
    
    # 1. KEV-listed CVEs
    kev_cves = get_kev_cves(kev_data)
    selected_cves.update(kev_cves)
    print(f"  ✓ KEV-listed: {len(kev_cves)} CVEs")
    
    # 2. Famous CVEs
    famous_cves = get_famous_cves()
    selected_cves.update(famous_cves)
    print(f"  ✓ Famous CVEs: {len(famous_cves)} CVEs")
    
    # 3. Top CWE representatives
    top_cwe_cves = get_top_cwe_cves(cve_data, top_n=20)
    selected_cves.update(top_cwe_cves)
    print(f"  ✓ Top CWE representatives: {len(top_cwe_cves)} CVEs")
    
    # 4. High EPSS scores
    high_epss_cves = get_high_epss_cves(epss_data, threshold=0.5)
    selected_cves.update(high_epss_cves)
    print(f"  ✓ High EPSS (≥0.5): {len(high_epss_cves)} CVEs")
    
    print(f"\n  Total unique CVEs selected: {len(selected_cves)}")
    
    # Filter CVE data
    print("\n📝 Filtering CVE data...")
    core_cves = []
    cve_dict = {}
    
    for cve in cve_data:
        cve_id = cve.get('cve_id') or cve.get('id')
        if cve_id in selected_cves:
            cve_dict[cve_id] = cve
    
    # Add selected CVEs in priority order
    for cve_id in list(selected_cves)[:max_cves]:
        if cve_id in cve_dict:
            core_cves.append(cve_dict[cve_id])
    
    print(f"  ✓ Filtered to {len(core_cves)} CVEs")
    
    # Save core dataset
    print(f"\n💾 Saving core dataset to {output_file}...")
    save_jsonl(core_cves, output_file)
    
    # Statistics
    print("\n📈 Core Dataset Statistics:")
    print("=" * 60)
    
    cwe_counts = defaultdict(int)
    severity_counts = defaultdict(int)
    
    for cve in core_cves:
        cwe_ids = cve.get('cwe_ids', [])
        for cwe_id in cwe_ids:
            if isinstance(cwe_id, dict):
                cwe_id = cwe_id.get('id') or cwe_id.get('cwe_id')
            if cwe_id:
                cwe_counts[cwe_id] += 1
        
        severity = cve.get('cvss_severity') or cve.get('severity', 'UNKNOWN')
        severity_counts[severity] += 1
    
    print(f"\nTotal CVEs: {len(core_cves)}")
    print(f"\nTop 10 CWEs:")
    for cwe_id, count in sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"  - {cve_id}: {count}")
    
    print(f"\nSeverity Distribution:")
    for severity, count in sorted(severity_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"  - {severity}: {count}")
    
    print(f"\n✅ Core dataset created: {output_file}")
    print(f"   Use this file for LLM code generation research!")


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Create curated core dataset for LLM research"
    )
    parser.add_argument(
        '--cve-file',
        type=Path,
        default=Path('data/input/cve.jsonl'),
        help='Input CVE JSONL file'
    )
    parser.add_argument(
        '--kev-file',
        type=Path,
        default=Path('data/input/kev.jsonl'),
        help='Input KEV JSONL file'
    )
    parser.add_argument(
        '--epss-file',
        type=Path,
        default=Path('data/input/epss.jsonl'),
        help='Input EPSS JSONL file'
    )
    parser.add_argument(
        '--output',
        type=Path,
        default=Path('data/input/cve_core.jsonl'),
        help='Output core dataset file'
    )
    parser.add_argument(
        '--max-cves',
        type=int,
        default=1000,
        help='Maximum number of CVEs in core dataset'
    )
    
    args = parser.parse_args()
    
    create_core_dataset(
        cve_file=args.cve_file,
        kev_file=args.kev_file,
        epss_file=args.epss_file,
        output_file=args.output,
        max_cves=args.max_cves
    )


if __name__ == '__main__':
    main()


