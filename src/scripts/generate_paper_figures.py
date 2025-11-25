#!/usr/bin/env python3
"""
Generate figures and tables for LaTeX paper from Neo4j data.

This script extracts data from Neo4j and generates:
- Tables (LaTeX format)
- Graphs (PNG/JPG for LaTeX)
- Statistics summaries
"""

import sys
import os
import json
from pathlib import Path
from typing import Dict, List, Any
from collections import defaultdict
from datetime import datetime

import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
import matplotlib.pyplot as plt
import matplotlib.font_manager as fm
import seaborn as sns
import numpy as np

sys.path.insert(0, str(Path(__file__).parent.parent))

from llmdump.hub import Neo4jConnection, HubQuery

# 한글 폰트 설정 (Windows)
plt.rcParams['font.family'] = 'DejaVu Sans'
plt.rcParams['axes.unicode_minus'] = False

# 출력 디렉토리
OUTPUT_DIR = Path('docs/paper/images')
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def get_node_counts(driver) -> Dict[str, int]:
    """Get Neo4j node counts."""
    with driver.session() as session:
        result = session.run("""
            MATCH (n)
            WITH labels(n) as labels, count(*) as count
            UNWIND labels as label
            WITH label, sum(count) as total
            RETURN label, total
            ORDER BY total DESC
        """)
        
        counts = {}
        for record in result:
            counts[record['label']] = record['total']
        
        return counts


def get_relationship_counts(driver) -> Dict[str, int]:
    """Get Neo4j relationship counts."""
    with driver.session() as session:
        result = session.run("""
            MATCH ()-[r]->()
            WITH type(r) as rel_type, count(*) as count
            RETURN rel_type, count
            ORDER BY count DESC
        """)
        
        counts = {}
        for record in result:
            counts[record['rel_type']] = record['count']
        
        return counts


def get_cve_by_severity(driver) -> Dict[str, int]:
    """Get CVE counts by severity."""
    with driver.session() as session:
        result = session.run("""
            MATCH (c:CVE)
            WHERE c.severity IS NOT NULL
            RETURN c.severity as severity, count(*) as count
            ORDER BY count DESC
        """)
        
        counts = {}
        for record in result:
            severity = record['severity'] or 'UNKNOWN'
            counts[severity] = record['count']
        
        return counts


def get_top_cwes(driver, top_n: int = 20) -> List[Dict[str, Any]]:
    """Get top N CWEs by CVE count."""
    with driver.session() as session:
        result = session.run("""
            MATCH (c:CVE)-[:HAS_WEAKNESS]->(cwe:CWE)
            WITH cwe.id as cwe_id, cwe.name as cwe_name, count(c) as cve_count
            RETURN cwe_id, cwe_name, cve_count
            ORDER BY cve_count DESC
            LIMIT $top_n
        """, top_n=top_n)
        
        return [
            {
                'cwe_id': record['cwe_id'],
                'cwe_name': record['cwe_name'],
                'count': record['cve_count']
            }
            for record in result
        ]


def get_commit_statistics(driver) -> Dict[str, Any]:
    """Get commit statistics."""
    with driver.session() as session:
        # Total commits
        result = session.run("MATCH (c:Commit) RETURN count(c) as total")
        total_commits = result.single()['total']
        
        # Commits by CVE
        result = session.run("""
            MATCH (cve:CVE)-[:HAS_COMMIT]->(c:Commit)
            RETURN cve.id as cve_id, count(c) as commit_count
            ORDER BY commit_count DESC
        """)
        
        commits_by_cve = [
            {
                'cve_id': record['cve_id'],
                'commit_count': record['commit_count']
            }
            for record in result
        ]
        
        return {
            'total_commits': total_commits,
            'commits_by_cve': commits_by_cve
        }


def generate_severity_distribution(driver, output_path: Path):
    """Generate CVSS severity distribution chart."""
    severity_counts = get_cve_by_severity(driver)
    
    if not severity_counts:
        print("⚠️  No severity data found")
        return
    
    # Sort by severity order
    severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']
    labels = [s for s in severity_order if s in severity_counts]
    values = [severity_counts[s] for s in labels]
    
    # Create pie chart
    fig, ax = plt.subplots(figsize=(8, 6))
    colors = ['#d32f2f', '#f57c00', '#fbc02d', '#388e3c', '#757575']
    
    wedges, texts, autotexts = ax.pie(
        values, 
        labels=labels, 
        autopct='%1.1f%%',
        colors=colors[:len(labels)],
        startangle=90
    )
    
    ax.set_title('CVE Severity Distribution', fontsize=14, fontweight='bold')
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"✅ Generated: {output_path}")


def generate_top_cwes_chart(driver, output_path: Path, top_n: int = 15):
    """Generate top CWE bar chart."""
    top_cwes = get_top_cwes(driver, top_n=top_n)
    
    if not top_cwes:
        print("⚠️  No CWE data found")
        return
    
    cwe_ids = [c['cwe_id'] for c in top_cwes]
    counts = [c['count'] for c in top_cwes]
    
    fig, ax = plt.subplots(figsize=(12, 8))
    
    bars = ax.barh(range(len(cwe_ids)), counts, color='#1976d2')
    ax.set_yticks(range(len(cwe_ids)))
    ax.set_yticklabels(cwe_ids)
    ax.set_xlabel('Number of CVEs', fontsize=12)
    ax.set_title(f'Top {top_n} CWE Types by CVE Count', fontsize=14, fontweight='bold')
    ax.invert_yaxis()
    
    # Add value labels
    for i, (bar, count) in enumerate(zip(bars, counts)):
        ax.text(count + max(counts) * 0.01, i, str(count), 
                va='center', fontsize=9)
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"✅ Generated: {output_path}")


def generate_cve_timeline(driver, output_path: Path):
    """Generate CVE publication timeline."""
    with driver.session() as session:
        result = session.run("""
            MATCH (c:CVE)
            WHERE c.published IS NOT NULL
            WITH substring(c.published, 0, 7) as year_month, count(*) as count
            RETURN year_month, count
            ORDER BY year_month
        """)
        
        dates = []
        counts = []
        
        for record in result:
            dates.append(record['year_month'])
            counts.append(record['count'])
        
        if not dates:
            print("⚠️  No timeline data found")
            return
        
        fig, ax = plt.subplots(figsize=(14, 6))
        ax.plot(dates, counts, marker='o', linewidth=2, markersize=4)
        ax.set_xlabel('Year-Month', fontsize=12)
        ax.set_ylabel('Number of CVEs', fontsize=12)
        ax.set_title('CVE Publication Timeline', fontsize=14, fontweight='bold')
        ax.grid(True, alpha=0.3)
        
        # Rotate x-axis labels
        plt.xticks(rotation=45, ha='right')
        
        plt.tight_layout()
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"✅ Generated: {output_path}")


def generate_latex_table(data: List[List[str]], headers: List[str], 
                         caption: str, label: str, output_path: Path):
    """Generate LaTeX table code."""
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("\\begin{table}[h]\n")
        f.write("\\centering\n")
        f.write(f"\\caption{{{caption}}}\n")
        f.write(f"\\label{{{label}}}\n")
        
        # Determine column alignment
        num_cols = len(headers)
        col_spec = "l" + "r" * (num_cols - 1)  # First column left, rest right
        
        f.write(f"\\begin{{tabular}}{{{col_spec}}}\n")
        f.write("\\toprule\n")
        
        # Header
        f.write(" & ".join([f"\\textbf{{{h}}}" for h in headers]) + " \\\\\n")
        f.write("\\midrule\n")
        
        # Data rows
        for row in data:
            f.write(" & ".join(str(cell) for cell in row) + " \\\\\n")
        
        f.write("\\bottomrule\n")
        f.write("\\end{tabular}\n")
        f.write("\\end{table}\n")
    
    print(f"✅ Generated LaTeX table: {output_path}")


def generate_data_source_table(driver, output_path: Path):
    """Generate data source table."""
    node_counts = get_node_counts(driver)
    
    # Map node types to display names
    display_map = {
        'CVE': ('CVE (NVD)', node_counts.get('CVE', 0)),
        'EPSS': ('EPSS', node_counts.get('EPSS', 0)),
        'KEV': ('KEV (CISA)', node_counts.get('KEV', 0)),
        'Commit': ('GitHub Commits', node_counts.get('Commit', 0)),
        'Exploit': ('Exploits (Exploit-DB)', node_counts.get('Exploit', 0)),
        'Advisory': ('GitHub Advisory', node_counts.get('Advisory', 0)),
    }
    
    data = []
    for key, (name, count) in display_map.items():
        status = "완료" if count > 0 else "미완료"
        data.append([name, f"{count:,}", status])
    
    headers = ["데이터 소스", "수집 건수", "상태"]
    generate_latex_table(
        data, headers,
        "데이터 소스 현황",
        "tab:data_sources",
        output_path
    )


def generate_neo4j_nodes_table(driver, output_path: Path):
    """Generate Neo4j nodes table."""
    node_counts = get_node_counts(driver)
    
    # Sort by count
    sorted_nodes = sorted(node_counts.items(), key=lambda x: x[1], reverse=True)
    
    data = []
    descriptions = {
        'CVE': '취약점 정보',
        'Commit': 'GitHub Commit',
        'KEV': '실제 악용 확인',
        'CWE': '취약점 유형',
        'CPE': '제품 식별자',
        'Product': '영향받는 제품',
        'Reference': '외부 참조',
        'Consequence': '영향 결과',
        'Vendor': '소프트웨어 벤더',
        'Package': '소프트웨어 패키지',
        'Exploit': '공개 익스플로잇',
        'Advisory': 'GitHub 권고',
        'GitHubSignal': '행동 신호',
    }
    
    for node_type, count in sorted_nodes:
        desc = descriptions.get(node_type, '')
        data.append([node_type, f"{count:,}", desc])
    
    headers = ["Node 유형", "개수", "설명"]
    generate_latex_table(
        data, headers,
        "Neo4j Nodes 현황",
        "tab:neo4j_nodes",
        output_path
    )


def generate_neo4j_relationships_table(driver, output_path: Path):
    """Generate Neo4j relationships table."""
    rel_counts = get_relationship_counts(driver)
    
    # Sort by count
    sorted_rels = sorted(rel_counts.items(), key=lambda x: x[1], reverse=True)
    
    data = []
    descriptions = {
        'HAS_COMMIT': 'CVE → Commit',
        'RELATED_TO': 'CVE 관계',
        'HAS_CONSEQUENCE': 'CVE → Consequence',
        'AFFECTS': 'CVE → Product',
        'HAS_VERSION': 'Product → CPE',
        'HAS_REFERENCE': 'CVE → Reference',
        'PRODUCES': 'Vendor → Product',
        'HAS_EXPLOIT': 'CVE → Exploit',
        'DEPENDS_ON': '패키지 의존성',
        'HAS_WEAKNESS': 'CVE → CWE',
        'HAS_ADVISORY': 'Package → Advisory',
        'HAS_KEV': 'CVE → KEV',
        'REFERENCES': 'Advisory → CVE',
        'HAS_SIGNAL': 'Package → Signal',
    }
    
    for rel_type, count in sorted_rels:
        desc = descriptions.get(rel_type, '')
        data.append([rel_type, f"{count:,}", desc])
    
    headers = ["Relationships 유형", "개수", "설명"]
    generate_latex_table(
        data, headers,
        "Neo4j Relationships 현황",
        "tab:neo4j_relationships",
        output_path
    )


def load_cve_from_jsonl(jsonl_path: Path) -> List[Dict[str, Any]]:
    """Load CVE data from JSONL file."""
    cves = []
    if not jsonl_path.exists():
        return cves
    
    with open(jsonl_path, 'r', encoding='utf-8') as f:
        for line in f:
            if not line.strip():
                continue
            entry = json.loads(line)
            
            # Handle NVD API format
            if 'payload' in entry and 'vulnerabilities' in entry['payload']:
                for vuln in entry['payload']['vulnerabilities']:
                    cve_data = vuln.get('cve', {})
                    if 'id' not in cve_data:
                        continue
                    
                    # Extract CVSS score and severity
                    cvss_score = None
                    severity = None
                    if 'metrics' in cve_data:
                        if 'cvssMetricV31' in cve_data['metrics']:
                            cvss = cve_data['metrics']['cvssMetricV31'][0]
                            cvss_score = cvss.get('cvssData', {}).get('baseScore')
                            severity = cvss.get('cvssData', {}).get('baseSeverity')
                        elif 'cvssMetricV2' in cve_data['metrics']:
                            cvss = cve_data['metrics']['cvssMetricV2'][0]
                            cvss_score = cvss.get('cvssData', {}).get('baseScore')
                            severity = cvss.get('baseSeverity')
                    
                    # Extract CWE IDs
                    cwe_ids = []
                    if 'weaknesses' in cve_data:
                        for weakness in cve_data['weaknesses']:
                            for desc in weakness.get('description', []):
                                cwe_id = desc.get('value', '')
                                if cwe_id.startswith('CWE-'):
                                    cwe_ids.append(cwe_id)
                    
                    cves.append({
                        'cve_id': cve_data['id'],
                        'published': cve_data.get('published'),
                        'cvss_score': cvss_score,
                        'severity': severity,
                        'cwe_ids': cwe_ids,
                    })
            # Handle normalized format
            elif 'cve_id' in entry:
                cves.append(entry)
    
    return cves


def generate_from_jsonl(cve_file: Path, output_dir: Path, tables_dir: Path):
    """Generate figures and tables from JSONL files."""
    print("\n📥 Loading data from JSONL files...")
    cves = load_cve_from_jsonl(cve_file)
    
    if not cves:
        print(f"⚠️  No CVE data found in {cve_file}")
        return False
    
    print(f"  Loaded {len(cves)} CVEs")
    
    # Generate severity distribution
    print("\n📈 Generating severity distribution...")
    severity_counts = defaultdict(int)
    for cve in cves:
        severity = cve.get('severity') or 'UNKNOWN'
        severity_counts[severity] += 1
    
    if severity_counts:
        labels = [s for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'] if s in severity_counts]
        values = [severity_counts[s] for s in labels]
        
        fig, ax = plt.subplots(figsize=(8, 6))
        colors = ['#d32f2f', '#f57c00', '#fbc02d', '#388e3c', '#757575']
        ax.pie(values, labels=labels, autopct='%1.1f%%', colors=colors[:len(labels)], startangle=90)
        ax.set_title('CVE Severity Distribution', fontsize=14, fontweight='bold')
        plt.tight_layout()
        plt.savefig(output_dir / 'severity_distribution.png', dpi=300, bbox_inches='tight')
        plt.close()
        print(f"  ✅ Generated: {output_dir / 'severity_distribution.png'}")
    
    # Generate top CWEs
    print("\n📈 Generating top CWE chart...")
    cwe_counts = defaultdict(int)
    for cve in cves:
        for cwe_id in cve.get('cwe_ids', []):
            cwe_counts[cwe_id] += 1
    
    if cwe_counts:
        top_cwes = sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True)[:15]
        cwe_ids = [c[0] for c in top_cwes]
        counts = [c[1] for c in top_cwes]
        
        fig, ax = plt.subplots(figsize=(12, 8))
        bars = ax.barh(range(len(cwe_ids)), counts, color='#1976d2')
        ax.set_yticks(range(len(cwe_ids)))
        ax.set_yticklabels(cwe_ids)
        ax.set_xlabel('Number of CVEs', fontsize=12)
        ax.set_title('Top 15 CWE Types by CVE Count', fontsize=14, fontweight='bold')
        ax.invert_yaxis()
        for i, (bar, count) in enumerate(zip(bars, counts)):
            ax.text(count + max(counts) * 0.01, i, str(count), va='center', fontsize=9)
        plt.tight_layout()
        plt.savefig(output_dir / 'top_cwes.png', dpi=300, bbox_inches='tight')
        plt.close()
        print(f"  ✅ Generated: {output_dir / 'top_cwes.png'}")
    
    # Generate data source table
    print("\n📋 Generating LaTeX tables...")
    tables_dir.mkdir(parents=True, exist_ok=True)
    
    # Simple data source table
    data = [
        ["CVE (NVD)", f"{len(cves):,}", "완료"],
    ]
    headers = ["데이터 소스", "수집 건수", "상태"]
    generate_latex_table(data, headers, "데이터 소스 현황", "tab:data_sources", 
                        tables_dir / 'data_sources.tex')
    
    print("\n✅ All figures and tables generated!")
    return True


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Generate figures and tables for LaTeX paper"
    )
    parser.add_argument(
        '--neo4j-uri',
        default=os.getenv('NEO4J_URI', 'bolt://localhost:7687'),
        help='Neo4j URI'
    )
    parser.add_argument(
        '--neo4j-user',
        default=os.getenv('NEO4J_USER', 'neo4j'),
        help='Neo4j username'
    )
    parser.add_argument(
        '--neo4j-password',
        default=os.getenv('NEO4J_PASSWORD', ''),
        help='Neo4j password'
    )
    parser.add_argument(
        '--cve-file',
        type=Path,
        default=Path('data/input/cve.jsonl'),
        help='CVE JSONL file (alternative to Neo4j)'
    )
    parser.add_argument(
        '--output-dir',
        type=Path,
        default=OUTPUT_DIR,
        help='Output directory for figures'
    )
    parser.add_argument(
        '--tables-dir',
        type=Path,
        default=Path('docs/paper/tables'),
        help='Output directory for LaTeX tables'
    )
    parser.add_argument(
        '--use-jsonl',
        action='store_true',
        help='Use JSONL files instead of Neo4j'
    )
    
    args = parser.parse_args()
    
    print("📊 Generating paper figures and tables...")
    print("=" * 60)
    
    # Try JSONL first if requested or if Neo4j password not provided
    if args.use_jsonl or (not args.neo4j_password and args.cve_file.exists()):
        print("\n📁 Using JSONL files (Neo4j not required)")
        if generate_from_jsonl(args.cve_file, args.output_dir, args.tables_dir):
            return 0
        else:
            print("\n⚠️  JSONL generation failed, trying Neo4j...")
    
    # Try Neo4j
    if not args.neo4j_password:
        print("\n❌ Error: NEO4J_PASSWORD required or use --use-jsonl flag")
        print("   Using JSONL files instead...")
        if args.cve_file.exists():
            return 0 if generate_from_jsonl(args.cve_file, args.output_dir, args.tables_dir) else 1
        return 1
    
    print("\n🔌 Connecting to Neo4j...")
    try:
        with Neo4jConnection(
            uri=args.neo4j_uri,
            user=args.neo4j_user,
            password=args.neo4j_password
        ) as conn:
            driver = conn.driver
            
            # Generate figures
            print("\n📈 Generating figures...")
            generate_severity_distribution(
                driver, 
                args.output_dir / 'severity_distribution.png'
            )
            generate_top_cwes_chart(
                driver,
                args.output_dir / 'top_cwes.png',
                top_n=15
            )
            generate_cve_timeline(
                driver,
                args.output_dir / 'cve_timeline.png'
            )
            
            # Generate tables
            print("\n📋 Generating LaTeX tables...")
            args.tables_dir.mkdir(parents=True, exist_ok=True)
            
            generate_data_source_table(
                driver,
                args.tables_dir / 'data_sources.tex'
            )
            generate_neo4j_nodes_table(
                driver,
                args.tables_dir / 'neo4j_nodes.tex'
            )
            generate_neo4j_relationships_table(
                driver,
                args.tables_dir / 'neo4j_relationships.tex'
            )
            
            print("\n✅ All figures and tables generated!")
            print(f"\n📁 Figures: {args.output_dir}")
            print(f"📁 Tables: {args.tables_dir}")
            
    except Exception as e:
        print(f"\n⚠️  Neo4j connection failed: {e}")
        print("   Falling back to JSONL files...")
        if args.cve_file.exists():
            if generate_from_jsonl(args.cve_file, args.output_dir, args.tables_dir):
                return 0
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == '__main__':
    sys.exit(main())

