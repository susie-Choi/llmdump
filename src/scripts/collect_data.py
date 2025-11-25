#!/usr/bin/env python3
"""
Unified data collection script for LLMDump.

Collects data from multiple sources:
- CVE data from NVD
- EPSS scores
- KEV catalog
- GitHub commits
- Exploits
- GitHub advisories
"""

import argparse
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from llmdump.spokes.cve import CVECollector
from llmdump.spokes.epss import EPSSCollector
from llmdump.spokes.kev import KEVCollector
from llmdump.spokes.github import GitHubSignalsCollector
from llmdump.spokes.exploit_db import ExploitDBCollector
from llmdump.spokes.github_advisory import GitHubAdvisoryCollector


def collect_cve(args):
    """Collect CVE data from NVD."""
    print("📥 Collecting CVE data from NVD...")
    collector = CVECollector()
    
    if args.start_date and args.end_date:
        stats = collector.collect(
            start_date=args.start_date,
            end_date=args.end_date
        )
    else:
        # Collect recent CVEs (last 30 days)
        from datetime import datetime, timedelta
        end_date = datetime.now()
        start_date = end_date - timedelta(days=30)
        stats = collector.collect(
            start_date=start_date.strftime("%Y-%m-%d"),
            end_date=end_date.strftime("%Y-%m-%d")
        )
    
    print(f"✅ Collected {stats.get('total_cves', 0)} CVEs")
    return stats


def collect_epss(args):
    """Collect EPSS scores."""
    print("📥 Collecting EPSS scores...")
    collector = EPSSCollector()
    
    if args.cve_ids:
        stats = collector.collect(cve_ids=args.cve_ids)
    else:
        # Collect all EPSS scores
        stats = collector.collect()
    
    print(f"✅ Collected EPSS scores")
    return stats


def collect_kev(args):
    """Collect KEV catalog."""
    print("📥 Collecting KEV catalog...")
    collector = KEVCollector()
    stats = collector.collect()
    
    print(f"✅ Collected KEV catalog")
    return stats


def collect_commits(args):
    """Collect GitHub commits."""
    print("📥 Collecting GitHub commits...")
    
    if not args.repository:
        print("❌ Error: --repository required for commit collection")
        return None
    
    collector = GitHubSignalsCollector()
    stats = collector.collect(
        repository=args.repository,
        days_back=args.days_back or 30
    )
    
    print(f"✅ Collected {stats.get('total_commits', 0)} commits")
    return stats


def collect_exploits(args):
    """Collect exploit data."""
    print("📥 Collecting exploit data...")
    collector = ExploitDBCollector()
    stats = collector.collect()
    
    print(f"✅ Collected exploit data")
    return stats


def collect_advisory(args):
    """Collect GitHub advisories."""
    print("📥 Collecting GitHub advisories...")
    collector = GitHubAdvisoryCollector()
    stats = collector.collect()
    
    print(f"✅ Collected GitHub advisories")
    return stats


def collect_all(args):
    """Collect all data sources."""
    print("=" * 80)
    print("LLMDump Data Collection - Collecting All Sources")
    print("=" * 80)
    print()
    
    results = {}
    
    # Collect each source
    results['cve'] = collect_cve(args)
    print()
    
    results['epss'] = collect_epss(args)
    print()
    
    results['kev'] = collect_kev(args)
    print()
    
    results['exploits'] = collect_exploits(args)
    print()
    
    results['advisory'] = collect_advisory(args)
    print()
    
    # Summary
    print("=" * 80)
    print("Collection Summary")
    print("=" * 80)
    for source, stats in results.items():
        if stats:
            print(f"✅ {source.upper()}: Success")
        else:
            print(f"❌ {source.upper()}: Failed")
    
    return results


def main():
    parser = argparse.ArgumentParser(
        description="Unified data collection for LLMDump",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Collect all data sources
  python src/scripts/collect_data.py --all
  
  # Collect specific source
  python src/scripts/collect_data.py --cve
  python src/scripts/collect_data.py --epss
  python src/scripts/collect_data.py --kev
  
  # Collect CVE data for date range
  python src/scripts/collect_data.py --cve --start-date 2024-01-01 --end-date 2024-12-31
  
  # Collect GitHub commits
  python src/scripts/collect_data.py --commits --repository django/django --days-back 30
        """
    )
    
    # Data source selection
    parser.add_argument('--all', action='store_true', help='Collect all data sources')
    parser.add_argument('--cve', action='store_true', help='Collect CVE data')
    parser.add_argument('--epss', action='store_true', help='Collect EPSS scores')
    parser.add_argument('--kev', action='store_true', help='Collect KEV catalog')
    parser.add_argument('--commits', action='store_true', help='Collect GitHub commits')
    parser.add_argument('--exploits', action='store_true', help='Collect exploit data')
    parser.add_argument('--advisory', action='store_true', help='Collect GitHub advisories')
    
    # Options
    parser.add_argument('--start-date', help='Start date for CVE collection (YYYY-MM-DD)')
    parser.add_argument('--end-date', help='End date for CVE collection (YYYY-MM-DD)')
    parser.add_argument('--repository', help='GitHub repository (owner/repo) for commit collection')
    parser.add_argument('--days-back', type=int, help='Number of days to look back for commits')
    parser.add_argument('--cve-ids', nargs='+', help='Specific CVE IDs for EPSS collection')
    
    args = parser.parse_args()
    
    # Check if any source is selected
    if not any([args.all, args.cve, args.epss, args.kev, args.commits, args.exploits, args.advisory]):
        parser.print_help()
        sys.exit(1)
    
    # Collect data
    try:
        if args.all:
            collect_all(args)
        else:
            if args.cve:
                collect_cve(args)
            if args.epss:
                collect_epss(args)
            if args.kev:
                collect_kev(args)
            if args.commits:
                collect_commits(args)
            if args.exploits:
                collect_exploits(args)
            if args.advisory:
                collect_advisory(args)
        
        print("\n✅ Data collection completed successfully!")
        
    except Exception as e:
        print(f"\n❌ Error during data collection: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
