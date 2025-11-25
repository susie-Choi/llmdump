#!/usr/bin/env python3
"""
Unified Neo4j data loading script for LLMDump.

Loads collected data into Neo4j graph database:
- CVE data
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

from llmdump.hub.connection import Neo4jConnection
from llmdump.hub.loader import DataLoader


def load_cve(loader, args):
    """Load CVE data to Neo4j."""
    print("📥 Loading CVE data to Neo4j...")
    
    data_file = Path("data/input/cve.jsonl")
    if not data_file.exists():
        print(f"❌ Error: {data_file} not found")
        return None
    
    stats = loader.load_cve_data(data_file)
    print(f"✅ Loaded {stats.get('loaded', 0)} CVEs")
    return stats


def load_epss(loader, args):
    """Load EPSS scores to Neo4j."""
    print("📥 Loading EPSS scores to Neo4j...")
    
    data_file = Path("data/input/epss.jsonl")
    if not data_file.exists():
        print(f"❌ Error: {data_file} not found")
        return None
    
    stats = loader.load_epss_data(data_file)
    print(f"✅ Loaded EPSS scores")
    return stats


def load_kev(loader, args):
    """Load KEV catalog to Neo4j."""
    print("📥 Loading KEV catalog to Neo4j...")
    
    data_file = Path("data/input/kev.jsonl")
    if not data_file.exists():
        print(f"❌ Error: {data_file} not found")
        return None
    
    stats = loader.load_kev_data(data_file)
    print(f"✅ Loaded KEV catalog")
    return stats


def load_commits(loader, args):
    """Load GitHub commits to Neo4j."""
    print("📥 Loading GitHub commits to Neo4j...")
    
    data_file = Path("data/input/commits.jsonl")
    if not data_file.exists():
        print(f"❌ Error: {data_file} not found")
        return None
    
    stats = loader.load_commit_data(data_file)
    print(f"✅ Loaded {stats.get('loaded', 0)} commits")
    return stats


def load_exploits(loader, args):
    """Load exploit data to Neo4j."""
    print("📥 Loading exploit data to Neo4j...")
    
    data_file = Path("data/input/exploits.jsonl")
    if not data_file.exists():
        print(f"❌ Error: {data_file} not found")
        return None
    
    stats = loader.load_exploit_data(data_file)
    print(f"✅ Loaded exploit data")
    return stats


def load_advisory(loader, args):
    """Load GitHub advisories to Neo4j."""
    print("📥 Loading GitHub advisories to Neo4j...")
    
    data_file = Path("data/input/advisory.jsonl")
    if not data_file.exists():
        print(f"❌ Error: {data_file} not found")
        return None
    
    stats = loader.load_advisory_data(data_file)
    print(f"✅ Loaded GitHub advisories")
    return stats


def load_all(loader, args):
    """Load all data sources to Neo4j."""
    print("=" * 80)
    print("LLMDump Neo4j Loading - Loading All Sources")
    print("=" * 80)
    print()
    
    results = {}
    
    # Load each source
    results['cve'] = load_cve(loader, args)
    print()
    
    results['epss'] = load_epss(loader, args)
    print()
    
    results['kev'] = load_kev(loader, args)
    print()
    
    results['commits'] = load_commits(loader, args)
    print()
    
    results['exploits'] = load_exploits(loader, args)
    print()
    
    results['advisory'] = load_advisory(loader, args)
    print()
    
    # Summary
    print("=" * 80)
    print("Loading Summary")
    print("=" * 80)
    for source, stats in results.items():
        if stats:
            print(f"✅ {source.upper()}: Success")
        else:
            print(f"❌ {source.upper()}: Failed or no data")
    
    return results


def main():
    parser = argparse.ArgumentParser(
        description="Unified Neo4j data loading for LLMDump",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Load all data sources
  python src/scripts/load_to_neo4j.py --all
  
  # Load specific source
  python src/scripts/load_to_neo4j.py --cve
  python src/scripts/load_to_neo4j.py --epss
  python src/scripts/load_to_neo4j.py --commits
  
  # Load with custom Neo4j connection
  python src/scripts/load_to_neo4j.py --all --uri bolt://localhost:7687 --password mypassword
        """
    )
    
    # Data source selection
    parser.add_argument('--all', action='store_true', help='Load all data sources')
    parser.add_argument('--cve', action='store_true', help='Load CVE data')
    parser.add_argument('--epss', action='store_true', help='Load EPSS scores')
    parser.add_argument('--kev', action='store_true', help='Load KEV catalog')
    parser.add_argument('--commits', action='store_true', help='Load GitHub commits')
    parser.add_argument('--exploits', action='store_true', help='Load exploit data')
    parser.add_argument('--advisory', action='store_true', help='Load GitHub advisories')
    
    # Neo4j connection options
    parser.add_argument('--uri', help='Neo4j URI (default: from .env)')
    parser.add_argument('--user', help='Neo4j user (default: from .env)')
    parser.add_argument('--password', help='Neo4j password (default: from .env)')
    
    args = parser.parse_args()
    
    # Check if any source is selected
    if not any([args.all, args.cve, args.epss, args.kev, args.commits, args.exploits, args.advisory]):
        parser.print_help()
        sys.exit(1)
    
    # Connect to Neo4j
    try:
        print("🔌 Connecting to Neo4j...")
        
        connection_args = {}
        if args.uri:
            connection_args['uri'] = args.uri
        if args.user:
            connection_args['user'] = args.user
        if args.password:
            connection_args['password'] = args.password
        
        with Neo4jConnection(**connection_args) as conn:
            print("✅ Connected to Neo4j")
            print()
            
            loader = DataLoader(conn)
            
            # Load data
            if args.all:
                load_all(loader, args)
            else:
                if args.cve:
                    load_cve(loader, args)
                if args.epss:
                    load_epss(loader, args)
                if args.kev:
                    load_kev(loader, args)
                if args.commits:
                    load_commits(loader, args)
                if args.exploits:
                    load_exploits(loader, args)
                if args.advisory:
                    load_advisory(loader, args)
            
            print("\n✅ Data loading completed successfully!")
    
    except Exception as e:
        print(f"\n❌ Error during data loading: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
