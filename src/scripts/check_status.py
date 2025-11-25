#!/usr/bin/env python3
"""
System status checker for LLMDump.

Checks:
- Data files existence
- Neo4j connection
- Neo4j data statistics
- Environment variables
"""

import argparse
import sys
from pathlib import Path
import os

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))


def check_data_files():
    """Check if data files exist."""
    print("=" * 80)
    print("Data Files Status")
    print("=" * 80)
    
    data_files = {
        'CVE': 'data/input/cve.jsonl',
        'EPSS': 'data/input/epss.jsonl',
        'KEV': 'data/input/kev.jsonl',
        'Commits': 'data/input/commits.jsonl',
        'Exploits': 'data/input/exploits.jsonl',
        'Advisory': 'data/input/advisory.jsonl',
    }
    
    all_exist = True
    for name, path in data_files.items():
        file_path = Path(path)
        if file_path.exists():
            size = file_path.stat().st_size
            size_mb = size / (1024 * 1024)
            print(f"✅ {name:12} {path:40} ({size_mb:.2f} MB)")
        else:
            print(f"❌ {name:12} {path:40} (NOT FOUND)")
            all_exist = False
    
    print()
    return all_exist


def check_environment():
    """Check environment variables."""
    print("=" * 80)
    print("Environment Variables")
    print("=" * 80)
    
    env_vars = {
        'GITHUB_TOKEN': 'GitHub API access',
        'GEMINI_API_KEY': 'Gemini LLM access',
        'NEO4J_URI': 'Neo4j connection',
        'NEO4J_USER': 'Neo4j authentication',
        'NEO4J_PASSWORD': 'Neo4j authentication',
    }
    
    all_set = True
    for var, description in env_vars.items():
        value = os.getenv(var)
        if value:
            # Mask sensitive values
            if 'TOKEN' in var or 'KEY' in var or 'PASSWORD' in var:
                masked = value[:8] + '...' if len(value) > 8 else '***'
                print(f"✅ {var:20} {masked:30} ({description})")
            else:
                print(f"✅ {var:20} {value:30} ({description})")
        else:
            print(f"❌ {var:20} {'NOT SET':30} ({description})")
            all_set = False
    
    print()
    return all_set


def check_neo4j():
    """Check Neo4j connection and data."""
    print("=" * 80)
    print("Neo4j Status")
    print("=" * 80)
    
    try:
        from llmdump.hub.connection import Neo4jConnection
        
        with Neo4jConnection() as conn:
            print("✅ Neo4j connection successful")
            print()
            
            # Get node counts
            print("Node Counts:")
            node_types = ['CVE', 'Commit', 'KEV', 'CWE', 'CPE', 'Product', 'Package', 'Exploit', 'Advisory']
            
            for node_type in node_types:
                query = f"MATCH (n:{node_type}) RETURN count(n) as count"
                result = conn.query(query)
                count = result[0]['count'] if result else 0
                print(f"  {node_type:15} {count:>10,}")
            
            print()
            
            # Get relationship counts
            print("Relationship Counts:")
            rel_types = ['HAS_COMMIT', 'AFFECTS', 'HAS_KEV', 'HAS_EXPLOIT', 'HAS_CWE']
            
            for rel_type in rel_types:
                query = f"MATCH ()-[r:{rel_type}]->() RETURN count(r) as count"
                result = conn.query(query)
                count = result[0]['count'] if result else 0
                print(f"  {rel_type:15} {count:>10,}")
            
            print()
            return True
            
    except Exception as e:
        print(f"❌ Neo4j connection failed: {e}")
        print()
        return False


def check_system():
    """Check overall system status."""
    print("\n")
    print("=" * 80)
    print("LLMDump System Status Check")
    print("=" * 80)
    print()
    
    # Check data files
    data_ok = check_data_files()
    
    # Check environment
    env_ok = check_environment()
    
    # Check Neo4j
    neo4j_ok = check_neo4j()
    
    # Summary
    print("=" * 80)
    print("Summary")
    print("=" * 80)
    print(f"Data Files:    {'✅ OK' if data_ok else '❌ MISSING'}")
    print(f"Environment:   {'✅ OK' if env_ok else '❌ INCOMPLETE'}")
    print(f"Neo4j:         {'✅ OK' if neo4j_ok else '❌ FAILED'}")
    print()
    
    if data_ok and env_ok and neo4j_ok:
        print("✅ System is ready!")
        return 0
    else:
        print("❌ System has issues. Please fix the problems above.")
        return 1


def main():
    parser = argparse.ArgumentParser(
        description="Check LLMDump system status",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check full system status
  python src/scripts/check_status.py
  
  # Check only data files
  python src/scripts/check_status.py --data-only
  
  # Check only Neo4j
  python src/scripts/check_status.py --neo4j-only
        """
    )
    
    parser.add_argument('--data-only', action='store_true', help='Check only data files')
    parser.add_argument('--env-only', action='store_true', help='Check only environment variables')
    parser.add_argument('--neo4j-only', action='store_true', help='Check only Neo4j')
    
    args = parser.parse_args()
    
    try:
        if args.data_only:
            check_data_files()
        elif args.env_only:
            check_environment()
        elif args.neo4j_only:
            check_neo4j()
        else:
            exit_code = check_system()
            sys.exit(exit_code)
    
    except Exception as e:
        print(f"\n❌ Error during status check: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
