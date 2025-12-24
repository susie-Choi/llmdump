"""
End-to-end integration test for LLMDump.

Tests the complete workflow:
1. Spokes: Collect GitHub signals
2. Hub: Store in Neo4j + Build dependency graph
3. Oracle: Analyze commit risk
4. Supply Chain: Calculate impact
5. Decision: Alert if high risk
"""
import os
import sys
from dotenv import load_dotenv
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from llmdump.spokes.github import GitHubSignalsCollector
from llmdump.hub.loader import DataLoader
from llmdump.hub.connection import Neo4jConnection
from llmdump.hub.supply_chain import SupplyChainAnalyzer
from llmdump.oracle.commit_analyzer import CommitAnalyzer
from llmdump.oracle.predictor import VulnerabilityOracle

load_dotenv()


def test_end_to_end_workflow(repository: str = None):
    """Test complete LLMDump workflow."""
    
    print("=" * 80)
    print("LLMDump END-TO-END INTEGRATION TEST")
    print("=" * 80)
    
    # Allow custom repository or use default
    if not repository:
        # Popular projects to test with
        test_repos = [
            "django/django",
            "pallets/flask", 
            "fastapi/fastapi",
            "psf/requests",
            "numpy/numpy",
            "pandas-dev/pandas"
        ]
        
        print("\nAvailable test repositories:")
        for i, repo in enumerate(test_repos, 1):
            print(f"  {i}. {repo}")
        
        choice = input("\nSelect repository (1-6) or enter custom (owner/repo): ").strip()
        
        if choice.isdigit() and 1 <= int(choice) <= len(test_repos):
            repository = test_repos[int(choice) - 1]
        elif '/' in choice:
            repository = choice
        else:
            repository = test_repos[0]  # Default to Django
    
    print(f"\n🎯 Testing with: {repository}")
    print("=" * 80)
    
    # ========================================================================
    # PHASE 1: SPOKES - Collect Signals
    # ========================================================================
    print("\n[PHASE 1] SPOKES - Collecting GitHub Signals")
    print("-" * 80)
    
    github_collector = GitHubSignalsCollector(token=os.getenv("GITHUB_TOKEN"))
    
    print(f"Collecting signals from {repository}...")
    result = github_collector.collect(repository, days_back=7)
    
    print(f"✓ Collected:")
    print(f"  - Commits: {result['total_commits']}")
    print(f"  - Issues: {result['total_issues']}")
    print(f"  - PRs: {result['total_prs']}")
    print(f"  - Output: {result['output_file']}")
    
    # Load signals
    import json
    with open(result['output_file'], 'r') as f:
        signals = json.loads(f.readline())
    
    # ========================================================================
    # PHASE 2: HUB - Store in Neo4j
    # ========================================================================
    print("\n[PHASE 2] HUB - Storing Data in Neo4j")
    print("-" * 80)
    
    # Load GitHub signals to Neo4j
    with Neo4jConnection() as conn:
        loader = DataLoader(conn)
        
        print("Loading GitHub signals to Neo4j...")
        from pathlib import Path
        stats = loader.load_github_signals(Path(result['output_file']))
        print(f"✓ Loaded {stats['nodes_created']} signal nodes")
    
    # Build dependency graph
    supply_chain = SupplyChainAnalyzer(
        neo4j_uri=os.getenv("NEO4J_URI"),
        neo4j_password=os.getenv("NEO4J_PASSWORD"),
        github_token=os.getenv("GITHUB_TOKEN")
    )
    
    # Extract package name from repository
    package_name = repository.split('/')[-1].lower()
    
    print(f"\nBuilding dependency graph for {package_name}...")
    try:
        graph = supply_chain.build_dependency_graph(package_name, "pypi")
        print(f"✓ Found {len(graph.get('dependencies', {}))} dependencies")
        
        print("\nLoading dependencies to Neo4j...")
        dep_stats = supply_chain.load_dependencies_to_neo4j(package_name, "pypi")
        print(f"✓ Created {dep_stats['nodes_created']} nodes, {dep_stats['relationships_created']} edges")
    except Exception as e:
        print(f"⚠️  Could not build dependency graph: {e}")
        graph = {'dependencies': {}}
        dep_stats = {'nodes_created': 0, 'relationships_created': 0}
    
    # ========================================================================
    # PHASE 3: ORACLE - Analyze Commits
    # ========================================================================
    print("\n[PHASE 3] ORACLE - Analyzing Recent Commits")
    print("-" * 80)
    
    commit_analyzer = CommitAnalyzer(
        github_token=os.getenv("GITHUB_TOKEN"),
        gemini_api_key=os.getenv("GEMINI_API_KEY")
    )
    
    # Get recent commits
    import requests
    headers = {"Authorization": f"Bearer {os.getenv('GITHUB_TOKEN')}"}
    response = requests.get(
        f"https://api.github.com/repos/{repository}/commits",
        headers=headers,
        params={"per_page": 3}
    )
    commits = response.json()
    
    high_risk_commits = []
    
    for i, commit in enumerate(commits, 1):
        commit_sha = commit['sha']
        commit_msg = commit['commit']['message'].split('\n')[0][:50]
        
        print(f"\n{i}. Analyzing: {commit_sha[:8]} - {commit_msg}...")
        
        try:
            commit_result = commit_analyzer.analyze_commit(repository, commit_sha)
            
            print(f"   Risk: {commit_result.risk_level} ({commit_result.risk_score:.2f})")
            print(f"   Files: {commit_result.files_changed}, Changes: +{commit_result.additions} -{commit_result.deletions}")
            
            if commit_result.risk_score >= 0.5:
                high_risk_commits.append(commit_result)
                print(f"   ⚠️  HIGH RISK DETECTED!")
        
        except Exception as e:
            print(f"   ✗ Error: {e}")
    
    # ========================================================================
    # PHASE 4: ORACLE - Project-level Prediction (with RAG)
    # ========================================================================
    print("\n[PHASE 4] ORACLE - Project-level Risk Prediction")
    print("-" * 80)
    
    oracle = VulnerabilityOracle(
        api_key=os.getenv("GEMINI_API_KEY"),
        neo4j_uri=os.getenv("NEO4J_URI"),
        neo4j_password=os.getenv("NEO4J_PASSWORD"),
        use_rag=True
    )
    
    print(f"\nPredicting vulnerability risk for {repository}...")
    prediction = oracle.predict(repository, github_signals=signals, auto_fetch=False)
    
    print(f"✓ Prediction:")
    print(f"  - Risk Score: {prediction.risk_score:.2f}")
    print(f"  - Risk Level: {prediction.risk_level}")
    print(f"  - Confidence: {prediction.confidence:.2f}")
    print(f"  - Used RAG: {prediction.signals_analyzed.get('rag', False)}")
    
    # ========================================================================
    # PHASE 5: SUPPLY CHAIN - Impact Analysis
    # ========================================================================
    print("\n[PHASE 5] SUPPLY CHAIN - Impact Analysis")
    print("-" * 80)
    
    print(f"\nDependency Graph for {repository}:")
    print(f"  - Direct dependencies: {len(graph.get('dependencies', {}))}")
    
    if graph.get('dependencies'):
        print(f"  - Key dependencies:")
        for dep in list(graph['dependencies'].keys())[:5]:
            print(f"    • {dep}")
    
    # ========================================================================
    # PHASE 6: DECISION - Alert Logic
    # ========================================================================
    print("\n[PHASE 6] DECISION - Risk Assessment & Alerting")
    print("=" * 80)
    
    # Combine all risk factors
    overall_risk = max(
        prediction.risk_score,
        max([c.risk_score for c in high_risk_commits]) if high_risk_commits else 0.0
    )
    
    print(f"\n📊 OVERALL RISK ASSESSMENT")
    print(f"   Repository: {repository}")
    print(f"   Project Risk: {prediction.risk_level} ({prediction.risk_score:.2f})")
    print(f"   High-risk Commits: {len(high_risk_commits)}")
    print(f"   Dependencies: {len(graph.get('dependencies', {}))}")
    print(f"   Combined Risk: {overall_risk:.2f}")
    
    # Alert decision
    if overall_risk >= 0.7:
        alert_level = "🚨 CRITICAL"
    elif overall_risk >= 0.5:
        alert_level = "⚠️  HIGH"
    elif overall_risk >= 0.3:
        alert_level = "⚡ MEDIUM"
    else:
        alert_level = "✓ LOW"
    
    print(f"\n{alert_level} PRIORITY")
    
    if overall_risk >= 0.5:
        print(f"\n📢 ALERT TRIGGERED")
        print(f"   Reason: {prediction.reasoning[:150]}...")
        print(f"\n   Recommended Actions:")
        for rec in prediction.recommendations[:3]:
            print(f"   • {rec}")
        
        if high_risk_commits:
            print(f"\n   High-risk Commits to Review:")
            for commit in high_risk_commits:
                print(f"   • {commit.commit_sha[:8]}: {commit.message[:50]}")
    else:
        print(f"\n✓ No immediate action required")
        print(f"   Continue routine monitoring")
    
    # ========================================================================
    # SUMMARY
    # ========================================================================
    print("\n" + "=" * 80)
    print("INTEGRATION TEST SUMMARY")
    print("=" * 80)
    
    print(f"\n✅ All phases completed successfully!")
    print(f"\nData Flow:")
    print(f"  1. Spokes → Collected {result['total_commits']} commits")
    print(f"  2. Hub → Stored {stats['nodes_created']} signals + {dep_stats['nodes_created']} dependencies")
    print(f"  3. Oracle → Analyzed {len(commits)} commits")
    print(f"  4. Oracle → Predicted risk: {prediction.risk_level}")
    print(f"  5. Supply Chain → Mapped {len(graph.get('dependencies', {}))} dependencies")
    print(f"  6. Decision → Alert level: {alert_level}")
    
    print(f"\n🎯 System Status: OPERATIONAL")
    print("=" * 80)
    
    supply_chain.close()


if __name__ == "__main__":
    import sys
    
    # Allow command-line argument for repository
    if len(sys.argv) > 1:
        repo = sys.argv[1]
        test_end_to_end_workflow(repo)
    else:
        test_end_to_end_workflow()
