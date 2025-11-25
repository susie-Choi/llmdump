"""Test integrated oracle - comprehensive risk assessment."""
import os
import sys
from dotenv import load_dotenv

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from llmdump.oracle.integrated_oracle import IntegratedOracle

load_dotenv()


def test_integrated_assessment(repository: str = None):
    """Test comprehensive integrated risk assessment."""
    
    print("=" * 80)
    print("LLMDump INTEGRATED ORACLE TEST")
    print("=" * 80)
    
    # Select repository
    if not repository:
        test_repos = [
            "pallets/flask",
            "django/django",
            "fastapi/fastapi",
            "psf/requests"
        ]
        
        print("\nAvailable repositories:")
        for i, repo in enumerate(test_repos, 1):
            print(f"  {i}. {repo}")
        
        choice = input("\nSelect (1-4) or enter custom: ").strip()
        
        if choice.isdigit() and 1 <= int(choice) <= len(test_repos):
            repository = test_repos[int(choice) - 1]
        elif '/' in choice:
            repository = choice
        else:
            repository = test_repos[0]
    
    print(f"\n🎯 Analyzing: {repository}")
    print("=" * 80)
    
    # Initialize integrated oracle
    oracle = IntegratedOracle(
        github_token=os.getenv("GITHUB_TOKEN"),
        gemini_api_key=os.getenv("GEMINI_API_KEY"),
        neo4j_uri=os.getenv("NEO4J_URI"),
        neo4j_password=os.getenv("NEO4J_PASSWORD"),
        use_rag=True
    )
    
    # Perform comprehensive assessment
    print("\n🔍 Starting comprehensive risk assessment...")
    print("   This will analyze commits, project signals, and supply chain...\n")
    
    assessment = oracle.assess_risk(
        repository=repository,
        days_back=7,
        max_commits_to_analyze=5,
        analyze_supply_chain=True
    )
    
    # Display results
    print("\n" + "=" * 80)
    print("INTEGRATED RISK ASSESSMENT RESULTS")
    print("=" * 80)
    
    print(f"\n📊 Overall Assessment:")
    print(f"   Repository: {assessment.repository}")
    print(f"   Risk Score: {assessment.overall_risk_score:.2f}")
    print(f"   Risk Level: {assessment.overall_risk_level}")
    print(f"   Confidence: {assessment.confidence:.2f}")
    print(f"   Alert Priority: {assessment.alert_priority}")
    
    print(f"\n📈 Component Scores:")
    print(f"   Commit Risk:       {assessment.commit_risk_score:.2f}")
    print(f"   Project Risk:      {assessment.project_risk_score:.2f}")
    print(f"   Supply Chain Risk: {assessment.supply_chain_risk_score:.2f}")
    
    print(f"\n⚠️  Risk Factors ({len(assessment.risk_factors)}):")
    for i, factor in enumerate(assessment.risk_factors[:5], 1):
        print(f"   {i}. {factor}")
    
    if assessment.high_risk_commits:
        print(f"\n🚨 High-Risk Commits ({len(assessment.high_risk_commits)}):")
        for commit in assessment.high_risk_commits[:3]:
            print(f"   • {commit.commit_sha[:8]}: {commit.message[:60]}")
            print(f"     Risk: {commit.risk_score:.2f}, Files: {commit.files_changed}, Changes: +{commit.additions} -{commit.deletions}")
    
    if assessment.supply_chain_impact:
        impact = assessment.supply_chain_impact
        print(f"\n🔗 Supply Chain Impact:")
        print(f"   Total Dependents: {impact.total_dependents}")
        print(f"   Direct Dependents: {len(impact.direct_dependents)}")
        if impact.critical_dependents:
            print(f"   Critical Dependents: {len(impact.critical_dependents)}")
    
    print(f"\n💡 Recommendations ({len(assessment.recommendations)}):")
    for i, rec in enumerate(assessment.recommendations[:5], 1):
        print(f"   {i}. {rec}")
    
    print(f"\n📝 Reasoning:")
    print(f"   {assessment.reasoning[:300]}...")
    
    # Decision
    print("\n" + "=" * 80)
    print("DECISION")
    print("=" * 80)
    
    if assessment.overall_risk_score >= 0.7:
        print("\n🚨 CRITICAL ALERT")
        print("   Immediate action required!")
        print("   • Block merges until security review")
        print("   • Notify security team")
        print("   • Conduct thorough code audit")
    elif assessment.overall_risk_score >= 0.5:
        print("\n⚠️  HIGH PRIORITY ALERT")
        print("   Security review recommended before merge")
        print("   • Review high-risk commits")
        print("   • Run additional security scans")
        print("   • Consider delaying release")
    elif assessment.overall_risk_score >= 0.3:
        print("\n⚡ MEDIUM PRIORITY")
        print("   Monitor closely")
        print("   • Standard review process")
        print("   • Keep security team informed")
    else:
        print("\n✓ LOW RISK")
        print("   Routine monitoring sufficient")
        print("   • Continue normal development")
    
    print("\n" + "=" * 80)
    print("✅ Integrated assessment completed!")
    print("=" * 80)
    
    oracle.close()
    
    return assessment


if __name__ == "__main__":
    import sys
    
    repo = sys.argv[1] if len(sys.argv) > 1 else None
    test_integrated_assessment(repo)
