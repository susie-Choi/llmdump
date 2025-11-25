# LLMDump User Guide

Complete guide for using LLMDump to predict zero-day vulnerabilities in software supply chains.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [System Overview](#system-overview)
3. [Installation](#installation)
4. [Core Workflows](#core-workflows)
5. [API Reference](#api-reference)
6. [Configuration](#configuration)
7. [Troubleshooting](#troubleshooting)
8. [Best Practices](#best-practices)

---

## Quick Start

### Get Started in 5 Minutes

#### Step 1: Environment Setup

```bash
# 1. Clone repository
git clone https://github.com/susie-Choi/llmdump.git
cd llmdump

# 2. Install dependencies
pip install -r requirements.txt

# 3. Set environment variables
cat > .env << EOF
GITHUB_TOKEN=your_github_personal_access_token
GEMINI_API_KEY=your_gemini_api_key
NEO4J_URI=bolt://localhost:7687
NEO4J_PASSWORD=your_neo4j_password
EOF
```

**API Key Setup:**
- **GitHub Token**: https://github.com/settings/tokens (requires repo permission)
- **Gemini API Key**: https://makersuite.google.com/app/apikey

#### Step 2: Start Neo4j

```bash
# Using Docker Compose
docker-compose up -d
```

#### Step 3: Load Data

```bash
# Collect all data sources
python src/scripts/collect_data.py --all

# Load to Neo4j
python src/scripts/load_to_neo4j.py --all

# Check status
python src/scripts/check_status.py
```

#### Step 4: Run Analysis

```python
from llmdump.oracle.integrated_oracle import IntegratedOracle

# Initialize oracle
oracle = IntegratedOracle(use_rag=True)

# Analyze repository
assessment = oracle.assess_risk(
    repository="pallets/flask",
    days_back=7,
    max_commits_to_analyze=10
)

# View results
print(f"Risk Level: {assessment.overall_risk_level}")
print(f"Risk Score: {assessment.overall_risk_score:.2f}")
print(f"High-Risk Commits: {len(assessment.high_risk_commits)}")
```

---

## System Overview

### What is LLMDump?

LLMDump is an LLM-powered vulnerability prediction system that analyzes open-source software supply chains to detect potential zero-day vulnerabilities **before** they are exploited.

### Core Innovation

Unlike traditional vulnerability scanners that detect **known** CVEs, LLMDump predicts **future** vulnerabilities by analyzing:
- Individual commit risk patterns
- Developer behavior anomalies
- Supply chain propagation impact
- Historical CVE patterns (via RAG)

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    INTEGRATED ORACLE                         │
│  (Comprehensive Risk Assessment & Decision Engine)           │
└────────────┬────────────────────────────────┬────────────────┘
             │                                │
    ┌────────▼────────┐              ┌───────▼────────┐
    │ COMMIT ANALYZER │              │ PROJECT ORACLE │
    │  (Individual    │              │  (Behavioral   │
    │   Commits)      │              │   Signals)     │
    └────────┬────────┘              └───────┬────────┘
             │                                │
             └────────────┬───────────────────┘
                          │
         ┌────────────────┼────────────────┐
         │                │                │
    ┌────▼────┐      ┌────▼────┐     ┌────▼────┐
    │ SPOKES  │      │   HUB   │     │ SUPPLY  │
    │ (Data)  │─────▶│ (Neo4j) │◀────│ CHAIN   │
    └─────────┘      └─────────┘     └─────────┘
```

### Components

#### 1. Spokes (Data Collection)
Collects data from multiple sources:
- GitHub (commits, PRs, issues)
- NVD (CVE data)
- EPSS (exploit prediction scores)
- CISA KEV (known exploited vulnerabilities)
- Exploit-DB (public exploits)

#### 2. Hub (Knowledge Graph)
Neo4j graph database storing:
- CVE records and relationships
- Package dependencies
- GitHub signals
- Historical patterns

#### 3. Oracle (Prediction Engine)
LLM-based analysis using Google Gemini:
- **Commit Analyzer**: Individual commit risk
- **Project Oracle**: Overall project risk
- **Integrated Oracle**: Combined assessment

#### 4. Supply Chain Analyzer
Tracks dependency relationships and impact propagation.

### Data Flow

```
1. User Request
   ↓
2. Integrated Oracle
   ↓
3. Parallel Analysis:
   ├─ Commit Analyzer (recent commits)
   ├─ Project Oracle (behavioral signals + RAG)
   └─ Supply Chain (dependency impact)
   ↓
4. Risk Score Combination
   ↓
5. Alert Decision
   ↓
6. Recommendations
```

### Data Storage

```
data/
├── input/                        # Input data (consolidated)
│   ├── cve.jsonl                 # CVE data from NVD
│   ├── commits.jsonl             # GitHub commits
│   ├── epss.jsonl                # EPSS scores
│   ├── kev.jsonl                 # KEV catalog
│   ├── exploits.jsonl            # Exploit-DB data
│   └── advisory.jsonl            # GitHub advisories
│
├── output/                       # Analysis results
│   ├── analysis/                 # Analysis outputs
│   ├── predictions/              # Prediction results
│   └── paper/                    # Paper-related data
│
├── multimodal/                   # Multimodal extension
│   ├── apt/                      # APT samples
│   └── legitimate/               # Legitimate package data
│
└── archive/                      # Archived old structure
```

---

## Installation

### Prerequisites
- Python 3.10 or higher
- Neo4j 5.x
- GitHub Personal Access Token
- Google Gemini API Key

### Step-by-Step Installation

#### 1. Clone Repository
```bash
git clone https://github.com/susie-Choi/llmdump.git
cd llmdump
```

#### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

#### 3. Configure Environment
Create a `.env` file:

```bash
# Required
GITHUB_TOKEN=ghp_your_github_token_here
GEMINI_API_KEY=your_gemini_api_key_here

# Optional (for RAG features)
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=your_neo4j_password
```

#### 4. Start Neo4j
```bash
docker-compose up -d
```

#### 5. Verify Installation
```bash
python src/scripts/check_status.py
```

---

## Core Workflows

### Workflow 1: Commit-Level Analysis

Analyze individual commits before merging.

```python
from rota.oracle.commit_analyzer import CommitAnalyzer

analyzer = CommitAnalyzer()

# Analyze specific commit
result = analyzer.analyze_commit(
    repository="pallets/flask",
    commit_sha="adf36367"
)

print(f"Risk: {result.risk_level} ({result.risk_score:.2f})")
print(f"Files Changed: {result.files_changed}")
print(f"Reasoning: {result.reasoning}")

# Check for specific risks
if result.risk_score >= 0.5:
    print("⚠️ HIGH RISK - Manual review required")
    for factor in result.risk_factors:
        print(f"  • {factor}")
```

### Workflow 2: Pull Request Analysis

Analyze all commits in a PR.

```python
from rota.oracle.commit_analyzer import CommitAnalyzer

analyzer = CommitAnalyzer()

# Analyze PR
results = analyzer.analyze_pr(
    repository="pallets/flask",
    pr_number=5812
)

# Find high-risk commits
high_risk = [r for r in results if r.risk_score >= 0.5]

if high_risk:
    print(f"⚠️ {len(high_risk)} high-risk commits in PR")
    for commit in high_risk:
        print(f"  • {commit.commit_sha[:8]}: {commit.message[:50]}")
```

### Workflow 3: Project-Level Prediction

Assess overall project vulnerability risk.

```python
from llmdump.oracle.predictor import VulnerabilityOracle
from llmdump.spokes.github import GitHubSignalsCollector

# Collect signals
collector = GitHubSignalsCollector()
result = collector.collect("django/django", days_back=30)

# Load signals
import json
with open(result['output_file'], 'r') as f:
    signals = json.loads(f.readline())

# Predict with RAG
oracle = VulnerabilityOracle(use_rag=True)
prediction = oracle.predict(
    "django/django",
    github_signals=signals
)

print(f"Risk: {prediction.risk_level}")
print(f"Confidence: {prediction.confidence:.2f}")
print(f"Reasoning: {prediction.reasoning}")
```

### Workflow 4: Supply Chain Impact Analysis

Understand downstream impact of a vulnerability.

```python
from llmdump.hub.supply_chain import SupplyChainAnalyzer

analyzer = SupplyChainAnalyzer()

# Build dependency graph
graph = analyzer.build_dependency_graph("flask", "pypi")

print(f"Dependencies: {len(graph['dependencies'])}")
print(f"Popularity: {graph['popularity']['downloads_last_month']:,} downloads/month")

# Analyze impact
impact = analyzer.analyze_impact("flask", "pypi", max_depth=2)

print(f"Total Dependents: {impact.total_dependents}")
print(f"Blast Radius: {impact.blast_radius}")

if impact.critical_dependents:
    print(f"Critical Dependents:")
    for dep in impact.critical_dependents:
        print(f"  • {dep}")
```

### Workflow 5: End-to-End Pipeline

Complete analysis from data collection to decision.

```python
from llmdump.oracle.integrated_oracle import IntegratedOracle

oracle = IntegratedOracle(use_rag=True)

# Comprehensive assessment
assessment = oracle.assess_risk(
    repository="pallets/flask",
    days_back=7,
    max_commits_to_analyze=10,
    analyze_supply_chain=True
)

# Decision logic
if assessment.overall_risk_score >= 0.7:
    print("🚨 CRITICAL - Block merge immediately")
    print("Actions:")
    print("  1. Notify security team")
    print("  2. Conduct thorough code audit")
    print("  3. Review all high-risk commits")
    
elif assessment.overall_risk_score >= 0.5:
    print("⚠️ HIGH - Security review required")
    print("Actions:")
    print("  1. Manual security review")
    print("  2. Run additional scans")
    print("  3. Consider delaying release")
    
else:
    print("✓ LOW - Routine monitoring")
```

---

## API Reference

### IntegratedOracle

Main interface for comprehensive risk assessment.

```python
class IntegratedOracle:
    def __init__(
        self,
        github_token: Optional[str] = None,
        gemini_api_key: Optional[str] = None,
        neo4j_uri: Optional[str] = None,
        neo4j_password: Optional[str] = None,
        use_rag: bool = True
    )
    
    def assess_risk(
        self,
        repository: str,
        days_back: int = 7,
        max_commits_to_analyze: int = 10,
        analyze_supply_chain: bool = True
    ) -> IntegratedRiskAssessment
```

**Returns**: `IntegratedRiskAssessment`
- `overall_risk_score`: float (0.0-1.0)
- `overall_risk_level`: str (LOW, MEDIUM, HIGH, CRITICAL)
- `confidence`: float (0.0-1.0)
- `high_risk_commits`: List[CommitRiskResult]
- `project_prediction`: PredictionResult
- `supply_chain_impact`: ImpactAnalysis
- `recommendations`: List[str]

### CommitAnalyzer

Analyzes individual commits.

```python
class CommitAnalyzer:
    def __init__(
        self,
        github_token: Optional[str] = None,
        gemini_api_key: Optional[str] = None
    )
    
    def analyze_commit(
        self,
        repository: str,
        commit_sha: str
    ) -> CommitRiskResult
    
    def analyze_pr(
        self,
        repository: str,
        pr_number: int
    ) -> List[CommitRiskResult]
```

**Returns**: `CommitRiskResult`
- `risk_score`: float (0.0-1.0)
- `risk_level`: str (LOW, MEDIUM, HIGH, CRITICAL)
- `confidence`: float (0.0-1.0)
- `risk_factors`: List[str]
- `recommendations`: List[str]

### VulnerabilityOracle

Project-level prediction.

```python
class VulnerabilityOracle:
    def __init__(
        self,
        api_key: Optional[str] = None,
        neo4j_uri: Optional[str] = None,
        neo4j_password: Optional[str] = None,
        use_rag: bool = True
    )
    
    def predict(
        self,
        package: str,
        github_signals: Optional[Dict] = None,
        days_back: int = 30,
        auto_fetch: bool = True
    ) -> PredictionResult
```

### SupplyChainAnalyzer

Dependency analysis.

```python
class SupplyChainAnalyzer:
    def __init__(
        self,
        neo4j_uri: Optional[str] = None,
        neo4j_password: Optional[str] = None,
        github_token: Optional[str] = None
    )
    
    def build_dependency_graph(
        self,
        package: str,
        ecosystem: str = "pypi"
    ) -> Dict[str, Any]
    
    def analyze_impact(
        self,
        package: str,
        ecosystem: str = "pypi",
        max_depth: int = 3
    ) -> ImpactAnalysis
```

---

## Configuration

### Risk Thresholds

Customize risk level thresholds:

```python
# Default thresholds
CRITICAL_THRESHOLD = 0.7
HIGH_THRESHOLD = 0.5
MEDIUM_THRESHOLD = 0.3

# Custom thresholds (more conservative)
if risk_score >= 0.8:
    level = "CRITICAL"
```

### Component Weights

Adjust integration formula:

```python
# Default weights
overall_risk = (
    commit_risk * 0.4 +
    project_risk * 0.4 +
    supply_chain_risk * 0.2
)

# Custom weights (emphasize commits)
overall_risk = (
    commit_risk * 0.6 +
    project_risk * 0.3 +
    supply_chain_risk * 0.1
)
```

### RAG Configuration

Control RAG context retrieval:

```python
oracle = VulnerabilityOracle(
    use_rag=True,  # Enable RAG
    neo4j_uri="bolt://localhost:7687"
)

# RAG retrieves:
# - Similar CVEs by CWE (5 most recent)
# - Package history (10 CVEs)
# - EPSS trends (3 similar CVEs)
# - Dependency risks (depth=2)
```

---

## Troubleshooting

### Issue: GitHub Rate Limiting

**Symptom**: `403 Forbidden` or `429 Too Many Requests`

**Solution**:
```python
# Use authenticated requests
collector = GitHubSignalsCollector(token=os.getenv("GITHUB_TOKEN"))

# Reduce request frequency
assessment = oracle.assess_risk(
    repository="...",
    max_commits_to_analyze=5  # Reduce from 10
)
```

### Issue: Neo4j Connection Failed

**Symptom**: `Could not connect to Neo4j`

**Solution**:
```bash
# Check Neo4j is running
docker ps | grep neo4j

# Verify credentials
echo $NEO4J_PASSWORD

# Test connection
python src/scripts/check_status.py
```

### Issue: LLM Response Parsing Error

**Symptom**: `Failed to parse LLM response`

**Solution**:
```python
# The system has fallback handling
# Check logs for raw response
import logging
logging.basicConfig(level=logging.DEBUG)

# Retry with different model
oracle = IntegratedOracle(
    gemini_api_key="...",
    # Model will default to gemini-2.5-flash
)
```

### Issue: No Supply Chain Data

**Symptom**: `Total Dependents: 0`

**Solution**:
```python
# PyPI/npm don't provide reverse dependencies
# This is expected behavior
# Use libraries.io API for reverse deps (future work)

# Check forward dependencies work
graph = analyzer.build_dependency_graph("flask", "pypi")
print(graph['dependencies'])  # Should show dependencies
```

---

## Best Practices

### 1. Regular Monitoring
```python
# Monitor critical projects daily
critical_projects = [
    "django/django",
    "pallets/flask",
    "psf/requests"
]

for project in critical_projects:
    assessment = oracle.assess_risk(project, days_back=1)
    if assessment.overall_risk_score >= 0.5:
        send_alert(project, assessment)
```

### 2. Pre-Merge Checks
```python
# Analyze PR before merge
def check_pr(repo, pr_number):
    analyzer = CommitAnalyzer()
    results = analyzer.analyze_pr(repo, pr_number)
    
    high_risk = [r for r in results if r.risk_score >= 0.5]
    
    if high_risk:
        return "BLOCK", high_risk
    return "APPROVE", []
```

### 3. Historical Tracking
```python
# Save assessments for trend analysis
import json
from datetime import datetime

assessment = oracle.assess_risk("flask")

with open(f"assessments/{datetime.now().isoformat()}.json", "w") as f:
    json.dump({
        "repository": assessment.repository,
        "risk_score": assessment.overall_risk_score,
        "risk_level": assessment.overall_risk_level,
        "timestamp": assessment.analyzed_at.isoformat()
    }, f)
```

---

## Need Help?

- **GitHub Issues**: https://github.com/susie-Choi/llmdump/issues
- **Documentation**: https://github.com/susie-Choi/llmdump/tree/main/docs
- **Development Guide**: See `docs/DEVELOPMENT.md`
- **Research Plan**: See `docs/RESEARCH.md`

---

**LLMDump v0.2.0** - LLM-powered Zero-Day Vulnerability Prediction

*Detecting vulnerabilities before CVE publication through LLM-based signal analysis*
