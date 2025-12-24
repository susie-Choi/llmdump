---
inclusion: always
---

# Product Overview

**LLMDump** is an LLM-powered zero-day vulnerability prediction system that analyzes software development signals to predict future CVEs before they are disclosed.

## Core Innovation

Traditional vulnerability detection is **reactive** - we find vulnerabilities after disclosure. LLMDump is **proactive** - it predicts vulnerabilities before disclosure by analyzing development patterns with LLM-based reasoning.

## How It Works

```
1. Collect Development Signals
   ↓ (GitHub commits, PRs, issues, releases)
   
2. LLM Analysis (Oracle)
   ↓ (Gemini analyzes patterns with RAG)
   
3. Risk Prediction
   ↓ (Risk score, level, reasoning)
   
4. Validation
   ↓ (Compare with actual CVE disclosures)
```

## Current Status

**Version**: 0.2.0 (Alpha)

**Baseline Data**: ✅ Complete
- 11,441 CVEs from NVD
- 35,080 vulnerability-fixing commits
- 969 CWE classifications
- 1,666 KEV (Known Exploited Vulnerabilities)
- EPSS scores for all CVEs

**Prediction System**: 🔄 In Progress
- LLM-based Oracle with Gemini
- RAG integration with Neo4j
- GitHub signal collection
- Risk scoring and reasoning

**Evaluation Framework**: 📋 Planned
- Temporal validation
- Baseline comparisons
- Statistical analysis

## Architecture

**Spokes** (Data Collection)
- CVE/NVD collector - Historical vulnerability data
- GitHub signals collector - Development activity patterns
- EPSS collector - Exploit probability scores
- KEV collector - Confirmed exploited vulnerabilities
- Exploit-DB collector - Public exploits

**Hub** (Data Integration)
- Neo4j knowledge graph - Stores all data with relationships
- Historical CVE patterns - Training data for clustering
- Temporal data management - Prevents data leakage
- RAG context retrieval - Provides relevant history to LLM

**Oracle** (LLM-Based Prediction)
- Signal analysis - Analyzes commits, PRs, issues with LLM
- Pattern recognition - Identifies vulnerability indicators
- Risk scoring - Calculates probability of future CVE
- Explainable reasoning - Provides human-readable explanations
- RAG enhancement - Uses historical patterns for context

**Axle** (Evaluation)
- Temporal validation - Tests predictions on historical data
- Baseline comparison - Compares with CVSS/EPSS/Random
- Metrics calculation - Precision, recall, F1, lead time
- Statistical testing - Significance and confidence intervals

## Key Features

### 1. True Prediction (Not Post-Mortem)
- Predicts FUTURE CVEs from CURRENT signals
- Uses only data available before CVE disclosure
- Temporal validation ensures no data leakage

### 2. LLM-Powered Analysis
- Gemini analyzes natural language (commit messages, discussions)
- Identifies subtle patterns humans might miss
- Provides explainable reasoning for every prediction
- Adapts to new vulnerability types

### 3. RAG-Enhanced Context
- Retrieves similar historical CVEs from Neo4j
- Provides relevant patterns to LLM
- Improves prediction accuracy with historical context
- Enables learning from past vulnerabilities

### 4. Explainable Predictions
- Every prediction includes reasoning
- Identifies which signals triggered the alert
- Provides actionable recommendations
- Enables human review and validation

## Research Goals

**Primary Research Question:**
Can LLM-based analysis of development signals predict future CVEs before disclosure?

**Key Metrics:**
- **Precision**: % of predictions that were correct
- **Recall**: % of actual CVEs we predicted
- **Lead Time**: Days before CVE disclosure
- **Baseline Improvement**: How much better than CVSS/EPSS?

**Success Criteria:**
- Statistically significant improvement over baselines
- Average lead time > 30 days
- Precision > 30%, Recall > 30%

## Use Cases

### 1. Proactive Security Monitoring
Monitor critical dependencies and get early warnings before CVEs are disclosed.

### 2. Security Research
Validate new prediction methods and understand vulnerability patterns.

### 3. Supply Chain Risk Management
Identify high-risk packages in your dependency chain before vulnerabilities are exploited.

### 4. Vulnerability Research
Discover potential vulnerabilities through pattern analysis and LLM reasoning.

## Target Publication

**Top-tier security conferences:**
- USENIX Security
- ACM CCS
- NDSS
- IEEE S&P

**Novelty:**
- First LLM-based zero-day prediction system
- Large-scale temporal validation (11,441 CVEs)
- Explainable predictions with reasoning
- Significant improvement over traditional methods

## Technology Stack

- **Language**: Python 3.10+
- **LLM**: Google Gemini (via API)
- **Database**: Neo4j (knowledge graph)
- **Data Format**: JSONL
- **Visualization**: Matplotlib, Seaborn
- **Optional**: Streamlit dashboard

## Installation

```bash
# Basic installation
pip install llmdump

# With Neo4j support
pip install llmdump[neo4j]

# With dashboard
pip install llmdump[dashboard]
```

## Quick Start

```python
from llmdump.oracle import VulnerabilityOracle

# Initialize oracle with RAG
oracle = VulnerabilityOracle(use_rag=True)

# Predict future vulnerability risk
prediction = oracle.predict(
    package="django/django",
    days_back=30
)

print(f"Risk Score: {prediction.risk_score}")
print(f"Risk Level: {prediction.risk_level}")
print(f"Reasoning: {prediction.reasoning}")
```

## Project Status

**Phase 1**: ✅ Baseline data collection complete
**Phase 2**: 🔄 Signal collection and LLM prediction in progress
**Phase 3**: 📋 Evaluation framework planned
**Phase 4**: 📋 Paper writing planned

## Contributing

This is a research project. Contributions are welcome, especially:
- New signal collectors
- Improved LLM prompts
- Evaluation methods
- Case studies

## License

MIT License - see LICENSE for details
