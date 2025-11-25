---
inclusion: always
---

# Research Guidelines

## Project Goal

**Develop an LLM-powered zero-day vulnerability prediction system** that analyzes current software development signals to predict future CVEs before they are disclosed.

## Core Concept

Traditional vulnerability detection is **reactive** - we find vulnerabilities after they're disclosed. This research aims to be **proactive** - predict vulnerabilities before disclosure by analyzing development patterns.

```
Current Development Signals
    ↓
LLM Analysis (Oracle)
    ↓
Predict Future CVE Risk
    ↓
Validate Against Actual CVEs
```

## Research Questions

**RQ1**: Can LLM-based analysis of development signals predict future CVEs?

**RQ2**: Which signals are most predictive of future vulnerabilities?
- Commit patterns
- Issue discussions
- PR activity
- Code changes
- Developer behavior

**RQ3**: How much lead time can we achieve?
- Can we predict 30 days before disclosure?
- 60 days? 90 days?

**RQ4**: How does LLM-based prediction compare to traditional methods?
- CVSS-based ranking
- EPSS scores
- Frequency-based prediction

## Methodology

### Phase 1: Baseline Data Collection ✅ Complete

**Historical vulnerability data for training and validation:**
- 11,441 CVEs from NVD (2020-2024)
- 35,080 vulnerability-fixing commits
- 969 CWE classifications
- 1,666 KEV (Known Exploited Vulnerabilities)
- EPSS scores for all CVEs

**Purpose**: 
- Train clustering models on historical patterns
- Validate predictions against known CVEs
- Establish baseline prediction methods

### Phase 2: Signal Collection 🔄 In Progress

**Collect development signals before CVE disclosure:**
- GitHub commits (messages, files, authors)
- Pull requests (titles, descriptions, reviews)
- Issues (discussions, labels, keywords)
- Releases (versions, dependencies)
- Developer activity patterns

**Temporal constraint**: Only use data from BEFORE CVE disclosure to prevent data leakage.

### Phase 3: LLM-Based Prediction 🔄 In Progress

**Use LLM (Gemini) to analyze signals:**

```python
# Oracle analyzes current signals
oracle = VulnerabilityOracle(use_rag=True)

# Predict future vulnerability risk
prediction = oracle.predict(
    package="django/django",
    github_signals=current_signals,
    days_back=30
)

# Output:
# - risk_score: 0.0-1.0
# - risk_level: LOW/MEDIUM/HIGH/CRITICAL
# - confidence: 0.0-1.0
# - reasoning: Why this package is at risk
# - recommendations: What to do
```

**LLM advantages:**
- Understands natural language (commit messages, discussions)
- Identifies subtle patterns humans might miss
- Provides explainable reasoning
- Adapts to new vulnerability types

### Phase 4: Validation & Evaluation 📋 Planned

**Temporal validation:**
1. Set cutoff date (e.g., 2024-01-01)
2. Collect signals BEFORE cutoff
3. Make predictions
4. Check if CVE was disclosed AFTER cutoff
5. Calculate metrics (precision, recall, lead time)

**Baseline comparisons:**
- Random selection
- CVSS-based ranking
- EPSS-based ranking
- Frequency-based prediction

**Success metrics:**
- Precision: % of predictions that were correct
- Recall: % of actual CVEs we predicted
- Lead time: Days before disclosure
- F1-Score: Harmonic mean of precision/recall

## Architecture

### Spokes (Data Collection)
- CVE collector
- GitHub signals collector
- EPSS collector
- KEV collector
- Exploit-DB collector

### Hub (Data Integration)
- Neo4j knowledge graph
- Historical CVE patterns
- Dependency relationships
- Temporal data management

### Oracle (LLM-Based Prediction)
- Signal analysis with Gemini
- RAG (Retrieval-Augmented Generation) using Neo4j
- Risk scoring
- Explainable predictions

### Axle (Evaluation)
- Temporal validation
- Baseline comparisons
- Metrics calculation
- Statistical significance testing

## Code Standards

### Language
- All code, comments, docstrings: **English only**
- Documentation (.md files): **English preferred**
- No emojis in code or comments (only in .md files for status)

### Temporal Integrity
- **CRITICAL**: Never use future data for past predictions
- Always use cutoff dates
- Validate temporal constraints in tests
- Document data collection timestamps

### Experimentation
- Document all experiments in `docs/paper/`
- Use version control for experiment tracking
- Save all intermediate results
- Include random seeds for reproducibility
- Always include confidence intervals

## Key Principles

### 1. True Prediction, Not Post-Mortem
- We predict FUTURE CVEs from CURRENT signals
- Not analyzing known CVEs (that's post-mortem)
- Temporal validation is essential

### 2. LLM as Analysis Tool
- LLM analyzes signals and patterns
- LLM provides reasoning and explanations
- LLM helps identify subtle risk indicators
- Not just pattern matching

### 3. Ground Truth Validation
- KEV provides ground truth (confirmed exploits)
- Historical CVEs validate predictions
- Compare against baseline methods
- Statistical significance required

### 4. Explainability
- Every prediction must have reasoning
- Identify which signals triggered the prediction
- Provide actionable recommendations
- Enable human review and override

## Multi-Computer Workflow

This project is developed across multiple computers:
- Commit and push frequently
- Document decisions in .md files
- Keep RESEARCH.md updated with latest findings
- Use branches for experimental features
- Tag important milestones

## Paper Target

**Top-tier security conferences:**
- USENIX Security
- ACM CCS
- NDSS
- IEEE S&P

**Focus**: Novel LLM-based vulnerability prediction with temporal validation

**Novelty**: 
- First LLM-based zero-day prediction system
- Large-scale temporal validation (11,441 CVEs)
- Explainable predictions with reasoning
- Comparison with traditional methods

## Evaluation Metrics

### Primary Metrics
- **Precision**: % of predictions that were correct
- **Recall**: % of actual CVEs we predicted
- **F1-Score**: Harmonic mean of precision/recall
- **Lead Time**: Average days before CVE disclosure

### Secondary Metrics
- **ROC-AUC**: Area under ROC curve
- **Confidence Calibration**: Are confidence scores accurate?
- **Signal Importance**: Which signals matter most?
- **Baseline Comparison**: How much better than CVSS/EPSS?

### Success Criteria

**Minimum Viable Paper:**
- 100+ CVEs validated
- Statistically significant improvement over baselines (p < 0.05)
- Average lead time > 30 days
- Precision > 30%, Recall > 30%

**Strong Paper:**
- 500+ CVEs validated
- 2x improvement over best baseline
- Average lead time > 60 days
- Precision > 50%, Recall > 50%
- Ablation study showing signal importance
- Case studies of famous CVEs (Log4Shell, etc.)

## Current Status

**Baseline Data**: ✅ Complete (11,441 CVEs, 35,080 commits)

**Signal Collection**: 🔄 In Progress
- GitHub collector implemented
- Temporal filtering working
- Need more diverse projects

**LLM Prediction**: 🔄 In Progress
- Oracle implemented with Gemini
- RAG integration with Neo4j
- Need prompt engineering refinement

**Evaluation**: 📋 Planned
- Framework designed
- Need to implement temporal validation
- Need baseline implementations

## Next Steps

1. **Collect diverse dataset**: 100+ projects with CVEs
2. **Refine LLM prompts**: Improve prediction accuracy
3. **Implement temporal validation**: Test on historical data
4. **Baseline comparison**: Implement CVSS/EPSS/Random baselines
5. **Statistical analysis**: Significance testing, confidence intervals
6. **Case studies**: Analyze famous CVEs (Log4Shell, Spring4Shell)
7. **Paper writing**: Document methodology and results
