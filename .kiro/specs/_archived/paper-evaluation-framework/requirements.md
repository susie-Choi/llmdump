# Requirements Document

## Introduction

논문 투고를 위한 평가 프레임워크(Evaluation Framework)를 구축합니다. 이 시스템은 Zero-Day 예측 시스템의 성능을 정량적으로 측정하고, 탑티어 보안 컨퍼런스/저널(USENIX Security, IEEE S&P, CCS, NDSS 등)의 요구사항을 충족하는 실험 결과를 생성합니다.

핵심 목표는 Historical Validation을 통해 과거 CVE를 예측할 수 있었는지 검증하고, Baseline 방법들과 비교하여 우리 시스템의 우수성을 정량적으로 증명하는 것입니다.

## Requirements

### Requirement 1: Historical Validation Pipeline

**User Story:** As a researcher, I want to validate predictions against historical CVE data, so that I can prove the system's effectiveness with real-world cases.

#### Acceptance Criteria

1. WHEN a cutoff date is specified THEN the system SHALL collect only data available before that date
2. WHEN predictions are made at the cutoff date THEN the system SHALL compare them with actual CVEs disclosed after the cutoff
3. WHEN validation completes THEN the system SHALL calculate Precision, Recall, F1-Score, and Lead Time metrics
4. IF a CVE was predicted before disclosure THEN the system SHALL record the lead time in days
5. WHEN multiple CVEs are validated THEN the system SHALL generate aggregate statistics and confidence intervals

### Requirement 2: Large-Scale Dataset Collection

**User Story:** As a researcher, I want to collect a diverse dataset of 100+ CVEs with GitHub repositories, so that I can demonstrate the system's generalizability.

#### Acceptance Criteria

1. WHEN collecting CVEs THEN the system SHALL gather at least 100 CVEs from diverse open-source projects
2. WHEN a CVE is collected THEN the system SHALL verify it has an associated GitHub repository
3. WHEN collecting CVEs THEN the system SHALL ensure diversity across CVSS scores (7.0-10.0), vulnerability types (RCE, SQLi, XSS, etc.), and projects
4. WHEN dataset collection completes THEN the system SHALL generate statistical summaries (distributions, correlations)
5. WHEN a CVE lacks sufficient data THEN the system SHALL flag it and exclude from the evaluation dataset

### Requirement 3: Baseline Implementation

**User Story:** As a researcher, I want to compare my system against baseline methods, so that I can demonstrate performance improvements.

#### Acceptance Criteria

1. WHEN evaluating THEN the system SHALL implement a CVSS-only baseline that ranks packages by historical CVSS scores
2. WHEN evaluating THEN the system SHALL implement an EPSS-only baseline that ranks packages by EPSS scores
3. WHEN evaluating THEN the system SHALL implement a random baseline for statistical significance testing
4. WHEN baselines run THEN they SHALL use the same temporal constraints as the main system
5. WHEN evaluation completes THEN the system SHALL generate a comparison table with all methods

### Requirement 4: Ablation Study Framework

**User Story:** As a researcher, I want to measure each component's contribution, so that I can justify the system design.

#### Acceptance Criteria

1. WHEN running ablation study THEN the system SHALL test performance with each feature group disabled (commit signals, PR signals, issue signals, graph features, LLM reasoning)
2. WHEN a component is disabled THEN the system SHALL re-run predictions and calculate performance metrics
3. WHEN ablation study completes THEN the system SHALL generate feature importance rankings
4. WHEN comparing configurations THEN the system SHALL calculate statistical significance (p-values)
5. WHEN results are ready THEN the system SHALL generate visualization plots (bar charts, heatmaps)

### Requirement 5: Performance Metrics Calculation

**User Story:** As a researcher, I want comprehensive performance metrics, so that I can report results in my paper.

#### Acceptance Criteria

1. WHEN predictions are evaluated THEN the system SHALL calculate Precision, Recall, F1-Score, Accuracy
2. WHEN predictions are evaluated THEN the system SHALL calculate True Positive Rate (TPR) and False Positive Rate (FPR)
3. WHEN predictions are evaluated THEN the system SHALL generate ROC curves and calculate AUC
4. WHEN predictions are evaluated THEN the system SHALL calculate average Lead Time (days before CVE disclosure)
5. WHEN predictions are evaluated THEN the system SHALL calculate Coverage (percentage of CVEs predicted)
6. WHEN multiple runs are performed THEN the system SHALL calculate confidence intervals (95%)

### Requirement 6: Case Study Generation

**User Story:** As a researcher, I want detailed case studies of famous CVEs, so that I can provide qualitative analysis in my paper.

#### Acceptance Criteria

1. WHEN generating case studies THEN the system SHALL analyze at least 3 high-profile CVEs (e.g., Log4Shell, Spring4Shell, Text4Shell)
2. WHEN analyzing a CVE THEN the system SHALL extract the timeline of signals leading to the vulnerability
3. WHEN analyzing a CVE THEN the system SHALL identify which signals were most predictive
4. WHEN case study completes THEN the system SHALL generate a visualization of the signal timeline
5. WHEN case study completes THEN the system SHALL generate a narrative explanation of why the CVE was predictable

### Requirement 7: Paper-Ready Output Generation

**User Story:** As a researcher, I want publication-ready figures and tables, so that I can directly include them in my paper.

#### Acceptance Criteria

1. WHEN evaluation completes THEN the system SHALL generate LaTeX tables for performance comparison
2. WHEN evaluation completes THEN the system SHALL generate high-resolution plots (PDF/PNG) for figures
3. WHEN generating outputs THEN the system SHALL follow academic publication standards (IEEE, ACM formats)
4. WHEN generating tables THEN the system SHALL include statistical significance markers (*, **, ***)
5. WHEN generating outputs THEN the system SHALL create a summary report with all key findings

### Requirement 8: Reproducibility Support

**User Story:** As a researcher, I want reproducible experiments, so that reviewers can verify my results.

#### Acceptance Criteria

1. WHEN running experiments THEN the system SHALL log all parameters (random seeds, cutoff dates, thresholds)
2. WHEN experiments complete THEN the system SHALL save all intermediate results and predictions
3. WHEN saving results THEN the system SHALL include timestamps and version information
4. WHEN experiments are re-run THEN the system SHALL produce identical results given the same parameters
5. WHEN sharing results THEN the system SHALL generate a reproducibility package with data, code, and instructions

### Requirement 9: Statistical Validation

**User Story:** As a researcher, I want statistical validation of results, so that I can claim significance in my paper.

#### Acceptance Criteria

1. WHEN comparing methods THEN the system SHALL perform paired t-tests or Wilcoxon signed-rank tests
2. WHEN reporting results THEN the system SHALL include p-values and effect sizes
3. WHEN multiple comparisons are made THEN the system SHALL apply Bonferroni correction
4. WHEN calculating metrics THEN the system SHALL use cross-validation or bootstrap for confidence intervals
5. WHEN results show no significance THEN the system SHALL report this honestly

### Requirement 10: Experiment Orchestration

**User Story:** As a researcher, I want to run all experiments with a single command, so that I can efficiently generate all paper results.

#### Acceptance Criteria

1. WHEN running the full pipeline THEN the system SHALL execute data collection, prediction, validation, and analysis in sequence
2. WHEN an experiment fails THEN the system SHALL log the error and continue with remaining experiments
3. WHEN experiments run THEN the system SHALL display progress bars and estimated time remaining
4. WHEN experiments complete THEN the system SHALL generate a summary dashboard with all results
5. WHEN resuming experiments THEN the system SHALL skip already-completed steps
