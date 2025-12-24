# Requirements Document

## Introduction

Zero-Day Defense 예측 시스템은 t 시점의 다양한 신호(코드 변경, 의존성 변화, 개발자 활동 등)를 분석하여 t+1 시점에 발생할 수 있는 zero-day 취약점을 사전에 예측하는 LLM 기반 지능형 분석 시스템입니다. 이 시스템은 시간적 데이터 누수(temporal leakage)를 방지하면서 과거 CVE 패턴을 학습하고, 새로운 신호를 실시간으로 분석하여 위협을 조기에 탐지합니다.

## Requirements

### Requirement 1: 시간적 신호 수집 시스템

**User Story:** As a security researcher, I want to collect time-series signals from multiple sources before CVE disclosure, so that I can identify pre-vulnerability patterns.

#### Acceptance Criteria

1. WHEN a package is specified THEN the system SHALL collect GitHub commit history with timestamps
2. WHEN collecting commit data THEN the system SHALL extract commit messages, changed files, and author information
3. WHEN a package is specified THEN the system SHALL collect pull request history with creation and merge timestamps
4. WHEN collecting PR data THEN the system SHALL extract PR titles, descriptions, labels, and review comments
5. WHEN a package is specified THEN the system SHALL collect issue discussion history with timestamps
6. WHEN collecting issue data THEN the system SHALL identify security-related keywords (e.g., "vulnerability", "security", "exploit", "patch")
7. WHEN a package is specified THEN the system SHALL collect package release history with version numbers and dates
8. WHEN collecting release data THEN the system SHALL track dependency changes between versions
9. WHEN a CVE ID is provided THEN the system SHALL identify the CVE disclosure date as the cutoff point
10. WHEN collecting signals THEN the system SHALL only include data from before the CVE disclosure date to prevent temporal leakage

### Requirement 2: 특징 벡터 생성 및 임베딩

**User Story:** As a data scientist, I want to convert raw signals into meaningful feature vectors, so that I can perform similarity analysis and clustering.

#### Acceptance Criteria

1. WHEN commit messages are collected THEN the system SHALL generate semantic embeddings using LLM
2. WHEN code changes are collected THEN the system SHALL extract structural features (lines added/deleted, file types, function changes)
3. WHEN dependency changes are detected THEN the system SHALL create dependency graph features
4. WHEN developer activity is collected THEN the system SHALL compute behavioral features (commit frequency, contributor diversity, response time)
5. WHEN security keywords are found THEN the system SHALL create keyword frequency vectors
6. WHEN temporal data is available THEN the system SHALL encode time-series patterns (trend, seasonality, anomalies)
7. WHEN all features are extracted THEN the system SHALL normalize and combine them into a unified feature vector
8. WHEN feature vectors are created THEN the system SHALL store them with associated metadata (package name, time window, CVE ID if applicable)

### Requirement 3: CVE 클러스터링 및 패턴 학습

**User Story:** As a machine learning engineer, I want to cluster historical CVE data by vulnerability patterns, so that I can identify similar threat signatures.

#### Acceptance Criteria

1. WHEN historical CVE data is available THEN the system SHALL extract pre-disclosure signals for each CVE
2. WHEN CVE signals are extracted THEN the system SHALL generate feature vectors for each CVE
3. WHEN CVE feature vectors are created THEN the system SHALL perform clustering analysis (e.g., K-means, DBSCAN, hierarchical)
4. WHEN clustering is complete THEN the system SHALL label each cluster with dominant characteristics (e.g., "memory corruption", "injection", "authentication bypass")
5. WHEN a cluster is formed THEN the system SHALL compute the cluster centroid and variance
6. WHEN clusters are created THEN the system SHALL store cluster metadata in Neo4j graph database
7. WHEN a new CVE is added THEN the system SHALL assign it to the nearest cluster
8. IF a CVE doesn't fit existing clusters THEN the system SHALL create a new cluster or mark it as an outlier

### Requirement 4: 실시간 위협 예측 엔진

**User Story:** As a security analyst, I want to analyze current package signals and predict potential vulnerabilities, so that I can proactively address security risks.

#### Acceptance Criteria

1. WHEN a target package is specified THEN the system SHALL collect current signals (commits, PRs, issues, releases)
2. WHEN current signals are collected THEN the system SHALL generate feature vectors using the same pipeline as historical CVE data
3. WHEN a feature vector is generated THEN the system SHALL compute similarity scores to all CVE clusters
4. WHEN similarity scores are computed THEN the system SHALL identify the top-k nearest clusters
5. WHEN nearest clusters are identified THEN the system SHALL calculate a threat score based on distance and cluster severity
6. IF the threat score exceeds a threshold THEN the system SHALL flag the package as high-risk
7. WHEN a package is flagged THEN the system SHALL generate a detailed threat report with similar historical CVEs
8. WHEN a threat report is generated THEN the system SHALL include confidence score and reasoning

### Requirement 5: LLM Agent 기반 지능형 분석

**User Story:** As a security researcher, I want an LLM agent to interpret signals and provide contextual threat analysis, so that I can understand the reasoning behind predictions.

#### Acceptance Criteria

1. WHEN a high-risk package is identified THEN the system SHALL invoke an LLM agent for detailed analysis
2. WHEN the LLM agent is invoked THEN it SHALL analyze commit messages for security implications
3. WHEN the LLM agent analyzes code changes THEN it SHALL identify potentially vulnerable code patterns
4. WHEN the LLM agent reviews discussions THEN it SHALL extract security concerns and developer responses
5. WHEN the LLM agent examines dependencies THEN it SHALL assess transitive vulnerability risks
6. WHEN the LLM agent completes analysis THEN it SHALL generate a natural language threat scenario
7. WHEN a threat scenario is generated THEN it SHALL include attack vectors, potential impact, and affected components
8. WHEN the LLM agent provides recommendations THEN it SHALL suggest mitigation strategies and monitoring actions
9. WHEN multiple signals conflict THEN the LLM agent SHALL weigh evidence and explain its reasoning
10. WHEN the analysis is complete THEN the system SHALL store the LLM agent's output with the prediction record

### Requirement 6: 예측 검증 및 피드백 루프

**User Story:** As a system administrator, I want to validate predictions against actual CVE disclosures, so that I can improve model accuracy over time.

#### Acceptance Criteria

1. WHEN a prediction is made THEN the system SHALL store the prediction with timestamp and confidence score
2. WHEN a new CVE is disclosed THEN the system SHALL check if it was previously predicted
3. IF a CVE was predicted THEN the system SHALL calculate prediction accuracy (true positive)
4. IF a CVE was not predicted THEN the system SHALL mark it as a false negative
5. IF a prediction did not result in a CVE THEN the system SHALL mark it as a false positive after a time window
6. WHEN validation results are available THEN the system SHALL compute precision, recall, and F1 scores
7. WHEN false negatives are identified THEN the system SHALL analyze missed signals for model improvement
8. WHEN false positives are identified THEN the system SHALL adjust threshold parameters
9. WHEN validation metrics are computed THEN the system SHALL update the dashboard with performance statistics
10. WHEN feedback is collected THEN the system SHALL retrain clustering models with new data

### Requirement 7: 대시보드 통합 및 시각화

**User Story:** As a security team lead, I want to visualize threat predictions and analysis results in a dashboard, so that I can prioritize security efforts.

#### Acceptance Criteria

1. WHEN the dashboard loads THEN it SHALL display a list of monitored packages with threat scores
2. WHEN a package is selected THEN the dashboard SHALL show its signal timeline (commits, PRs, issues)
3. WHEN a package is selected THEN the dashboard SHALL display its feature vector visualization (radar chart, heatmap)
4. WHEN a package is selected THEN the dashboard SHALL show nearest CVE clusters with similarity scores
5. WHEN a high-risk package is selected THEN the dashboard SHALL display the LLM agent's threat analysis
6. WHEN viewing predictions THEN the dashboard SHALL show confidence scores and historical accuracy
7. WHEN viewing clusters THEN the dashboard SHALL visualize the cluster distribution in 2D/3D space (t-SNE, UMAP)
8. WHEN viewing validation results THEN the dashboard SHALL display precision-recall curves and confusion matrices
9. WHEN a user requests details THEN the dashboard SHALL provide drill-down views to raw signal data
10. WHEN new predictions are made THEN the dashboard SHALL update in real-time or on refresh

### Requirement 8: 데이터 파이프라인 및 스케줄링

**User Story:** As a DevOps engineer, I want to automate data collection and prediction workflows, so that the system runs continuously without manual intervention.

#### Acceptance Criteria

1. WHEN the system starts THEN it SHALL load configuration for monitored packages and update frequency
2. WHEN a scheduled time arrives THEN the system SHALL automatically collect signals for all monitored packages
3. WHEN signal collection completes THEN the system SHALL automatically generate feature vectors
4. WHEN feature vectors are ready THEN the system SHALL automatically run threat prediction
5. WHEN predictions are made THEN the system SHALL automatically invoke LLM agents for high-risk packages
6. WHEN analysis completes THEN the system SHALL automatically update Neo4j database and dashboard
7. IF an error occurs during pipeline execution THEN the system SHALL log the error and continue with remaining packages
8. WHEN a new CVE is disclosed THEN the system SHALL automatically trigger validation workflow
9. WHEN validation completes THEN the system SHALL automatically update model performance metrics
10. WHEN the pipeline runs THEN it SHALL respect API rate limits and implement exponential backoff for retries
