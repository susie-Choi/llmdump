# Implementation Plan

- [x] 1. Set up project structure and base classes for prediction system


  - Create directory structure for signal collectors, feature extractors, and prediction engine
  - Define base classes and data models (Signal, FeatureVector, ThreatScore dataclasses)
  - Add new dependencies to requirements.txt (openai, scikit-learn, umap-learn)
  - _Requirements: 8.1, 8.2_

- [x] 2. Implement GitHub signal collection
  - [x] 2.1 Create GitHubSignalCollector class with commit history collection



    - Implement collect_commit_history() method with time range filtering
    - Extract commit message, author, timestamp, files changed, lines added/deleted
    - Add rate limiting and error handling for GitHub API
    - Write unit tests for commit collection
    - _Requirements: 1.1, 1.2, 8.10_

  - [x] 2.2 Add pull request history collection


    - Implement collect_pr_history() method with time range filtering
    - Extract PR title, description, labels, review comments, merge time
    - Write unit tests for PR collection
    - _Requirements: 1.3, 1.4_

  - [x] 2.3 Add issue discussion collection

    - Implement collect_issue_history() method with time range filtering
    - Extract issue title, body, labels, comments, security keywords
    - Implement security keyword detection (vulnerability, exploit, patch, etc.)
    - Write unit tests for issue collection
    - _Requirements: 1.5, 1.6_

  - [x] 2.4 Add release and dependency history collection


    - Implement collect_release_history() method
    - Implement collect_dependency_changes() to track dependency diffs between versions
    - Write unit tests for release collection
    - _Requirements: 1.7, 1.8_

  - [x] 2.5 Implement TimeSeriesStore for signal persistence


    - Create save_signals() method to write signals to JSONL files
    - Create load_signals() method to read signals from JSONL files
    - Organize output by package name and signal type
    - Write unit tests for storage operations
    - _Requirements: 1.9, 1.10_

- [x] 3. Implement feature extraction and embedding
  - [x] 3.1 Create FeatureExtractor class with commit feature extraction
    - Implement extract_commit_features() to compute commit frequency, lines changed, author diversity
    - Implement file type distribution analysis
    - Implement commit time pattern analysis
    - Write unit tests for commit features
    - _Requirements: 2.2_

  - [x] 3.2 Add PR and issue feature extraction
    - Implement extract_pr_features() for PR frequency, merge time, review count, size
    - Implement extract_issue_features() for issue frequency, security keyword ratio, response time
    - Write unit tests for PR and issue features
    - _Requirements: 2.2_

  - [x] 3.3 Add dependency and temporal feature extraction
    - Implement extract_dependency_features() for dependency churn, version bump patterns
    - Implement extract_temporal_features() for trend, volatility, anomaly detection
    - Write unit tests for dependency and temporal features
    - _Requirements: 2.2_

  - [x] 3.4 Create LLMEmbedder class for semantic embeddings
    - Implement embed_commit_messages() using Gemini API
    - Implement embed_pr_descriptions() for PR titles and descriptions
    - Implement embed_issue_discussions() for issue content
    - Implement aggregate_embeddings() to combine multiple embeddings
    - Write unit tests with mocked API
    - _Requirements: 2.1_

  - [x] 3.5 Create FeatureVectorBuilder to combine all features
    - Implement build_vector() to combine structural and semantic features
    - Implement normalize_features() using StandardScaler
    - Create combined normalized vector representation
    - Write unit tests for vector building and normalization
    - _Requirements: 2.3, 2.4, 2.5, 2.6, 2.7, 2.8_



- [x] 4. Implement CVE clustering and pattern learning
  - [x] 4.1 Create CVEClusterer class with clustering algorithms
    - Implement fit() method with K-means and DBSCAN support
    - Implement predict_cluster() to assign new vectors to clusters
    - Implement get_cluster_metadata() to extract cluster characteristics
    - Write unit tests for clustering operations
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_

  - [x] 4.2 Add Neo4j integration for cluster storage
    - Implement save_to_neo4j() to store cluster model and metadata
    - Create Cluster nodes with centroid, size, dominant CWE, avg CVSS/EPSS
    - Create BELONGS_TO_CLUSTER and CONTAINS_CVE relationships
    - Write integration tests for Neo4j storage
    - _Requirements: 3.6_

  - [x] 4.3 Implement cluster assignment for new CVEs
    - Implement logic to assign new CVEs to nearest cluster
    - Implement outlier detection for CVEs that don't fit existing clusters
    - Update cluster metadata when new CVEs are added
    - Write unit tests for cluster assignment
    - _Requirements: 3.7, 3.8_

- [x] 5. Implement prediction engine
  - [x] 5.1 Create PredictionScorer class with threat scoring
    - Implement score_package() to calculate threat score based on cluster similarity
    - Implement calculate_similarity() using cosine similarity
    - Implement find_similar_cves() to find top-k most similar historical CVEs
    - Determine risk level (LOW/MEDIUM/HIGH/CRITICAL) based on score and cluster severity
    - Write unit tests for scoring logic
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5_

  - [x] 5.2 Add threshold-based flagging and reporting
    - Implement threshold comparison to flag high-risk packages
    - Generate detailed threat report with similar CVEs and cluster info
    - Calculate confidence score based on distance and cluster variance
    - Write unit tests for flagging logic
    - _Requirements: 4.6, 4.7, 4.8_

  - [x] 5.3 Implement Neo4j integration for predictions
    - Implement save_prediction() to store predictions in Neo4j
    - Create Prediction nodes with score, confidence, risk level
    - Create HAS_PREDICTION, SIMILAR_TO_CVE, NEAREST_CLUSTER relationships
    - Write integration tests for prediction storage
    - _Requirements: 4.8_

- [x] 6. Implement LLM agent analysis system
  - [x] 6.1 Create SignalAnalyzerAgent for signal interpretation
    - Implement analyze_commits() to identify security-related patterns in commits
    - Implement analyze_discussions() to extract security concerns from issues/PRs
    - Implement analyze_dependencies() to assess dependency risks
    - Use Gemini API with structured prompts for analysis
    - Write unit tests with mocked API
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5_

  - [x] 6.2 Create ThreatAssessmentAgent for scenario generation
    - Implement generate_threat_scenario() to create attack vectors and impact analysis
    - Implement assess_confidence() to evaluate prediction confidence
    - Implement compare_with_historical() to compare with similar CVEs
    - Generate natural language threat scenarios with reasoning
    - Write unit tests for scenario generation
    - _Requirements: 5.6, 5.7, 5.9_

  - [x] 6.3 Create RecommendationAgent for mitigation strategies
    - Implement generate_recommendations() for immediate actions and monitoring
    - Provide mitigation options and alternative packages
    - Generate timeline for recommended actions
    - Write unit tests for recommendation generation
    - _Requirements: 5.8_

  - [x] 6.4 Integrate LLM agents with prediction pipeline
    - Invoke SignalAnalyzerAgent when high-risk package is identified
    - Chain agents: Signal Analysis → Threat Assessment → Recommendations
    - Store agent outputs (ThreatScenario, Recommendations) in Neo4j
    - Create HAS_SCENARIO and HAS_RECOMMENDATION relationships
    - Write integration tests for agent pipeline
    - _Requirements: 5.10_

- [x] 7. Implement validation and feedback loop
  - [x] 7.1 Create PredictionValidator class
    - Implement validate_prediction() to compare predictions with actual CVEs
    - Classify outcomes as TP/FP/TN/FN based on CVE disclosure
    - Calculate time_to_disclosure for true positives
    - Write unit tests for validation logic
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5_

  - [x] 7.2 Add performance metrics calculation
    - Implement calculate_metrics() for precision, recall, F1 score, accuracy
    - Generate confusion matrix for validation results
    - Implement save_metrics() to store metrics in Neo4j
    - Write unit tests for metrics calculation
    - _Requirements: 6.6_

  - [x] 7.3 Create FeedbackLoop class for model improvement
    - Implement analyze_false_negatives() to identify missed signals
    - Implement adjust_threshold() to optimize prediction threshold
    - Implement retrain_clusterer() to update model with new CVE data
    - Write unit tests for feedback loop operations
    - _Requirements: 6.7, 6.8, 6.9, 6.10_

- [ ] 8. Implement automated pipeline and scheduling
  - [ ] 8.1 Create PredictionPipeline orchestrator class
    - Implement run_signal_collection() to collect signals for monitored packages
    - Implement run_feature_extraction() to generate feature vectors
    - Implement run_prediction() to score packages and invoke LLM agents
    - Implement run_validation() to validate predictions against new CVEs
    - Write integration tests for pipeline orchestration
    - _Requirements: 8.2, 8.3, 8.4, 8.5, 8.6, 8.8_

  - [ ] 8.2 Add configuration and error handling
    - Load monitored packages and update frequency from YAML config
    - Implement error logging and graceful degradation
    - Implement API rate limit handling with exponential backoff
    - Continue processing remaining packages if one fails
    - Write unit tests for error handling
    - _Requirements: 8.1, 8.7, 8.10_

  - [x] 8.3 Create command-line scripts for pipeline execution


    - Create scripts/run_prediction_pipeline.py for manual execution
    - Create scripts/validate_predictions.py for validation workflow
    - Add command-line arguments for package selection and time ranges
    - Write documentation for script usage
    - _Requirements: 8.2, 8.3, 8.4, 8.5, 8.6, 8.8, 8.9_

- [ ] 9. Extend dashboard with prediction visualizations
  - [ ] 9.1 Add "Threat Predictions" page to dashboard
    - Display list of monitored packages with threat scores
    - Show risk level indicators (LOW/MEDIUM/HIGH/CRITICAL)
    - Display confidence scores and prediction timestamps
    - Add filtering by risk level and package name
    - _Requirements: 7.1, 7.6_

  - [ ] 9.2 Add "Signal Timeline" page for package analysis
    - Visualize commit, PR, issue, release signals over time
    - Display feature vector components (radar chart or heatmap)
    - Show temporal patterns and anomalies
    - Add drill-down to raw signal data
    - _Requirements: 7.2, 7.3, 7.9_

  - [ ] 9.3 Add "Cluster Analysis" page for CVE patterns
    - Visualize cluster distribution using t-SNE or UMAP in 2D/3D
    - Display cluster metadata (size, dominant CWE, avg CVSS/EPSS)
    - Show example CVEs for each cluster
    - Display nearest clusters for selected packages
    - _Requirements: 7.4, 7.7_

  - [ ] 9.4 Add "LLM Analysis" page for threat scenarios
    - Display LLM agent's threat analysis for high-risk packages
    - Show attack vectors, affected components, potential impact
    - Display recommendations with immediate actions and mitigation options
    - Show reasoning and confidence assessment
    - _Requirements: 7.5_

  - [ ] 9.5 Add "Model Performance" page for validation metrics
    - Display precision, recall, F1 score, accuracy over time
    - Show precision-recall curves and confusion matrices
    - Display validation results (TP/FP/TN/FN) with details
    - Add historical accuracy trends
    - _Requirements: 7.6, 7.8_

  - [ ] 9.6 Implement real-time dashboard updates
    - Add auto-refresh functionality for new predictions
    - Display notification badges for new high-risk predictions
    - Implement WebSocket or polling for real-time updates
    - _Requirements: 7.10_

- [ ] 10. Create end-to-end integration tests and documentation
  - [ ] 10.1 Write integration tests for complete prediction workflow
    - Test signal collection → feature extraction → prediction → LLM analysis
    - Test validation workflow with historical CVE data
    - Test Neo4j data persistence and retrieval
    - Verify no temporal data leakage in test scenarios
    - _Requirements: All requirements_

  - [ ] 10.2 Create user documentation
    - Write README for prediction system setup and usage
    - Document configuration options and environment variables
    - Provide examples for monitoring new packages
    - Document dashboard usage and interpretation
    - _Requirements: All requirements_

  - [ ] 10.3 Create developer documentation
    - Document architecture and component interactions
    - Provide API documentation for key classes
    - Document Neo4j schema extensions
    - Provide troubleshooting guide
    - _Requirements: All requirements_
