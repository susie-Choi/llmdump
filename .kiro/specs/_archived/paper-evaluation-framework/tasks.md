# Implementation Plan

- [x] 1. Setup evaluation infrastructure


  - Create directory structure for evaluation modules
  - Add evaluation dependencies to requirements.txt
  - Create base classes and interfaces
  - _Requirements: All_






- [ ] 2. Implement dataset collection module
  - [x] 2.1 Create PaperDatasetCollector class


    - Implement CVE collection with GitHub repository mapping
    - Add filtering logic (CVSS >= 7.0, has GitHub repo)
    - Implement diversity checks (projects, vulnerability types)
    - _Requirements: 2.1, 2.2, 2.3_


  
  - [ ] 2.2 Create DatasetValidator class
    - Implement GitHub repository existence check
    - Validate sufficient signal data (commits, PRs, issues)
    - Add data quality scoring


    - _Requirements: 2.5_
  
  - [-] 2.3 Create DatasetStatistics class



    - Calculate CVSS score distribution
    - Calculate vulnerability type distribution
    - Calculate project distribution
    - Generate correlation matrices
    - _Requirements: 2.4_
  
  - [ ] 2.4 Create dataset collection script
    - Implement CLI for dataset collection
    - Add progress tracking and logging
    - Save collected dataset to JSONL format
    - _Requirements: 2.1, 2.2, 2.3, 2.4_

- [ ] 3. Implement historical validation module
  - [ ] 3.1 Create TemporalSplitter class
    - Implement cutoff date-based data splitting
    - Add temporal leakage validation
    - Create time window calculation logic
    - _Requirements: 1.1, 1.2_
  
  - [ ] 3.2 Create ValidationRunner class
    - Implement prediction execution at cutoff dates
    - Add support for multiple top-K values
    - Implement parallel validation for multiple CVEs
    - _Requirements: 1.2_
  
  - [ ] 3.3 Create GroundTruthMatcher class
    - Implement prediction-to-CVE matching logic
    - Calculate lead time for successful predictions
    - Classify results as TP/FP/TN/FN
    - _Requirements: 1.3, 1.4_
  
  - [ ] 3.4 Create MetricsCalculator class
    - Implement Precision, Recall, F1-Score calculation
    - Implement TPR, FPR, ROC-AUC calculation
    - Calculate average and median lead time
    - Calculate coverage percentage
    - _Requirements: 1.3, 5.1, 5.2, 5.3, 5.4, 5.5_
  
  - [ ] 3.5 Create historical validation script
    - Implement end-to-end validation pipeline
    - Add configuration loading
    - Save validation results to JSONL
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5_

- [ ] 4. Implement baseline methods
  - [ ] 4.1 Create BaselineMethod abstract class
    - Define common interface for all baselines
    - Implement temporal constraint handling
    - Add result formatting
    - _Requirements: 3.4_
  
  - [ ] 4.2 Implement CVSSBaseline class
    - Calculate historical average CVSS scores
    - Rank repositories by CVSS score
    - Return top-K predictions
    - _Requirements: 3.1, 3.4_
  
  - [ ] 4.3 Implement EPSSBaseline class
    - Fetch EPSS scores at cutoff date
    - Rank repositories by EPSS score
    - Return top-K predictions
    - _Requirements: 3.2, 3.4_
  
  - [ ] 4.4 Implement RandomBaseline class
    - Implement random repository selection
    - Add seed for reproducibility
    - Return top-K predictions
    - _Requirements: 3.3, 3.4_
  
  - [ ] 4.5 Implement FrequencyBaseline class
    - Calculate historical CVE frequency per repository
    - Rank by frequency
    - Return top-K predictions
    - _Requirements: 3.4_
  
  - [ ] 4.6 Create baseline comparison script
    - Run all baseline methods
    - Compare with main system
    - Generate comparison table
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_

- [ ] 5. Implement ablation study module
  - [ ] 5.1 Create FeatureAblator class
    - Implement feature group disabling logic
    - Support commit, PR, issue, graph, LLM ablation
    - Run predictions with disabled features
    - _Requirements: 4.1, 4.2_
  
  - [ ] 5.2 Create AblationAnalyzer class
    - Calculate performance delta for each ablation
    - Rank features by importance
    - Generate feature importance scores
    - _Requirements: 4.3_
  
  - [ ] 5.3 Create ablation study script
    - Run all ablation configurations
    - Compare performance across configurations
    - Generate ablation results table
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5_

- [ ] 6. Implement statistical analysis module
  - [ ] 6.1 Create SignificanceTest class
    - Implement paired t-test
    - Implement Wilcoxon signed-rank test
    - Add Bonferroni correction for multiple comparisons
    - _Requirements: 9.1, 9.3_
  
  - [ ] 6.2 Create ConfidenceInterval class
    - Implement bootstrap confidence intervals
    - Calculate 95% confidence intervals for metrics
    - Support multiple metrics
    - _Requirements: 5.6, 9.4_
  
  - [ ] 6.3 Create EffectSize class
    - Implement Cohen's d calculation
    - Calculate effect sizes for comparisons
    - Interpret effect size magnitudes
    - _Requirements: 9.2_
  
  - [ ] 6.4 Integrate statistical tests into validation
    - Add significance testing to baseline comparison
    - Add confidence intervals to all metrics
    - Report p-values and effect sizes
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5_

- [ ] 7. Implement results generation module
  - [ ] 7.1 Create LaTeXTableGenerator class
    - Generate performance comparison table
    - Generate ablation study table
    - Add statistical significance markers (*, **, ***)
    - Format according to IEEE/ACM standards
    - _Requirements: 7.1, 7.3, 7.4_
  
  - [ ] 7.2 Create PlotGenerator class
    - Generate ROC curves for all methods
    - Generate Precision-Recall curves
    - Generate feature importance bar chart
    - Generate lead time distribution histogram
    - Generate confusion matrices
    - Save plots in PDF format
    - _Requirements: 7.2, 7.3_
  
  - [ ] 7.3 Create CaseStudyAnalyzer class
    - Analyze signal timeline for specific CVEs
    - Identify most predictive signals
    - Generate timeline visualization
    - Write narrative explanation
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5_
  
  - [ ] 7.4 Create ReportWriter class
    - Generate comprehensive summary report
    - Include all key findings
    - Add experiment metadata
    - Format for easy reading
    - _Requirements: 7.5_

- [ ] 8. Implement experiment orchestration
  - [ ] 8.1 Create ExperimentOrchestrator class
    - Implement full pipeline execution
    - Add progress tracking
    - Implement error handling and recovery
    - Support resuming from checkpoints
    - _Requirements: 10.1, 10.2, 10.3, 10.5_
  
  - [ ] 8.2 Create experiment configuration system
    - Define ExperimentConfig dataclass
    - Support YAML configuration files
    - Add configuration validation
    - _Requirements: 8.1_
  
  - [ ] 8.3 Create main experiment script
    - Implement run_paper_experiments.py
    - Add CLI with argparse
    - Display progress and ETA
    - Generate final summary dashboard
    - _Requirements: 10.1, 10.2, 10.3, 10.4_

- [ ] 9. Implement reproducibility support
  - [ ] 9.1 Add experiment logging
    - Log all parameters (seeds, dates, thresholds)
    - Log intermediate results
    - Add timestamps and version info
    - _Requirements: 8.1, 8.2, 8.3_
  
  - [ ] 9.2 Create reproducibility package generator
    - Package data, code, and instructions
    - Generate README with setup steps
    - Include expected results
    - _Requirements: 8.5_
  
  - [ ] 9.3 Add deterministic execution
    - Set random seeds for all random operations
    - Ensure consistent ordering
    - Validate reproducibility with test runs
    - _Requirements: 8.4_

- [ ] 10. Create integration tests
  - [ ] 10.1 Test dataset collection pipeline
    - Test CVE collection with GitHub mapping
    - Test data validation
    - Test statistics generation
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5_
  
  - [ ] 10.2 Test historical validation pipeline
    - Test temporal splitting
    - Test prediction execution
    - Test metrics calculation
    - Test with known CVE cases (Log4Shell)
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5_
  
  - [ ] 10.3 Test baseline comparison
    - Test all baseline methods
    - Test comparison logic
    - Verify statistical tests
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_
  
  - [ ] 10.4 Test ablation study
    - Test feature disabling
    - Test performance tracking
    - Test importance ranking
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5_
  
  - [ ] 10.5 Test results generation
    - Test LaTeX table generation
    - Test plot generation
    - Test case study analysis
    - Verify output formats
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5_

- [ ] 11. Create documentation
  - [ ] 11.1 Write evaluation framework guide
    - Document architecture and design
    - Explain each module's purpose
    - Provide usage examples
    - _Requirements: All_
  
  - [ ] 11.2 Write experiment running guide
    - Document how to run full experiments
    - Explain configuration options
    - Provide troubleshooting tips
    - _Requirements: 10.1, 10.2, 10.3, 10.4_
  
  - [ ] 11.3 Write results interpretation guide
    - Explain how to read generated tables
    - Explain how to interpret plots
    - Provide statistical interpretation guidelines
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5_

- [ ] 12. Run pilot experiments
  - [ ] 12.1 Collect pilot dataset
    - Collect 10-20 CVEs for testing
    - Validate data quality
    - Generate statistics
    - _Requirements: 2.1, 2.2, 2.3, 2.4_
  
  - [ ] 12.2 Run pilot validation
    - Run historical validation on pilot dataset
    - Calculate metrics
    - Identify issues
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5_
  
  - [ ] 12.3 Run pilot baseline comparison
    - Run all baselines on pilot dataset
    - Compare results
    - Verify statistical tests
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_
  
  - [ ] 12.4 Generate pilot results
    - Generate tables and plots
    - Review output quality
    - Refine formatting
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5_

- [ ] 13. Run full-scale experiments
  - [ ] 13.1 Collect full dataset
    - Collect 100+ CVEs
    - Validate all data
    - Generate comprehensive statistics
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5_
  
  - [ ] 13.2 Run full historical validation
    - Run validation on all CVEs
    - Calculate all metrics
    - Generate confidence intervals
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 5.6_
  
  - [ ] 13.3 Run full baseline comparison
    - Run all baselines
    - Perform significance tests
    - Generate comparison table
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 9.1, 9.2_
  
  - [ ] 13.4 Run full ablation study
    - Run all ablation configurations
    - Calculate feature importance
    - Perform significance tests
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5_
  
  - [ ] 13.5 Generate case studies
    - Analyze Log4Shell, Spring4Shell, Text4Shell
    - Generate timelines and visualizations
    - Write narratives
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5_
  
  - [ ] 13.6 Generate all paper results
    - Generate all LaTeX tables
    - Generate all plots
    - Generate summary report
    - Create reproducibility package
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 8.5_
