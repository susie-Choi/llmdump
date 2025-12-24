# Design Document

## Overview

논문 투고를 위한 평가 프레임워크는 Zero-Day 예측 시스템의 성능을 정량적으로 측정하고 검증하는 종합적인 실험 인프라입니다. 이 시스템은 Historical Validation, Baseline 비교, Ablation Study, 통계 분석을 자동화하여 탑티어 보안 컨퍼런스/저널의 요구사항을 충족하는 실험 결과를 생성합니다.

핵심 설계 원칙:
1. **Temporal Correctness**: 모든 실험에서 시간적 데이터 누수(temporal leakage) 방지
2. **Reproducibility**: 동일한 파라미터로 동일한 결과 보장
3. **Statistical Rigor**: 통계적 유의성 검증 포함
4. **Automation**: 전체 실험을 단일 명령으로 실행 가능
5. **Publication-Ready**: 논문에 직접 사용 가능한 출력 생성

## Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                  Experiment Orchestrator                     │
│                  (run_paper_experiments.py)                  │
└────────────┬────────────────────────────────────────────────┘
             │
             ├─────────────────────────────────────────────────┐
             │                                                 │
             ▼                                                 ▼
┌────────────────────────┐                    ┌────────────────────────┐
│  Dataset Collection    │                    │  Baseline Methods      │
│  ─────────────────     │                    │  ────────────────      │
│  • CVE Collector       │                    │  • CVSS Baseline       │
│  • GitHub Mapper       │                    │  • EPSS Baseline       │
│  • Signal Collector    │                    │  • Random Baseline     │
│  • Dataset Validator   │                    │  • Frequency Baseline  │
└────────────┬───────────┘                    └───────────┬────────────┘
             │                                            │
             └──────────────┬─────────────────────────────┘
                            │
                            ▼
             ┌──────────────────────────────┐
             │  Historical Validator        │
             │  ────────────────────         │
             │  • Temporal Splitter         │
             │  • Prediction Runner         │
             │  • Ground Truth Matcher      │
             │  • Metrics Calculator        │
             └──────────────┬───────────────┘
                            │
             ┌──────────────┴───────────────┐
             │                              │
             ▼                              ▼
┌────────────────────────┐    ┌────────────────────────┐
│  Ablation Study        │    │  Statistical Analysis  │
│  ──────────────        │    │  ───────────────────   │
│  • Feature Ablator     │    │  • Significance Tests  │
│  • Component Disabler  │    │  • Confidence Intervals│
│  • Performance Tracker │    │  • Effect Size Calc    │
└────────────┬───────────┘    └───────────┬────────────┘
             │                            │
             └──────────────┬─────────────┘
                            │
                            ▼
             ┌──────────────────────────────┐
             │  Results Generator           │
             │  ─────────────────           │
             │  • LaTeX Table Generator     │
             │  • Plot Generator (matplotlib)│
             │  • Case Study Analyzer       │
             │  • Summary Report Writer     │
             └──────────────────────────────┘
```

### Component Architecture

#### 1. Dataset Collection Module

```python
src/zero_day_defense/evaluation/
├── dataset/
│   ├── __init__.py
│   ├── collector.py          # CVE + GitHub 데이터 수집
│   ├── validator.py          # 데이터 품질 검증
│   └── statistics.py         # 데이터셋 통계 생성
```

**Key Classes:**
- `PaperDatasetCollector`: 논문용 대규모 데이터셋 수집
- `DatasetValidator`: 데이터 품질 검증 (GitHub repo 존재, 충분한 신호 등)
- `DatasetStatistics`: 분포, 상관관계 등 통계 계산

**Data Flow:**
1. CVE 목록 로드 (NVD API)
2. GitHub 저장소 매핑
3. 각 CVE의 시간 범위 결정 (disclosure date - 6 months)
4. GitHub 신호 수집 (commits, PRs, issues)
5. 데이터 품질 검증
6. 통계 생성 및 저장

#### 2. Historical Validation Module

```python
src/zero_day_defense/evaluation/
├── validation/
│   ├── __init__.py
│   ├── temporal_splitter.py  # 시간 기반 데이터 분할
│   ├── runner.py              # 예측 실행
│   ├── matcher.py             # 예측-실제 매칭
│   └── metrics.py             # 성능 메트릭 계산
```

**Key Classes:**
- `TemporalSplitter`: cutoff date 기준으로 데이터 분할
- `ValidationRunner`: 각 cutoff date에서 예측 실행
- `GroundTruthMatcher`: 예측과 실제 CVE 매칭
- `MetricsCalculator`: Precision, Recall, F1, Lead Time 계산

**Validation Process:**
```
For each CVE:
  1. Set cutoff_date = CVE_disclosure_date - prediction_window (e.g., 90 days)
  2. Collect signals up to cutoff_date
  3. Run prediction system
  4. Get top-K predictions
  5. Check if actual CVE repository is in top-K
  6. Calculate lead time if predicted
  7. Record TP/FP/TN/FN
```

**Metrics:**
- **Precision**: TP / (TP + FP)
- **Recall**: TP / (TP + FN)
- **F1-Score**: 2 * (Precision * Recall) / (Precision + Recall)
- **Lead Time**: Average days between prediction and actual disclosure
- **Coverage**: Percentage of CVEs predicted
- **ROC-AUC**: Area under ROC curve

#### 3. Baseline Methods Module

```python
src/zero_day_defense/evaluation/
├── baselines/
│   ├── __init__.py
│   ├── base.py               # Abstract baseline class
│   ├── cvss_baseline.py      # CVSS 점수 기반
│   ├── epss_baseline.py      # EPSS 점수 기반
│   ├── random_baseline.py    # 랜덤 선택
│   └── frequency_baseline.py # 과거 CVE 빈도 기반
```

**Baseline Strategies:**

1. **CVSS Baseline**: 과거 평균 CVSS 점수로 랭킹
2. **EPSS Baseline**: EPSS 점수로 랭킹
3. **Random Baseline**: 무작위 선택 (통계적 유의성 검증용)
4. **Frequency Baseline**: 과거 CVE 발생 빈도로 랭킹

**Interface:**
```python
class BaselineMethod(ABC):
    @abstractmethod
    def predict(self, cutoff_date: datetime, top_k: int) -> List[str]:
        """Return top-K repository predictions at cutoff_date"""
        pass
```

#### 4. Ablation Study Module

```python
src/zero_day_defense/evaluation/
├── ablation/
│   ├── __init__.py
│   ├── feature_ablator.py    # Feature group ablation
│   ├── component_disabler.py # Component-level ablation
│   └── analyzer.py           # 결과 분석
```

**Ablation Configurations:**
```python
ABLATION_CONFIGS = {
    "full": {
        "commit_signals": True,
        "pr_signals": True,
        "issue_signals": True,
        "graph_features": True,
        "llm_reasoning": True,
    },
    "no_commits": {
        "commit_signals": False,
        # ... rest True
    },
    "no_prs": {
        "pr_signals": False,
        # ... rest True
    },
    "no_issues": {
        "issue_signals": False,
        # ... rest True
    },
    "no_graph": {
        "graph_features": False,
        # ... rest True
    },
    "no_llm": {
        "llm_reasoning": False,
        # ... rest True
    },
    "signals_only": {
        "commit_signals": True,
        "pr_signals": True,
        "issue_signals": True,
        "graph_features": False,
        "llm_reasoning": False,
    },
}
```

**Analysis:**
- Feature importance ranking
- Performance delta when removing each component
- Statistical significance of each component

#### 5. Statistical Analysis Module

```python
src/zero_day_defense/evaluation/
├── statistics/
│   ├── __init__.py
│   ├── significance.py       # 통계적 유의성 검증
│   ├── confidence.py         # 신뢰구간 계산
│   └── effect_size.py        # Effect size 계산
```

**Statistical Tests:**
- Paired t-test (parametric)
- Wilcoxon signed-rank test (non-parametric)
- Bonferroni correction (multiple comparisons)
- Bootstrap confidence intervals (95%)
- Cohen's d (effect size)

#### 6. Results Generation Module

```python
src/zero_day_defense/evaluation/
├── results/
│   ├── __init__.py
│   ├── latex_generator.py    # LaTeX 테이블 생성
│   ├── plot_generator.py     # Matplotlib 플롯 생성
│   ├── case_study.py         # Case study 분석
│   └── report_writer.py      # 종합 리포트 작성
```

**Output Formats:**

1. **LaTeX Tables:**
```latex
\begin{table}[t]
\centering
\caption{Performance Comparison}
\begin{tabular}{lcccc}
\toprule
Method & Precision & Recall & F1-Score & Lead Time (days) \\
\midrule
Random & 0.12 & 0.50 & 0.19 & - \\
CVSS-only & 0.45 & 0.52 & 0.48 & 23.4 \\
EPSS-only & 0.51 & 0.58 & 0.54 & 31.2 \\
Ours (no LLM) & 0.68*** & 0.65*** & 0.66*** & 42.7 \\
Ours (full) & \textbf{0.73***} & \textbf{0.68***} & \textbf{0.70***} & \textbf{45.3} \\
\bottomrule
\end{tabular}
\end{table}
```

2. **Plots:**
- ROC curves (all methods)
- Precision-Recall curves
- Feature importance bar chart
- Lead time distribution histogram
- Confusion matrices

3. **Case Studies:**
- Timeline visualization
- Signal strength over time
- Prediction confidence evolution
- Narrative explanation

## Data Models

### Experiment Configuration

```python
@dataclass
class ExperimentConfig:
    """Configuration for paper experiments"""
    
    # Dataset
    min_cves: int = 100
    min_cvss: float = 7.0
    prediction_window_days: int = 90
    
    # Validation
    top_k_values: List[int] = field(default_factory=lambda: [10, 20, 50, 100])
    cross_validation_folds: int = 5
    
    # Baselines
    baseline_methods: List[str] = field(default_factory=lambda: [
        "cvss", "epss", "random", "frequency"
    ])
    
    # Ablation
    ablation_configs: List[str] = field(default_factory=lambda: [
        "full", "no_commits", "no_prs", "no_issues", 
        "no_graph", "no_llm", "signals_only"
    ])
    
    # Statistical
    confidence_level: float = 0.95
    significance_threshold: float = 0.05
    bootstrap_iterations: int = 1000
    
    # Output
    output_dir: Path = Path("results/paper")
    generate_latex: bool = True
    generate_plots: bool = True
    plot_format: str = "pdf"
```

### Validation Result

```python
@dataclass
class ValidationResult:
    """Result of historical validation"""
    
    cve_id: str
    repository: str
    disclosure_date: datetime
    cutoff_date: datetime
    
    # Prediction
    predicted: bool
    prediction_rank: Optional[int]
    prediction_score: Optional[float]
    lead_time_days: Optional[int]
    
    # Classification
    true_positive: bool
    false_positive: bool
    true_negative: bool
    false_negative: bool
    
    # Metadata
    cvss_score: float
    vulnerability_type: str
    signals_collected: Dict[str, int]
```

### Performance Metrics

```python
@dataclass
class PerformanceMetrics:
    """Comprehensive performance metrics"""
    
    # Basic metrics
    precision: float
    recall: float
    f1_score: float
    accuracy: float
    
    # ROC metrics
    tpr: float  # True Positive Rate
    fpr: float  # False Positive Rate
    roc_auc: float
    
    # Prediction quality
    avg_lead_time: float
    median_lead_time: float
    coverage: float  # % of CVEs predicted
    
    # Confusion matrix
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    
    # Statistical
    confidence_interval: Tuple[float, float]
    p_value: Optional[float]
    
    # Metadata
    method_name: str
    top_k: int
    num_cves: int
```

## Error Handling

### Temporal Leakage Prevention

```python
class TemporalLeakageError(Exception):
    """Raised when data from after cutoff date is used"""
    pass

def validate_temporal_correctness(data, cutoff_date):
    """Ensure no data after cutoff_date is used"""
    for item in data:
        if item.timestamp > cutoff_date:
            raise TemporalLeakageError(
                f"Data from {item.timestamp} used with cutoff {cutoff_date}"
            )
```

### Data Quality Issues

```python
class InsufficientDataError(Exception):
    """Raised when CVE lacks sufficient data for evaluation"""
    pass

def validate_cve_data(cve_data):
    """Validate CVE has sufficient data"""
    if not cve_data.github_repo:
        raise InsufficientDataError("No GitHub repository")
    
    if len(cve_data.commits) < 10:
        raise InsufficientDataError("Insufficient commit history")
```

### Experiment Failures

```python
class ExperimentError(Exception):
    """Base class for experiment errors"""
    pass

# Graceful degradation: log error and continue
try:
    result = run_experiment(config)
except ExperimentError as e:
    logger.error(f"Experiment failed: {e}")
    results.append(None)  # Mark as failed
    continue  # Continue with next experiment
```

## Testing Strategy

### Unit Tests

```python
tests/evaluation/
├── test_temporal_splitter.py
├── test_metrics_calculator.py
├── test_baselines.py
├── test_ablation.py
└── test_statistics.py
```

**Key Test Cases:**
- Temporal correctness (no data leakage)
- Metrics calculation accuracy
- Baseline method correctness
- Statistical test validity
- Output format correctness

### Integration Tests

```python
tests/integration/
├── test_full_validation.py
├── test_baseline_comparison.py
└── test_ablation_study.py
```

**Test Scenarios:**
- End-to-end validation pipeline
- Multiple baseline comparison
- Complete ablation study
- Results generation

### Validation Tests

```python
tests/validation/
├── test_log4shell_case.py
└── test_known_cves.py
```

**Known Cases:**
- Log4Shell (CVE-2021-44228)
- Spring4Shell (CVE-2022-22965)
- Text4Shell (CVE-2022-42889)

## Performance Considerations

### Computational Efficiency

1. **Caching**: Cache GitHub API responses
2. **Parallel Processing**: Run multiple validations in parallel
3. **Incremental Updates**: Skip already-processed CVEs
4. **Batch Processing**: Process CVEs in batches

### Memory Management

1. **Streaming**: Process large datasets in chunks
2. **Cleanup**: Delete intermediate results after aggregation
3. **Compression**: Compress stored predictions

### API Rate Limiting

1. **GitHub API**: Respect rate limits (5000/hour with token)
2. **NVD API**: 6 seconds between requests (without key)
3. **Retry Logic**: Exponential backoff on failures

## Deployment

### Directory Structure

```
results/paper/
├── dataset/
│   ├── cves.jsonl
│   ├── statistics.json
│   └── distributions.pdf
├── validation/
│   ├── results_by_cve.jsonl
│   ├── metrics_by_method.json
│   └── confusion_matrices.pdf
├── baselines/
│   ├── cvss_results.json
│   ├── epss_results.json
│   └── comparison_table.tex
├── ablation/
│   ├── feature_importance.json
│   ├── component_contributions.pdf
│   └── ablation_table.tex
├── case_studies/
│   ├── log4shell/
│   │   ├── timeline.pdf
│   │   ├── signals.json
│   │   └── narrative.md
│   └── spring4shell/
│       └── ...
└── summary/
    ├── paper_results.tex
    ├── all_figures.pdf
    └── experiment_log.txt
```

### Reproducibility Package

```
reproducibility/
├── README.md              # Setup instructions
├── requirements.txt       # Python dependencies
├── config.yaml           # Experiment configuration
├── data/                 # Collected dataset
├── scripts/              # Experiment scripts
└── results/              # Expected results
```

## Security Considerations

1. **API Keys**: Store in environment variables, never commit
2. **Data Privacy**: Anonymize any sensitive information
3. **Rate Limiting**: Respect API terms of service
4. **Data Storage**: Secure storage of collected data

## Future Extensions

1. **More Baselines**: ML-based baselines (Random Forest, XGBoost)
2. **Cross-Ecosystem**: Extend to npm, Maven, etc.
3. **Real-Time Monitoring**: Deploy as continuous monitoring system
4. **Interactive Dashboard**: Web-based results exploration
5. **Automated Paper Writing**: Generate paper sections from results
