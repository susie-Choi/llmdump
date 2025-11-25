# Temporal Validation 개선 방안

## 문제점: 단순 Temporal Split의 한계

### 문제 1: Distribution Shift
```
Train: 2015년 이전 CVE (오래된 패턴)
Test:  2020년 이후 CVE (최신 패턴)

→ Train과 Test의 분포가 너무 다름
→ 모델이 과거 패턴만 학습해서 최신 패턴 못 맞춤
```

### 문제 2: Loss 차이
- Train loss: 낮음 (과거 패턴에 overfit)
- Test loss: 높음 (최신 패턴 못 맞춤)
- → 모델이 일반화 못함

## 해결 방안

### 방안 1: Rolling Window Cross-Validation (추천)

시간 윈도우를 이동시키면서 학습/테스트:

```
Fold 1: Train [2015-2017] → Test [2018]
Fold 2: Train [2016-2018] → Test [2019]
Fold 3: Train [2017-2019] → Test [2020]
Fold 4: Train [2018-2020] → Test [2021]
...
```

**장점:**
- Train과 Test의 시간 차이가 작음 (1-2년)
- 분포 변화를 점진적으로 학습
- 여러 시점에서 성능 측정 가능

**단점:**
- 계산 비용 증가
- 각 fold마다 모델 재학습 필요

### 방안 2: Stratified Temporal Split

각 시간대에서 균등하게 샘플링:

```
2015-2017: Train 70%, Test 30%
2018-2020: Train 70%, Test 30%
2021-2023: Train 70%, Test 30%
```

**장점:**
- Train과 Test 모두 다양한 시간대 포함
- 분포 차이 최소화

**단점:**
- 여전히 미래 정보 사용 가능성 (주의 필요)
- Temporal leakage 방지 로직 필요

### 방안 3: Leave-One-Out with Temporal Constraints (가장 엄격)

각 CVE를 테스트로, 나머지 중 **그 CVE보다 이전** 데이터만 학습:

```python
for test_cve in all_cves:
    test_date = get_cve_date(test_cve)
    
    # Train: 이 테스트 CVE보다 이전 CVE만 사용
    train_cves = [c for c in all_cves 
                  if get_cve_date(c) < test_date]
    
    # Test: 이 CVE 발표 전 시점에서 예측
    prediction_date = test_date - timedelta(days=30)
    signals = collect_signals_before(prediction_date)
    
    model.fit(train_cves)
    prediction = model.predict(signals)
```

**장점:**
- 가장 현실적인 시나리오
- Temporal leakage 완전 방지
- 각 CVE마다 독립적 평가

**단점:**
- 계산 비용 매우 높음 (CVE마다 재학습)
- 초기 CVE는 학습 데이터 부족

### 방안 4: Historical Backtesting (실용적)

각 CVE에 대해 실제 예측 시나리오 시뮬레이션:

```python
for cve in test_cves:
    disclosure_date = get_cve_date(cve)
    prediction_date = disclosure_date - timedelta(days=30)
    
    # Train: 이 CVE보다 이전 모든 CVE
    train_cves = [c for c in all_cves 
                  if get_cve_date(c) < disclosure_date]
    
    # Signals: prediction_date 이전만 수집
    signals = collect_signals(
        repo=get_repo(cve),
        until=prediction_date  # ⚠️ CVE 발표일 이전!
    )
    
    model.fit(train_cves)
    prediction = model.predict(signals)
    
    # Evaluate
    if prediction.is_vulnerable:
        lead_time = (disclosure_date - prediction_date).days
        record_success(cve, lead_time)
```

**장점:**
- 실제 사용 시나리오와 동일
- Lead time 측정 가능
- 논문에 설명하기 쉬움

**단점:**
- 여전히 계산 비용 높음
- 하지만 가장 현실적

## 추천: 하이브리드 접근

### Phase 1: Rolling Window (개발/튜닝)
- 빠른 반복
- 하이퍼파라미터 튜닝
- 모델 선택

### Phase 2: Historical Backtesting (최종 평가)
- 논문 결과
- 실제 성능 측정
- Lead time 분석

## 구현 예시

```python
def rolling_window_cv(cves, window_years=3, test_years=1):
    """
    Rolling window cross-validation
    
    Args:
        cves: List of CVEs with dates
        window_years: Training window size (years)
        test_years: Test window size (years)
    """
    results = []
    
    # Sort by date
    sorted_cves = sorted(cves, key=lambda x: x['date'])
    start_year = sorted_cves[0]['date'].year
    end_year = sorted_cves[-1]['date'].year
    
    # Rolling windows
    for train_start_year in range(start_year, end_year - window_years - test_years + 1):
        train_end_year = train_start_year + window_years
        test_start_year = train_end_year
        test_end_year = test_start_year + test_years
        
        # Split
        train_cves = [c for c in sorted_cves 
                     if train_start_year <= c['date'].year < train_end_year]
        test_cves = [c for c in sorted_cves 
                    if test_start_year <= c['date'].year < test_end_year]
        
        if len(train_cves) == 0 or len(test_cves) == 0:
            continue
        
        # Train
        model.fit(train_cves)
        
        # Test (with temporal constraints)
        for test_cve in test_cves:
            prediction_date = test_cve['date'] - timedelta(days=30)
            signals = collect_signals_before(test_cve['repo'], prediction_date)
            prediction = model.predict(signals)
            
            results.append({
                'fold': f"{train_start_year}-{train_end_year}",
                'test_cve': test_cve['id'],
                'success': prediction.is_vulnerable,
                'lead_time': (test_cve['date'] - prediction_date).days if prediction.is_vulnerable else None
            })
    
    return results


def historical_backtesting(cves, prediction_days_before=30):
    """
    Historical backtesting: 가장 현실적인 평가
    
    Args:
        cves: List of CVEs with dates
        prediction_days_before: How many days before CVE disclosure to predict
    """
    results = []
    
    # Sort by date
    sorted_cves = sorted(cves, key=lambda x: x['date'])
    
    for i, test_cve in enumerate(sorted_cves):
        disclosure_date = test_cve['date']
        prediction_date = disclosure_date - timedelta(days=prediction_days_before)
        
        # Train: 이 CVE보다 이전 모든 CVE
        train_cves = sorted_cves[:i]  # 이전 CVE만
        
        if len(train_cves) < 10:  # 최소 학습 데이터 필요
            continue
        
        # Train model
        model.fit(train_cves)
        
        # Collect signals (prediction_date 이전만!)
        signals = collect_signals(
            repo=test_cve['repo'],
            until=prediction_date  # ⚠️ CVE 발표일 이전!
        )
        
        # Predict
        prediction = model.predict(signals)
        
        # Evaluate
        results.append({
            'test_cve': test_cve['id'],
            'disclosure_date': disclosure_date,
            'prediction_date': prediction_date,
            'success': prediction.is_vulnerable,
            'lead_time': prediction_days_before if prediction.is_vulnerable else None,
            'train_size': len(train_cves)
        })
    
    return results
```

## 논문에 설명할 내용

### 평가 방법

> "평가는 두 가지 방법을 사용했다:
> 
> 1. **Rolling Window Cross-Validation**: 3년 학습 윈도우, 1년 테스트 윈도우로 시간을 이동시키면서 평가하여 시간에 따른 일반화 능력을 측정했다.
> 
> 2. **Historical Backtesting**: 각 CVE에 대해 실제 예측 시나리오를 시뮬레이션했다. 각 테스트 CVE보다 이전 CVE만 학습 데이터로 사용하고, CVE 발표일 30일 전 시점에서의 신호만 사용하여 예측을 수행했다. 이를 통해 실제 조기 탐지 능력과 Lead Time을 측정했다."

### 그래프

1. **Rolling Window Performance**: 각 fold별 성능 변화
2. **Historical Backtesting Results**: CVE별 성공/실패, Lead Time 분포
3. **Train/Test Distribution Comparison**: 시간대별 CVE 분포 (분포 차이 확인)


