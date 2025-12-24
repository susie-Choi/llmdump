# Temporal Data Leakage 문제 및 해결 방안

## 문제점

### 현재 논문의 문제

논문에서 "CVE 발표일 기준 ±180일 Window"를 사용하는 것은 **temporal data leakage**를 일으킬 수 있습니다:

1. **모델이 CVE 발표일을 이미 알고 있음**
   - CVE 발표일을 기준으로 ±180일 Window를 잡으면, 모델이 항상 "중간값"을 예측하도록 학습될 수 있음
   - 실제로는 CVE 발표일을 모르는 상태에서 예측해야 함

2. **미래 정보 사용**
   - CVE 발표일 이후의 데이터를 사용하면, 실제 예측 시점에는 사용할 수 없는 정보를 사용하는 것

3. **평가의 왜곡**
   - ±180일 Window 내에서 평가하면 성능이 과대평가됨
   - 실제로는 CVE 발표 전 시점에서만 예측 가능해야 함

## 올바른 접근

### 1. 데이터 수집 vs 모델 학습 구분

**±180일 Window의 목적:**
- **데이터 수집 효율성**: 어떤 Commit을 수집할지 결정
- **모델 학습에는 사용하지 않음**: 학습 시에는 CVE 발표일 이전 데이터만 사용

### 2. 올바른 평가 방법

#### Temporal Split

```
Training Set: CVE 발표일 < cutoff_date
Test Set: CVE 발표일 >= cutoff_date

예: cutoff_date = 2020-01-01
- Training: 2019년 이전 CVE
- Test: 2020년 이후 CVE
```

#### Historical Backtesting

각 CVE에 대해:
1. **Prediction Point**: CVE 발표일 - N일 (예: 30일 전)
2. **Signal Collection**: Prediction Point 이전 데이터만 사용
3. **Evaluation**: Prediction Point에서 예측, 실제 CVE와 비교

```
Timeline:
┌─────────────────────────────────────────────────┐
│                                                 │
│  Signal Collection    Prediction    CVE        │
│  Period              Point          Disclosure  │
│  ────────────────>   │              │          │
│                      │              │          │
│  [Only use this]     [Predict]      [Ground   │
│                      [here]         Truth]    │
│                                                 │
└─────────────────────────────────────────────────┘
```

### 3. 수정된 그래프

#### 기존 (잘못된) 그래프
- "±180일 Window로 92.4% 탐지" → **데이터 수집 효율성**을 보여주는 것

#### 수정된 그래프
- "CVE 발표 전 N일 시점에서의 예측 성공률"
- "Temporal split에 따른 성능 변화"
- "Lead Time (CVE 발표 전 탐지 일수) 분포"

## 논문 수정 사항

### 1. ±180일 Window 설명 수정

**기존:**
> "CVE 발표일 기준 ±180일 Window를 적용했다"

**수정:**
> "데이터 수집 효율성을 위해 CVE 발표일 기준 ±180일 Window 내의 Commit을 수집했다. 
> 그러나 모델 학습 및 평가 시에는 **CVE 발표일 이전 데이터만 사용**하여 temporal data leakage를 방지했다."

### 2. 평가 방법 명시

**추가:**
> "평가는 temporal split을 사용하여 수행했다. 
> - Training: 2020년 이전 CVE (과거 패턴 학습)
> - Test: 2020년 이후 CVE (미래 예측)
> 
> 각 테스트 CVE에 대해, CVE 발표일 30일 전 시점에서의 신호만 사용하여 예측을 수행했다."

### 3. 그래프 수정

**기존 그래프:**
- Time Window vs Detection Rate (데이터 수집 효율성)

**수정된 그래프:**
- Prediction Days Before CVE vs Success Rate (실제 예측 성능)
- Temporal Split (cutoff_date) vs Performance (시간에 따른 일반화)
- Lead Time Distribution (CVE 발표 전 탐지 일수)

## 구현 예시

```python
def temporal_validation(cve_id: str, prediction_days_before: int = 30):
    """
    CVE 발표 전 시점에서 예측 시뮬레이션
    
    Args:
        cve_id: CVE ID
        prediction_days_before: CVE 발표 몇 일 전에 예측할지
    """
    # 1. CVE 발표일 확인
    cve_disclosure_date = get_cve_disclosure_date(cve_id)
    
    # 2. 예측 시점 설정 (CVE 발표 전)
    prediction_date = cve_disclosure_date - timedelta(days=prediction_days_before)
    
    # 3. 신호 수집 기간 (예측 시점 이전만)
    signal_start = prediction_date - timedelta(days=30)
    signal_end = prediction_date  # CVE 발표일 이전!
    
    # 4. 신호 수집 (temporal leakage 방지)
    signals = collect_signals(
        repository=get_repo_for_cve(cve_id),
        since=signal_start,
        until=signal_end  # ⚠️ CVE 발표일 이전만!
    )
    
    # 5. 예측 수행
    prediction = model.predict(signals)
    
    # 6. 평가
    if prediction.is_vulnerable:
        lead_time = (cve_disclosure_date - prediction_date).days
        return {
            'success': True,
            'lead_time': lead_time,
            'predicted_before_disclosure': True
        }
    else:
        return {
            'success': False,
            'lead_time': None,
            'predicted_before_disclosure': False
        }
```

## 핵심 원칙

1. **Never use future data**: CVE 발표일 이후 데이터는 절대 사용하지 않음
2. **Temporal split**: 시간 순서를 고려한 데이터 분할
3. **Historical simulation**: 실제 예측 시나리오 시뮬레이션
4. **Lead time measurement**: CVE 발표 전 얼마나 일찍 탐지했는지 측정

