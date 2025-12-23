# 프로젝트 현황 정리

## 핵심 목표

1. **2024-2025 동안 AI로 인한 보안 위협 증가량 측정**
   - CVE(with CVSS) 데이터로 분석
   - AI 관련 CVE 수집 및 추세 분석

2. **새로운 CVE가 등록되기 전에 탐지**
   - 개발 신호(GitHub commits, PRs, issues) 분석
   - LLM 기반 예측 시스템

## 현재 상태

### ✅ 핵심 기능 (유지 필요)

1. **AI CVE 수집 및 분석**
   - `src/scripts/collect_ai_cves.py` - 2024-2025 AI 관련 CVE 수집
   - CVSS 점수 분석 포함
   - 결과: `data/output/analysis/`

2. **CVE 예측 시스템**
   - `src/llmdump/oracle/` - 새로운 CVE 예측
   - `src/llmdump/oracle/predictor.py` - LLM 기반 예측
   - `src/llmdump/oracle/integrated_oracle.py` - 통합 예측 시스템

3. **데이터 수집 (Spokes)**
   - `src/llmdump/spokes/` - CVE, EPSS, KEV, GitHub 데이터 수집
   - 핵심 목표에 필요

4. **데이터 통합 (Hub)**
   - `src/llmdump/hub/` - Neo4j 지식 그래프 통합
   - RAG를 위한 히스토리컬 패턴 검색

### ⚠️ 부가 기능 (검토 필요)

1. **threats/ 모듈**
   - 목적: AI 위협 분석 (Prompt Injection, MCP 분석 등)
   - 사용처: CLI에서 사용 중
   - 관련성: AI 위협 분석과 관련 있지만, 핵심 목표(CVE 분석 및 예측)와는 간접적
   - 결정: 유지 또는 별도 모듈로 분리

2. **cases/ 모듈**
   - 목적: 케이스 스터디 생성 (React2Shell, MCP Tool Poisoning 등)
   - 사용처: CLI에서 사용 중
   - 관련성: 부가적인 분석 도구
   - 결정: 유지 또는 제거

3. **experiment/ 모듈**
   - 목적: 실험 프레임워크 (공격 페이로드, 메트릭 계산 등)
   - 사용처: CLI에서 사용 중
   - 관련성: 실험 및 검증에 유용하지만 핵심 기능은 아님
   - 결정: 유지 또는 제거

### ❌ 불필요한 부분 (제거 고려)

1. **LLM 생성 코드 분석 관련 코드**
   - README에 있던 "LLM-generated code analysis" 관련 내용
   - 실제 목표와 다름
   - 상태: README는 이미 수정됨

## 다음 단계

### 1. 모듈 정리 결정
- [ ] `threats/` 모듈 유지/제거 결정
- [ ] `cases/` 모듈 유지/제거 결정
- [ ] `experiment/` 모듈 유지/제거 결정

### 2. AI CVE 수집 개선
- [ ] 샘플 크기 확대 (현재 600-800개 → 더 많은 샘플)
- [ ] AI 관련 CVE 키워드 정확도 향상
- [ ] 전체 데이터셋 분석 (샘플링 없이)

### 3. 예측 시스템 개선
- [ ] Temporal validation 완성
- [ ] 더 많은 신호 통합
- [ ] Lead time 측정 및 개선

### 4. 문서화
- [ ] 프로젝트 아키텍처 문서화
- [ ] 사용 가이드 업데이트
- [ ] 연구 방법론 문서화

## 현재 분석 결과

### 2024-2025 AI CVE 분석 (샘플)

| Year | Total CVEs | Sample | AI-Related | AI % |
|------|-----------|--------|------------|------|
| 2024 | 21,559 | 600 | 0 | 0.0% |
| 2025 | 32,366 | 800 | 1 | 0.1% |

**문제점**: 샘플 크기가 작아서 실제 AI 관련 CVE를 충분히 포착하지 못할 수 있음

**개선 필요**: 
- 샘플 크기 확대
- 키워드 정확도 향상
- 전체 데이터셋 분석

