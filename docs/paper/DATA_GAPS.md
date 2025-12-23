# 데이터 수집 현황 및 부족한 부분 분석

## 현재 수집된 데이터

| 데이터 타입 | 개수 | 상태 | 비고 |
|------------|------|------|------|
| CVE (NVD) | 11,441 | ✅ 충분 | Baseline으로 사용 가능 |
| EPSS | 10,026 | ✅ 충분 | CVE와 매칭됨 |
| KEV | 1,666 | ✅ 충분 | 실제 악용 확인 |
| CWE | 969 | ✅ 충분 | 취약점 분류 |
| Commits | 35,080 | ⚠️ **부족** | **3개 CVE에만 집중** |
| Exploits | 30 | ❌ 매우 부족 | 통계적 의미 없음 |
| GitHub Advisory | 3 | ❌ 매우 부족 | 통계적 의미 없음 |

## 연구 질문별 필요한 데이터 vs 현재 상태

### RQ1: Supply Chain Propagation

**필요한 데이터:**
- ✅ CVE 데이터 (11,441개)
- ❌ **패키지 의존성 그래프** (DEPENDS_ON 관계)
- ❌ **패키지 인기도** (downloads, stars, forks)
- ❌ **의존성 깊이** (dependency depth)
- ❌ **전파 타임라인** (언제 전파되었는지)

**현재 상태:**
- Neo4j에 Package 노드 33개만 있음
- DEPENDS_ON 관계 20개만 있음
- **매우 부족함**

### RQ2: Early Detection

**필요한 데이터:**
- ⚠️ Commits (35,080개 있지만 **3개 CVE에만 집중**)
- ❌ **코드 diff** (실제 변경 내용)
- ❌ **파일 변경 정보** (어떤 파일이 변경되었는지)
- ❌ **Commit 타임라인** (CVE 발표 전후 패턴)

**현재 상태:**
- Commit 메시지만 있음
- 코드 diff 없음 → **H1-2 (Code Change Pattern) 검증 불가**
- 파일 변경 정보 없음 → **H1-3 (File Concentration) 검증 불가**

### RQ3: Historical Pattern Learning

**필요한 데이터:**
- ✅ CVE 데이터 (11,441개)
- ✅ CWE 데이터 (969개)
- ✅ Commit 데이터 (일부)
- ⚠️ **유사 CVE 패턴 매칭** (구현 필요)

**현재 상태:**
- Baseline 데이터는 충분
- RAG 구현은 되어 있지만 실제 검증 데이터 부족

### RQ4: Multi-signal Integration

**필요한 데이터:**
- ⚠️ Commit 메시지 (있음)
- ❌ **코드 diff** (없음)
- ❌ **GitHub Issues** (수집 안 됨)
- ❌ **Pull Requests** (수집 안 됨)
- ❌ **PR 리뷰 정보** (없음)
- ❌ **개발자 활동 패턴** (없음)

**현재 상태:**
- `GitHubSignalsCollector`가 있지만 실제로 Issue/PR 수집 안 됨
- 코드에서 `TODO` 주석으로 표시됨:
  - `'new_contributors': 0,  # TODO: Compare with historical data`
  - `'files_modified': 0,  # TODO: Analyze commit diffs`
  - `'security_files': 0,  # TODO: Detect security-sensitive files`

## 가설별 검증 가능 여부

### Commit 레벨 가설

| 가설 | 필요한 데이터 | 현재 상태 | 검증 가능 여부 |
|------|--------------|----------|---------------|
| **H1-1**: 보안 Issue/PR 증가 패턴 | Issues, PRs | ❌ 없음 | **불가능** |
| **H1-2**: 코드 변경량 패턴 | 코드 diff | ❌ 없음 | **불가능** |
| **H1-3**: 파일 유형 집중 | 파일 변경 정보 | ❌ 없음 | **불가능** |
| **H1-4**: CWE 패턴 일반화 | CVE, CWE, Commits | ⚠️ 부분적 | **제한적 가능** |

### Contributor 레벨 가설

| 가설 | 필요한 데이터 | 현재 상태 | 검증 가능 여부 |
|------|--------------|----------|---------------|
| **H2-1**: 경험 효과 | 개발자 히스토리 | ❌ 없음 | **불가능** |
| **H2-2**: 개발자 이탈 | 개발자 활동 패턴 | ❌ 없음 | **불가능** |
| **H2-3**: Code Review 효과 | PR 리뷰 정보 | ❌ 없음 | **불가능** |

### Supply Chain 레벨 가설

| 가설 | 필요한 데이터 | 현재 상태 | 검증 가능 여부 |
|------|--------------|----------|---------------|
| **H3-1**: Amplification Effect | 의존성 그래프 | ❌ 매우 부족 | **불가능** |
| **H3-2**: 전파 속도 | 의존성 타임라인 | ❌ 없음 | **불가능** |
| **H3-3**: Popularity Paradox | 패키지 인기도 | ❌ 없음 | **불가능** |

## 심각한 데이터 부족 문제

### 1. Commit 데이터가 3개 CVE에만 집중

**문제:**
- CVE-2011-3188 (Linux Kernel): 32,675개
- CVE-2012-3503 (Katello): 2,011개
- CVE-2012-4406 (OpenStack Swift): 394개

**영향:**
- 일반화 불가능 (3개 프로젝트만)
- 통계적 유의성 부족
- 프로젝트 특성에 따른 편향

**필요:**
- 최소 50-100개 CVE에 대한 Commit 데이터
- 다양한 프로젝트 (Python, Java, JavaScript 등)
- 다양한 CWE 유형

### 2. 코드 diff 데이터 없음

**문제:**
- Commit 메시지만으로는 취약점 도입 여부 판단 불가
- H1-2, H1-3 가설 검증 불가능

**필요:**
- 각 Commit의 실제 코드 변경 (diff)
- 변경된 파일 경로 및 유형
- 추가/삭제된 라인 수

### 3. GitHub 행동 신호 부족

**문제:**
- Issues, PRs 수집 안 됨
- H1-1, H2-3 가설 검증 불가능

**필요:**
- 보안 관련 Issues
- Pull Requests 및 리뷰 정보
- 개발자 논의 패턴

### 4. Supply Chain 데이터 부족

**문제:**
- Package 33개만 있음
- DEPENDS_ON 관계 20개만 있음
- RQ1, H3-1~H3-3 검증 불가능

**필요:**
- 최소 1,000개 패키지
- 의존성 그래프 (깊이 3+)
- 패키지 인기도 데이터

## 우선순위별 데이터 수집 계획

### Priority 1: 필수 (논문 핵심 주장)

1. **Commit 데이터 확장**
   - 목표: 50-100개 CVE에 대한 Commit
   - 방법: KEV 등록 CVE 우선, 다양한 프로젝트
   - 예상 시간: 2-3주

2. **코드 diff 수집**
   - 목표: 모든 Commit의 실제 변경 내용
   - 방법: GitHub API `commits/{sha}` 엔드포인트
   - 예상 시간: 1-2주

3. **파일 변경 정보**
   - 목표: 변경된 파일 경로, 유형
   - 방법: Commit diff에서 추출
   - 예상 시간: 1주

### Priority 2: 중요 (가설 검증)

4. **GitHub Issues/PRs**
   - 목표: 보안 관련 Issues, PRs
   - 방법: GitHub API Issues, Pull Requests 엔드포인트
   - 예상 시간: 2주

5. **개발자 활동 패턴**
   - 목표: Contributor 경험, 활동 히스토리
   - 방법: GitHub API Users, Contributors 엔드포인트
   - 예상 시간: 2주

### Priority 3: 보완 (Supply Chain)

6. **패키지 의존성 그래프**
   - 목표: 1,000개 패키지, 깊이 3+
   - 방법: PyPI/npm API, requirements.txt 분석
   - 예상 시간: 3-4주

7. **패키지 인기도**
   - 목표: downloads, stars, forks
   - 방법: PyPI/npm API, GitHub API
   - 예상 시간: 1주

## 논문 수정 제안

### 현재 한계 명시

논문에 다음을 추가해야 함:

> "현재 데이터셋의 한계점:
> 
> 1. **Commit 데이터**: 3개 CVE에만 집중되어 있어 일반화에 한계가 있다. 향후 50-100개 CVE로 확장 예정이다.
> 
> 2. **코드 diff 부재**: Commit 메시지만으로는 취약점 도입 여부를 정확히 판단하기 어려워, 코드 diff 분석이 필요하다.
> 
> 3. **GitHub 행동 신호 부족**: Issues, PRs 데이터가 부족하여 H1-1, H2-3 가설 검증이 제한적이다.
> 
> 4. **Supply Chain 데이터 부족**: 패키지 의존성 그래프가 부족하여 RQ1, H3-1~H3-3 검증이 어렵다."

### 연구 범위 조정

현재 데이터로 검증 가능한 것만 논문에 포함:

**검증 가능:**
- ✅ CVE 발표 전 Commit 탐지 가능성 (제한적)
- ✅ 키워드 기반 보안 Commit 분류
- ✅ CWE 패턴 분석 (기본적)

**검증 불가능 (논문에서 제외 또는 "향후 연구"로):**
- ❌ 코드 변경량 패턴 (H1-2)
- ❌ 파일 유형 집중 (H1-3)
- ❌ 개발자 경험 효과 (H2-1~H2-3)
- ❌ Supply Chain 전파 (RQ1, H3-1~H3-3)

## 결론

**현재 데이터로는 논문의 핵심 주장을 검증하기 어렵습니다.**

**권장 사항:**
1. **데이터 수집 우선**: Priority 1 항목부터 수집
2. **연구 범위 축소**: 검증 가능한 가설만 포함
3. **향후 연구 명시**: 부족한 데이터로 인한 한계와 향후 계획 명시






