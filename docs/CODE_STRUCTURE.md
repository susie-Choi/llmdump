# LLMDump 코드 구조

LLMDump는 LLM 기반 Zero-Day 취약점 예측 시스템입니다. 이 문서는 코드 구조와 각 모듈의 역할을 설명합니다.

## 디렉토리 구조

```
llmdump/
├── src/
│   ├── llmdump/              # 메인 패키지
│   │   ├── spokes/           # 데이터 수집 모듈
│   │   ├── hub/              # Neo4j 연동 모듈
│   │   ├── oracle/           # LLM 분석 모듈
│   │   └── ...               # 기타 (미사용)
│   └── scripts/              # 실행 스크립트
├── config/                   # 설정 파일
├── data/                     # 데이터 저장소
├── docs/                     # 문서
└── submission/               # 논문 제출용 데이터
```

---

## 메인 패키지 (`src/llmdump/`)

### 1. Spokes - 데이터 수집 (`spokes/`)

다양한 소스에서 취약점 관련 데이터를 수집합니다.

| 파일 | 클래스 | 역할 |
|------|--------|------|
| `base.py` | `BaseCollector` | 모든 Collector의 기본 클래스 |
| `cve.py` | `CVECollector` | NVD API에서 CVE 데이터 수집 |
| `epss.py` | `EPSSCollector` | FIRST API에서 EPSS 점수 수집 |
| `kev.py` | `KEVCollector` | CISA KEV 카탈로그 수집 |
| `cwe.py` | `CWECollector` | CWE 분류 데이터 수집 |
| `github.py` | `GitHubSignalsCollector` | GitHub 커밋/PR/이슈 수집 |
| `github_advisory.py` | `GitHubAdvisoryCollector` | GitHub Security Advisory 수집 |
| `exploit_db.py` | `ExploitDBCollector` | Exploit-DB 데이터 수집 |
| `package.py` | `PackageCollector` | 패키지 의존성 정보 수집 |

**사용 예시:**
```python
from llmdump.spokes import CVECollector

collector = CVECollector()
stats = collector.collect(start_date="2024-01-01", end_date="2024-12-31")
```

### 2. Hub - Neo4j 연동 (`hub/`)

Neo4j 그래프 데이터베이스와의 연동을 담당합니다.

| 파일 | 클래스 | 역할 |
|------|--------|------|
| `connection.py` | `Neo4jConnection` | Neo4j 연결 관리 (Context Manager) |
| `loader.py` | `DataLoader` | JSONL 데이터를 Neo4j에 로드 |
| `query.py` | `HubQuery` | 그래프 쿼리 유틸리티 |
| `supply_chain.py` | - | 공급망 분석 쿼리 |

**사용 예시:**
```python
from llmdump.hub import Neo4jConnection, DataLoader

with Neo4jConnection() as conn:
    loader = DataLoader(conn)
    loader.load_cve_data(Path("data/input/cve.jsonl"))
```

### 3. Oracle - LLM 분석 (`oracle/`)

LLM(Gemini)을 사용한 취약점 분석 및 예측을 수행합니다.

| 파일 | 클래스 | 역할 |
|------|--------|------|
| `predictor.py` | `VulnerabilityOracle` | 프로젝트 전체 취약점 위험 예측 |
| `commit_analyzer.py` | `CommitAnalyzer` | 개별 커밋의 취약점 분석 |
| `integrated_oracle.py` | `IntegratedOracle` | RAG 통합 분석 |
| `prompts/` | - | LLM 프롬프트 템플릿 |

**사용 예시:**
```python
from llmdump.oracle import VulnerabilityOracle

oracle = VulnerabilityOracle(use_rag=True)
prediction = oracle.predict(package="django/django", days_back=30)
```

---

## 실행 스크립트 (`src/scripts/`)

### 데이터 수집

| 스크립트 | 역할 | 사용법 |
|----------|------|--------|
| `collect_data.py` | 통합 데이터 수집 | `python collect_data.py --all` |
| `collect_vulnerable_code.py` | 특정 프로젝트 커밋 수집 | `python collect_vulnerable_code.py` |

**collect_data.py 옵션:**
```bash
# 전체 수집
python src/scripts/collect_data.py --all

# 개별 수집
python src/scripts/collect_data.py --cve --start-date 2024-01-01
python src/scripts/collect_data.py --epss
python src/scripts/collect_data.py --kev
```

### Neo4j 로딩

| 스크립트 | 역할 | 사용법 |
|----------|------|--------|
| `load_to_neo4j.py` | 수집된 데이터를 Neo4j에 로드 | `python load_to_neo4j.py --all` |

```bash
# 전체 로드
python src/scripts/load_to_neo4j.py --all

# 개별 로드
python src/scripts/load_to_neo4j.py --cve
python src/scripts/load_to_neo4j.py --epss
```

### 분석 및 실험

| 스크립트 | 역할 | 사용법 |
|----------|------|--------|
| `analyze_ai_cve.py` | AI 관련 CVE 분석 및 그래프 생성 | `python analyze_ai_cve.py` |
| `experiment_code_analysis.py` | Multi-Agent 취약점 탐지 실험 | `python experiment_code_analysis.py` |
| `check_status.py` | 시스템 상태 확인 | `python check_status.py` |

**experiment_code_analysis.py:**
- CVE-2025-5120 (smolagents) 대상 Multi-Agent 실험
- 5개 전문 Agent (Code Injection, SQL Injection, XSS, Path Traversal, Deserialization)
- 390개 Python 커밋 분석
- 결과: `submission/data/analysis/experiment/multiagent_results.jsonl`

### 아카이브 (`_archived/`)

더 이상 사용하지 않는 스크립트들이 보관되어 있습니다.

---

## 데이터 구조

### 입력 데이터 (`data/input/`)

| 파일 | 내용 | 형식 |
|------|------|------|
| `cve.jsonl` | CVE 데이터 (NVD) | JSONL |
| `epss.jsonl` | EPSS 점수 | JSONL |
| `kev.jsonl` | KEV 카탈로그 | JSONL |
| `commits.jsonl` | GitHub 커밋 | JSONL |
| `exploits.jsonl` | Exploit-DB 데이터 | JSONL |
| `advisory.jsonl` | GitHub Advisory | JSONL |

### 출력 데이터 (`data/output/`)

분석 결과 및 예측 결과가 저장됩니다.

### 논문용 데이터 (`submission/data/`)

| 경로 | 내용 |
|------|------|
| `analysis/figures/` | 논문용 그래프 (JPG) |
| `analysis/smolagents/` | smolagents 커밋 데이터 |
| `analysis/experiment/` | Multi-Agent 실험 결과 |

---

## 설정 파일 (`config/`)

| 파일 | 용도 |
|------|------|
| `cve_config.yaml` | CVE 수집 설정 |
| `epss_config.yaml` | EPSS 수집 설정 |
| `exploit_config.yaml` | Exploit-DB 수집 설정 |
| `github_advisory_config.yaml` | GitHub Advisory 수집 설정 |

---

## 환경 변수 (`.env`)

```bash
# GitHub API (커밋 수집용)
GITHUB_TOKEN=your_github_token

# Google Gemini API (LLM 분석용)
GEMINI_API_KEY=your_gemini_api_key

# Neo4j Database
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=your_password
```

---

## 아키텍처 다이어그램

```
┌─────────────────────────────────────────────────────────────┐
│                        LLMDump                              │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │
│  │   Spokes    │───▶│     Hub     │◀───│   Oracle    │     │
│  │ (수집)      │    │  (Neo4j)    │    │  (LLM)      │     │
│  └─────────────┘    └─────────────┘    └─────────────┘     │
│        │                  │                  │              │
│        ▼                  ▼                  ▼              │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                    Data Layer                        │   │
│  │  data/input/*.jsonl  │  Neo4j Graph  │  Predictions  │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**데이터 흐름:**
1. **Spokes**: 외부 API에서 데이터 수집 → `data/input/*.jsonl`
2. **Hub**: JSONL 데이터를 Neo4j 그래프로 로드
3. **Oracle**: Neo4j에서 RAG 컨텍스트 조회 + LLM 분석 → 예측 결과

---

## 논문과의 매핑

| 논문 섹션 | 코드 위치 |
|-----------|-----------|
| Spokes (데이터 수집) | `src/llmdump/spokes/` |
| Hub (지식 그래프) | `src/llmdump/hub/` |
| Oracle (예측 엔진) | `src/llmdump/oracle/` |
| Multi-Agent 실험 | `src/scripts/experiment_code_analysis.py` |
| AI CVE 분석 | `src/scripts/analyze_ai_cve.py` |

---

## Quick Start

```bash
# 1. 환경 설정
cp .env.example .env
# .env 파일에 API 키 입력

# 2. 의존성 설치
pip install -e .[neo4j]

# 3. 데이터 수집
python src/scripts/collect_data.py --all

# 4. Neo4j 로드 (Docker 필요)
docker compose up -d
python src/scripts/load_to_neo4j.py --all

# 5. 상태 확인
python src/scripts/check_status.py
```
