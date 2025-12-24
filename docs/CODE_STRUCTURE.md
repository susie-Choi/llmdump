# LLMDump 코드 구조

## 디렉토리 구조

```
llmdump/
├── src/llmdump/              # 메인 패키지
│   ├── cli/                  # CLI 인터페이스
│   │   └── main.py           # 진입점 (python -m llmdump)
│   ├── spokes/               # 데이터 수집 모듈
│   ├── hub/                  # Neo4j 연동 모듈
│   └── oracle/               # LLM 분석 모듈
│       └── multiagent.py     # Multi-Agent 분석기
├── config/                   # 설정 파일
├── data/                     # 데이터 저장소
├── docs/                     # 문서
└── submission/               # 논문 제출용
```

## 주요 모듈

### CLI (`cli/main.py`)

```bash
python -m llmdump status              # 상태 확인
python -m llmdump collect --cve       # CVE 수집
python -m llmdump collect --commits   # 커밋 수집
python -m llmdump analyze --input     # 취약점 분석
```

### Spokes (데이터 수집)

| 파일 | 역할 |
|------|------|
| `cve.py` | NVD API에서 CVE 수집 |
| `github_commits.py` | GitHub 커밋 수집 |
| `epss.py` | EPSS 점수 수집 |
| `kev.py` | KEV 카탈로그 수집 |

### Oracle (LLM 분석)

| 파일 | 역할 |
|------|------|
| `multiagent.py` | Multi-Agent 취약점 분석 (Adversarial Thinking) |
| `commit_analyzer.py` | 개별 커밋 분석 |

## 아키텍처

```
┌─────────────────────────────────────────────────────────────┐
│                        LLMDump CLI                          │
├─────────────────────────────────────────────────────────────┤
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
└─────────────────────────────────────────────────────────────┘
```
