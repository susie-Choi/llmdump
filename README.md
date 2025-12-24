# LLMDump: LLM-Powered Zero-Day Vulnerability Prediction

AI 시스템의 취약점을 CVE 공개 전에 탐지하는 LLM 기반 예측 시스템입니다.

## 핵심 기능

- **Multi-Agent 분석**: 5개 전문 Agent (CWE-94, CWE-89, CWE-79, CWE-22, CWE-502)
- **Adversarial Thinking**: Red Team 방법론 기반 프롬프트로 방어 우회 가능성 탐색
- **GitHub 커밋 분석**: 저장소 커밋을 수집하고 취약점 패턴 분석

## 설치 및 실행

```bash
# 1. 설치
pip install -e .

# 2. 환경 변수 설정 (.env 파일)
GITHUB_TOKEN=your_github_token
GEMINI_API_KEY=your_gemini_api_key

# 3. 테스트
python -m llmdump status
python -m llmdump analyze --input submission/data/analysis/smolagents/executor_commits.jsonl
```

## 사용법

### CLI 명령어

```bash
# 상태 확인
python -m llmdump status

# CVE 데이터 수집
python -m llmdump collect --cve --start-date 2024-01-01 --end-date 2025-12-31

# GitHub 커밋 수집
python -m llmdump collect --commits --repo huggingface/smolagents --file src/smolagents/local_python_executor.py -o data/input/commits.jsonl

# 취약점 분석
python -m llmdump analyze --input data/input/commits.jsonl --output results.jsonl --threshold 0.7
```

### Python API

```python
from llmdump.oracle.multiagent import MultiAgentAnalyzer

# 분석기 초기화
analyzer = MultiAgentAnalyzer()

# 단일 커밋 분석
result = analyzer.analyze_commit(
    filename="executor.py",
    message="Fix security issue",
    code="def execute(code): eval(code)"
)

print(f"Vulnerable: {result['summary']['is_vulnerable']}")
print(f"Detected by: {result['summary']['detected_by']}")
```

## 연구 결과

### AI CVE 동향 (2023-2025)

| 연도 | AI 관련 CVE | 증가율 | HIGH 이상 |
|------|------------|--------|----------|
| 2023 | 54 | - | 58.2% |
| 2024 | 167 | +209% | |
| 2025 | 241 | +44% | |

### CVE-2025-5120 탐지 실험

huggingface/smolagents의 Sandbox Escape 취약점 (CVSS 10.0) 탐지 실험:

| 프롬프트 | 탐지 결과 |
|---------|----------|
| Baseline | ❌ 실패 (safe 판정) |
| Adversarial v1 | ❌ 실패 |
| **Adversarial v2** | **✅ 성공** |

Adversarial Thinking 프롬프트가 방어 코드의 우회 가능성을 정확히 식별함.

## 프로젝트 구조

```
llmdump/
├── src/llmdump/
│   ├── cli/main.py           # CLI 엔트리포인트
│   ├── spokes/               # 데이터 수집
│   │   ├── cve.py            # NVD CVE 수집
│   │   └── github_commits.py # GitHub 커밋 수집
│   └── oracle/               # LLM 분석
│       └── multiagent.py     # Multi-Agent 분석기
├── data/input/               # 입력 데이터
├── submission/data/analysis/ # 분석 결과
└── docs/paper/report/        # 논문
```

## Multi-Agent 구성

| Agent | CWE | 탐지 대상 |
|-------|-----|----------|
| Code Injection | CWE-94 | eval/exec, sandbox escape |
| SQL Injection | CWE-89 | SQL 쿼리 인젝션 |
| XSS | CWE-79 | 크로스 사이트 스크립팅 |
| Path Traversal | CWE-22 | 경로 탐색 |
| Deserialization | CWE-502 | 안전하지 않은 역직렬화 |

## Adversarial Thinking 프롬프트

기존 프롬프트의 한계:
> "방어 코드가 있으면 안전하다"고 판단

개선된 프롬프트:
> "Defense EXISTING ≠ Defense being COMPLETE. Check for GAPS."

핵심 원칙:
1. 모든 방어는 우회 가능성이 있다고 가정
2. 화이트리스트 객체가 위험한 모듈로 연결될 수 있는지 확인
3. 간접 경로를 통한 공격 가능성 탐색

## 기술 스택

- Python 3.10+
- Google Gemini API
- GitHub API

## 라이선스

MIT License
