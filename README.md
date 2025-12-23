# LLMDump: LLM-Powered Zero-Day Vulnerability Prediction for AI Systems

AI 시스템 관련 CVE를 분석하고, LLM을 활용하여 취약점을 사전에 탐지하는 연구 프로젝트입니다.

## 연구 목표

1. **AI 관련 CVE 동향 분석**: 2023-2025년 AI/ML 관련 CVE 증가 추세 분석
2. **LLM 기반 취약점 탐지**: CVE 공개 전에 코드 분석을 통한 취약점 사전 탐지 가능성 검증

## 주요 결과

### AI CVE 동향 (2023-2025)

| 연도 | AI 관련 CVE | 전년 대비 증가율 |
|------|------------|----------------|
| 2023 | 54 | - |
| 2024 | 167 | +209% |
| 2025 | 241 | +44% |

- 전체 462개 AI 관련 CVE 수집 (OWASP LLM Top 10 키워드 기반)
- 58.2%가 HIGH 이상 심각도
- 주요 카테고리: ML Platform (32.5%), AI Service (28.1%), LLM Framework (18.8%)

### LLM 취약점 탐지 실험

- 대상: huggingface/smolagents (CVE-2025-5120, CVSS 10.0)
- 방법: 전체 커밋 코드를 LLM(Gemini 2.5 Flash)으로 블라인드 분석
- 프롬프트: 코드 보안 감사 요청 (CVE 정보 미제공)
- 결과: 실험 진행 중

## LLM 프롬프트

```
You are a security researcher doing a code audit.
Analyze this code for security vulnerabilities.

FILE: {filename}
COMMIT: {sha}
MESSAGE: {message}

[code]

Look for:
- Code injection / arbitrary code execution
- Sandbox escape vulnerabilities
- Unsafe eval/exec usage
- Input validation issues
- Authentication/authorization bypass
- Any other security concerns

Respond with JSON only:
{
    "has_vulnerability": true/false,
    "findings": [...],
    "confidence": 0.0-1.0
}
```

## 프로젝트 구조

```
llmdump/
├── src/
│   ├── llmdump/              # 메인 패키지
│   │   ├── spokes/           # 데이터 수집 (CVE, EPSS, KEV, GitHub)
│   │   ├── hub/              # Neo4j 통합
│   │   └── oracle/           # LLM 기반 분석
│   └── scripts/              # 실행 스크립트
│       ├── analyze_ai_cve.py           # AI CVE 분석
│       ├── collect_vulnerable_code.py  # GitHub 커밋 수집
│       └── experiment_code_analysis.py # LLM 탐지 실험
├── submission/
│   └── data/analysis/        # 분석 결과 데이터
│       ├── ai_cves.jsonl     # AI 관련 CVE 목록
│       ├── summary.json      # 분석 요약
│       └── figures/          # 시각화 결과
├── docs/
│   ├── CODE_STRUCTURE.md     # 상세 코드 구조 문서
│   └── paper/report/         # 논문
└── config/                   # 설정 파일
```

> 📖 상세한 코드 구조는 [docs/CODE_STRUCTURE.md](docs/CODE_STRUCTURE.md)를 참조하세요.

## 실행 방법

### 환경 설정

```bash
# 의존성 설치
pip install -e .

# 환경 변수 설정 (.env 파일)
GITHUB_TOKEN=your_github_token
GEMINI_API_KEY=your_gemini_api_key
```

### AI CVE 분석

```bash
# AI 관련 CVE 수집 및 분석
python src/scripts/analyze_ai_cve.py
```

### LLM 취약점 탐지 실험

```bash
# 1. 대상 프로젝트 커밋 수집
python src/scripts/collect_vulnerable_code.py

# 2. LLM 분석 실행
python src/scripts/experiment_code_analysis.py
```

## 데이터

### 입력 데이터
- `data/input/cve.jsonl`: NVD CVE 데이터
- `data/input/epss.jsonl`: EPSS 점수
- `data/input/kev.jsonl`: KEV 목록

### 분석 결과
- `submission/data/analysis/ai_cves.jsonl`: AI 관련 CVE 462개
- `submission/data/analysis/summary.json`: 분석 요약
- `submission/data/analysis/figures/`: 시각화 (fig1~fig4.jpg)

## 기술 스택

- Python 3.10+
- Google Gemini API (gemini-2.5-flash)
- Neo4j (선택)
- matplotlib, seaborn

## 참고 자료

- [NVD (National Vulnerability Database)](https://nvd.nist.gov/)
- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [FIRST EPSS](https://www.first.org/epss/)

## 라이선스

MIT License
