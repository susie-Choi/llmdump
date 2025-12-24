# LLMDump 사용 가이드

## 환경 설정

### 1. 의존성 설치

```bash
pip install -e .
```

### 2. 환경 변수 설정

`.env` 파일 생성:

```bash
GITHUB_TOKEN=your_github_token
GEMINI_API_KEY=your_gemini_api_key
NEO4J_URI=bolt://localhost:7687
NEO4J_PASSWORD=your_password
```

## 주요 기능

### AI CVE 분석

AI/ML 관련 CVE를 수집하고 분석합니다.

```bash
python src/scripts/analyze_ai_cve.py
```

출력:
- `submission/data/analysis/ai_cves.jsonl` - AI 관련 CVE 목록
- `submission/data/analysis/summary.json` - 분석 요약
- `submission/data/analysis/figures/` - 시각화 결과

### LLM 취약점 탐지 실험

GitHub 프로젝트의 코드를 LLM으로 분석하여 취약점을 탐지합니다.

```bash
# 1. 커밋 수집
python src/scripts/collect_vulnerable_code.py

# 2. LLM 분석
python src/scripts/experiment_code_analysis.py
```

## 데이터 구조

### 입력 데이터

```
data/input/
├── cve.jsonl      # NVD CVE 데이터
├── epss.jsonl     # EPSS 점수
└── kev.jsonl      # KEV 목록
```

### 분석 결과

```
submission/data/analysis/
├── ai_cves.jsonl           # AI 관련 CVE
├── summary.json            # 분석 요약
├── figures/                # 시각화
├── smolagents/             # 실험 데이터
└── experiment/             # 실험 결과
```

## LLM 프롬프트

취약점 탐지 실험에서 사용하는 프롬프트:

```
You are a security researcher doing a code audit.
Analyze this code for security vulnerabilities.

FILE: {filename}
COMMIT: {sha}
MESSAGE: {message}

```python
{code}
```

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
    "findings": [
        {
            "type": "vulnerability type",
            "severity": "LOW/MEDIUM/HIGH/CRITICAL",
            "location": "function or line",
            "description": "what the issue is",
            "cwe": "CWE-XXX if known"
        }
    ],
    "confidence": 0.0-1.0
}
```

- **모델**: Gemini 2.5 Flash
- **입력**: 파일명, 커밋 SHA, 커밋 메시지, 코드
- **출력**: JSON 형식의 취약점 분석 결과

## API 키 발급

- **GitHub Token**: https://github.com/settings/tokens
- **Gemini API Key**: https://makersuite.google.com/app/apikey
