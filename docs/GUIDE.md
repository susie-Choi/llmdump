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

## CLI 사용법

모든 기능은 `python -m llmdump` 명령으로 실행합니다.

### 상태 확인

```bash
python -m llmdump status
```

### 데이터 수집

```bash
# CVE 데이터 수집
python -m llmdump collect --cve

# GitHub 커밋 수집
python -m llmdump collect --commits --repo owner/repo
```

### 취약점 분석

```bash
# Multi-Agent 분석 (Adversarial Thinking 적용)
python -m llmdump analyze --input data/input/commits.jsonl
```

## 데이터 구조

### 입력 데이터

```
data/input/
├── cve.jsonl      # NVD CVE 데이터
├── commits.jsonl  # GitHub 커밋
├── epss.jsonl     # EPSS 점수
└── kev.jsonl      # KEV 목록
```

### 제출용 데이터

```
submission/
├── paper/         # 논문
├── data/          # 실험 데이터
└── figures/       # Figure
```

## API 키 발급

- **GitHub Token**: https://github.com/settings/tokens
- **Gemini API Key**: https://makersuite.google.com/app/apikey
