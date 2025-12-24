# LLMDump: LLM-Based Zero-Day Vulnerability Detection

## Submission Package

이 폴더는 논문 제출용 패키지입니다.

## 구조

```
submission/
├── paper/                      # 논문
│   └── llmdump_paper.tex
├── data/                       # 실험 데이터
│   ├── ai_cves.jsonl           # AI 관련 CVE 462개
│   ├── experiment/             # 실험 결과
│   │   ├── adversarial_results.jsonl    # Adversarial Thinking 실험
│   │   └── multiagent_results.jsonl     # Multi-Agent 탐지 결과
│   └── smolagents/             # smolagents 프로젝트 커밋 데이터
└── figures/                    # 논문 Figure
    ├── fig1_cve_trend_10year.jpg
    ├── fig2_ai_cve_growth.jpg
    ├── fig3_ai_severity_dist.jpg
    └── fig4_ai_categories.jpg
```

## 주요 실험 결과

### 1. Multi-Agent 취약점 탐지 (smolagents)

- **대상**: huggingface/smolagents (CVE-2025-5120, CVSS 10.0)
- **방법**: 5개 전문 Agent로 529개 Python 커밋 분석
- **결과**: 53개 커밋 탐지, 17개(32%)가 실제 보안 관련

### 2. Adversarial Thinking 프롬프트 실험

CVE-2025-5120 패치 커밋 탐지 결과:

| 프롬프트 | 탐지 결과 | Confidence |
|---------|----------|------------|
| Baseline | ❌ MISSED | 0.9 |
| Adversarial v1 | ❌ MISSED | 0.9 |
| **Adversarial v2** | **✅ DETECTED** | 0.9 |

Adversarial v2 성공 요인: 구체적 공격 패턴(subclass walking, whitelisted module chaining)과 "Defense EXISTING ≠ Defense COMPLETE" 명시

## 재현 방법

```bash
# 설치
pip install -e .

# 상태 확인
python -m llmdump status

# 커밋 수집
python -m llmdump collect --commits --repo huggingface/smolagents

# 취약점 분석
python -m llmdump analyze --input data/input/commits.jsonl
```

## 라이선스

MIT License
