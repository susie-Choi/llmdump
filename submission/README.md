# AI-Era CVE Analysis: Submission Package

## 프로젝트 개요

AI/ML 시스템 관련 CVE 동향 분석 및 LLM 기반 취약점 사전 탐지 연구입니다.

## 디렉토리 구조

```
submission/
├── README.md                    # 이 파일
└── data/
    └── analysis/
        ├── ai_cves.jsonl        # AI 관련 CVE 462개
        ├── summary.json         # 분석 요약
        ├── figures/             # 시각화 결과
        │   ├── fig1_cve_trend.jpg
        │   ├── fig2_ai_cve_growth.jpg
        │   ├── fig3_severity.jpg
        │   └── fig4_category.jpg
        ├── smolagents/          # LLM 탐지 실험 데이터
        │   ├── commits.json
        │   ├── commits_with_code.jsonl
        │   └── ground_truth.json
        └── experiment/          # 실험 결과
            ├── analysis_results.jsonl
            └── experiment_summary.json
```

## 주요 결과

### AI CVE 동향 (2023-2025)

| 연도 | AI 관련 CVE | 증가율 |
|------|------------|--------|
| 2023 | 54 | - |
| 2024 | 167 | +209% |
| 2025 | 241 | +44% |

- **총 462개** AI 관련 CVE 수집
- **58.2%**가 HIGH 이상 심각도
- 주요 카테고리: ML Platform, AI Service, LLM Framework, Prompt Injection

### LLM 취약점 탐지 실험

- **대상**: huggingface/smolagents
- **Ground Truth**: CVE-2025-5120 (CVSS 10.0, Sandbox Escape)
- **방법**: 전체 커밋 코드를 Gemini 2.5 Flash로 블라인드 분석
- **결과**: 실험 결과 파일 참조

## 데이터 설명

### ai_cves.jsonl

AI 관련 CVE 목록 (JSONL 형식)

```json
{
  "cve_id": "CVE-2025-5120",
  "published": "2025-07-27T08:15:25.403",
  "year": "2025",
  "description": "A sandbox escape vulnerability...",
  "cvss_score": 10.0,
  "cvss_severity": "CRITICAL",
  "cwe_ids": ["CWE-94"],
  "keyword": "huggingface",
  "category": "platform_ml"
}
```

### summary.json

분석 요약 통계

### figures/

논문용 시각화 결과 (JPG 형식)

## 재현 방법

```bash
# 1. AI CVE 분석
python src/scripts/analyze_ai_cve.py

# 2. 커밋 수집 (smolagents)
python src/scripts/collect_vulnerable_code.py

# 3. LLM 탐지 실험
python src/scripts/experiment_code_analysis.py
```

## 라이선스

MIT License
