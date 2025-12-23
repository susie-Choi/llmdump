# LLMDump Scripts

AI CVE 분석 및 LLM 취약점 탐지 실험을 위한 스크립트 모음입니다.

## 핵심 스크립트

### `analyze_ai_cve.py` - AI CVE 분석

AI/ML 관련 CVE를 수집하고 분석합니다.

```bash
python src/scripts/analyze_ai_cve.py
```

**출력**:
- `submission/data/analysis/ai_cves.jsonl` - AI 관련 CVE 목록
- `submission/data/analysis/summary.json` - 분석 요약
- `submission/data/analysis/figures/` - 시각화 결과 (fig1~fig4.jpg)

### `collect_vulnerable_code.py` - 커밋 수집

GitHub 프로젝트의 전체 커밋과 코드를 수집합니다.

```bash
python src/scripts/collect_vulnerable_code.py
```

**출력**:
- `submission/data/analysis/smolagents/commits.json` - 커밋 목록
- `submission/data/analysis/smolagents/commits_with_code.jsonl` - 코드 포함 커밋

### `experiment_code_analysis.py` - LLM 탐지 실험

수집된 코드를 LLM으로 분석하여 취약점을 탐지합니다.

```bash
python src/scripts/experiment_code_analysis.py
```

**출력**:
- `submission/data/analysis/experiment/analysis_results.jsonl` - 분석 결과
- `submission/data/analysis/experiment/experiment_summary.json` - 실험 요약

## 인프라 스크립트

### `collect_data.py` - 기본 데이터 수집

CVE, EPSS, KEV 등 기본 데이터를 수집합니다.

```bash
python src/scripts/collect_data.py --all
python src/scripts/collect_data.py --cve --start-date 2024-01-01
```

### `load_to_neo4j.py` - Neo4j 로딩

수집된 데이터를 Neo4j에 로드합니다.

```bash
python src/scripts/load_to_neo4j.py --all
```

### `check_status.py` - 상태 확인

시스템 상태를 확인합니다.

```bash
python src/scripts/check_status.py
```

## 환경 변수

`.env` 파일에 설정:

```bash
GITHUB_TOKEN=your_github_token
GEMINI_API_KEY=your_gemini_api_key
NEO4J_URI=bolt://localhost:7687
NEO4J_PASSWORD=your_password
```
