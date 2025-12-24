# 논문용 그래프 및 표 생성 가이드

LaTeX 논문에 필요한 그래프와 표를 자동으로 생성하는 스크립트입니다.

## 사용 방법

### 1. 환경 변수 설정

```bash
export NEO4J_URI=bolt://localhost:7687
export NEO4J_USER=neo4j
export NEO4J_PASSWORD=your_password
```

또는 `.env` 파일에 설정:

```bash
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=your_password
```

### 2. 스크립트 실행

```bash
python src/scripts/generate_paper_figures.py
```

### 3. 생성되는 파일

#### 그래프 (PNG)

`docs/paper/images/` 폴더에 생성됩니다:

- `severity_distribution.png` - CVE 심각도 분포 (파이 차트)
- `top_cwes.png` - Top 15 CWE 유형 (막대 그래프)
- `cve_timeline.png` - CVE 발표 타임라인 (라인 차트)

#### LaTeX 표

`docs/paper/tables/` 폴더에 생성됩니다:

- `data_sources.tex` - 데이터 소스 현황 표
- `neo4j_nodes.tex` - Neo4j 노드 현황 표
- `neo4j_relationships.tex` - Neo4j 관계 현황 표

### 4. LaTeX에 삽입

#### 그래프 삽입

```latex
\begin{figure}[h]
\centering
\includegraphics[width=0.8\textwidth]{images/severity_distribution.png}
\caption{CVE 심각도 분포}
\label{fig:severity}
\end{figure}
```

#### 표 삽입

```latex
\input{tables/data_sources.tex}
```

## 커스터마이징

### 다른 출력 디렉토리 사용

```bash
python src/scripts/generate_paper_figures.py \
    --output-dir docs/paper/my_images \
    --tables-dir docs/paper/my_tables
```

### Top CWE 개수 변경

스크립트 내에서 `top_n` 파라미터를 수정:

```python
generate_top_cwes_chart(
    driver,
    args.output_dir / 'top_cwes.png',
    top_n=20  # 15 → 20으로 변경
)
```

## 생성되는 표 형식

### 데이터 소스 현황 표

| 데이터 소스 | 수집 건수 | 상태 |
|------------|----------|------|
| CVE (NVD) | 11,441 | 완료 |
| EPSS | 10,026 | 완료 |
| KEV (CISA) | 1,666 | 완료 |
| GitHub Commits | 35,080 | 완료 |
| Exploits (Exploit-DB) | 30 | 완료 |
| GitHub Advisory | 3 | 완료 |

### Neo4j 노드 현황 표

| Node 유형 | 개수 | 설명 |
|----------|------|------|
| CVE | 11,441 | 취약점 정보 |
| Commit | 35,080 | GitHub Commit |
| KEV | 1,666 | 실제 악용 확인 |
| CWE | 969 | 취약점 유형 |
| ... | ... | ... |

### Neo4j 관계 현황 표

| Relationships 유형 | 개수 | 설명 |
|-------------------|------|------|
| HAS_COMMIT | 35,080 | CVE → Commit |
| RELATED_TO | 1,434 | CVE 관계 |
| HAS_CONSEQUENCE | 1,189 | CVE → Consequence |
| ... | ... | ... |

## 문제 해결

### Neo4j 연결 오류

```
❌ Error: Unable to connect to Neo4j
```

- Neo4j가 실행 중인지 확인: `docker compose ps`
- URI, 사용자명, 비밀번호 확인
- 방화벽 설정 확인

### 그래프가 생성되지 않음

```
⚠️  No severity data found
```

- Neo4j에 데이터가 로드되어 있는지 확인
- `python src/scripts/check_status.py --neo4j-only` 실행

### 한글 폰트 문제

Windows에서 한글이 깨질 경우:

```python
# 스크립트 내에서 폰트 설정 수정
plt.rcParams['font.family'] = 'Malgun Gothic'  # Windows
# 또는
plt.rcParams['font.family'] = 'AppleGothic'  # macOS
```

## 추가 그래프 생성

새로운 그래프를 추가하려면 `generate_paper_figures.py`에 함수를 추가:

```python
def generate_custom_chart(driver, output_path: Path):
    """Generate custom chart."""
    # Neo4j 쿼리
    with driver.session() as session:
        result = session.run("YOUR CYPHER QUERY")
        # 데이터 처리
    
    # matplotlib로 그래프 생성
    fig, ax = plt.subplots(figsize=(10, 6))
    # ... 그래프 그리기 ...
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()
```

그리고 `main()` 함수에서 호출:

```python
generate_custom_chart(
    driver,
    args.output_dir / 'custom_chart.png'
)
```


