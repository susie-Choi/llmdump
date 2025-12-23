# Implementation Plan: AI Threat Analyzer

## Overview

AI 시스템 위협 분석 도구를 구현합니다. 기존 llmdump 코드베이스를 단순화하고, AI 위협 분석에 집중하는 새로운 모듈을 추가합니다.

## Tasks

- [x] 1. 프로젝트 구조 설정 및 기존 코드 정리
  - [x] 1.1 threats/ 모듈 디렉토리 생성
    - `src/llmdump/threats/` 디렉토리 및 `__init__.py` 생성
    - _Requirements: 7.1, 7.2_
  - [x] 1.2 cases/ 모듈 디렉토리 생성
    - `src/llmdump/cases/` 디렉토리 및 `__init__.py` 생성
    - _Requirements: 7.1, 7.2_
  - [x] 1.3 experiment/ 모듈 디렉토리 생성
    - `src/llmdump/experiment/` 디렉토리 및 `__init__.py` 생성
    - _Requirements: 7.1, 7.2_

- [x] 2. 위협 분류 체계 구현 (Threat Taxonomy)
  - [x] 2.1 taxonomy.py 구현
    - AttackVector, AttackSurface, Severity, AffectedComponent Enum 정의
    - ThreatClassification dataclass 구현
    - _Requirements: 1.1, 1.2, 1.3, 1.4_
  - [ ]* 2.2 Property test: Threat Classification Completeness
    - **Property 1: Threat Classification Completeness**
    - **Validates: Requirements 1.1, 1.2, 1.3, 1.4**

- [x] 3. Prompt Injection 탐지기 구현
  - [x] 3.1 detector.py 기본 구조 구현
    - InjectionFinding dataclass 정의
    - InjectionDetector 클래스 기본 구조
    - _Requirements: 4.1, 4.4, 4.5, 4.6_
  - [x] 3.2 직접 주입 탐지 구현
    - DIRECT_PATTERNS 정의 및 _detect_direct() 메서드
    - _Requirements: 4.1_
  - [x] 3.3 간접 주입 탐지 구현
    - INDIRECT_PATTERNS 정의 및 _detect_indirect() 메서드
    - _Requirements: 4.2_
  - [x] 3.4 인코딩된 페이로드 탐지 구현
    - ENCODED_PATTERNS 정의 및 _detect_encoded() 메서드
    - base64, URL 인코딩 디코딩 로직
    - _Requirements: 4.3_
  - [ ]* 3.5 Property test: Injection Detection Completeness
    - **Property 3: Injection Detection Completeness**
    - **Validates: Requirements 4.1, 4.2, 4.3, 4.4, 4.5, 4.6**
  - [ ]* 3.6 Property test: Confidence Score Bounds
    - **Property 5: Confidence Score Bounds**
    - **Validates: Requirements 4.6**

- [x] 4. Checkpoint - 탐지기 테스트
  - Ensure all tests pass, ask the user if questions arise.

- [x] 5. MCP 분석기 구현
  - [x] 5.1 analyzer.py 기본 구조 구현
    - MCPVulnerability dataclass 정의
    - MCPAnalyzer 클래스 기본 구조
    - _Requirements: 3.1, 3.5_
  - [x] 5.2 Tool Poisoning 탐지 구현
    - POISONING_PATTERNS 정의 및 analyze_tool_description() 메서드
    - _Requirements: 3.1_
  - [x] 5.3 안전하지 않은 실행 패턴 탐지 구현
    - UNSAFE_EXECUTION_PATTERNS 정의 및 analyze_tool_code() 메서드
    - _Requirements: 3.2, 3.3_
  - [x] 5.4 MCP 서버 분석 구현
    - analyze_mcp_server() 메서드
    - _Requirements: 3.4_
  - [ ]* 5.5 Property test: MCP Analysis Completeness
    - **Property 4: MCP Analysis Completeness**
    - **Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5**

- [-] 6. 케이스 스터디 생성기 구현
  - [x] 6.1 case_study.py 기본 구조 구현
    - Timeline, CaseStudy dataclass 정의
    - CaseStudyGenerator 클래스 기본 구조
    - _Requirements: 2.1, 2.2, 2.3_
  - [x] 6.2 React2Shell 케이스 데이터 추가
    - KNOWN_CASES에 react2shell 데이터 추가
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5_
  - [x] 6.3 MCP Tool Poisoning 케이스 데이터 추가
    - KNOWN_CASES에 mcp_tool_poisoning 데이터 추가
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5_
  - [x] 6.4 LaTeX 출력 구현
    - CaseStudy.to_latex() 메서드
    - _Requirements: 8.1, 8.5_
  - [ ]* 6.5 Property test: Case Study Completeness
    - **Property 2: Case Study Completeness**
    - **Validates: Requirements 2.1, 2.2, 2.3, 2.4, 2.5**

- [x] 7. Checkpoint - 케이스 스터디 테스트
  - Ensure all tests pass, ask the user if questions arise.

- [x] 8. 실험 프레임워크 구현
  - [x] 8.1 payloads.py 구현
    - ATTACK_PAYLOADS 딕셔너리 정의 (direct, indirect, encoded, tool_poisoning)
    - _Requirements: 5.2_
  - [x] 8.2 metrics.py 구현
    - ExperimentResult dataclass 정의
    - Wilson score confidence interval 계산
    - _Requirements: 5.3, 5.5_
  - [x] 8.3 runner.py 구현
    - ExperimentRunner 클래스
    - run_detection_experiment() 메서드
    - _Requirements: 5.1, 5.2, 5.3, 5.4_
  - [ ]* 8.4 Property test: Experiment Results Completeness
    - **Property 6: Experiment Results Completeness**
    - **Validates: Requirements 5.3, 5.5**

- [x] 9. CLI 명령어 구현
  - [x] 9.1 detect 명령어 구현
    - `llmdump detect --input` 및 `--file` 옵션
    - _Requirements: 4.1, 4.2, 4.3_
  - [x] 9.2 analyze-mcp 명령어 구현
    - `llmdump analyze-mcp --config` 옵션
    - _Requirements: 3.1, 3.2, 3.3, 3.4_
  - [x] 9.3 case-study 명령어 구현
    - `llmdump case-study <case_id> --output` 옵션
    - _Requirements: 2.6, 8.1_
  - [x] 9.4 experiment 명령어 구현
    - `llmdump experiment --payloads --output` 옵션
    - _Requirements: 5.1, 5.6_

- [x] 10. 방어 권고사항 모듈 구현
  - [x] 10.1 recommendations.py 구현
    - DefenseRecommendation dataclass 정의
    - RecommendationGenerator 클래스
    - _Requirements: 6.1, 6.2, 6.3, 6.5_
  - [ ]* 10.2 Property test: Recommendation Completeness
    - **Property 7: Recommendation Completeness**
    - **Validates: Requirements 6.1, 6.2, 6.3, 6.5**

- [x] 11. Final Checkpoint - 전체 테스트
  - Ensure all tests pass, ask the user if questions arise.
  - 코드 라인 수 확인 (1500줄 이하 목표)
  - _Requirements: 7.3_

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- 기존 llmdump 코드 중 spokes/, hub/, oracle/은 그대로 유지 (필요시 재사용)
- 새로운 threats/, cases/, experiment/ 모듈에 집중
- Property tests는 Hypothesis 라이브러리 사용
- 각 task는 이전 task에 의존하므로 순서대로 진행
