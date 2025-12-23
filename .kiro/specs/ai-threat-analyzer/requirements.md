# Requirements Document

## Introduction

AI 시스템(LLM Agent, MCP, Tool Use)에 대한 새로운 보안 위협을 분석하고 탐지하는 도구를 개발합니다. React2Shell(CVE-2025-55182), MCP Tool Poisoning, Prompt Injection 등 AI 시대의 새로운 공격 벡터에 집중합니다.

### 배경

기존 보안 연구는 전통적인 소프트웨어 취약점(SQL Injection, XSS 등)에 집중했습니다. 하지만 AI Agent가 널리 사용되면서 새로운 유형의 위협이 등장했습니다:

- **Prompt Injection**: AI의 지시를 조작하여 의도하지 않은 행동 유발
- **Tool Poisoning**: MCP 서버나 Tool의 설명을 조작하여 악성 행동 유도
- **RAG Poisoning**: 검색 결과에 악성 콘텐츠를 삽입하여 AI 응답 조작
- **Agent Hijacking**: AI Agent의 권한을 탈취하여 시스템 명령 실행

### 핵심 원칙

1. **Quality over Quantity**: 소수의 고품질 케이스 스터디로 임팩트 있는 연구
2. **Real-World Focus**: 실제 발생한 취약점과 공격 사례 분석
3. **Reproducibility**: 모든 분석과 탐지 결과는 재현 가능해야 함
4. **Actionable Insights**: 방어 전략과 권고사항 제공

## Glossary

- **AI Agent**: LLM을 기반으로 도구를 사용하고 작업을 수행하는 자율 시스템
- **MCP (Model Context Protocol)**: Anthropic이 개발한 AI-도구 연결 프로토콜
- **Prompt Injection**: AI 시스템에 악성 지시를 삽입하는 공격
- **Tool Poisoning**: 도구 설명이나 응답에 악성 지시를 숨기는 공격
- **RAG (Retrieval-Augmented Generation)**: 외부 데이터를 검색하여 AI 응답을 보강하는 기술
- **RAG Poisoning**: RAG 시스템의 검색 결과를 조작하는 공격
- **Agent Hijacking**: AI Agent의 제어권을 탈취하는 공격
- **Indirect Prompt Injection**: 외부 콘텐츠(웹페이지, 문서 등)를 통한 간접적 프롬프트 주입

## Requirements

### Requirement 1: AI 위협 분류 체계 (Threat Taxonomy)

**User Story:** As a security researcher, I want a comprehensive taxonomy of AI system threats, so that I can systematically categorize and analyze new attack vectors.

#### Acceptance Criteria

1. WHEN classifying threats THEN the System SHALL categorize by attack vector (Prompt Injection, Tool Poisoning, RAG Poisoning, Agent Hijacking)
2. WHEN classifying threats THEN the System SHALL categorize by attack surface (Direct, Indirect, Supply Chain)
3. WHEN classifying threats THEN the System SHALL include severity assessment (Low, Medium, High, Critical)
4. WHEN classifying threats THEN the System SHALL document affected components (LLM, Tool, RAG, Agent)
5. WHEN a new threat is identified THEN the System SHALL map it to existing categories or create new ones
6. WHEN documenting threats THEN the System SHALL include real-world examples where available

### Requirement 2: 케이스 스터디 분석 (Case Study Analysis)

**User Story:** As a researcher, I want detailed case studies of real AI security incidents, so that I can understand attack patterns and develop defenses.

#### Acceptance Criteria

1. WHEN analyzing a case THEN the System SHALL document the attack timeline (discovery, disclosure, patch)
2. WHEN analyzing a case THEN the System SHALL identify the attack vector and technique used
3. WHEN analyzing a case THEN the System SHALL document the impact (data exfiltration, RCE, privilege escalation)
4. WHEN analyzing a case THEN the System SHALL identify what signals existed before the attack
5. WHEN analyzing a case THEN the System SHALL provide defense recommendations
6. WHEN case analysis is complete THEN the System SHALL generate publication-ready documentation
7. WHEN selecting cases THEN the System SHALL prioritize high-impact, well-documented incidents

### Requirement 3: MCP/Tool 취약점 분석 (MCP/Tool Vulnerability Analysis)

**User Story:** As a developer, I want to analyze MCP servers and tools for security vulnerabilities, so that I can identify and fix potential attack vectors.

#### Acceptance Criteria

1. WHEN analyzing an MCP server THEN the System SHALL check for Tool Poisoning vulnerabilities in tool descriptions
2. WHEN analyzing an MCP server THEN the System SHALL check for unsafe command execution patterns
3. WHEN analyzing an MCP server THEN the System SHALL check for data exfiltration risks
4. WHEN analyzing a tool THEN the System SHALL verify input validation and sanitization
5. WHEN vulnerabilities are found THEN the System SHALL assign severity scores
6. WHEN analysis is complete THEN the System SHALL generate a security report with recommendations

### Requirement 4: Prompt Injection 탐지 (Prompt Injection Detection)

**User Story:** As a security engineer, I want to detect prompt injection attempts in AI system inputs, so that I can prevent malicious manipulation.

#### Acceptance Criteria

1. WHEN scanning input THEN the System SHALL detect direct prompt injection patterns
2. WHEN scanning input THEN the System SHALL detect indirect prompt injection in external content
3. WHEN scanning input THEN the System SHALL detect encoded/obfuscated injection attempts (base64, etc.)
4. WHEN an injection is detected THEN the System SHALL classify the attack type
5. WHEN an injection is detected THEN the System SHALL estimate the potential impact
6. WHEN detection completes THEN the System SHALL provide a confidence score for each finding

### Requirement 5: 실험 프레임워크 (Experiment Framework)

**User Story:** As a researcher, I want a reproducible experiment framework, so that I can test AI system defenses against known attack patterns.

#### Acceptance Criteria

1. WHEN setting up experiments THEN the System SHALL provide a controlled test environment
2. WHEN running experiments THEN the System SHALL test against a curated set of attack payloads
3. WHEN running experiments THEN the System SHALL measure detection rates (true positive, false positive)
4. WHEN running experiments THEN the System SHALL compare against baseline defenses
5. WHEN experiments complete THEN the System SHALL generate statistical analysis with confidence intervals
6. WHEN sharing results THEN the System SHALL include all data and scripts for reproducibility

### Requirement 6: 방어 전략 권고 (Defense Recommendations)

**User Story:** As a developer, I want actionable defense recommendations, so that I can protect my AI systems from known threats.

#### Acceptance Criteria

1. WHEN providing recommendations THEN the System SHALL prioritize by threat severity
2. WHEN providing recommendations THEN the System SHALL include implementation guidance
3. WHEN providing recommendations THEN the System SHALL reference industry best practices (OWASP, etc.)
4. WHEN providing recommendations THEN the System SHALL include code examples where applicable
5. WHEN recommendations are generated THEN the System SHALL categorize by defense layer (input validation, output filtering, sandboxing)

### Requirement 7: 프로젝트 구조 단순화 (Simplified Project Structure)

**User Story:** As a maintainer, I want a simple, focused codebase, so that the project is easy to understand and extend.

#### Acceptance Criteria

1. WHEN restructuring THEN the System SHALL focus on AI threat analysis (remove unrelated CVE prediction code)
2. WHEN restructuring THEN the System SHALL maintain a flat, simple module structure
3. WHEN restructuring THEN the System SHALL keep core code under 1500 lines
4. WHEN restructuring THEN the System SHALL reuse existing data collection utilities where applicable
5. WHEN restructuring THEN the System SHALL provide clear CLI commands for each analysis type
6. WHEN restructuring is complete THEN the codebase SHALL be understandable in under 30 minutes

### Requirement 8: 논문용 출력 (Publication-Ready Output)

**User Story:** As a paper author, I want publication-ready outputs, so that I can directly use analysis results in my research paper.

#### Acceptance Criteria

1. WHEN generating output THEN the System SHALL produce LaTeX-compatible tables and figures
2. WHEN generating output THEN the System SHALL include proper citations for referenced work
3. WHEN generating output THEN the System SHALL provide statistical significance tests where applicable
4. WHEN generating output THEN the System SHALL include methodology descriptions
5. WHEN generating case studies THEN the System SHALL format them for academic publication
6. WHEN output is complete THEN the System SHALL organize files by paper section (introduction, methodology, results)
