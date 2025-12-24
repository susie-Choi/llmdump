# Scripts

이 폴더의 스크립트들은 `_archived/`로 이동되었습니다.

## 새로운 사용법

모든 기능은 CLI를 통해 사용합니다:

```bash
# 상태 확인
python -m llmdump status

# CVE 수집
python -m llmdump collect --cve --start-date 2024-01-01

# GitHub 커밋 수집
python -m llmdump collect --commits --repo owner/repo --file path/to/file.py

# 취약점 분석
python -m llmdump analyze --input data.jsonl --output results.jsonl
```

자세한 사용법은 `python -m llmdump --help`를 참조하세요.
