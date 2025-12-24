#!/usr/bin/env python3
"""
LLMDump CLI - 통합 명령줄 인터페이스

Usage:
    python -m llmdump collect --cve [--start-date DATE] [--end-date DATE]
    python -m llmdump collect --commits --repo REPO [--file FILE]
    python -m llmdump analyze --input FILE [--output FILE] [--threshold 0.7]
    python -m llmdump status
"""
import argparse
import sys
from pathlib import Path


def cmd_collect(args):
    """데이터 수집 명령"""
    if args.cve:
        from llmdump.spokes.cve import CVECollector
        collector = CVECollector()
        print(f"Collecting CVEs from {args.start_date} to {args.end_date}...")
        stats = collector.collect(
            start_date=args.start_date,
            end_date=args.end_date
        )
        print(f"Collected {stats.get('total', 0)} CVEs")
        
    elif args.commits:
        from llmdump.spokes.github_commits import GitHubCommitCollector
        if not args.repo:
            print("Error: --repo is required for commit collection")
            sys.exit(1)
        collector = GitHubCommitCollector()
        print(f"Collecting commits from {args.repo}...")
        stats = collector.collect(
            repo=args.repo,
            file_filter=args.file,
            output=args.output
        )
        print(f"Collected {stats.get('total', 0)} commits")
    else:
        print("Error: Specify --cve or --commits")
        sys.exit(1)


def cmd_analyze(args):
    """취약점 분석 명령 (Adversarial Thinking Multi-Agent)"""
    from llmdump.oracle.multiagent import MultiAgentAnalyzer
    
    analyzer = MultiAgentAnalyzer()
    print(f"Running Multi-Agent analysis on {args.input}...")
    print(f"Threshold: {args.threshold}")
    print()
    
    results = analyzer.analyze_file(
        input_file=args.input,
        output_file=args.output,
        threshold=args.threshold
    )
    print(f"\nAnalysis complete: {results.get('detected', 0)} vulnerabilities detected")


def cmd_status(args):
    """현재 상태 확인"""
    print("=" * 60)
    print("LLMDump Status")
    print("=" * 60)
    
    # 데이터 파일 확인
    data_dir = Path("data/input")
    if data_dir.exists():
        print("\n[Data Files]")
        for f in data_dir.glob("*.jsonl"):
            lines = sum(1 for _ in open(f, encoding='utf-8'))
            print(f"  {f.name}: {lines:,} records")
    
    # 분석 결과 확인
    analysis_dir = Path("submission/data/analysis")
    if analysis_dir.exists():
        print("\n[Analysis Results]")
        for f in analysis_dir.rglob("*.jsonl"):
            lines = sum(1 for _ in open(f, encoding='utf-8'))
            print(f"  {f.relative_to(analysis_dir)}: {lines:,} records")
    
    # 환경 변수 확인
    import os
    print("\n[Environment]")
    print(f"  GEMINI_API_KEY: {'✓ Set' if os.getenv('GEMINI_API_KEY') else '✗ Not set'}")
    print(f"  GITHUB_TOKEN: {'✓ Set' if os.getenv('GITHUB_TOKEN') else '✗ Not set'}")
    print()


def cli():
    """메인 CLI 엔트리포인트"""
    parser = argparse.ArgumentParser(
        prog='llmdump',
        description='LLM-Powered Zero-Day Vulnerability Prediction System'
    )
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # collect 명령
    collect_parser = subparsers.add_parser('collect', help='Collect data from various sources')
    collect_parser.add_argument('--cve', action='store_true', help='Collect CVE data from NVD')
    collect_parser.add_argument('--commits', action='store_true', help='Collect commits from GitHub')
    collect_parser.add_argument('--repo', type=str, help='GitHub repository (owner/repo)')
    collect_parser.add_argument('--file', type=str, help='Filter commits by filename')
    collect_parser.add_argument('--start-date', type=str, default='2024-01-01', help='Start date (YYYY-MM-DD)')
    collect_parser.add_argument('--end-date', type=str, default='2025-12-31', help='End date (YYYY-MM-DD)')
    collect_parser.add_argument('--output', '-o', type=str, help='Output file path')
    collect_parser.set_defaults(func=cmd_collect)
    
    # analyze 명령
    analyze_parser = subparsers.add_parser('analyze', help='Analyze commits for vulnerabilities')
    analyze_parser.add_argument('--input', '-i', type=str, required=True, help='Input JSONL file with commits')
    analyze_parser.add_argument('--output', '-o', type=str, help='Output file path')
    analyze_parser.add_argument('--threshold', '-t', type=float, default=0.7, help='Confidence threshold (default: 0.7)')
    analyze_parser.set_defaults(func=cmd_analyze)
    
    # status 명령
    status_parser = subparsers.add_parser('status', help='Check system status')
    status_parser.set_defaults(func=cmd_status)
    
    args = parser.parse_args()
    
    if args.command is None:
        parser.print_help()
        sys.exit(0)
    
    args.func(args)


if __name__ == '__main__':
    cli()
