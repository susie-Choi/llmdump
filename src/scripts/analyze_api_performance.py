#!/usr/bin/env python3
"""
Analyze API performance and detect bottlenecks.

This script:
1. Measures API call speed
2. Detects rate limits
3. Identifies authentication issues
4. Recommends improvements (API keys, authentication, etc.)
"""

import sys
import time
import os
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import requests
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).parent.parent))

from llmdump.spokes.cve import CVECollector
from llmdump.spokes.github import GitHubSignalsCollector
from llmdump.spokes.epss import EPSSCollector
from llmdump.spokes.kev import KEVCollector


class APIPerformanceAnalyzer:
    """Analyze API performance and detect issues."""
    
    def __init__(self):
        self.results = defaultdict(list)
        self.rate_limit_info = {
            'github': {
                'authenticated': {'limit': 5000, 'window': 3600},  # 5000/hour
                'unauthenticated': {'limit': 60, 'window': 3600},  # 60/hour
            },
            'nvd': {
                'authenticated': {'limit': 50, 'window': 30},  # 50/30s = 6000/hour
                'unauthenticated': {'limit': 5, 'window': 30},  # 5/30s = 600/hour
            },
            'epss': {
                'authenticated': {'limit': None, 'window': None},  # No official limit
                'unauthenticated': {'limit': None, 'window': None},
            },
            'kev': {
                'authenticated': {'limit': None, 'window': None},  # Public API
                'unauthenticated': {'limit': None, 'window': None},
            },
        }
    
    def measure_api_call(self, api_name: str, func, *args, **kwargs) -> Dict[str, Any]:
        """Measure API call performance."""
        start_time = time.time()
        error = None
        status_code = None
        response_time = None
        
        try:
            result = func(*args, **kwargs)
            response_time = time.time() - start_time
            
            # Try to get status code from result
            if isinstance(result, requests.Response):
                status_code = result.status_code
            elif isinstance(result, dict) and 'status_code' in result:
                status_code = result['status_code']
            
            return {
                'api_name': api_name,
                'success': True,
                'response_time': response_time,
                'status_code': status_code,
                'error': None,
                'timestamp': datetime.now().isoformat(),
            }
        except Exception as e:
            response_time = time.time() - start_time
            error = str(e)
            
            # Detect error types
            error_type = 'unknown'
            if '401' in error or 'Unauthorized' in error:
                error_type = 'authentication'
            elif '403' in error or 'Forbidden' in error:
                error_type = 'authorization'
            elif '429' in error or 'rate limit' in error.lower():
                error_type = 'rate_limit'
            elif 'timeout' in error.lower():
                error_type = 'timeout'
            
            return {
                'api_name': api_name,
                'success': False,
                'response_time': response_time,
                'status_code': status_code,
                'error': error,
                'error_type': error_type,
                'timestamp': datetime.now().isoformat(),
            }
    
    def test_github_api(self) -> Dict[str, Any]:
        """Test GitHub API performance."""
        print("\n🔍 Testing GitHub API...")
        
        token = os.getenv("GITHUB_TOKEN")
        if not token:
            return {
                'api_name': 'github',
                'status': 'no_token',
                'recommendation': 'GitHub token이 없습니다. GITHUB_TOKEN 환경변수를 설정하세요.',
                'impact': 'Rate limit: 60/hour (비인증) → 5000/hour (인증)',
            }
        
        try:
            collector = GitHubSignalsCollector(token=token)
            
            # Test 1: Simple API call (rate limit check)
            print("  Testing rate limit endpoint...")
            url = "https://api.github.com/rate_limit"
            start = time.time()
            response = requests.get(url, headers=collector.headers, timeout=10)
            response_time = time.time() - start
            
            if response.status_code == 200:
                rate_limit_data = response.json()['resources']['core']
                remaining = rate_limit_data['remaining']
                limit = rate_limit_data['limit']
                reset_time = datetime.fromtimestamp(rate_limit_data['reset'])
                
                # Test 2: Actual API call
                print("  Testing commits API call...")
                test_result = self.measure_api_call(
                    'github',
                    collector._collect_commits,
                    'torvalds/linux',
                    datetime.now() - timedelta(days=1)
                )
                
                return {
                    'api_name': 'github',
                    'status': 'working',
                    'authenticated': True,
                    'rate_limit': {
                        'remaining': remaining,
                        'limit': limit,
                        'reset_time': reset_time.isoformat(),
                        'usage_percent': (limit - remaining) / limit * 100,
                    },
                    'response_time': response_time,
                    'test_call': test_result,
                    'recommendation': self._analyze_github_rate_limit(remaining, limit),
                }
            else:
                return {
                    'api_name': 'github',
                    'status': 'error',
                    'status_code': response.status_code,
                    'recommendation': 'GitHub API 인증에 문제가 있습니다. 토큰을 확인하세요.',
                }
        except Exception as e:
            return {
                'api_name': 'github',
                'status': 'error',
                'error': str(e),
                'recommendation': f'GitHub API 테스트 실패: {e}',
            }
    
    def test_nvd_api(self) -> Dict[str, Any]:
        """Test NVD API performance."""
        print("\n🔍 Testing NVD API...")
        
        api_key = os.getenv("NVD_API_KEY")
        has_key = api_key is not None
        
        try:
            collector = CVECollector(api_key=api_key)
            
            # Test API call
            print("  Testing CVE API call...")
            test_result = self.measure_api_call(
                'nvd',
                collector._collect_by_id,
                'CVE-2021-44228'  # Log4Shell
            )
            
            # Calculate expected time
            rate_limit = 0.6 if has_key else 6.0
            expected_time_per_request = rate_limit
            
            return {
                'api_name': 'nvd',
                'status': 'working',
                'authenticated': has_key,
                'rate_limit_seconds': rate_limit,
                'requests_per_hour': int(3600 / rate_limit),
                'test_call': test_result,
                'recommendation': self._analyze_nvd_performance(has_key, test_result.get('response_time', 0)),
            }
        except Exception as e:
            return {
                'api_name': 'nvd',
                'status': 'error',
                'error': str(e),
                'recommendation': f'NVD API 테스트 실패: {e}',
            }
    
    def test_epss_api(self) -> Dict[str, Any]:
        """Test EPSS API performance."""
        print("\n🔍 Testing EPSS API...")
        
        try:
            collector = EPSSCollector()
            
            # Test API call
            print("  Testing EPSS API call...")
            test_result = self.measure_api_call(
                'epss',
                collector._fetch_epss_data,
                ['CVE-2021-44228']
            )
            
            return {
                'api_name': 'epss',
                'status': 'working' if test_result['success'] else 'error',
                'test_call': test_result,
                'recommendation': 'EPSS API는 공개 API입니다. Rate limit이 없습니다.',
            }
        except Exception as e:
            return {
                'api_name': 'epss',
                'status': 'error',
                'error': str(e),
                'recommendation': f'EPSS API 테스트 실패: {e}',
            }
    
    def test_kev_api(self) -> Dict[str, Any]:
        """Test KEV API performance."""
        print("\n🔍 Testing KEV API...")
        
        try:
            collector = KEVCollector()
            
            # Test API call
            print("  Testing KEV API call...")
            test_result = self.measure_api_call(
                'kev',
                collector._fetch_kev_catalog
            )
            
            return {
                'api_name': 'kev',
                'status': 'working' if test_result['success'] else 'error',
                'test_call': test_result,
                'recommendation': 'KEV API는 공개 API입니다. Rate limit이 없습니다.',
            }
        except Exception as e:
            return {
                'api_name': 'kev',
                'status': 'error',
                'error': str(e),
                'recommendation': f'KEV API 테스트 실패: {e}',
            }
    
    def _analyze_github_rate_limit(self, remaining: int, limit: int) -> str:
        """Analyze GitHub rate limit and provide recommendations."""
        usage_percent = (limit - remaining) / limit * 100
        
        if limit == 60:
            return "⚠️  GitHub API가 비인증 상태입니다. GITHUB_TOKEN을 설정하면 5000/hour로 증가합니다."
        elif usage_percent > 80:
            return f"⚠️  Rate limit 사용률이 높습니다 ({usage_percent:.1f}%). 잠시 대기하거나 여러 계정 사용을 고려하세요."
        elif usage_percent > 50:
            return f"ℹ️  Rate limit 사용률: {usage_percent:.1f}% ({remaining}/{limit} 남음)"
        else:
            return f"✅ Rate limit 여유: {remaining}/{limit} ({100-usage_percent:.1f}% 남음)"
    
    def _analyze_nvd_performance(self, has_key: bool, response_time: float) -> str:
        """Analyze NVD API performance and provide recommendations."""
        if not has_key:
            return "⚠️  NVD API 키가 없습니다. NVD_API_KEY를 설정하면 rate limit이 6초 → 0.6초로 10배 빨라집니다."
        
        if response_time > 2.0:
            return f"⚠️  응답 시간이 느립니다 ({response_time:.2f}초). 네트워크 문제일 수 있습니다."
        elif response_time > 1.0:
            return f"ℹ️  응답 시간: {response_time:.2f}초 (정상 범위)"
        else:
            return f"✅ 응답 시간: {response_time:.2f}초 (빠름)"
    
    def estimate_collection_time(self, api_name: str, num_items: int) -> Dict[str, Any]:
        """Estimate time needed to collect N items."""
        estimates = {}
        
        if api_name == 'github':
            # GitHub: 5000/hour (authenticated)
            rate_per_hour = 5000
            time_hours = num_items / rate_per_hour
            estimates['authenticated'] = {
                'time_hours': time_hours,
                'time_days': time_hours / 24,
                'rate_per_hour': rate_per_hour,
            }
            
            # Unauthenticated: 60/hour
            rate_per_hour = 60
            time_hours = num_items / rate_per_hour
            estimates['unauthenticated'] = {
                'time_hours': time_hours,
                'time_days': time_hours / 24,
                'rate_per_hour': rate_per_hour,
            }
        
        elif api_name == 'nvd':
            # NVD: 6000/hour (with key), 600/hour (without key)
            for auth_type, rate_per_hour in [('authenticated', 6000), ('unauthenticated', 600)]:
                time_hours = num_items / rate_per_hour
                estimates[auth_type] = {
                    'time_hours': time_hours,
                    'time_days': time_hours / 24,
                    'rate_per_hour': rate_per_hour,
                }
        
        return estimates
    
    def generate_report(self, results: List[Dict[str, Any]]) -> str:
        """Generate performance analysis report."""
        report = []
        report.append("=" * 80)
        report.append("API Performance Analysis Report")
        report.append("=" * 80)
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")
        
        # Summary
        report.append("## Summary")
        report.append("")
        
        for result in results:
            api_name = result.get('api_name', 'unknown')
            status = result.get('status', 'unknown')
            
            if status == 'working':
                report.append(f"✅ {api_name.upper()}: 정상 작동")
            elif status == 'no_token':
                report.append(f"⚠️  {api_name.upper()}: 인증 토큰 없음")
            elif status == 'error':
                report.append(f"❌ {api_name.upper()}: 오류 발생")
            else:
                report.append(f"❓ {api_name.upper()}: 상태 불명")
        
        report.append("")
        report.append("## Detailed Analysis")
        report.append("")
        
        # Detailed results
        for result in results:
            api_name = result.get('api_name', 'unknown')
            report.append(f"### {api_name.upper()} API")
            report.append("")
            
            if 'rate_limit' in result:
                rl = result['rate_limit']
                report.append(f"- Rate Limit: {rl['remaining']}/{rl['limit']} ({rl['usage_percent']:.1f}% 사용)")
                report.append(f"- Reset Time: {rl['reset_time']}")
            
            if 'rate_limit_seconds' in result:
                report.append(f"- Rate Limit: {result['rate_limit_seconds']}초/요청")
                report.append(f"- Requests/Hour: {result.get('requests_per_hour', 'N/A')}")
            
            if 'test_call' in result:
                tc = result['test_call']
                if tc.get('success'):
                    report.append(f"- Test Call: 성공 ({tc.get('response_time', 0):.2f}초)")
                else:
                    report.append(f"- Test Call: 실패 - {tc.get('error', 'Unknown error')}")
            
            if 'recommendation' in result:
                report.append(f"- 권장사항: {result['recommendation']}")
            
            report.append("")
        
        # Collection time estimates
        report.append("## Collection Time Estimates")
        report.append("")
        
        # Estimate for 100 CVEs
        nvd_estimates = self.estimate_collection_time('nvd', 100)
        report.append("### NVD: 100개 CVE 수집 예상 시간")
        if 'authenticated' in nvd_estimates:
            est = nvd_estimates['authenticated']
            report.append(f"- 인증 (API 키 있음): {est['time_hours']:.2f}시간 ({est['time_days']:.2f}일)")
        if 'unauthenticated' in nvd_estimates:
            est = nvd_estimates['unauthenticated']
            report.append(f"- 비인증 (API 키 없음): {est['time_hours']:.2f}시간 ({est['time_days']:.2f}일)")
        report.append("")
        
        # Estimate for 1000 commits
        github_estimates = self.estimate_collection_time('github', 1000)
        report.append("### GitHub: 1000개 Commit 수집 예상 시간")
        if 'authenticated' in github_estimates:
            est = github_estimates['authenticated']
            report.append(f"- 인증 (토큰 있음): {est['time_hours']:.2f}시간 ({est['time_days']:.2f}일)")
        if 'unauthenticated' in github_estimates:
            est = github_estimates['unauthenticated']
            report.append(f"- 비인증 (토큰 없음): {est['time_hours']:.2f}시간 ({est['time_days']:.2f}일)")
        report.append("")
        
        # Recommendations
        report.append("## Recommendations")
        report.append("")
        
        needs_github_token = any(r.get('status') == 'no_token' and r.get('api_name') == 'github' for r in results)
        needs_nvd_key = any(not r.get('authenticated', False) and r.get('api_name') == 'nvd' for r in results)
        
        if needs_github_token:
            report.append("1. **GitHub Token 설정 필요**")
            report.append("   - GITHUB_TOKEN 환경변수 설정")
            report.append("   - Rate limit: 60/hour → 5000/hour (83배 증가)")
            report.append("   - 생성: https://github.com/settings/tokens")
            report.append("")
        
        if needs_nvd_key:
            report.append("2. **NVD API Key 설정 필요**")
            report.append("   - NVD_API_KEY 환경변수 설정")
            report.append("   - Rate limit: 6초 → 0.6초 (10배 빨라짐)")
            report.append("   - 신청: https://nvd.nist.gov/developers/request-an-api-key")
            report.append("")
        
        if not needs_github_token and not needs_nvd_key:
            report.append("✅ 모든 API가 최적 설정으로 작동 중입니다.")
            report.append("")
        
        return "\n".join(report)


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Analyze API performance and detect bottlenecks"
    )
    parser.add_argument(
        '--output',
        type=Path,
        default=Path('data/output/api_performance_report.txt'),
        help='Output file for report'
    )
    parser.add_argument(
        '--test-all',
        action='store_true',
        help='Test all APIs'
    )
    parser.add_argument(
        '--test-github',
        action='store_true',
        help='Test GitHub API only'
    )
    parser.add_argument(
        '--test-nvd',
        action='store_true',
        help='Test NVD API only'
    )
    
    args = parser.parse_args()
    
    analyzer = APIPerformanceAnalyzer()
    results = []
    
    print("🔍 API Performance Analysis")
    print("=" * 80)
    
    # Test APIs
    if args.test_all or args.test_github or (not args.test_nvd and not args.test_github):
        results.append(analyzer.test_github_api())
    
    if args.test_all or args.test_nvd or (not args.test_nvd and not args.test_github):
        results.append(analyzer.test_nvd_api())
    
    if args.test_all:
        results.append(analyzer.test_epss_api())
        results.append(analyzer.test_kev_api())
    
    # Generate report
    report = analyzer.generate_report(results)
    
    # Print to console
    print("\n" + report)
    
    # Save to file
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, 'w', encoding='utf-8') as f:
        f.write(report)
    
    print(f"\n📄 Report saved to: {args.output}")


if __name__ == '__main__':
    main()

