#!/usr/bin/env python3
"""
Measure actual data collection speed and identify bottlenecks.

This script:
1. Collects a small sample of data
2. Measures actual collection speed
3. Estimates time for full collection
4. Identifies bottlenecks (API keys, rate limits, etc.)
"""

import sys
import time
import os
import requests
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta

# Load .env file if exists
try:
    from dotenv import load_dotenv
    env_path = Path('.env')
    if env_path.exists():
        load_dotenv(env_path)
        print(f"[INFO] Loaded .env file from {env_path.absolute()}")
except ImportError:
    pass  # python-dotenv not installed, skip
except Exception as e:
    print(f"[WARN] Failed to load .env file: {e}")

sys.path.insert(0, str(Path(__file__).parent.parent))

from llmdump.spokes.cve import CVECollector
from llmdump.spokes.github import GitHubSignalsCollector
from llmdump.spokes.epss import EPSSCollector


def measure_cve_collection_speed(num_samples: int = 10) -> Dict[str, Any]:
    """Measure CVE collection speed."""
    print(f"\n[MEASURE] Measuring CVE collection speed ({num_samples} samples)...")
    
    api_key = os.getenv("NVD_API_KEY")
    has_key = api_key is not None
    
    collector = CVECollector(api_key=api_key)
    
    # Test CVEs
    test_cves = [
        'CVE-2021-44228', 'CVE-2021-45046', 'CVE-2021-45105',
        'CVE-2021-3156', 'CVE-2021-26855', 'CVE-2020-0601',
        'CVE-2017-5638', 'CVE-2014-0160', 'CVE-2017-0144',
        'CVE-2014-6271',
    ][:num_samples]
    
    times = []
    errors = []
    
    start_total = time.time()
    
    for i, cve_id in enumerate(test_cves, 1):
        print(f"  [{i}/{num_samples}] Collecting {cve_id}...", end=' ', flush=True)
        
        start = time.time()
        try:
            result = collector._collect_by_id(cve_id)
            elapsed = time.time() - start
            times.append(elapsed)
            print(f"[OK] {elapsed:.2f}초")
        except Exception as e:
            elapsed = time.time() - start
            errors.append({'cve_id': cve_id, 'error': str(e), 'time': elapsed})
            print(f"[ERROR] {elapsed:.2f}초 - {str(e)[:50]}")
    
    total_time = time.time() - start_total
    
    if not times:
        return {
            'success': False,
            'error': 'All samples failed',
            'errors': errors,
        }
    
    avg_time = sum(times) / len(times)
    min_time = min(times)
    max_time = max(times)
    
    # Calculate rate limit
    rate_limit_seconds = 0.6 if has_key else 6.0
    effective_rate = 1.0 / max(avg_time, rate_limit_seconds)
    
    recommendation = _get_cve_recommendation(has_key, avg_time, rate_limit_seconds)
    
    return {
        'success': True,
        'authenticated': has_key,
        'samples': len(times),
        'errors': len(errors),
        'times': {
            'total': total_time,
            'average': avg_time,
            'min': min_time,
            'max': max_time,
        },
        'rate_limit_seconds': rate_limit_seconds,
        'effective_rate_per_hour': effective_rate * 3600,
        'bottleneck': 'rate_limit' if avg_time < rate_limit_seconds else 'network',
        'recommendation': recommendation.get('summary', ''),
        'recommendation_details': recommendation,
    }


def measure_github_collection_speed(repo: str = 'torvalds/linux', days_back: int = 7) -> Dict[str, Any]:
    """Measure GitHub commit collection speed."""
    print(f"\n[MEASURE] Measuring GitHub commit collection speed...")
    print(f"  Repository: {repo}")
    print(f"  Days back: {days_back}")
    
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        return {
            'success': False,
            'error': 'GITHUB_TOKEN not set',
            'recommendation': 'GitHub token이 없습니다. 60/hour 제한이 적용됩니다.',
        }
    
    try:
        collector = GitHubSignalsCollector(token=token)
        
        # Check rate limit first
        print("  Checking rate limit...", end=' ', flush=True)
        rate_limit_url = "https://api.github.com/rate_limit"
        rate_response = requests.get(rate_limit_url, headers=collector.headers, timeout=10)
        
        if rate_response.status_code == 200:
            rate_data = rate_response.json()['resources']['core']
            remaining = rate_data['remaining']
            limit = rate_data['limit']
            print(f"[OK] {remaining}/{limit} 남음")
        else:
            print(f"[WARN] Rate limit 확인 실패")
            remaining = None
            limit = None
        
        # Measure commit collection
        print("  Collecting commits...", end=' ', flush=True)
        since = datetime.now() - timedelta(days=days_back)
        
        start = time.time()
        commits = collector._collect_commits(repo, since)
        elapsed = time.time() - start
        
        num_commits = len(commits)
        commits_per_second = num_commits / elapsed if elapsed > 0 else 0
        
        print(f"[OK] {num_commits}개 수집 ({elapsed:.2f}초)")
        
        # Estimate for larger collection
        estimated_rate = commits_per_second * 3600  # per hour
        
        recommendation = _get_github_recommendation(remaining, limit, estimated_rate)
        
        return {
            'success': True,
            'authenticated': limit != 60,
            'commits_collected': num_commits,
            'time_seconds': elapsed,
            'commits_per_second': commits_per_second,
            'commits_per_hour': estimated_rate,
            'rate_limit': {
                'remaining': remaining,
                'limit': limit,
            },
            'recommendation': recommendation.get('summary', ''),
            'recommendation_details': recommendation,
        }
        
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'recommendation': f'GitHub API 오류: {e}',
        }


def measure_epss_collection_speed(num_samples: int = 10) -> Dict[str, Any]:
    """Measure EPSS collection speed."""
    print(f"\n[MEASURE] Measuring EPSS collection speed ({num_samples} samples)...")
    
    collector = EPSSCollector()
    
    test_cves = [
        'CVE-2021-44228', 'CVE-2021-45046', 'CVE-2021-45105',
        'CVE-2021-3156', 'CVE-2021-26855', 'CVE-2020-0601',
        'CVE-2017-5638', 'CVE-2014-0160', 'CVE-2017-0144',
        'CVE-2014-6271',
    ][:num_samples]
    
    start = time.time()
    times = []
    
    for i, cve_id in enumerate(test_cves, 1):
        print(f"  [{i}/{num_samples}] Collecting {cve_id}...", end=' ', flush=True)
        
        call_start = time.time()
        try:
            result = collector._collect_batch([cve_id])
            elapsed = time.time() - call_start
            times.append(elapsed)
            print(f"[OK] {elapsed:.2f}초")
        except Exception as e:
            elapsed = time.time() - call_start
            print(f"[ERROR] {elapsed:.2f}초 - {str(e)[:50]}")
    
    total_time = time.time() - start
    
    if not times:
        return {
            'success': False,
            'error': 'All samples failed',
        }
    
    avg_time = sum(times) / len(times)
    effective_rate = 1.0 / avg_time if avg_time > 0 else 0
    
    return {
        'success': True,
        'samples': len(times),
        'times': {
            'total': total_time,
            'average': avg_time,
        },
        'effective_rate_per_hour': effective_rate * 3600,
        'recommendation': 'EPSS API는 공개 API입니다. Rate limit이 없습니다.',
    }


def _get_cve_recommendation(has_key: bool, avg_time: float, rate_limit: float) -> Dict[str, Any]:
    """Get detailed recommendation for CVE collection."""
    recommendations = []
    issues = []
    
    if not has_key:
        speedup = rate_limit / 0.6  # 6초 → 0.6초
        issues.append({
            'severity': 'high',
            'issue': 'NVD API 키 없음',
            'current_speed': f'{rate_limit:.1f}초/요청',
            'improved_speed': '0.6초/요청',
            'speedup': f'{speedup:.0f}배',
            'action': 'NVD API 키 설정 필요',
            'url': 'https://nvd.nist.gov/developers/request-an-api-key',
            'env_var': 'NVD_API_KEY'
        })
        recommendations.append(f"⚠️  NVD API 키가 없습니다. 설정하면 {speedup:.0f}배 빨라집니다 (6초 → 0.6초).")
    else:
        recommendations.append("✅ NVD API 키가 설정되어 있습니다.")
    
    if avg_time > rate_limit * 1.5:
        issues.append({
            'severity': 'medium',
            'issue': '응답 시간이 느림',
            'current_speed': f'{avg_time:.2f}초',
            'expected_speed': f'{rate_limit:.2f}초',
            'action': '네트워크 연결 확인 필요',
        })
        recommendations.append(f"⚠️  응답 시간이 느립니다 ({avg_time:.2f}초). 네트워크 문제일 수 있습니다.")
    elif avg_time < rate_limit * 0.8:
        recommendations.append(f"✅ 응답 시간이 빠릅니다 ({avg_time:.2f}초). Rate limit 여유가 있습니다.")
    else:
        recommendations.append(f"ℹ️  응답 시간: {avg_time:.2f}초 (정상 범위)")
    
    return {
        'summary': ' | '.join(recommendations),
        'issues': issues,
        'needs_api_key': not has_key,
    }


def _get_github_recommendation(remaining: Optional[int], limit: Optional[int], rate_per_hour: float) -> Dict[str, Any]:
    """Get detailed recommendation for GitHub collection."""
    recommendations = []
    issues = []
    
    if limit == 60:
        speedup = 5000 / 60  # 83배
        issues.append({
            'severity': 'critical',
            'issue': 'GitHub API 비인증 상태',
            'current_limit': '60/hour',
            'improved_limit': '5000/hour',
            'speedup': f'{speedup:.0f}배',
            'action': 'GitHub Personal Access Token 설정 필요',
            'url': 'https://github.com/settings/tokens',
            'env_var': 'GITHUB_TOKEN',
            'impact': '현재 속도로는 대규모 수집 불가능'
        })
        recommendations.append(f"⚠️  GitHub API가 비인증 상태입니다. GITHUB_TOKEN 설정 시 {speedup:.0f}배 빨라집니다 (60 → 5000/hour).")
    elif limit == 5000:
        recommendations.append("✅ GitHub API가 인증 상태입니다.")
    
    if remaining is None or limit is None:
        recommendations.append("ℹ️  Rate limit 정보를 확인할 수 없습니다.")
        return {
            'summary': ' | '.join(recommendations),
            'issues': issues,
            'needs_token': limit == 60 if limit else None,
        }
    
    usage_percent = (limit - remaining) / limit * 100
    
    if usage_percent > 80:
        issues.append({
            'severity': 'high',
            'issue': 'Rate limit 사용률 높음',
            'usage': f'{usage_percent:.1f}%',
            'remaining': remaining,
            'action': 'Rate limit 복구 대기 필요',
        })
        recommendations.append(f"⚠️  Rate limit 사용률이 높습니다 ({usage_percent:.1f}%). 잠시 대기하세요.")
    elif rate_per_hour > limit * 0.9:
        issues.append({
            'severity': 'medium',
            'issue': '수집 속도가 Rate limit 근접',
            'current_rate': f'{rate_per_hour:.0f}/hour',
            'limit': f'{limit}/hour',
            'action': '수집 속도 조절 필요',
        })
        recommendations.append(f"⚠️  수집 속도가 Rate limit에 근접합니다 ({rate_per_hour:.0f}/hour). 속도를 줄이세요.")
    else:
        recommendations.append(f"✅ Rate limit 여유: {remaining}/{limit} ({100-usage_percent:.1f}% 남음)")
    
    return {
        'summary': ' | '.join(recommendations),
        'issues': issues,
        'needs_token': limit == 60,
        'rate_limit_usage': usage_percent,
    }


def estimate_collection_time(target_counts: Dict[str, int], results: Dict[str, Any]) -> Dict[str, Any]:
    """Estimate time needed for full collection."""
    estimates = {}
    
    # CVE estimates
    if 'cve' in results and results['cve'].get('success'):
        cve_result = results['cve']
        rate_per_hour = cve_result.get('effective_rate_per_hour', 0)
        if rate_per_hour > 0 and 'cve' in target_counts:
            hours = target_counts['cve'] / rate_per_hour
            estimates['cve'] = {
                'target_count': target_counts['cve'],
                'rate_per_hour': rate_per_hour,
                'estimated_hours': hours,
                'estimated_days': hours / 24,
            }
    
    # GitHub estimates
    if 'github' in results and results['github'].get('success'):
        github_result = results['github']
        rate_per_hour = github_result.get('commits_per_hour', 0)
        if rate_per_hour > 0 and 'commits' in target_counts:
            hours = target_counts['commits'] / rate_per_hour
            estimates['github'] = {
                'target_count': target_counts['commits'],
                'rate_per_hour': rate_per_hour,
                'estimated_hours': hours,
                'estimated_days': hours / 24,
            }
    
    return estimates


def analyze_bottlenecks(results: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze bottlenecks and missing credentials."""
    bottlenecks = {
        'critical_issues': [],
        'high_priority': [],
        'recommendations': [],
        'estimated_impact': {},
    }
    
    # Check CVE API
    if 'cve' in results:
        cve_result = results['cve']
        if cve_result.get('success'):
            rec_details = cve_result.get('recommendation_details', {})
            if rec_details.get('needs_api_key'):
                bottlenecks['critical_issues'].append({
                    'api': 'NVD',
                    'issue': 'API 키 없음',
                    'current_rate': f"{cve_result.get('effective_rate_per_hour', 0):.0f}/hour",
                    'improved_rate': '6000/hour',
                    'speedup': '10배',
                    'action': 'NVD_API_KEY 환경변수 설정',
                })
    
    # Check GitHub API
    if 'github' in results:
        github_result = results['github']
        if github_result.get('success'):
            rec_details = github_result.get('recommendation_details', {})
            if rec_details.get('needs_token'):
                bottlenecks['critical_issues'].append({
                    'api': 'GitHub',
                    'issue': '인증 토큰 없음',
                    'current_rate': f"{github_result.get('commits_per_hour', 0):.0f}/hour",
                    'improved_rate': '5000/hour',
                    'speedup': '83배',
                    'action': 'GITHUB_TOKEN 환경변수 설정',
                })
        elif not github_result.get('success'):
            bottlenecks['critical_issues'].append({
                'api': 'GitHub',
                'issue': 'API 호출 실패',
                'error': github_result.get('error', 'Unknown'),
                'action': 'GITHUB_TOKEN 확인 필요',
            })
    
    # Estimate impact
    if bottlenecks['critical_issues']:
        bottlenecks['estimated_impact'] = {
            'message': '인증 설정 없이는 대규모 데이터 수집이 어렵습니다.',
            'collection_time_multiplier': '10-83배',
        }
    
    return bottlenecks


def generate_report(results: Dict[str, Any], estimates: Dict[str, Any]) -> str:
    """Generate collection speed report."""
    report = []
    report.append("=" * 80)
    report.append("Data Collection Speed Analysis")
    report.append("=" * 80)
    report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append("")
    
    # Analyze bottlenecks
    bottlenecks = analyze_bottlenecks(results)
    
    # Summary
    report.append("## Summary")
    report.append("")
    
    for api_name, result in results.items():
        if result.get('success'):
            if api_name == 'cve':
                rate = result.get('effective_rate_per_hour', 0)
                auth = "인증" if result.get('authenticated') else "비인증"
                report.append(f"✅ CVE: {rate:.0f}/hour ({auth})")
            elif api_name == 'github':
                rate = result.get('commits_per_hour', 0)
                auth = "인증" if result.get('authenticated') else "비인증"
                report.append(f"✅ GitHub: {rate:.0f} commits/hour ({auth})")
            elif api_name == 'epss':
                rate = result.get('effective_rate_per_hour', 0)
                report.append(f"✅ EPSS: {rate:.0f}/hour")
        else:
            report.append(f"❌ {api_name.upper()}: {result.get('error', 'Unknown error')}")
    
    report.append("")
    
    # Critical Issues
    if bottlenecks['critical_issues']:
        report.append("## ⚠️  Critical Issues (즉시 조치 필요)")
        report.append("")
        for issue in bottlenecks['critical_issues']:
            report.append(f"### {issue['api']} API")
            report.append(f"- 문제: {issue['issue']}")
            if 'current_rate' in issue:
                report.append(f"- 현재 속도: {issue['current_rate']}")
                report.append(f"- 개선 후: {issue['improved_rate']} ({issue['speedup']} 증가)")
            if 'error' in issue:
                report.append(f"- 오류: {issue['error']}")
            report.append(f"- 조치: {issue['action']}")
            report.append("")
    
    report.append("")
    
    # Detailed results
    report.append("## Detailed Results")
    report.append("")
    
    if 'cve' in results:
        cve = results['cve']
        report.append("### CVE Collection")
        report.append("")
        if cve.get('success'):
            times = cve.get('times', {})
            report.append(f"- Samples: {cve.get('samples', 0)}")
            report.append(f"- Average time: {times.get('average', 0):.2f}초")
            report.append(f"- Rate limit: {cve.get('rate_limit_seconds', 0)}초/요청")
            report.append(f"- Effective rate: {cve.get('effective_rate_per_hour', 0):.0f}/hour")
            report.append(f"- Bottleneck: {cve.get('bottleneck', 'unknown')}")
            report.append(f"- Recommendation: {cve.get('recommendation', 'N/A')}")
        else:
            report.append(f"- Error: {cve.get('error', 'Unknown')}")
        report.append("")
    
    if 'github' in results:
        github = results['github']
        report.append("### GitHub Collection")
        report.append("")
        if github.get('success'):
            report.append(f"- Commits collected: {github.get('commits_collected', 0)}")
            report.append(f"- Time: {github.get('time_seconds', 0):.2f}초")
            report.append(f"- Rate: {github.get('commits_per_hour', 0):.0f} commits/hour")
            if 'rate_limit' in github:
                rl = github['rate_limit']
                if rl.get('remaining') is not None:
                    report.append(f"- Rate limit: {rl.get('remaining')}/{rl.get('limit')} 남음")
            report.append(f"- Recommendation: {github.get('recommendation', 'N/A')}")
        else:
            report.append(f"- Error: {github.get('error', 'Unknown')}")
        report.append("")
    
    # Estimates
    if estimates:
        report.append("## Collection Time Estimates")
        report.append("")
        
        if 'cve' in estimates:
            est = estimates['cve']
            report.append(f"### CVE: {est['target_count']}개 수집")
            report.append(f"- Rate: {est['rate_per_hour']:.0f}/hour")
            report.append(f"- Estimated time: {est['estimated_hours']:.2f}시간 ({est['estimated_days']:.2f}일)")
            report.append("")
        
        if 'github' in estimates:
            est = estimates['github']
            report.append(f"### GitHub: {est['target_count']}개 Commit 수집")
            report.append(f"- Rate: {est['rate_per_hour']:.0f}/hour")
            report.append(f"- Estimated time: {est['estimated_hours']:.2f}시간 ({est['estimated_days']:.2f}일)")
            report.append("")
    
    # Detailed Recommendations
    report.append("## Detailed Recommendations")
    report.append("")
    
    for api_name, result in results.items():
        if not result.get('success'):
            continue
            
        rec_details = result.get('recommendation_details', {})
        if not rec_details:
            continue
            
        report.append(f"### {api_name.upper()} API")
        report.append("")
        report.append(f"**요약**: {rec_details.get('summary', 'N/A')}")
        report.append("")
        
        issues = rec_details.get('issues', [])
        if issues:
            report.append("**발견된 문제:**")
            report.append("")
            for issue in issues:
                severity_icon = {'critical': '🔴', 'high': '🟠', 'medium': '🟡'}.get(issue.get('severity', ''), '⚪')
                report.append(f"{severity_icon} **{issue.get('issue', 'Unknown')}**")
                if 'current_speed' in issue:
                    report.append(f"   - 현재: {issue['current_speed']}")
                if 'improved_speed' in issue:
                    report.append(f"   - 개선 후: {issue['improved_speed']}")
                if 'speedup' in issue:
                    report.append(f"   - 속도 증가: {issue['speedup']}")
                if 'action' in issue:
                    report.append(f"   - 조치: {issue['action']}")
                if 'url' in issue:
                    report.append(f"   - 링크: {issue['url']}")
                if 'env_var' in issue:
                    report.append(f"   - 환경변수: `export {issue['env_var']}=your_key`")
                report.append("")
        
        report.append("")
    
    # Overall Assessment
    report.append("## Overall Assessment")
    report.append("")
    
    all_authenticated = all(
        results.get(api, {}).get('authenticated', False) 
        for api in ['cve', 'github'] 
        if api in results and results[api].get('success')
    )
    
    if all_authenticated:
        report.append("✅ **모든 API가 최적 설정으로 작동 중입니다.**")
        report.append("")
        report.append("대규모 데이터 수집이 가능합니다.")
    else:
        report.append("⚠️  **인증 설정이 필요합니다.**")
        report.append("")
        report.append("현재 설정으로는:")
        report.append("- 소규모 데이터 수집만 가능")
        report.append("- 수집 시간이 매우 오래 걸림")
        report.append("- Rate limit에 자주 걸림")
        report.append("")
        report.append("**권장 조치:**")
        for issue in bottlenecks['critical_issues']:
            report.append(f"1. {issue['action']}")
        report.append("")
    
    return "\n".join(report)


def main():
    """Main entry point."""
    import argparse
    import requests
    
    parser = argparse.ArgumentParser(
        description="Measure actual data collection speed"
    )
    parser.add_argument(
        '--samples',
        type=int,
        default=5,
        help='Number of samples to test'
    )
    parser.add_argument(
        '--output',
        type=Path,
        default=Path('data/output/collection_speed_report.txt'),
        help='Output file for report'
    )
    
    args = parser.parse_args()
    
    print("Data Collection Speed Measurement")
    print("=" * 80)
    
    results = {}
    
    # Measure CVE collection
    try:
        results['cve'] = measure_cve_collection_speed(num_samples=args.samples)
    except Exception as e:
        results['cve'] = {'success': False, 'error': str(e)}
    
    # Measure GitHub collection
    try:
        results['github'] = measure_github_collection_speed()
    except Exception as e:
        results['github'] = {'success': False, 'error': str(e)}
    
    # Measure EPSS collection
    try:
        results['epss'] = measure_epss_collection_speed(num_samples=args.samples)
    except Exception as e:
        results['epss'] = {'success': False, 'error': str(e)}
    
    # Estimate collection time
    target_counts = {
        'cve': 100,  # 100 CVEs
        'commits': 1000,  # 1000 commits
    }
    estimates = estimate_collection_time(target_counts, results)
    
    # Generate report
    report = generate_report(results, estimates)
    
    # Print to console
    print("\n" + report)
    
    # Save to file
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, 'w', encoding='utf-8') as f:
        f.write(report)
    
    print(f"\n📄 Report saved to: {args.output}")


if __name__ == '__main__':
    main()

