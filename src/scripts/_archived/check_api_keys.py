#!/usr/bin/env python3
"""
Check API keys and credentials status.

This script:
1. Checks which API keys are set
2. Tests API connectivity
3. Shows rate limits
4. Recommends missing keys
"""

import sys
import os
from pathlib import Path
from typing import Dict, List, Any, Optional
import requests

# Load .env file if exists
try:
    from dotenv import load_dotenv
    env_path = Path('.env')
    if env_path.exists():
        load_dotenv(env_path)
except ImportError:
    pass  # python-dotenv not installed, skip

sys.path.insert(0, str(Path(__file__).parent.parent))


def check_env_file() -> Dict[str, bool]:
    """Check if .env file exists and what keys are in it."""
    env_file = Path('.env')
    env_example = Path('.env.example')
    
    result = {
        'env_file_exists': env_file.exists(),
        'env_example_exists': env_example.exists(),
        'keys_in_file': {},
    }
    
    if env_file.exists():
        with open(env_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key = line.split('=')[0].strip()
                    value = line.split('=', 1)[1].strip()
                    # Remove quotes if present
                    if value.startswith('"') and value.endswith('"'):
                        value = value[1:-1]
                    elif value.startswith("'") and value.endswith("'"):
                        value = value[1:-1]
                    result['keys_in_file'][key] = value != '' and not value.startswith('your_') and value != ''
    
    return result


def check_api_keys() -> Dict[str, Dict[str, Any]]:
    """Check which API keys are set in environment."""
    keys = {
        'GITHUB_TOKEN': {
            'name': 'GitHub Personal Access Token',
            'required': True,
            'purpose': 'Commit, Issue, PR collection',
            'url': 'https://github.com/settings/tokens',
            'impact': '60/hour → 5000/hour (83x faster)',
            'set': bool(os.getenv('GITHUB_TOKEN')),
            'value': os.getenv('GITHUB_TOKEN', ''),
        },
        'NVD_API_KEY': {
            'name': 'NVD API Key',
            'required': False,
            'purpose': 'CVE data collection',
            'url': 'https://nvd.nist.gov/developers/request-an-api-key',
            'impact': '6s/req → 0.6s/req (10x faster)',
            'set': bool(os.getenv('NVD_API_KEY')),
            'value': os.getenv('NVD_API_KEY', ''),
        },
        'GEMINI_API_KEY': {
            'name': 'Google Gemini API Key',
            'required': True,
            'purpose': 'LLM predictions and analysis',
            'url': 'https://ai.google.dev/',
            'impact': 'Required for Oracle predictions',
            'set': bool(os.getenv('GEMINI_API_KEY')),
            'value': os.getenv('GEMINI_API_KEY', ''),
        },
        'NEO4J_URI': {
            'name': 'Neo4j URI',
            'required': True,
            'purpose': 'Graph database connection',
            'url': None,
            'impact': 'Required for data storage',
            'set': bool(os.getenv('NEO4J_URI')),
            'value': os.getenv('NEO4J_URI', 'bolt://localhost:7687'),
        },
        'NEO4J_USER': {
            'name': 'Neo4j Username',
            'required': True,
            'purpose': 'Graph database authentication',
            'url': None,
            'impact': 'Required for data storage',
            'set': bool(os.getenv('NEO4J_USER')),
            'value': os.getenv('NEO4J_USER', 'neo4j'),
        },
        'NEO4J_PASSWORD': {
            'name': 'Neo4j Password',
            'required': True,
            'purpose': 'Graph database authentication',
            'url': None,
            'impact': 'Required for data storage',
            'set': bool(os.getenv('NEO4J_PASSWORD')),
            'value': os.getenv('NEO4J_PASSWORD', ''),
        },
    }
    
    return keys


def test_github_token(token: Optional[str]) -> Dict[str, Any]:
    """Test GitHub token validity."""
    if not token:
        return {
            'valid': False,
            'error': 'Token not set',
            'rate_limit': {'limit': 60, 'remaining': 0},
        }
    
    try:
        headers = {
            'Authorization': f'Bearer {token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        response = requests.get('https://api.github.com/rate_limit', headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()['resources']['core']
            return {
                'valid': True,
                'rate_limit': {
                    'limit': data['limit'],
                    'remaining': data['remaining'],
                    'reset': data['reset'],
                },
                'authenticated': data['limit'] > 60,
            }
        elif response.status_code == 401:
            return {
                'valid': False,
                'error': 'Invalid token (401 Unauthorized)',
            }
        else:
            return {
                'valid': False,
                'error': f'HTTP {response.status_code}',
            }
    except Exception as e:
        return {
            'valid': False,
            'error': str(e),
        }


def test_nvd_key(key: Optional[str]) -> Dict[str, Any]:
    """Test NVD API key validity."""
    if not key:
        return {
            'valid': False,
            'error': 'Key not set',
            'rate_limit': {'limit': 5, 'window': 30},  # 5 requests per 30 seconds
        }
    
    try:
        headers = {'apiKey': key} if key else {}
        url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
        params = {'resultsPerPage': 1}
        
        response = requests.get(url, headers=headers, params=params, timeout=10, verify=False)
        
        if response.status_code == 200:
            return {
                'valid': True,
                'rate_limit': {'limit': 50, 'window': 30},  # 50 requests per 30 seconds
            }
        elif response.status_code == 403:
            return {
                'valid': False,
                'error': 'Invalid API key (403 Forbidden)',
            }
        else:
            return {
                'valid': False,
                'error': f'HTTP {response.status_code}',
            }
    except Exception as e:
        return {
            'valid': False,
            'error': str(e),
        }


def generate_report(keys_status: Dict[str, Dict], env_status: Dict, test_results: Dict) -> str:
    """Generate API keys status report."""
    report = []
    report.append("=" * 80)
    report.append("API Keys and Credentials Status")
    report.append("=" * 80)
    report.append("")
    
    # Environment file status
    report.append("## Environment File Status")
    report.append("")
    if env_status['env_file_exists']:
        report.append("[OK] .env file exists")
        report.append(f"   Found {len(env_status['keys_in_file'])} configured keys")
    else:
        report.append("[WARN] .env file not found")
        if env_status['env_example_exists']:
            report.append("   Copy .env.example to .env and fill in your keys")
        else:
            report.append("   Create .env file with your API keys")
    report.append("")
    
    # API Keys Status
    report.append("## API Keys Status")
    report.append("")
    
    required_missing = []
    optional_missing = []
    
    for key_name, info in keys_status.items():
        status_icon = "[OK]" if info['set'] else "[MISSING]"
        required_mark = "(필수)" if info['required'] else "(선택)"
        
        report.append(f"{status_icon} {info['name']} {required_mark}")
        report.append(f"   환경변수: {key_name}")
        report.append(f"   용도: {info['purpose']}")
        
        if info['set']:
            # Mask the key value
            masked_value = info['value'][:8] + "..." if len(info['value']) > 8 else "***"
            report.append(f"   값: {masked_value}")
            
            # Test result
            if key_name in test_results:
                test = test_results[key_name]
                if test.get('valid'):
                    if key_name == 'GITHUB_TOKEN':
                        rl = test['rate_limit']
                        report.append(f"   [TEST] Valid - Rate limit: {rl['remaining']}/{rl['limit']}")
                    else:
                        report.append(f"   [TEST] Valid")
                else:
                    report.append(f"   [TEST] Invalid - {test.get('error', 'Unknown error')}")
        else:
            report.append(f"   상태: 설정되지 않음")
            if info['url']:
                report.append(f"   신청: {info['url']}")
            report.append(f"   영향: {info['impact']}")
            
            if info['required']:
                required_missing.append(key_name)
            else:
                optional_missing.append(key_name)
        
        report.append("")
    
    # Summary
    report.append("## Summary")
    report.append("")
    
    if required_missing:
        report.append(f"[CRITICAL] 필수 API 키 {len(required_missing)}개가 없습니다:")
        for key in required_missing:
            report.append(f"   - {key}")
        report.append("")
        report.append("이 키들이 없으면 데이터 수집이 불가능하거나 매우 느립니다.")
        report.append("")
    
    if optional_missing:
        report.append(f"[WARN] 선택적 API 키 {len(optional_missing)}개가 없습니다:")
        for key in optional_missing:
            report.append(f"   - {key}")
        report.append("")
        report.append("이 키들을 설정하면 수집 속도가 크게 향상됩니다.")
        report.append("")
    
    if not required_missing and not optional_missing:
        report.append("[OK] 모든 API 키가 설정되어 있습니다!")
        report.append("")
    
    # Recommendations
    report.append("## Recommendations")
    report.append("")
    
    if not env_status['env_file_exists']:
        report.append("1. Create .env file:")
        report.append("   cp .env.example .env")
        report.append("   # Then edit .env and fill in your keys")
        report.append("")
    
    if required_missing:
        report.append("2. Set required API keys:")
        for key in required_missing:
            info = keys_status[key]
            report.append(f"   export {key}=your_key_here")
            if info['url']:
                report.append(f"   # Get key: {info['url']}")
        report.append("")
    
    if optional_missing:
        report.append("3. Set optional API keys (for speed improvement):")
        for key in optional_missing:
            info = keys_status[key]
            report.append(f"   export {key}=your_key_here")
            if info['url']:
                report.append(f"   # Get key: {info['url']}")
            report.append(f"   # Impact: {info['impact']}")
        report.append("")
    
    return "\n".join(report)


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Check API keys and credentials status"
    )
    parser.add_argument(
        '--test',
        action='store_true',
        help='Test API connectivity'
    )
    parser.add_argument(
        '--output',
        type=Path,
        default=Path('data/output/api_keys_status.txt'),
        help='Output file for report'
    )
    
    args = parser.parse_args()
    
    print("Checking API Keys and Credentials...")
    print("=" * 80)
    
    # Check environment file
    env_status = check_env_file()
    
    # Check API keys
    keys_status = check_api_keys()
    
    # Test APIs if requested
    test_results = {}
    if args.test:
        print("\nTesting API connectivity...")
        
        github_token = os.getenv('GITHUB_TOKEN')
        if github_token:
            print("  Testing GitHub token...", end=' ', flush=True)
            test_results['GITHUB_TOKEN'] = test_github_token(github_token)
            if test_results['GITHUB_TOKEN'].get('valid'):
                print("[OK]")
            else:
                print(f"[FAIL] {test_results['GITHUB_TOKEN'].get('error')}")
        
        nvd_key = os.getenv('NVD_API_KEY')
        if nvd_key:
            print("  Testing NVD API key...", end=' ', flush=True)
            test_results['NVD_API_KEY'] = test_nvd_key(nvd_key)
            if test_results['NVD_API_KEY'].get('valid'):
                print("[OK]")
            else:
                print(f"[FAIL] {test_results['NVD_API_KEY'].get('error')}")
    
    # Generate report
    report = generate_report(keys_status, env_status, test_results)
    
    # Print to console
    print("\n" + report)
    
    # Save to file
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, 'w', encoding='utf-8') as f:
        f.write(report)
    
    print(f"\nReport saved to: {args.output}")


if __name__ == '__main__':
    main()

