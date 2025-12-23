"""Find AI/LLM related CVEs in existing data."""
import json
from pathlib import Path

def main():
    cve_file = Path("data/input/cve.jsonl")
    
    with open(cve_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    print(f"Total CVE records: {len(lines)}")
    
    # AI/LLM related keywords
    ai_keywords = [
        'llm', 'langchain', 'agent', 'prompt injection', 'mcp', 
        'chatgpt', 'openai', 'anthropic', 'gemini', 'claude',
        'ai assistant', 'language model', 'chatbot', 'copilot',
        'rag', 'retrieval augmented', 'vector database'
    ]
    
    ai_cves = []
    
    for line in lines:
        data = json.loads(line)
        payload = data.get('payload', {})
        vulns = payload.get('vulnerabilities', [])
        
        for v in vulns:
            cve = v.get('cve', {})
            cve_id = cve.get('id', '')
            desc = ''
            
            for d in cve.get('descriptions', []):
                if d.get('lang') == 'en':
                    desc = d.get('value', '').lower()
                    break
            
            for kw in ai_keywords:
                if kw in desc:
                    ai_cves.append({
                        'id': cve_id, 
                        'keyword': kw, 
                        'desc': desc[:200]
                    })
                    break
    
    print(f"\nAI/LLM related CVEs found: {len(ai_cves)}")
    print("-" * 60)
    
    for cve in ai_cves[:20]:
        print(f"\n{cve['id']} [keyword: {cve['keyword']}]")
        print(f"  {cve['desc']}...")

if __name__ == "__main__":
    main()
