"""LLMDump Command Line Interface."""

import click
import logging
import os
from pathlib import Path

from ..config import get_config, load_config
from ..__version__ import __version__

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)


@click.group()
@click.version_option(version=__version__)
@click.option('--config', type=click.Path(exists=True), help='Configuration file')
@click.pass_context
def cli(ctx, config):
    """
    LLMDump - LLM-powered Zero-Day Vulnerability Prediction
    
    Zero-day vulnerability prediction using LLM-based signal analysis.
    """
    ctx.ensure_object(dict)
    
    if config:
        ctx.obj['config'] = load_config(Path(config))
    else:
        ctx.obj['config'] = get_config()


# Spokes commands (Data Collection)
@cli.group()
def spokes():
    """Data collection commands."""
    pass


@spokes.command('collect-cve')
@click.option('--cve-ids', multiple=True, help='Specific CVE IDs to collect')
@click.option('--start-date', help='Start date (YYYY-MM-DD)')
@click.option('--end-date', help='End date (YYYY-MM-DD)')
@click.option('--keyword', help='Keyword to search for')
@click.option('--max-results', default=100, help='Maximum results')
@click.option('--output', default='data/raw', help='Output directory')
def collect_cve(cve_ids, start_date, end_date, keyword, max_results, output):
    """Collect CVE data from NVD."""
    from ..spokes import CVECollector
    
    collector = CVECollector(output_dir=output)
    
    if cve_ids:
        stats = collector.collect(cve_ids=list(cve_ids))
    elif start_date and end_date:
        stats = collector.collect(start_date=start_date, end_date=end_date, max_results=max_results)
    elif keyword:
        stats = collector.collect(keyword=keyword, max_results=max_results)
    else:
        click.echo("Error: Must provide --cve-ids, date range, or --keyword")
        return
    
    click.echo(f"✓ Collected {stats['total_records']} CVEs")
    click.echo(f"✓ Saved to {stats['output_dir']}")


@spokes.command('collect-epss')
@click.option('--cve-ids', multiple=True, help='Specific CVE IDs')
@click.option('--date', help='Specific date (YYYY-MM-DD)')
@click.option('--output', default='data/raw', help='Output directory')
def collect_epss(cve_ids, date, output):
    """Collect EPSS scores from FIRST.org."""
    from ..spokes import EPSSCollector
    
    collector = EPSSCollector(output_dir=output)
    
    if cve_ids:
        stats = collector.collect(cve_ids=list(cve_ids), date=date)
    else:
        stats = collector.collect(date=date)
    
    click.echo(f"✓ Collected {stats['total_records']} EPSS scores")
    click.echo(f"✓ Saved to {stats['output_dir']}")


@spokes.command('collect-kev')
@click.option('--output', default='data/raw', help='Output directory')
def collect_kev(output):
    """Collect CISA KEV catalog."""
    from ..spokes import KEVCollector
    
    collector = KEVCollector(output_dir=output)
    stats = collector.collect()
    
    click.echo(f"✓ Collected {stats['total_records']} KEV entries")
    click.echo(f"✓ Saved to {stats['output_dir']}")


@spokes.command('collect-cwe')
@click.option('--output', default='data/raw', help='Output directory')
def collect_cwe(output):
    """Collect CWE database from MITRE."""
    from ..spokes import CWECollector
    
    collector = CWECollector(output_dir=output)
    stats = collector.collect()
    
    click.echo(f"✓ Collected {stats['total_records']} CWE entries")
    click.echo(f"✓ Saved to {stats['output_dir']}")


# Hub commands (Data Integration)
@cli.group()
def hub():
    """Data integration commands."""
    pass


@hub.command('load-cve')
@click.argument('jsonl_file', type=click.Path(exists=True))
@click.option('--neo4j-uri', envvar='NEO4J_URI', help='Neo4j URI')
@click.option('--neo4j-user', envvar='NEO4J_USER', default='neo4j', help='Neo4j username')
@click.option('--neo4j-password', envvar='NEO4J_PASSWORD', help='Neo4j password')
def load_cve(jsonl_file, neo4j_uri, neo4j_user, neo4j_password):
    """Load CVE data into Neo4j."""
    from ..hub import Neo4jConnection, DataLoader
    
    with Neo4jConnection(neo4j_uri, neo4j_user, neo4j_password) as conn:
        loader = DataLoader(conn)
        stats = loader.load_cve_data(Path(jsonl_file))
    
    click.echo(f"✓ Created {stats['nodes_created']} CVE nodes")
    click.echo(f"✓ Updated {stats['nodes_updated']} CVE nodes")


@hub.command('load-epss')
@click.argument('jsonl_file', type=click.Path(exists=True))
@click.option('--neo4j-uri', envvar='NEO4J_URI', help='Neo4j URI')
@click.option('--neo4j-user', envvar='NEO4J_USER', default='neo4j', help='Neo4j username')
@click.option('--neo4j-password', envvar='NEO4J_PASSWORD', help='Neo4j password')
def load_epss(jsonl_file, neo4j_uri, neo4j_user, neo4j_password):
    """Load EPSS data into Neo4j."""
    from ..hub import Neo4jConnection, DataLoader
    
    with Neo4jConnection(neo4j_uri, neo4j_user, neo4j_password) as conn:
        loader = DataLoader(conn)
        stats = loader.load_epss_data(Path(jsonl_file))
    
    click.echo(f"✓ Created {stats['relationships_created']} EPSS relationships")


@hub.command('load-kev')
@click.argument('jsonl_file', type=click.Path(exists=True))
@click.option('--neo4j-uri', envvar='NEO4J_URI', help='Neo4j URI')
@click.option('--neo4j-user', envvar='NEO4J_USER', default='neo4j', help='Neo4j username')
@click.option('--neo4j-password', envvar='NEO4J_PASSWORD', help='Neo4j password')
def load_kev(jsonl_file, neo4j_uri, neo4j_user, neo4j_password):
    """Load KEV data into Neo4j."""
    from ..hub import Neo4jConnection, DataLoader
    
    with Neo4jConnection(neo4j_uri, neo4j_user, neo4j_password) as conn:
        loader = DataLoader(conn)
        stats = loader.load_kev_data(Path(jsonl_file))
    
    click.echo(f"✓ Created {stats['nodes_created']} KEV nodes")
    click.echo(f"✓ Enriched {stats['cves_enriched']} CVE nodes")


@hub.command('load-cwe')
@click.argument('jsonl_file', type=click.Path(exists=True))
@click.option('--neo4j-uri', envvar='NEO4J_URI', help='Neo4j URI')
@click.option('--neo4j-user', envvar='NEO4J_USER', default='neo4j', help='Neo4j username')
@click.option('--neo4j-password', envvar='NEO4J_PASSWORD', help='Neo4j password')
def load_cwe(jsonl_file, neo4j_uri, neo4j_user, neo4j_password):
    """Load CWE data into Neo4j."""
    from ..hub import Neo4jConnection, DataLoader
    
    with Neo4jConnection(neo4j_uri, neo4j_user, neo4j_password) as conn:
        loader = DataLoader(conn)
        stats = loader.load_cwe_data(Path(jsonl_file))
    
    click.echo(f"✓ Created {stats['nodes_created']} CWE nodes")
    click.echo(f"✓ Created {stats['relationships_created']} relationships")


@hub.command('status')
@click.option('--neo4j-uri', envvar='NEO4J_URI', help='Neo4j URI')
@click.option('--neo4j-user', envvar='NEO4J_USER', default='neo4j', help='Neo4j username')
@click.option('--neo4j-password', envvar='NEO4J_PASSWORD', help='Neo4j password')
def hub_status(neo4j_uri, neo4j_user, neo4j_password):
    """Check Neo4j hub status."""
    from ..hub import Neo4jConnection
    
    conn = Neo4jConnection(neo4j_uri, neo4j_user, neo4j_password)
    
    if conn.verify_connectivity():
        click.echo("✓ Neo4j hub is connected")
    else:
        click.echo("✗ Neo4j hub connection failed")


# Wheel commands (Clustering)
@cli.group()
def wheel():
    """Clustering and pattern analysis commands."""
    pass


@wheel.command('cluster')
def cluster():
    """Run vulnerability clustering."""
    click.echo("Clustering not yet implemented")


# Oracle commands (Prediction)
@cli.group()
def oracle():
    """Prediction and risk assessment commands."""
    pass


@oracle.command('predict')
@click.argument('target')  # CVE ID or package name
@click.option('--package', help='Package name (if target is CVE ID)')
@click.option('--no-rag', is_flag=True, help='Disable RAG context')
@click.option('--output', type=click.Path(), help='Save result to JSON file')
def predict(target, package, no_rag, output):
    """
    Predict exploitation risk for a CVE or package.
    
    TARGET can be either a CVE ID (e.g., CVE-2024-1234) or package name.
    """
    from ..oracle import VulnerabilityOracle
    import json
    
    # Determine if target is CVE ID or package
    is_cve = target.startswith('CVE-')
    cve_id = target if is_cve else None
    pkg = package if is_cve else target
    
    if not pkg:
        click.echo("Error: Package name required when predicting CVE")
        return
    
    click.echo(f"🔮 Analyzing {target}...")
    
    try:
        oracle_engine = VulnerabilityOracle(use_rag=not no_rag)
        
        result = oracle_engine.predict(
            package=pkg,
            cve_id=cve_id,
            auto_fetch=True
        )
        
        # Display results
        click.echo("\n" + "="*80)
        click.echo(f"📊 Prediction Results")
        click.echo("="*80)
        click.echo(f"\nPackage: {result.package}")
        if result.cve_id:
            click.echo(f"CVE: {result.cve_id}")
        click.echo(f"\n🎯 Risk Score: {result.risk_score:.2f}/1.0")
        click.echo(f"⚠️  Risk Level: {result.risk_level}")
        click.echo(f"🎲 Confidence: {result.confidence:.2f}/1.0")
        
        click.echo(f"\n💭 Reasoning:")
        click.echo(f"{result.reasoning}")
        
        click.echo(f"\n📋 Recommendations:")
        for i, rec in enumerate(result.recommendations, 1):
            click.echo(f"  {i}. {rec}")
        
        click.echo(f"\n📡 Signals Analyzed:")
        for signal, available in result.signals_analyzed.items():
            status = "✓" if available else "✗"
            click.echo(f"  {status} {signal}")
        
        click.echo(f"\n⏰ Predicted at: {result.predicted_at}")
        click.echo("="*80)
        
        # Save to file if requested
        if output:
            result_dict = {
                'package': result.package,
                'cve_id': result.cve_id,
                'risk_score': result.risk_score,
                'risk_level': result.risk_level,
                'confidence': result.confidence,
                'reasoning': result.reasoning,
                'recommendations': result.recommendations,
                'signals_analyzed': result.signals_analyzed,
                'predicted_at': result.predicted_at.isoformat(),
            }
            with open(output, 'w') as f:
                json.dump(result_dict, f, indent=2)
            click.echo(f"\n💾 Results saved to {output}")
        
    except Exception as e:
        click.echo(f"\n❌ Error: {str(e)}", err=True)
        import traceback
        traceback.print_exc()


# Axle commands (Evaluation)
@cli.group()
def axle():
    """Evaluation and validation commands."""
    pass


@axle.command('validate')
def validate():
    """Run temporal validation."""
    click.echo("Validation not yet implemented")


@cli.command('analyze')
@click.argument('target')  # CVE ID or package
@click.option('--collect', is_flag=True, help='Collect fresh data before analysis')
@click.option('--load-hub', is_flag=True, help='Load data to Neo4j hub')
@click.option('--output', type=click.Path(), help='Save results to file')
def analyze(target, collect, load_hub, output):
    """
    Complete analysis workflow: collect → load → predict.
    
    TARGET can be a CVE ID or package name.
    """
    from ..oracle import VulnerabilityOracle
    from ..spokes import CVECollector, EPSSCollector, KEVCollector
    from ..hub import Neo4jConnection, DataLoader
    from pathlib import Path
    import json
    
    is_cve = target.startswith('CVE-')
    cve_id = target if is_cve else None
    package = target if not is_cve else None
    
    click.echo(f"🚀 Starting complete analysis for {target}")
    click.echo("="*80)
    
    # Step 1: Collect data (if requested)
    if collect:
        click.echo("\n📡 Step 1: Collecting data...")
        
        if cve_id:
            # Collect CVE data
            cve_collector = CVECollector(output_dir='data/raw')
            cve_stats = cve_collector.collect(cve_ids=[cve_id])
            click.echo(f"  ✓ Collected CVE data")
            
            # Collect EPSS
            epss_collector = EPSSCollector(output_dir='data/raw')
            epss_stats = epss_collector.collect(cve_ids=[cve_id])
            click.echo(f"  ✓ Collected EPSS data")
            
            # Collect KEV
            kev_collector = KEVCollector(output_dir='data/raw')
            kev_stats = kev_collector.collect()
            click.echo(f"  ✓ Collected KEV data")
    
    # Step 2: Load to Hub (if requested)
    if load_hub and collect:
        click.echo("\n🔄 Step 2: Loading data to Neo4j hub...")
        
        neo4j_uri = os.getenv('NEO4J_URI')
        neo4j_user = os.getenv('NEO4J_USERNAME', 'neo4j')
        neo4j_password = os.getenv('NEO4J_PASSWORD')
        
        if neo4j_uri and neo4j_password:
            with Neo4jConnection(neo4j_uri, neo4j_user, neo4j_password) as conn:
                loader = DataLoader(conn)
                
                # Load CVE
                cve_file = Path('data/raw/cve') / f"{cve_id}.jsonl"
                if cve_file.exists():
                    loader.load_cve_data(cve_file)
                    click.echo(f"  ✓ Loaded CVE data")
                
                # Load EPSS
                epss_file = Path('data/raw/epss') / 'latest.jsonl'
                if epss_file.exists():
                    loader.load_epss_data(epss_file)
                    click.echo(f"  ✓ Loaded EPSS data")
                
                # Load KEV
                kev_file = Path('data/raw/kev') / 'catalog.jsonl'
                if kev_file.exists():
                    loader.load_kev_data(kev_file)
                    click.echo(f"  ✓ Loaded KEV data")
        else:
            click.echo("  ⚠️  Neo4j credentials not found, skipping hub load")
    
    # Step 3: Predict
    click.echo("\n🔮 Step 3: Running prediction...")
    
    try:
        oracle_engine = VulnerabilityOracle(use_rag=True)
        
        result = oracle_engine.predict(
            package=package or 'unknown',
            cve_id=cve_id,
            auto_fetch=True
        )
        
        # Display results
        click.echo("\n" + "="*80)
        click.echo(f"📊 Analysis Results")
        click.echo("="*80)
        click.echo(f"\nTarget: {target}")
        click.echo(f"🎯 Risk Score: {result.risk_score:.2f}/1.0")
        click.echo(f"⚠️  Risk Level: {result.risk_level}")
        click.echo(f"🎲 Confidence: {result.confidence:.2f}/1.0")
        
        click.echo(f"\n💭 Reasoning:")
        click.echo(f"{result.reasoning}")
        
        click.echo(f"\n📋 Top Recommendations:")
        for i, rec in enumerate(result.recommendations[:3], 1):
            click.echo(f"  {i}. {rec}")
        
        click.echo("="*80)
        
        # Save results
        if output:
            result_dict = {
                'target': target,
                'package': result.package,
                'cve_id': result.cve_id,
                'risk_score': result.risk_score,
                'risk_level': result.risk_level,
                'confidence': result.confidence,
                'reasoning': result.reasoning,
                'recommendations': result.recommendations,
                'signals_analyzed': result.signals_analyzed,
                'predicted_at': result.predicted_at.isoformat(),
            }
            with open(output, 'w') as f:
                json.dump(result_dict, f, indent=2)
            click.echo(f"\n💾 Results saved to {output}")
        
        click.echo("\n✅ Analysis complete!")
        
    except Exception as e:
        click.echo(f"\n❌ Error during prediction: {str(e)}", err=True)
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    cli()


__all__ = ['cli']
