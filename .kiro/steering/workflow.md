---
inclusion: always
---

# Development Workflow Guidelines

## Code Before Creation Principle

**ALWAYS check existing resources before creating new code:**

1. **Check existing files first**
   - Use `listDirectory`, `fileSearch`, or `grepSearch` to find similar functionality
   - Read existing implementations to understand patterns
   - Reuse or extend existing code rather than duplicating

2. **Check existing data/resources**
   - Look for existing data files in `data/input/` and `data/output/`
   - Check if data has already been collected or processed
   - Verify what's in Neo4j database before querying

3. **Check existing scripts**
   - Look in `src/scripts/` directory for similar utilities
   - Check if a script already does what you need
   - Extend existing scripts rather than creating new ones

4. **Check existing documentation**
   - Read `docs/` files to understand what's already documented
   - Check README and guides for existing patterns
   - Look for existing examples or templates

## Workflow Steps

When asked to implement something:

1. **Explore** - Search for existing implementations
2. **Analyze** - Understand what exists and what's missing
3. **Plan** - Decide whether to reuse, extend, or create new
4. **Implement** - Write minimal code that builds on existing work
5. **Verify** - Test that it works with existing systems

## Module-Specific Guidelines

### Spokes (Data Collection)
- Inherit from `BaseDataSource` or `BaseCollector`
- Output JSONL format with consistent schema
- Handle API rate limiting and retries
- Log progress with tqdm progress bars

### Hub (Neo4j Integration)
- Use `Neo4jConnection` context manager
- Use `DataLoader` for loading data
- Create indexes for performance
- Use MERGE to avoid duplicates

### Oracle (Analysis)
- Use existing LLM integration patterns
- Cache expensive API calls
- Document prompt engineering decisions
- Include confidence scores in predictions

### Axle (Evaluation)
- Use existing metrics calculation utilities
- Generate publication-ready figures
- Include statistical significance tests
- Document experimental setup

## Common Patterns

### Data Collection
```python
from llmdump.spokes import CVECollector

collector = CVECollector()
stats = collector.collect(start_date="2024-01-01", end_date="2024-12-31")
```

### Neo4j Loading
```python
from llmdump.hub import Neo4jConnection, DataLoader
from pathlib import Path

with Neo4jConnection() as conn:
    loader = DataLoader(conn)
    stats = loader.load_cve_data(Path("data/input/cve.jsonl"))
```

### Running Scripts
```bash
# Check what data exists
python src/scripts/check_status.py

# Collect data
python src/scripts/collect_data.py --all

# Load to Neo4j
python src/scripts/load_to_neo4j.py --all
```

## Anti-Patterns to Avoid

❌ Immediately writing new code without checking existing files
❌ Creating duplicate functionality that already exists
❌ Ignoring existing patterns and conventions
❌ Re-collecting data that's already available
❌ Creating new files when existing ones could be extended
❌ Hardcoding values that should be in config files
❌ Skipping error handling and logging

## Testing Guidelines

- Write tests for new functionality
- Use pytest for testing
- Mock external API calls
- Test edge cases and error conditions
- Maintain test coverage above 70%

## Documentation Guidelines

- Add docstrings to all public functions/classes
- Update README.md when adding major features
- Document breaking changes in CHANGELOG.md
- Include usage examples in docstrings
- Keep docs/ directory up to date

## Git Workflow

- Commit frequently with clear messages
- Push to remote regularly (multi-computer workflow)
- Use branches for experimental features
- Keep main branch stable
- Tag releases with version numbers

## Remember

- **Exploration is not wasted time** - it prevents duplication
- **Reading existing code teaches patterns** - maintain consistency
- **Reusing code is faster** - less to write and test
- **Users appreciate efficiency** - don't reinvent the wheel
- **Documentation helps future you** - write it now
