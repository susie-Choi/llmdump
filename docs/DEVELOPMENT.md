# LLMDump Development Guide

Guide for developers working on LLMDump, including performance optimization, release management, and temporal validation.

---

## Table of Contents

1. [Performance Optimization](#performance-optimization)
2. [Release Management](#release-management)
3. [Temporal Validation](#temporal-validation)

---

## Performance Optimization

### Problem Analysis

**Current Speed**: ~22 minutes/CVE
- Collecting 180-day commit history
- Active projects like Django: ~1000+ commits
- Detailed API call for each commit
- **Result**: 1000 API calls × 1 second wait = 16+ minutes

### Optimization Strategies

#### 1. Batch API Calls (Most Effective)

**Problem**: Fetching commit details one by one
```python
for commit in commits:
    detail = get_commit_detail(commit.sha)  # N+1 problem
```

**Solution**: Use GraphQL API
```graphql
query {
  repository(owner: "django", name: "django") {
    object(expression: "main") {
      ... on Commit {
        history(first: 100, since: "2024-01-01") {
          nodes {
            oid
            message
            author {
              name
              email
              date
            }
            additions
            deletions
            changedFiles
          }
        }
      }
    }
  }
}
```

**Expected Improvement**: 1000 calls → 10 calls = **50x faster**

#### 2. Parallel Processing

**Problem**: Sequential processing
```python
for cve in cves:
    result = validate_cve(cve)  # One at a time
```

**Solution**: Use multiprocessing
```python
from multiprocessing import Pool

with Pool(processes=4) as pool:
    results = pool.map(validate_cve, cves)
```

**Expected Improvement**: 4x faster with 4 cores

#### 3. Caching

**Problem**: Repeated API calls for same data
```python
commits = fetch_commits(repo, since, until)  # Every time
```

**Solution**: Cache results
```python
import diskcache as dc

cache = dc.Cache('cache/')

@cache.memoize(expire=86400)  # 24 hours
def fetch_commits(repo, since, until):
    return api.get_commits(repo, since, until)
```

**Expected Improvement**: Near-instant for cached data

#### 4. Incremental Collection

**Problem**: Collecting all data every time
```python
commits = fetch_all_commits(repo)  # Full history
```

**Solution**: Collect only new data
```python
last_collected = get_last_collection_time(repo)
new_commits = fetch_commits_since(repo, last_collected)
```

**Expected Improvement**: 10-100x faster for updates

#### 5. Sampling Strategy

**Problem**: Analyzing all 1000+ commits
```python
for commit in all_commits:  # Too many
    analyze(commit)
```

**Solution**: Smart sampling
```python
# Sample commits intelligently
sampled = sample_commits(
    all_commits,
    strategy='stratified',  # By time period
    max_samples=100
)
```

**Expected Improvement**: 10x faster with minimal accuracy loss

### Implementation Priority

#### Phase 1: Quick Wins (1-2 days)
1. ✅ Add caching for API calls
2. ✅ Implement commit sampling
3. ✅ Add progress bars

#### Phase 2: Major Improvements (3-5 days)
1. ⏳ Switch to GraphQL API
2. ⏳ Add parallel processing
3. ⏳ Implement incremental collection

#### Phase 3: Advanced Optimization (1-2 weeks)
1. ⏳ Database indexing
2. ⏳ Distributed processing
3. ⏳ Predictive prefetching

### Expected Results

| Optimization | Current | Target | Improvement |
|--------------|---------|--------|-------------|
| Batch API | 22 min | 2 min | 11x |
| Parallel (4 cores) | 22 min | 5.5 min | 4x |
| Caching | 22 min | <1 sec | 1000x+ |
| Sampling | 22 min | 2 min | 11x |
| **Combined** | **22 min** | **<30 sec** | **40x+** |

### Monitoring

Track performance metrics:
```python
import time
from functools import wraps

def measure_time(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        duration = time.time() - start
        print(f"{func.__name__}: {duration:.2f}s")
        return result
    return wrapper

@measure_time
def collect_commits(repo):
    # ... implementation
    pass
```

### Testing

Benchmark with different project sizes:
- Small: <100 commits (fastapi)
- Medium: 100-500 commits (flask)
- Large: 500-1000 commits (requests)
- Very Large: 1000+ commits (django)

---

## Release Management

### Release Process Overview

1. Update version in `pyproject.toml`
2. Update `CHANGELOG.md`
3. Commit changes
4. Create and push git tag
5. GitHub Actions automatically:
   - Creates GitHub Release
   - Publishes to PyPI

### Step-by-Step Instructions

#### 1. Prepare Release

Update version and changelog:

```bash
# Edit pyproject.toml - bump version
# Edit CHANGELOG.md - add release notes

git add pyproject.toml CHANGELOG.md
git commit -m "chore: Prepare release v0.1.4"
git push origin main
```

#### 2. Create Release (Option A: Automated Script)

**Windows (PowerShell):**
```powershell
.\scripts\create_release.ps1 0.1.4
```

**Linux/Mac:**
```bash
chmod +x scripts/create_release.sh
./scripts/create_release.sh 0.1.4
```

#### 3. Create Release (Option B: Manual)

```bash
# Create tag
git tag -a v0.1.4 -m "Release version 0.1.4"

# Push tag
git push origin v0.1.4
```

#### 4. Verify Release

1. **GitHub Release**: https://github.com/susie-Choi/llmdump/releases
   - Check that release was created
   - Verify release notes from CHANGELOG

2. **PyPI**: https://pypi.org/project/llmdump/
   - Wait 1-2 minutes for Actions to complete
   - Verify new version is published

3. **Test Installation**:
   ```bash
   pip install --upgrade llmdump
   llmdump --version
   ```

### Release Checklist

Before creating a release:

- [ ] All tests passing
- [ ] Version bumped in `pyproject.toml`
- [ ] `CHANGELOG.md` updated with release notes
- [ ] Documentation updated if needed
- [ ] All changes committed and pushed to main
- [ ] Working directory is clean

### Version Numbering

LLMDump follows [Semantic Versioning](https://semver.org/):

- **MAJOR** (1.0.0): Breaking changes
- **MINOR** (0.1.0): New features, backwards compatible
- **PATCH** (0.0.1): Bug fixes, backwards compatible

Examples:
- `0.1.3` → `0.1.4`: Bug fixes or minor improvements
- `0.1.3` → `0.2.0`: New features added
- `0.1.3` → `1.0.0`: Major release or breaking changes

### CHANGELOG Format

Follow [Keep a Changelog](https://keepachangelog.com/) format:

```markdown
## [0.1.4] - 2025-10-28

### Added
- New feature X
- New feature Y

### Changed
- Improved Z

### Fixed
- Bug fix A
- Bug fix B

### Removed
- Deprecated feature C
```

### Troubleshooting

#### Tag Already Exists

```bash
# Delete local tag
git tag -d v0.1.4

# Delete remote tag
git push origin :refs/tags/v0.1.4

# Recreate tag
git tag -a v0.1.4 -m "Release version 0.1.4"
git push origin v0.1.4
```

#### Release Failed to Create

1. Check GitHub Actions logs
2. Verify `GITHUB_TOKEN` permissions
3. Manually create release on GitHub

#### PyPI Upload Failed

1. Check if version already exists on PyPI
2. Verify `PYPI_API_TOKEN` secret is set
3. Check Actions logs for error details
4. Manually upload if needed:
   ```bash
   python -m build
   python -m twine upload dist/*
   ```

### Automated Workflows

**On Tag Push (`v*`)**:
- Creates GitHub Release with CHANGELOG notes
- Publishes to PyPI

**On Main Branch Push (with version change)**:
- Automatically publishes to PyPI

### Best Practices

1. **Always test before releasing**: Run tests locally
2. **Write clear changelog**: Help users understand changes
3. **Use semantic versioning**: Makes version numbers meaningful
4. **Tag from main branch**: Ensure stable release point
5. **Verify after release**: Check GitHub and PyPI

### Emergency Rollback

If a release has critical issues:

1. **Yank from PyPI** (doesn't delete, marks as unavailable):
   Go to https://pypi.org/manage/project/llmdump/releases/ and yank the version

2. **Create hotfix release**:
   ```bash
   # Fix the issue
   git commit -m "fix: Critical bug in v0.1.4"
   
   # Release patch version
   ./scripts/create_release.sh 0.1.5
   ```

3. **Update documentation**: Warn users about the problematic version

---

## Temporal Validation

### The Problem

**Current Data:**
- CVE data: 2021-2025 (already disclosed)
- Current system: Collect signals "now" → Predict "future"

**Issues:**
- Training on past CVEs and testing with "current" signals is meaningless
- Predicting with data **after** CVE disclosure is cheating!

### Correct Usage

#### 1. Historical Backtesting (Past Time Simulation)

```bash
# Log4Shell (CVE-2021-44228) prediction simulation
# Actual disclosure: 2021-12-09
# Our prediction: 2021-11-09 (30 days before)

python scripts/experiments/historical_validation.py --cve CVE-2021-44228
```

**Timeline:**
```
2021-10-10 ────────> 2021-11-09 ────────> 2021-12-09
    │                    │                     │
Signal collection    Prediction point    Actual CVE disclosure
    starts                                      │
    │                    │                     │
    └─ 30 days signals ──┘                     │
                         │                     │
                    Our prediction        Ground Truth
```

#### 2. Actual Workflow

```python
from datetime import datetime

# 1. CVE information (in practice, load from Neo4j)
cve_disclosure = datetime(2021, 12, 9)  # Log4Shell

# 2. Set prediction point (30 days before CVE disclosure)
prediction_date = datetime(2021, 11, 9)

# 3. Signal collection period (30 days before prediction point)
signal_start = datetime(2021, 10, 10)
signal_end = datetime(2021, 11, 9)  # Before CVE disclosure!

# 4. Collect signals (no temporal leakage!)
commits = collector.collect_commit_history(
    "apache/log4j",
    since=signal_start,
    until=signal_end  # ⚠️ Only data before CVE disclosure!
)

# 5. Predict
threat_score = scorer.score_package(vector)

# 6. Validate
if threat_score.score > 0.7:
    print(f"✅ Prediction successful! Detected {(cve_disclosure - prediction_date).days} days before")
else:
    print(f"❌ Prediction failed")
```

### Validation Scenarios

#### Scenario 1: Could we have predicted Log4Shell?

```bash
python scripts/experiments/historical_validation.py \
    --cve CVE-2021-44228 \
    --prediction-days-before 30 \
    --signal-window-days 30
```

**Question:** Could we have predicted Log4Shell on November 9, 2021?

#### Scenario 2: Spring4Shell Prediction

```bash
python scripts/experiments/historical_validation.py \
    --cve CVE-2022-22965 \
    --prediction-days-before 60
```

### Correct Evaluation Method

#### Leave-One-Out Cross Validation

```python
# 1. All CVE list
all_cves = ["CVE-2021-44228", "CVE-2021-45046", "CVE-2022-22965", ...]

for test_cve in all_cves:
    # 2. Training: Train clusters with all CVEs except test CVE
    training_cves = [c for c in all_cves if c != test_cve]
    clusterer.fit(training_cve_vectors)
    
    # 3. Testing: Predict with signals before test CVE disclosure
    test_signals = collect_signals_before_disclosure(test_cve)
    prediction = scorer.score_package(test_signals)
    
    # 4. Evaluate
    if prediction.score > threshold:
        print(f"✅ {test_cve} prediction successful!")
```

### Core Principles

1. **Never use future data**
   - Don't predict with data after CVE disclosure
   - Don't use data after prediction point

2. **Strictly follow temporal order**
   ```
   Signal collection → Prediction → CVE disclosure
   (Past)              (Present)    (Future)
   ```

3. **Leave-One-Out for validation**
   - Exclude test CVE from training
   - Train clusters only with other CVEs

### Practical Usage

#### Real-time Prediction with Current System

```python
# Predict vulnerabilities right now
from datetime import datetime, timezone, timedelta

# 1. Current time
now = datetime.now(timezone.utc)
signal_start = now - timedelta(days=30)

# 2. Collect signals (last 30 days)
commits = collector.collect_commit_history(
    "target/repo",
    since=signal_start,
    until=now
)

# 3. Predict
threat_score = scorer.score_package(vector)

# 4. Interpret
if threat_score.score > 0.7:
    print(f"⚠️ High risk! CVE likely within next 30 days")
    print(f"Similar CVEs: {threat_score.similar_cves}")
```

---

## Resources

- [Semantic Versioning](https://semver.org/)
- [Keep a Changelog](https://keepachangelog.com/)
- [GitHub Releases](https://docs.github.com/en/repositories/releasing-projects-on-github)
- [PyPI Publishing](https://packaging.python.org/tutorials/packaging-projects/)

---

**ROTA v0.2.0** - Development Guide

*For user guide, see `docs/GUIDE.md`*  
*For research plan, see `docs/RESEARCH.md`*
