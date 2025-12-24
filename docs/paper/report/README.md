# LLMDump Paper

**Title**: LLMDump: LLM-powered Zero-Day Vulnerability Prediction

**Status**: Draft

## Files

- `rota_paper.tex` - LaTeX source file (IEEE conference format) [Legacy filename]
- `rota_paper.pdf` - Compiled PDF [Legacy filename]

## Compilation

```bash
pdflatex rota_paper.tex
```

Note: Paper files retain legacy "rota" filenames for compatibility.

## Current Results

### Dataset
- **CVEs analyzed**: 3 (CVE-2011-3188, CVE-2012-3503, CVE-2012-4406)
- **Total commits**: 35,080 (±180 days filtered)
- **Projects**: Linux Kernel, Katello, OpenStack Swift

### Key Findings
- Successfully identified fix commit for CVE-2012-3503
- Detected 42.7% of commits as security-related
- ±180 day window captures 92.4% of relevant commits

### Model
- Google Gemini 2.5 Flash

### Database
- Neo4j with 11,441 CVEs, 35,080 commits, 1,666 KEV entries

## Next Steps

See `ANALYSIS_RESULTS.md` in project root for detailed analysis and future work.
