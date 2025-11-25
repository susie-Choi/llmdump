# Create a new release for LLMDump
param(
    [Parameter(Mandatory=$true)]
    [string]$Version
)

$ErrorActionPreference = "Stop"

$Tag = "v$Version"

Write-Host "Creating release for version $Version..." -ForegroundColor Cyan

# Check if tag already exists
$tagExists = git rev-parse $Tag 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "Error: Tag $Tag already exists" -ForegroundColor Red
    exit 1
}

# Check if we're on main branch
$currentBranch = git branch --show-current
if ($currentBranch -ne "main") {
    Write-Host "Warning: You're not on main branch (current: $currentBranch)" -ForegroundColor Yellow
    $continue = Read-Host "Continue anyway? (y/n)"
    if ($continue -ne "y") {
        exit 1
    }
}

# Check if working directory is clean
$status = git status --porcelain
if ($status) {
    Write-Host "Error: Working directory is not clean. Commit or stash changes first." -ForegroundColor Red
    exit 1
}

# Create and push tag
Write-Host "Creating tag $Tag..." -ForegroundColor Green
git tag -a $Tag -m "Release version $Version"

Write-Host "Pushing tag to GitHub..." -ForegroundColor Green
git push origin $Tag

Write-Host ""
Write-Host "✅ Release tag created successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:"
Write-Host "1. GitHub Actions will automatically create the release"
Write-Host "2. Check: https://github.com/susie-Choi/llmdump/releases"
Write-Host "3. PyPI will automatically publish the package"
Write-Host "4. Check: https://pypi.org/project/llmdump/$Version/"
