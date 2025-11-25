#!/bin/bash
# Create a new release for LLMDump

set -e

# Check if version argument is provided
if [ -z "$1" ]; then
    echo "Usage: ./scripts/create_release.sh <version>"
    echo "Example: ./scripts/create_release.sh 0.1.3"
    exit 1
fi

VERSION=$1
TAG="v${VERSION}"

echo "Creating release for version ${VERSION}..."

# Check if tag already exists
if git rev-parse "$TAG" >/dev/null 2>&1; then
    echo "Error: Tag $TAG already exists"
    exit 1
fi

# Check if we're on main branch
CURRENT_BRANCH=$(git branch --show-current)
if [ "$CURRENT_BRANCH" != "main" ]; then
    echo "Warning: You're not on main branch (current: $CURRENT_BRANCH)"
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Check if working directory is clean
if [ -n "$(git status --porcelain)" ]; then
    echo "Error: Working directory is not clean. Commit or stash changes first."
    exit 1
fi

# Create and push tag
echo "Creating tag ${TAG}..."
git tag -a "$TAG" -m "Release version ${VERSION}"

echo "Pushing tag to GitHub..."
git push origin "$TAG"

echo ""
echo "✅ Release tag created successfully!"
echo ""
echo "Next steps:"
echo "1. GitHub Actions will automatically create the release"
echo "2. Check: https://github.com/susie-Choi/llmdump/releases"
echo "3. PyPI will automatically publish the package"
echo "4. Check: https://pypi.org/project/llmdump/${VERSION}/"
