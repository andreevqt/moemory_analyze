#!/usr/bin/env bash

set -euo pipefail

usage() {
    cat <<'EOF'
Usage: ./scripts/release.sh [patch|minor|major] [--push] [--dry-run]

Examples:
  ./scripts/release.sh --dry-run
  ./scripts/release.sh patch --push
  ./scripts/release.sh minor --push
EOF
}

bump="patch"
bump_set=false
push_tag=false
dry_run=false
remote="origin"

for arg in "$@"; do
    case "$arg" in
        patch|minor|major)
            if [[ "$bump_set" == true ]]; then
                echo "Only one version increment may be specified." >&2
                exit 2
            fi
            bump="$arg"
            bump_set=true
            ;;
        --push)
            push_tag=true
            ;;
        --dry-run)
            dry_run=true
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $arg" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "Run this script inside the repository." >&2
    exit 1
fi

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

if [[ "$dry_run" == false && -n "$(git status --porcelain)" ]]; then
    echo "The worktree is not clean. Commit or stash changes before creating a release." >&2
    exit 1
fi

if [[ "$push_tag" == true && "$dry_run" == false ]]; then
    git remote get-url "$remote" >/dev/null
    git fetch "$remote" --tags
fi

current_tag=""
major=0
minor=0
patch=0

while IFS= read -r tag; do
    if [[ "$tag" =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
        current_tag="$tag"
        major="${BASH_REMATCH[1]}"
        minor="${BASH_REMATCH[2]}"
        patch="${BASH_REMATCH[3]}"
        break
    fi
done < <(git tag --list 'v*' --sort=-v:refname)

case "$bump" in
    major)
        major=$((10#$major + 1))
        minor=0
        patch=0
        ;;
    minor)
        minor=$((10#$minor + 1))
        patch=0
        ;;
    patch)
        patch=$((10#$patch + 1))
        ;;
esac

next_tag="v${major}.${minor}.${patch}"

if git rev-parse --verify --quiet "refs/tags/$next_tag" >/dev/null; then
    echo "Tag $next_tag already exists." >&2
    exit 1
fi

if [[ -n "$current_tag" ]]; then
    echo "$current_tag -> $next_tag"
else
    echo "No SemVer tags found; first release will be $next_tag"
fi

if [[ "$dry_run" == true ]]; then
    exit 0
fi

git tag --annotate "$next_tag" --message "Release $next_tag"
echo "Created tag $next_tag at $(git rev-parse --short HEAD)."

if [[ "$push_tag" == true ]]; then
    git push "$remote" "$next_tag"
    echo "Pushed $next_tag. GitHub Actions will publish the release."
else
    echo "Push it when ready: git push $remote $next_tag"
fi
