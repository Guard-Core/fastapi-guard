#!/bin/bash
# Push the refreshed uv.lock to one branch and open or refresh the single lock PR, then dispatch CI on that branch (D-157).
# usage: lock_pr.sh <branch> <subject> <body-file>. Needs contents, pull-requests and actions write on GITHUB_TOKEN.
set -euo pipefail
branch=$1
subject=$2
body_file=$3

git config user.name "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
base=$(gh repo view --json defaultBranchRef --jq .defaultBranchRef.name)

git switch -C "$branch"
git add uv.lock
git commit -m "$subject"
git push --force origin "$branch"

number=$(gh pr list --head "$branch" --state open --json number --jq '.[0].number // empty')
if [ -n "$number" ]; then
  gh pr edit "$number" --title "$subject" --body-file "$body_file"
else
  gh pr create --base "$base" --head "$branch" --title "$subject" --body-file "$body_file" --label dependencies
fi

# Events caused by GITHUB_TOKEN start no workflow runs except workflow_dispatch, so the PR's own CI never starts: dispatch it on the branch head.
gh workflow run ci.yml --ref "$branch"
