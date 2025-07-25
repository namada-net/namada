#!/usr/bin/env bash
#
# A helper to merge e.g. a PR from draft to an RC branch where any neccessary
# conflicts resolutions are expected to have been trained with rerere.
#
# It merges PRs from "origin" remote which should be set to "git@github.com:namada-net/namada.git".
# Make sure to fetch latest before running with e.g. `git fetch origin`.
#
# Requires `gh` to be installed and authenticated.
#
# Usage example:
# $ scripts/merge_pr.sh 2627 2db3acdb21581bb502b27dc9c1c831b4e94ad013 && \
# $ scripts/merge_pr.sh 2698 0d3b252e7f5ceb85a276966fe8ee7d7e1c0c6e63 ce68d3a57eb342495a43dc65ee03394b116fd484 && \
# $ scripts/merge_pr.sh 2819
#
# The first argument is a PR number, followed by any number of evil commit
# hashes.

set -Eo pipefail

PR_NUM=$1

BRANCH=$(gh pr view "$PR_NUM" --json headRefName -q .headRefName)
echo "🔴 Merging branch $BRANCH https://github.com/namada-net/namada/pull/$PR_NUM ..."

# TODO: handle cross-repository PRs (and remote & fetch)
IS_CROSS=$(gh pr view "$PR_NUM" --json isCrossRepository -q .isCrossRepository)
if [ "$IS_CROSS" == "true" ]; then
    echo "🪦 Cross-repository PR, manual intervention needed for PR #$PR_NUM"
    exit 1
fi

# Merge the PR
git merge --no-ff -m "Merge branch '$BRANCH' (#$PR_NUM)" origin/"$BRANCH"

if [ $? -ne 0 ]; then
    echo ""
    echo "In rerere we trust 🙏"

    git add wasm_for_tests/*.wasm 

    git commit --no-edit

    if [ $? -ne 0 ]; then
        echo "🪦 Automatic resolution failed, manual intervention needed for PR #$PR_NUM"
        exit 1
    fi
fi

# Add evil commits
for var in "${@:2}" # Skip the first arg (PR number)
do
    echo ""
    echo "🙉 Adding evil $var..."
    git cherry-pick --no-commit "$var"
    git commit --amend --no-edit

    if [ $? -ne 0 ]; then
        echo "🪦 Evil commit failed to apply, manual intervention needed for PR #$PR_NUM"
        exit 1
    fi
done

echo ""
echo ""
