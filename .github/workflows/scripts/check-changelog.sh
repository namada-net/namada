#!/bin/bash

check_changelog_added_in_subfolders() {
    if [[ -z "${SHA}" ]]; then
        head_commit=$(git rev-parse HEAD)
    else
        head_commit="${SHA}"
    fi
    echo "Using sha: $head_commit"

    subfolders=("ci" "bug-fixes" "improvements" "miscellaneous" "features" "testing" "docs" "SDK")

    subfolder_pattern=$(printf "|%s" "${subfolders[@]}")
    subfolder_pattern=${subfolder_pattern:1} # Remove the leading '|'

    added_files=$(git diff --diff-filter=A --name-only "origin/main..$head_commit" | grep "\.changelog/")

    relevant_files=$(echo "$added_files" | grep -E "\.changelog/unreleased/($subfolder_pattern)/")

    if [ -n "$relevant_files" ]; then
        echo "Changelog found: $relevant_files"
        exit 0
    else
        echo "No files were added in the .changelog directory in the specified subfolders."
        exit 1
    fi
}

check_changelog_added_in_subfolders
