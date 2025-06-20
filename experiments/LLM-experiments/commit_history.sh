#!/bin/bash

# Usage: ./commit_history.sh <repo_url> <file_path> <output_file>

REPO_URL=$1
FILE_PATH=$2
OUTPUT_FILE=$3

# Extract repo name from URL
REPO_NAME=$(basename $REPO_URL .git)

# Clone repo (shallow clone to avoid huge history downloads)
git clone --depth 1 $REPO_URL $REPO_NAME
cd $REPO_NAME || exit

# Fetch full history for the given file, tracking renames
git log --follow --pretty=format:"%H %ad" --date=short --name-only -- $FILE_PATH > ../$OUTPUT_FILE

# Clean up
cd ..
rm -rf $REPO_NAME

echo "✅ Commit history saved to $OUTPUT_FILE"