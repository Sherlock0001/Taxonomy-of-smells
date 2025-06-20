#!/bin/bash

# Paths
EXCEL_FILE="Merged_Security_Fixes.xlsx"
SCRIPT="commit_history.sh"

# Extract repo URLs and file paths from Excel using Python
echo "📥 Extracting repositories and file paths..."
python3 - <<EOF > repo_files.txt
import pandas as pd

# Load Excel file
df = pd.read_excel("$EXCEL_FILE")

# Extract unique commit URLs and file paths
repo_files = df[["commit_url", "file_path"]].drop_duplicates()

# Write to text file
with open("repo_files.txt", "w") as f:
    for _, row in repo_files.iterrows():
        commit_url = row["commit_url"]
        repo_url = commit_url.split("/commits/")[0].replace("api.github.com/repos", "github.com") + ".git"
        file_path = row["file_path"]
        output_file = f"commit_history_{file_path.replace('/', '_')}.txt"
        f.write(f"{repo_url} {file_path} {output_file}\n")

print("✅ Extraction completed.")
EOF

# Run shell script for each repository and file
echo "🚀 Fetching commit history..."
while IFS=" " read -r repo_url file_path output_file; do
    echo "🔍 Processing $file_path in $repo_url..."
    bash $SCRIPT "$repo_url" "$file_path" "$output_file"
done < repo_files.txt

echo "✅ All repositories processed."