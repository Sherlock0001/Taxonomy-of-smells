import os
import subprocess
import json
import shutil
import sys
import stat
import pandas as pd

# === CONFIGURATION ===
# Set output directory for scan results and cache
OUTPUT_DIR = "."  # Replace with your desired output folder path
EXCEL_FILE = "dataset.xlsx"  # Path to Excel file with repo and commit info
CACHE_FILE = os.path.join(OUTPUT_DIR, "scan_cache.json")  # Cache file to store scan results

# Ensure output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

# === UTILS ===

# Extracts the repository name from a GitHub URL
def get_repo_name(repo_url):
    repo_name = repo_url.rstrip("/")
    if repo_name.endswith(".git"):
        repo_name = repo_name[:-4]
    return os.path.basename(repo_name)

# Handles permission errors when deleting files or directories
def handle_remove_readonly(func, path, exc):
    import errno
    excvalue = exc[1]
    if func in (os.rmdir, os.remove, os.unlink) and excvalue.errno in (errno.EACCES, errno.EPERM):
        try:
            os.chmod(path, stat.S_IWRITE)
            func(path)
        except Exception:
            pass
    else:
        raise

# Safely runs a Snyk scan and saves the output to a JSON file
def safe_run_snyk(command, output_file, cwd):
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, cwd=cwd, text=True)
        try:
            if result.stdout:
                json_data = json.loads(result.stdout)
                with open(output_file, "w", encoding="utf-8") as fout:
                    json.dump(json_data, fout, indent=2)
                return True
        except json.JSONDecodeError:
            pass
        # If JSON parsing fails, write raw output
        with open(output_file, "w", encoding="utf-8") as fout:
            fout.write(result.stdout or result.stderr or "Empty output")
        return result.returncode == 0
    except Exception as e:
        # On error, save error message to output file
        with open(output_file, "w", encoding="utf-8") as fout:
            json.dump({"error": str(e)}, fout, indent=2)
        return False

# === CACHE ===

# Load cached scan results from file
def load_scan_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

# Save current scan results to cache file
def save_scan_cache(cache):
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2)

# Load existing scan cache
scan_cache = load_scan_cache()

# === SCAN ===

# Runs Snyk scans (code + IaC) for the specified repo and commit
def run_snyk_scan(repo_url, commit_sha):
    if not repo_url.endswith('.git'):
        repo_url += '.git'
    repo_name = get_repo_name(repo_url)
    short_sha = commit_sha[:7]  # Abbreviated SHA for filenames

    # Check cache for existing scan results
    repo_cache = scan_cache.get(repo_url, {})
    sha_cache = repo_cache.get(commit_sha, {})

    code_output = os.path.join(OUTPUT_DIR, f"snyk-code-{repo_name}-{short_sha}.json")
    iac_output = os.path.join(OUTPUT_DIR, f"snyk-iac-{repo_name}-{short_sha}.json")

    if sha_cache.get("code_scanned") and sha_cache.get("iac_scanned"):
        print(f"✅ Already scanned: {repo_name}@{short_sha}")
        return

    folder = os.path.join(OUTPUT_DIR, repo_name)

    # Clone the repository if it doesn't already exist
    if os.path.exists(folder):
        print(f"📂 Using already cloned repository: {folder}")
    else:
        print(f"📥 Cloning repository: {repo_url}")
        result = subprocess.run(["git", "clone", repo_url, folder], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            print(f"❌ Clone error: {result.stderr}")
            return

    # Checkout the specific commit
    subprocess.run(["git", "checkout", commit_sha], cwd=folder)

    # Initialize cache entry for the repo and commit
    scan_cache.setdefault(repo_url, {}).setdefault(commit_sha, {})

    # Run Snyk Code scan if not already done
    if not sha_cache.get("code_scanned"):
        print(f"⚙️  Running Snyk CODE scan...")
        success = safe_run_snyk(["snyk", "code", "test", "--json"], code_output, cwd=folder)
        scan_cache[repo_url][commit_sha]["code_scanned"] = success

    # Run Snyk IaC scan if not already done
    if not sha_cache.get("iac_scanned"):
        print(f"⚙️  Running Snyk IaC scan...")
        success = safe_run_snyk(["snyk", "iac", "test", "--json"], iac_output, cwd=folder)
        scan_cache[repo_url][commit_sha]["iac_scanned"] = success

# === EXECUTION ===

# Main script execution: reads Excel file and runs scans on listed repos
if __name__ == "__main__":
    df = pd.read_excel(EXCEL_FILE)

    # Check for required columns in the Excel file
    if "repo_github" not in df.columns or "commit_sha" not in df.columns:
        print("❌ Missing columns in the Excel file")
        sys.exit(1)

    total = len(df)
    for i, row in df.iterrows():
        repo = row["repo_github"]
        sha = row["commit_sha"]
        if pd.isna(repo) or pd.isna(sha):
            continue
        print(f"\n🟦 [{i+1}/{total}] Repository: {repo} | Commit: {sha}")
        run_snyk_scan(repo.strip(), sha.strip())

    # Save updated scan results to cache
    save_scan_cache(scan_cache)
    print("\n✅ All scans completed.")
