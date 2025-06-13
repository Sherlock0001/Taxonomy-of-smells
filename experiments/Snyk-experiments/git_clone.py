import pandas as pd
import subprocess
import os

# --- Configuration ---
# Modify these values as needed
EXCEL_FILE_PATH = "dataset.xlsx"  # Replace with the path to your Excel file
REPO_COLUMN_NAME = "repo_github"  # Name of the column containing GitHub repository URLs
CLONE_DESTINATION_DIR = "" # Optional: Directory where the repositories will be cloned.
                           # Leave empty ("") to clone into the current script directory.
                           # If specified, the directory will be created if it doesn't exist.

# --- Utility Functions ---
def get_repo_name_from_url(url):
    """Extracts the repository name from the URL."""
    try:
        repo_name = url.split('/')[-1]
        if repo_name.endswith(".git"):
            repo_name = repo_name[:-4]
        return repo_name
    except Exception:
        return None

# --- Main Script ---
def main():
    print("--- Starting GitHub repository cloning script ---")

    # 1. Check if the Excel file exists
    if not os.path.exists(EXCEL_FILE_PATH):
        print(f"ERROR: Excel file '{EXCEL_FILE_PATH}' was not found.")
        print("Please check the path and filename in the 'EXCEL_FILE_PATH' variable.")
        return

    # 2. Create the destination directory if specified and does not exist
    clone_base_path_for_repos = os.getcwd() # By default, the script's current directory
    if CLONE_DESTINATION_DIR:
        # If CLONE_DESTINATION_DIR is an absolute path, it will be used as is.
        # If it's relative, it will be relative to the script's current directory.
        abs_clone_destination_dir = os.path.abspath(CLONE_DESTINATION_DIR)
        if not os.path.exists(abs_clone_destination_dir):
            try:
                os.makedirs(abs_clone_destination_dir)
                print(f"INFO: Destination directory '{abs_clone_destination_dir}' created.")
            except OSError as e:
                print(f"ERROR: Could not create destination directory '{abs_clone_destination_dir}': {e}")
                return
        clone_base_path_for_repos = abs_clone_destination_dir
        print(f"INFO: Repositories will be cloned into the directory: '{clone_base_path_for_repos}'")
    else:
        print(f"INFO: Repositories will be cloned into the script's current directory: '{clone_base_path_for_repos}'")

    # 3. Read the Excel file
    try:
        df = pd.read_excel(EXCEL_FILE_PATH)
        print(f"INFO: Excel file '{EXCEL_FILE_PATH}' successfully read.")
    except FileNotFoundError:
        print(f"ERROR: Excel file '{EXCEL_FILE_PATH}' was not found.")
        return
    except Exception as e:
        print(f"ERROR: An error occurred while reading the Excel file: {e}")
        return

    # 4. Check if the repository column exists
    if REPO_COLUMN_NAME not in df.columns:
        print(f"ERROR: Column '{REPO_COLUMN_NAME}' was not found in the Excel file.")
        print(f"Available columns: {', '.join(df.columns)}")
        print("Please check the column name in the 'REPO_COLUMN_NAME' variable.")
        return

    # 5. Iterate through each row and clone the repository
    for index, row in df.iterrows():
        repo_url = row[REPO_COLUMN_NAME]

        if pd.isna(repo_url) or not isinstance(repo_url, str) or not repo_url.strip():
            print(f"\nWARNING: Row {index + 2}: Missing, empty, or invalid repository URL. Skipped.")
            continue

        repo_url = repo_url.strip()
        print(f"\n--- Processing row {index + 2}: Repository '{repo_url}' ---")

        repo_name = get_repo_name_from_url(repo_url)
        if not repo_name:
            print(f"ERROR: Could not extract repository name from URL '{repo_url}'. Skipped.")
            continue
        
        destination_repo_path = os.path.join(clone_base_path_for_repos, repo_name)

        if os.path.exists(destination_repo_path):
            print(f"INFO: Directory '{destination_repo_path}' already exists. Cloning skipped for this repository.")
            continue

        # The git clone command will be `git clone <repo_url> <local_repo_name>`
        # It will be executed in `clone_base_path_for_repos`.
        command_to_run = ["git", "clone", repo_url, repo_name]

        try:
            print(f"INFO: Attempting to clone '{repo_url}'")
            print(f"Destination: '{destination_repo_path}'")
            print(f"Cloning progress for '{repo_name}' will be displayed below:")

            # Run the command. Git's output (progress, errors) will be shown directly in the console.
            process = subprocess.run(
                command_to_run,
                cwd=clone_base_path_for_repos, # Cloning will occur in this base directory
                check=False  # Important: do not raise exceptions on non-zero return codes
                             # because we want to handle the error ourselves.
                # No 'capture_output=True' so output goes directly to console.
                # No 'text=True' since we are not capturing the output for decoding.
            )

            if process.returncode == 0:
                print(f"\nSUCCESS: Repository '{repo_name}' successfully cloned into '{destination_repo_path}'.")
            else:
                # Git error messages will have already been printed to the console.
                print(f"\nERROR: Failed to clone repository '{repo_url}'.")
                print(f"Git return code: {process.returncode}")
                print("Please check Git's messages above for more details.")

        except FileNotFoundError:
            print("CRITICAL ERROR: The 'git' command was not found.")
            print("Make sure Git is installed and correctly configured in your system's PATH.")
            print("Stopping the script.")
            return # Stop the entire script if git is not found
        except Exception as e:
            print(f"UNEXPECTED ERROR: An error occurred while cloning '{repo_url}': {e}")

    print("\n--- End of cloning script ---")

if __name__ == "__main__":
    main()
