# ── ansible_rule_generation.py ──
"""
Generates Ansible-Lint rules in PYTHON format from an Excel file (vulnerability,
smell_category, code_snippet, filepath) via the OpenAI API. Writes the generated
rule in the 'generated_rule' column with validation logic.

By default, ansible-lint only scans files with .yaml or .yml extensions.

The `.ansible-lint` configuration file has been updated to extend the list of
supported file extensions to include `.py` files, so that Python-based test cases 
can be analyzed as part of the linting process.


Prerequisites:
    pip install openai pandas openpyxl tqdm backoff
    export OPENAI_API_KEY="sk-..."

Usage:
    python generate_ansible_lint_rules.py <input.xlsx> <output.xlsx> [model]
"""

import os
import re
import sys
import time
import textwrap
import pathlib
from typing import Dict, Any

import backoff
import openai
import pandas as pd
from tqdm import tqdm

# --- CONFIGURATION ---
MODEL = sys.argv[3] if len(sys.argv) > 3 else "gpt-3.5-turbo-0125"
TEMPERATURE = 0.0
MAX_TOKENS_RESPONSE = 1200
REQUEST_PAUSE = 0.7
MAX_RETRIES = 3

# --- PROMPT TEMPLATE FOR ANSIBLE-LINT RULES IN PYTHON ---
PROMPT_TEMPLATE = textwrap.dedent("""
You are an IaC security expert, specialized in writing **Ansible-Lint rules in Python**.

Your task is to produce a valid **Python** detection rule for Ansible-Lint, based on a vulnerability and a code snippet.

─────────────────────────────
### STRICT AND MANDATORY REQUIREMENTS

1.  **Rule Format:** The rule MUST be in Python code for Ansible-Lint.

2.  **Class Structure:**
    -   Import `AnsibleLintRule` from `ansiblelint.rules`.
    -   The class MUST inherit from `AnsibleLintRule`.
    -   The following attributes MUST be present: `id`, `shortdesc`, `description`, `severity`, `tags`, `version_added`.

3.  **Detection Logic:**
    -   For **YAML files (.yml/.yaml)**: Use `def match(self, line: str) -> bool | str:` method.
    -   For **Python files (.py)**: Use `def match(self, line: str) -> bool | str:` method.
    -   The method analyzes one line at a time. It returns a message string if a violation is found, and `False` otherwise.
    -   Use regular expressions (`re.compile`) for detection when appropriate.

4.  **Rule ID Format:**
    -   Use format "SECURITY{number}" for security rules (e.g., "SECURITY001", "SECURITY002").
    -   Use format "CUSTOM{number}" for other rules.

5.  **Example of a Valid Rule Skeleton for YAML:**
    ```python
    from __future__ import annotations
    import re
    from ansiblelint.rules import AnsibleLintRule

    class UnsafeYamlPatternRule(AnsibleLintRule):
        id = "SECURITY001"
        shortdesc = "Code Injection: Unsafe YAML pattern detected"
        description = "This pattern can lead to security vulnerabilities."
        severity = "HIGH"
        tags = {{"security", "yaml"}}
        version_added = "1.0.0"
        
        _pattern = re.compile(r"dangerous_pattern")

        def match(self, line: str) -> bool | str:
            if line.lstrip().startswith('#'):
                return False
            if self._pattern.search(line):
                return self.shortdesc
            return False
    ```

6.  **Example of a Valid Rule Skeleton for Python:**
    ```python
    from __future__ import annotations
    import re
    from ansiblelint.rules import AnsibleLintRule

    class UnsafePythonPatternRule(AnsibleLintRule):
        id = "SECURITY002"
        shortdesc = "Code Injection: Unsafe Python pattern detected"
        description = "This Python pattern can lead to security vulnerabilities."
        severity = "HIGH"
        tags = {{"security", "python"}}
        version_added = "1.0.0"
        
        _pattern = re.compile(r"dangerous_python_pattern")

        def match(self, line: str) -> bool | str:
            line_stripped = line.strip()
            if line_stripped.startswith('#'):
                return False
            if self._pattern.search(line):
                return self.shortdesc
            return False
    ```

7.  **Output Format:** Provide **only the complete Python code** for the rule. No ```python, no explanatory text.

─────────────────────────────
### INPUT

Vulnerability   : {vulnerability}
Smell Category  : {smell_category}
File Type       : {file_type}
Code Snippet:
```
{code_snippet}
```

Now, generate the requested Ansible-Lint rule in Python strictly following ALL the requirements.
The rule should detect the vulnerability shown in the code snippet above.
""").strip()

# --- HELPERS ---

class SafeDict(dict):
    """Avoids KeyError in str.format_map"""
    def __missing__(self, key):
        return '{' + key + '}'

def determine_file_type(row: pd.Series) -> str:
    """Determines the file type, giving priority to 'filepath'."""
    if "filepath" in row and pd.notna(row["filepath"]):
        filepath_str = str(row["filepath"]).lower().strip()
        if filepath_str.endswith(".py"): 
            return "python"
        elif filepath_str.endswith((".yml", ".yaml")): 
            return "yaml"
    
    # Fallback: analyze code snippet
    snippet = str(row.get("code_snippet", "")).strip()
    if any(keyword in snippet for keyword in ["import ", "def ", "class ", "if __name__"]):
        return "python"
    elif any(keyword in snippet for keyword in ["---", "tasks:", "name:", "hosts:"]):
        return "yaml"
    
    # Default fallback
    return "yaml"

# Regex patterns for validation
_CLASS_RE = re.compile(r"class\s+\w+\(AnsibleLintRule\):", re.MULTILINE)
_MATCH_FN_RE = re.compile(r"def\s+match\(self,\s*line:\s*str\)", re.MULTILINE)
_REQUIRED_ATTRS = ("id =", "shortdesc =", "description =", "severity =", "tags =", "version_added =")
_IMPORT_RE = re.compile(r"from ansiblelint\.rules import AnsibleLintRule", re.MULTILINE)

def is_valid_ansible_lint_rule(code: str) -> bool:
    """Validates the basic structure of the generated Ansible-Lint rule code."""
    if not code or not isinstance(code, str): 
        return False
    
    # Check required import
    if not _IMPORT_RE.search(code):
        return False
    
    # Check class structure
    if not _CLASS_RE.search(code):
        return False
    
    # Check match method
    if not _MATCH_FN_RE.search(code):
        return False
    
    # Check required attributes
    if not all(attr in code for attr in _REQUIRED_ATTRS):
        return False
    
    return True

def clean_generated_code(content: str) -> str:
    """Cleans the generated code by removing markdown markers."""
    if not content: 
        return content
    
    # Remove markdown code blocks
    content = re.sub(r'^```(python)?\s*\n', '', content, flags=re.MULTILINE)
    content = re.sub(r'```$', '', content.strip())
    
    return content.strip()

# --- OPENAI CLIENT ---

def get_api_key() -> str:
    """Retrieves the OpenAI API key from the environment."""
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        sys.exit("‼️  Environment variable OPENAI_API_KEY is missing.")
    return api_key

client = openai.OpenAI(api_key=get_api_key())

@backoff.on_exception(
    backoff.expo,
    (openai.RateLimitError, openai.APIError, openai.APIConnectionError),
    max_time=120, max_tries=5
)
def call_chatgpt(prompt: str) -> str:
    """Calls the OpenAI API with an automatic backoff strategy."""
    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": "You are an Ansible-Lint expert generating security rules in Python format."},
                {"role": "user", "content": prompt},
            ],
            temperature=TEMPERATURE,
            max_tokens=MAX_TOKENS_RESPONSE,
        )
        content = response.choices[0].message.content
        if not content: 
            raise ValueError("Empty response from OpenAI API")
        return clean_generated_code(content)
    except Exception as e:
        tqdm.write(f"⚠️  API call error: {e}")
        raise

# --- MAIN FUNCTIONS ---

def build_prompt(vuln: str, smell: str, ftype: str, snippet: str) -> str:
    """Builds the prompt using SafeDict for safe formatting."""
    if not PROMPT_TEMPLATE: 
        raise ValueError("PROMPT_TEMPLATE is not defined")
    
    vars_ = {
        "vulnerability": vuln.strip(),
        "smell_category": smell.strip(),
        "file_type": ftype.strip().lower(),
        "code_snippet": snippet.strip(),
    }
    return PROMPT_TEMPLATE.format_map(SafeDict(vars_))

def process_single_row(idx: int, row: pd.Series) -> str:
    """Processes a single DataFrame row and generates the Ansible-Lint rule."""
    vuln = str(row.get("vulnerability", "")).strip()
    smell = str(row.get("smell_category", "")).strip()
    code = str(row.get("code_snippet", "")).strip()

    if not (vuln and smell and code):
        return "[IGNORED] Incomplete data - missing vulnerability, smell_category, or code_snippet."

    ftype = determine_file_type(row)

    try:
        prompt = build_prompt(vuln, smell, ftype, code)
    except Exception as e:
        return f"[PROMPT ERROR] {e}"

    for attempt in range(MAX_RETRIES):
        try:
            rule = call_chatgpt(prompt)
            if is_valid_ansible_lint_rule(rule):
                return rule
            else:
                tqdm.write(f"⚠️  Row {idx+2}: Attempt {attempt+1} - invalid Ansible-Lint rule structure.")
                prompt += "\n\n❗ WARNING: The previous response was invalid. Ensure you follow the exact Ansible-Lint rule structure with proper imports and method signatures."
        except Exception as e:
            tqdm.write(f"⚠️  Row {idx+2}: Error attempt {attempt+1}: {e}")
            if attempt == MAX_RETRIES - 1: 
                return f"[API ERROR] {e}"
        time.sleep(REQUEST_PAUSE)

    return "[FAILURE] Could not obtain a valid Ansible-Lint rule after multiple attempts."

def generate_rules_excel(input_path: str, output_path: str) -> None:
    """Orchestrates the Ansible-Lint rule generation process."""
    if not os.path.exists(input_path):
        sys.exit(f"‼️  Input file '{input_path}' not found.")

    try:
        df = pd.read_excel(input_path, engine="openpyxl")
    except Exception as e:
        sys.exit(f"‼️  Error reading Excel file: {e}")

    mandatory_cols = {"vulnerability", "smell_category", "code_snippet"}
    if not mandatory_cols.issubset(df.columns):
        missing = mandatory_cols - set(df.columns)
        sys.exit(f"‼️  Missing columns: {', '.join(missing)}")

    # Add column for generated rules
    df["generated_ansible_lint_rule"] = ""

    print(f"🔧  Model: {MODEL}")
    print(f"📊  Rows to process: {len(df)}")
    print(f"📁  Input file: {input_path}")
    print(f"📁  Output file: {output_path}")
    print("-" * 50)

    for idx, row in tqdm(df.iterrows(), total=len(df), desc="Generating Ansible-Lint rules"):
        result = process_single_row(idx, row)
        df.at[idx, "generated_ansible_lint_rule"] = result
        time.sleep(REQUEST_PAUSE)

    try:
        output_dir = os.path.dirname(output_path)
        if output_dir and not os.path.exists(output_dir): 
            os.makedirs(output_dir)
        
        df.to_excel(output_path, index=False, engine="openpyxl")
        print(f"\n✅  Export completed successfully: {output_path}")
        
        # Statistics
        success_count = len(df[~df["generated_ansible_lint_rule"].str.startswith("[")])
        print(f"📈  Statistics: {success_count}/{len(df)} Ansible-Lint rules generated successfully")
        
        # Show file type distribution
        if "filepath" in df.columns:
            file_types = df.apply(determine_file_type, axis=1)
            type_counts = file_types.value_counts()
            print(f"📁  File types processed: {dict(type_counts)}")
            
    except Exception as e:
        sys.exit(f"‼️  Error during export: {e}")

# --- COMMAND-LINE INTERFACE ---
def main():
    """Main entry point of the script."""
    if len(sys.argv) < 3:
        print("Usage: python generate_ansible_lint_rules.py <input.xlsx> <output.xlsx> [model]")
        print("\nExample:")
        print("  python generate_ansible_lint_rules.py vulnerabilities.xlsx generated_rules.xlsx")
        print("  python generate_ansible_lint_rules.py data.xlsx output.xlsx gpt-4")
        print("\nRequired columns in Excel file:")
        print("  - vulnerability: Description of the security vulnerability")
        print("  - smell_category: Category of the code smell") 
        print("  - code_snippet: The vulnerable code to detect")
        print("  - filepath: (optional) File path to determine .py vs .yaml")
        sys.exit(1)

    input_file, output_file = sys.argv[1], sys.argv[2]

    if not input_file.endswith(('.xlsx', '.xls')):
        sys.exit("‼️  Input file must be an Excel file (.xlsx or .xls).")
    if not output_file.endswith(('.xlsx', '.xls')):
        sys.exit("‼️  Output file must be an Excel file (.xlsx or .xls).")

    generate_rules_excel(input_file, output_file)

if __name__ == "__main__":
    main()
