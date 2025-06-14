# ── generate_salt_lint_rules.py ──
"""
Generates Salt-Lint rules in PYTHON format from an Excel file (vulnerability,
smell_category, code_snippet, filepath) via the OpenAI API. Writes the generated
rule in the 'generated_rule' column with validation logic.

Prerequisites:
    pip install openai pandas openpyxl tqdm backoff
    export OPENAI_API_KEY="sk-..."

Usage:
    python generate_salt_lint_rules.py <input.xlsx> <output.xlsx> [model]
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
MAX_TOKENS_RESPONSE = 900
REQUEST_PAUSE = 0.7
MAX_RETRIES = 3

# --- PROMPT TEMPLATE FOR SALT-LINT RULES IN PYTHON ---
PROMPT_TEMPLATE = textwrap.dedent("""
You are an IaC security expert, specialized in writing **Salt-Lint rules in Python**.

Your task is to produce a valid **Python** detection rule for Salt-Lint, based on a vulnerability and a code snippet.

─────────────────────────────
### STRICT AND MANDATORY REQUIREMENTS

1.  **Rule Format:** The rule MUST be in Python code.

2.  **Class Structure:**
    -   Import `Rule` from `saltlint.linter.rule`.
    -   The class MUST inherit from `Rule`.
    -   The following attributes MUST be present: `id`, `shortdesc`, `description`, `severity`, `tags`, `version_added`.

3.  **Detection Logic (`match`):**
    -   The method signature MUST be `def match(self, file, line: str) -> bool | str:`.
    -   The method analyzes one line at a time. It returns `True` or a message if a violation is found, and `False` otherwise.
    -   Use regular expressions (`re.compile`) for detection.

4.  **Rule Alias (VERY IMPORTANT):**
    -   At the end of the file, you MUST add an alias. The alias variable name must match the file name in snake_case.
    -   **Example:** If the class is `MyRule`, the alias will be `my_rule = MyRule`. I will replace 'my_rule' with the filename later.

5.  **Example of a Valid Rule Skeleton:**
    ```python
    from __future__ import annotations
    import re
    from saltlint.linter.rule import Rule

    class MyPythonRule(Rule):
        id = "CUSTOM999"
        shortdesc = "Example short description."
        description = "This is a detailed description."
        severity = "MEDIUM"
        tags = ["security", "custom"]
        version_added = "1.0.0"
        _pattern = re.compile(r"some_pattern")

        def match(self, file, line: str) -> bool | str:
            if line.lstrip().startswith("#"):
                return False
            if self._pattern.search(line):
                return self.shortdesc
            return False

    # Alias for Salt-Lint loading
    my_python_rule = MyPythonRule
    ```

6.  **Output Format:** Provide **only the complete Python code** for the rule. No ```python, no explanatory text.

─────────────────────────────
### INPUT

Vulnerability   : {vulnerability}
Smell Category  : {smell_category}
File Type       : {file_type}
Code Snippet:
```
{code_snippet}
```
Now, generate the requested Salt-Lint rule in Python strictly following ALL the requirements.
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
        if filepath_str.endswith(".py"): return "py"
        elif filepath_str.endswith(".sls"): return "sls"
    snippet = str(row.get("code_snippet", "")).strip()
    return "py" if "import " in snippet or "def " in snippet else "sls"

_CLASS_RE_PY = re.compile(r"class\s+\w+\(Rule\):", re.MULTILINE)
_MATCH_FN_RE_PY = re.compile(r"def\s+match\(self, file, line: str\)", re.MULTILINE)
_REQUIRED_ATTRS_PY = ("id =", "shortdesc =", "description =", "severity =", "tags =", "version_added =")

def is_valid_salt_lint_python_rule(code: str) -> bool:
    """Validates the basic structure of the generated Python rule code."""
    if not code or not isinstance(code, str): return False
    if not _CLASS_RE_PY.search(code) or not _MATCH_FN_RE_PY.search(code): return False
    return all(attr in code for attr in _REQUIRED_ATTRS_PY)

def clean_generated_code(content: str) -> str:
    """Cleans the generated code by removing markdown markers."""
    if not content: return content
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
                {"role": "system", "content": "You are a Salt-Lint expert generating rules in Python format."},
                {"role": "user", "content": prompt},
            ],
            temperature=TEMPERATURE,
            max_tokens=MAX_TOKENS_RESPONSE,
        )
        content = response.choices[0].message.content
        if not content: raise ValueError("Empty response from OpenAI API")
        return clean_generated_code(content)
    except Exception as e:
        tqdm.write(f"⚠️  API call error: {e}")
        raise

# --- MAIN FUNCTIONS ---

def build_prompt(vuln: str, smell: str, ftype: str, snippet: str) -> str:
    """Builds the prompt using SafeDict for safe formatting."""
    if not PROMPT_TEMPLATE: raise ValueError("PROMPT_TEMPLATE is not defined")
    vars_ = {
        "vulnerability": vuln.strip(),
        "smell_category": smell.strip(),
        "file_type": ftype.strip().lower(),
        "code_snippet": snippet.strip(),
    }
    return PROMPT_TEMPLATE.format_map(SafeDict(vars_))

def process_single_row(idx: int, row: pd.Series) -> str:
    """Processes a single DataFrame row and generates the rule."""
    vuln = str(row.get("vulnerability", "")).strip()
    smell = str(row.get("smell_category", "")).strip()
    code = str(row.get("code_snippet", "")).strip()

    if not (vuln and smell and code):
        return "[IGNORED] Incomplete data."

    ftype = determine_file_type(row)

    try:
        prompt = build_prompt(vuln, smell, ftype, code)
    except Exception as e:
        return f"[PROMPT ERROR] {e}"

    for attempt in range(MAX_RETRIES):
        try:
            rule = call_chatgpt(prompt)
            if is_valid_salt_lint_python_rule(rule):
                return rule
            else:
                tqdm.write(f"⚠️  Row {idx+2}: Attempt {attempt+1} - invalid rule.")
                prompt += "\n\n❗ WARNING: The previous response was invalid. Ensure the exact required Python structure is followed, including the final alias."
        except Exception as e:
            tqdm.write(f"⚠️  Row {idx+2}: Error attempt {attempt+1}: {e}")
            if attempt == MAX_RETRIES - 1: return f"[API ERROR] {e}"
        time.sleep(REQUEST_PAUSE)

    return "[FAILURE] Could not obtain a valid rule after multiple attempts."

def generate_rules_excel(input_path: str, output_path: str) -> None:
    """Orchestrates the rule generation process."""
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

    df["generated_salt_lint_rule"] = ""

    print(f"🔧  Model: {MODEL}\n📊  Rows to process: {len(df)}\n📁  Input file: {input_path}\n📁  Output file: {output_path}\n" + "-" * 50)

    for idx, row in tqdm(df.iterrows(), total=len(df), desc="Generating rules"):
        result = process_single_row(idx, row)
        df.at[idx, "generated_salt_lint_rule"] = result
        time.sleep(REQUEST_PAUSE)

    try:
        output_dir = os.path.dirname(output_path)
        if output_dir and not os.path.exists(output_dir): os.makedirs(output_dir)
        df.to_excel(output_path, index=False, engine="openpyxl")
        print(f"\n✅  Export completed successfully: {output_path}")
        success_count = len(df[~df["generated_salt_lint_rule"].str.startswith("[")])
        print(f"📈  Statistics: {success_count}/{len(df)} rules generated successfully")
    except Exception as e:
        sys.exit(f"‼️  Error during export: {e}")

# --- COMMAND-LINE INTERFACE ---
def main():
    """Main entry point of the script."""
    if len(sys.argv) < 3:
        print("Usage: python generate_salt_lint_rules.py <input.xlsx> <output.xlsx> [model]")
        sys.exit(1)

    input_file, output_file = sys.argv[1], sys.argv[2]

    if not input_file.endswith(('.xlsx', '.xls')):
        sys.exit("‼️  Input file must be an Excel file.")
    if not output_file.endswith(('.xlsx', '.xls')):
        sys.exit("‼️  Output file must be an Excel file.")

    generate_rules_excel(input_file, output_file)

if __name__ == "__main__":
    main()
