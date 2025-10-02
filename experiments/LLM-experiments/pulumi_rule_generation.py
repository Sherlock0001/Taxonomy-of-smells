import pandas as pd
import openai
from tqdm import tqdm
import time

#The Rubocop linter only accepts files with the following extensions: .rb , .rake , .gemspec and .ru

# Initialize the OpenAI API
client = openai.OpenAI(
    api_key="API_KEY", 
    base_url="https://api.openai.com/v1"
)
# Loading Excel filep
input_file = "Snyk\dataset_150_30\pulumi\pulumi_snyk_analysis-final-20-n.xlsx" 
df = pd.read_excel(input_file)

# Prompt template for JS/TS (ESLint)
eslint_prompt_template = """
        You are a code security assistant specialized in generating **accurate ESLint security rules** for JavaScript/TypeScript (including Pulumi codebases). 
        Your job: from a short vulnerability description and a concrete code snippet, output a **complete, functional ESLint rule** (ES module) that detects the vulnerability with **high precision and low false positives**.

        ## Strong requirements

        1) **Scope / Ecosystem**
        - Target language: JS/TS using the ESTree AST (as parsed by @typescript-eslint/parser or espree).
        - The output must be a **single ESLint rule file** with `export default` (no extra prose).
        - Rule must work even if the project uses **Flat config** (ESLint ≥8) or legacy config.

        2) **Rule identity**
        - Derive a kebab-case rule name from the vulnerability, e.g. "Insecure Input Handling" → `insecure-input-handling`.
        - Use a `meta.docs.description` that clearly states the risk.
        - Use this message format for the primary message:
        **Security Smell [ <SmellType> ]: <why this is dangerous and what to do instead>.**
        Allowed `<SmellType>` values:
        - Command Injection
        - Path Traversal
        - Insecure Dependency Management
        - Insecure Configuration Management
        - Insecure Input Handling
        - Code Injection
        - Outdated Dependencies
        - Outdated Software Version
        - Sensitive Information Exposure
        - Inadequate Naming Convention

        3) **Detection logic (AST FIRST, no text search)**
        - Prefer **explicit ESTree structural checks** (node.type, callee.object/callee.property, left/right of BinaryExpression, etc.).
        - If you need pattern matching, use **selective checks** on specific node shapes; **do not** rely on generic string includes.
        - If you must fall back to heuristics, add a short code comment justifying why and limit scope to reduce FPs.

        4) **Minimal data-flow (when needed)**
        - Implement a small, local taint model **only if necessary** to match the snippet semantics, e.g. track identifiers that originate from **user-controlled sources** such as:
        - Express/Node: `req.query`, `req.params`, `req.body`, `req.headers`, `cookies`, `URLSearchParams`, `location.search/hash`.
        - Pulumi config: `new pulumi.Config().get(...)` or `.require(...)` when used unsafely (e.g., used directly in string ops, logs, or dangerous sinks).
        - Track taint through simple assignments and `.toLowerCase()/.toUpperCase()` or trivial wrappers.
        - Report **only when a tainted value** reaches the **exact risky pattern** found in the snippet (mirror its AST).

        5) **Performance & precision**
        - Bail out early when shapes don’t match.
        - Avoid walking the entire tree repeatedly; hook only needed node types.
        - Do not flag if **defensive checks** are present (e.g., type guards, schema validation) immediately guarding the use.

        6) **Ergonomics**
        - Provide `meta.schema` (empty array if no options).
        - Provide `meta.type: "problem"`.
        - Provide `messages` with at least one key (e.g., `main`).
        - If applicable, add **suggestions** (`hasSuggestions: true`) to propose a safer pattern (e.g., validate types, sanitize, or use strong Pulumi constructs like `pulumi.secret`).

        7) **Tests-as-doc in comments**
        - At the bottom of the file (as comments), include **minimal examples**:
        - `// ❌ invalid` (should be reported) using the given snippet shape.
        - `// ✅ valid` (safe alternative) showing how not to trigger.
        These examples must match exactly the rule’s matcher(s).

        ## Input
        Vulnerability:
        {vulnerability}

        Code Snippet:
        ```js
        {code_snippet}

        Output

        Return only a single JavaScript module that exports an object with both `meta` and a `create` function using `export default`, as required by ESLint rule modules. No extra text.

        Now generate an accurate and functional RuboCop cop class that detects this vulnerability.
        """


    # Prompt template for YAML (Yaml-lint)
yaml_prompt_template = """You're a code security assistant specializing in writing high-precision custom linting rules for Vagrant configuration files written in YAML.

    Your task is to write a **custom Yaml-lint rule in Python** that reliably detects a specific security vulnerability from :

    - A brief description of the vulnerability.
    - An extract of vulnerable YAML code that may appear in real code.

    ### Stringent requirements:

    1. **Namespace / File organization**:
    - The rule must be implemented as a standalone Python function stored under `rules/<rule_name>_rule.py`.
    - The function must be named `check_<rule_name>(file_path)` and accept a YAML file path as argument.
    - The function must return `True` if the vulnerability is detected, `False` otherwise.

    2. **Detection logic**:
    - Use `yaml.safe_load()` for parsing.
    - Ensure parsing is wrapped in a try/except block to avoid crashes on malformed YAML.
    - The rule must inspect the YAML structure precisely (dicts, keys, values).
    - Avoid over-generic checks: match the exact structure provided in the vulnerable code snippet.
    - Example: for a RoleBinding or ClusterRoleBinding, inspect the `roleRef.name` field and flag if its value is one of the default roles (`cluster-admin`, `admin`, `edit`, `view`).
    - Do not rely on substring search in the raw file; always parse and traverse the YAML tree.
    - Return `True` only if the specific smell is confirmed.

    3. **Message format**:
    - Define the message in this exact format:
    Security Smell [ <SmellType> ]: <Explanation of the vulnerability and why it is dangerous>.
    - Valid `<SmellType>` are as follows:
    - Command Injection
    - Path Traversal
    - Insecure Dependency Management
    - Insecure Configuration Management
    - Insecure Input Handling
    - Code Injection
    - Outdated Dependencies
    - Outdated Software Version
    - Sensitive Information Exposure
    - Inadequate Naming Convention

    4. **Implementation**:
    - Implement the detection in a Python function.
    - Return True when the vulnerable pattern is found.
    - Return False otherwise.

    5. **Runner script**:
    - Also generate a companion Python runner (`runner.py`) that:
    - Iterates over YAML manifests in a `./manifests` directory.
    - Imports the rule function from `rules/<rule_name>_rule.py`.
    - Runs the check on each file.
    - Prints a finding in this exact format when the vulnerability is detected:
        [<RULE_ID>] Security Smell: <filename> <message>
    - Otherwise, print `<filename> is OK ✅`.
    - Use a rule ID format: `VAGRANT###` (incremental, starting from 001).

    ### Output format:

    Provide two complete Python scripts:
    1. The rule implementation under `rules/<rule_name>_rule.py`.
    2. The runner script (`runner.py`) to execute the rule against YAML manifests.

    ### Input:

    Vulnerability:
    {vulnerability}

    Code Snippet:
    ```yaml
    {code_snippet}

    Now generate a complete and functional Yaml-lint security rule and runner script that detect this vulnerability.
    """


# Function to generate the correct rule depending on file extension
def generate_rule(row):
    vulnerability = row['vulnerability']
    code_snippet = row['code_snippet']
    file_path = str(row['filepath']).lower()

    if file_path.endswith((".js", ".ts")):
        prompt = eslint_prompt_template.format(vulnerability=vulnerability, code_snippet=code_snippet)
    elif file_path.endswith((".yaml", ".yml")):
        prompt = yaml_prompt_template.format(vulnerability=vulnerability, code_snippet=code_snippet)
    else:
        return "Unsupported file type"


    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1,     # sortie déterministe
            max_tokens=1000,     # limite de tokens en sortie
            top_p= 1.0,
            frequency_penalty= 0,
            presence_penalty= 0,
        )
        smell = response.choices[0].message.content.strip()
        return smell
    except Exception as e:
        print(f"Line error {row.name} : {e}")
        return "Error"

# Adding the ‘rule’ column with OpenAI generation
tqdm.pandas()
df['rule'] = df.progress_apply(generate_rule, axis=1)

# Save the file with the generated rules
output_file = "Snyk/dataset_150_30/pulumi/pulumi_snyk_analysis-final-20-with_rules.xlsx"
df.to_excel(output_file, index=False)
print(f"\n Enhanced file saved as : {output_file}")