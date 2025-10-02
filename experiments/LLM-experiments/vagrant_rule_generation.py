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
# Loading Excel file
input_file = "Snyk/dataset_150_30/vagrant/vagrant_snyk_analysis_final-15-python.xlsx" 
df = pd.read_excel(input_file)

yaml_prompt = """You're a code security assistant specializing in writing high-precision custom linting rules for Vagrant configuration files written in YAML.

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

python_prompt= """
You're a code security assistant specializing in writing **Bandit security plugins** for analyzing Python code in Vagrant-related projects.

Your task is to write a **custom Bandit rule in Python** that reliably detects a specific security vulnerability from:

- A short vulnerability description.
- A concrete Python code snippet that demonstrates the vulnerability.

---

### Stringent requirements:

#### 1. **Namespace / File organization**
- The rule must be implemented as a Bandit plugin (Python file) stored under `bandit_plugins/<rule_name>_check.py`.
- The function must be named `check_<rule_name>(context)`.
- Register the check with the `@bandit.checks` decorator on the **relevant AST node types** (`Call`, `Assign`, `Import`, etc.).
- Assign a **unique test ID** using `@bandit.test_id("VAGRANT###")` (incremental numbering).

#### 2. **Detection logic (AST-FIRST, no string search)**
- Use the Bandit API and AST node inspection:
  - `context.node` for AST traversal.
  - `context.call_function_name_qual` or `context.call_function_name` for call detection.
  - `context.get_call_args()` for function arguments.
- Explicitly check the **AST node shape** and values:
  - Use `ast.Constant` (Python ≥3.8) or `ast.Str` (Python <3.8) for string literals.
  - Verify keyword arguments precisely (`keyword.arg == "access_key"` etc.).
- Avoid over-generic matches:
  - Do not flag all calls to a function.
  - Detect only the exact vulnerability pattern given in the snippet.
- Handle **safe cases**:
  - If the code uses defensive patterns (validation, secure defaults), do not raise an issue.
- Return nothing if the smell is not detected.

#### 3. **Message format**
- Use this strict format for messages:
Security Smell [ <SmellType> ]: <Explanation of the vulnerability and why it is dangerous>.
- Valid `<SmellType>` values:
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

#### 4. **Issue reporting**
- Use `bandit.Issue` with:
- `severity` chosen among `bandit.HIGH`, `bandit.MEDIUM`, `bandit.LOW` depending on risk.
- `confidence` chosen among `bandit.HIGH`, `bandit.MEDIUM`, `bandit.LOW` depending on precision.
- `test_id` matching the assigned VAGRANT###.
- `lineno=context.node.lineno` for accurate reporting.
- Provide a `More Info` link comment that could be expanded later to documentation.

#### 5. **Testing-as-doc (examples inside comments)**
- At the end of the file, include **minimal test cases** in comments:
- `# ❌ vulnerable example` → code that triggers the rule.
- `# ✅ safe example` → code that must not trigger.

---

### Output format
Provide a **single, complete Python file** implementing the Bandit plugin (`bandit_plugins/<rule_name>_check.py`) that Bandit can load directly. No extra explanations outside the code.

---

### Input

Vulnerability:
{vulnerability}

Code Snippet:
```python
{code_snippet}

Now generate a complete and functional Bandit security plugin that detects this vulnerability.    
"""


# Function to generate the correct rule depending on file extension
def generate_rule(row):
    vulnerability = row['vulnerability']
    code_snippet = row['code_snippet']
    file_path = str(row['filepath']).lower()

    if file_path.endswith((".py")):
        prompt = python_prompt.format(vulnerability=vulnerability, code_snippet=code_snippet)
    elif file_path.endswith((".yaml", ".yml")):
        prompt = yaml_prompt.format(vulnerability=vulnerability, code_snippet=code_snippet)
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
output_file = "Snyk/dataset_150_30/vagrant/vagrant_snyk_analysis_final-15-python-with_rules-1.xlsx"
df.to_excel(output_file, index=False)
print(f"\n Enhanced file saved as : {output_file}")
