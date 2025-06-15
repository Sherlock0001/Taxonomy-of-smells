import pandas as pd
import openai
from tqdm import tqdm
import time
import re

# Initialize the OpenAI API
client = openai.OpenAI(
    api_key="sk-proj-*************************", 
    base_url="https://api.openai.com/v1"
)

# Load Excel file
input_file = "terraform_dataset_30-ruby_smells.xlsx"
df = pd.read_excel(input_file)

# Function to generate rule and metadata
def generate_terrarscan_rule(row):
    vulnerability = row['vulnerability']
    code_snippet = row['code_snippet']

    prompt = f"""You are a security policy assistant specialized in writing precise **OPA Rego rules for Terrascan** to detect misconfigurations and security vulnerabilities in **Terraform code**.

Your task is to generate:

1. A **Rego policy rule** to detect a specific vulnerability.
2. A **metadata JSON file** that describes and enables the rule in Terrascan.

---

### Strict requirements for the `.rego` rule:

- Define a policy inside the `package terrascan`.
- Include a `__rego__metadoc__` block at the top with the following keys:
- `"id"`: Use a unique ID like `CLOUD.SERVICE.Category.Severity.XYZ` (e.g., `AWS.S3.DataSecurity.High.001`)
- `"title"`: One-line summary of what the rule detects.
- `"description"`: Explain clearly what the rule checks and why it's dangerous.
- `"severity"`: One of `LOW`, `MEDIUM`, or `HIGH`.
- `"category"`: One of: `Access Control`, `Encryption`, `Logging`, `Monitoring`, `Networking`, `Data Security`, `Network Security`, `Resource Management`.
- `"version"`: Always `"1.1"`

- The `deny[msg]` rule must:
- Inspect `input.resource` (which contains a single Terraform resource block).
- Match the **exact misconfiguration pattern** shown in the provided Terraform snippet.
- Output a message in the format:
    ```rego
    msg := {{
    "msg": sprintf("...custom message with resource name..."),
    "resource": resource.name,
    "file": resource.source,
    "line": resource.line
    }}
    ```

---

### Metadata file:

Generate a valid `metadata.json` file placed alongside the `.rego` rule with:
- `"name"`: kebab-case version of the rule name, e.g., `expose-ssh`.
- `"file"`: name of the .rego file.
- `"policy_type"`: `"terraform"`
- `"resource_type"`: type of the resource (e.g., `"aws_s3_bucket"`, `"google_compute_firewall"`).
- `"cloud_type"`: `"aws"`, `"azure"`, `"gcp"` or `"k8s"` depending on the code snippet.
- `"description"`: Match the `"description"` from the `__rego__metadoc__`.
- `"severity"`: Copy from the metadata above.
- `"category"`: Copy from the metadata above.

---

### Output format:

Return both files in this format:

=== <filename>.rego ===
<content>

=== metadata.json ===
<content>

---

### Input:

**Vulnerability**:
{vulnerability}

**Terraform Code Snippet**:
```hcl
{code_snippet}
Now generate a complete and functional Terrascan rule (Rego + metadata).
"""

    try:
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}],
            temperature=0,
            max_tokens=850
        )
        output = response.choices[0].message.content.strip()

        # Extraction
        rego_match = re.search(r"===.*?\.rego ===\n(.*?)\n(?===|\Z)", output, re.DOTALL)
        metadata_match = re.search(r"=== metadata\.json ===\n(.*?)\Z", output, re.DOTALL)

        rego_code = rego_match.group(1).strip() if rego_match else "Not found"
        metadata = metadata_match.group(1).strip() if metadata_match else "Not found"

        return pd.Series([rego_code, metadata])

    except Exception as e:
        print(f"Line error {row.name} : {e}")
        return pd.Series(["Error", "Error"])

# Apply the function with progress bar
tqdm.pandas()
df[['rego_rule', 'metadata_json']] = df.progress_apply(generate_terrarscan_rule, axis=1)

# Save the new DataFrame to Excel
output_file = "terraform_dataset_30-with_rules_and_metadata.xlsx"
df.to_excel(output_file, index=False)
print(f"\n✅ Enhanced file saved as: {output_file}")
