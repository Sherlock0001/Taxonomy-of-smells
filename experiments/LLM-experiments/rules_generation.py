import pandas as pd
import openai
from tqdm import tqdm
import time

# Initialize the OpenAI API
client = openai.OpenAI(
    api_key="sk-proj-*************************", 
    base_url="https://api.openai.com/v1"
)

# Loading Excel file
input_file = "ruby\puppet_dataset_30-ruby_smells.xlsx" 
df = pd.read_excel(input_file)

# Function to generate prompt and call API
def generate_rubocop_rule(row):
    vulnerability = row['vulnerability']
    code_snippet = row['code_snippet']

    prompt = f"""You're a code security assistant specializing in writing high-precision custom RuboCop (cops) rules for Puppet modules written in Ruby.

    Your task is to write a custom RuboCop cop that reliably detects a specific security vulnerability from :

    - A brief description of the vulnerability.
    - An extract of vulnerable Ruby code that may appear in real code.

    ### Stringent requirements:

    1. **Namespace** : The cop must be defined in `RuboCop::Cop::Custom::<RuleName>`, where `<RuleName>` is a valid CamelCase class name derived from the vulnerability name.
    
    2. **Superclass** : Cop must inherit from `RuboCop::Cop::Base`.
    
    3. **Detection logic** :
    - You should use `def_node_matcher` to define the detection logic, as it provides a precise and efficient match based on Ruby's AST.
    - The matcher **must reflect the exact structure of the supplied code snippet** as it appears in the AST. Use tools like `ruby-parse` or RuboCop's AST documentation as a reference if necessary.
    - When looking for method calls involving constants (for example, `Net::HTTP.get_response(...)`), you **must model the complete path to the constant** using nested `(const ...)` expressions. For example:
      - `(const (const nil ? :Net) :HTTP)` to match `Net::HTTP`
    - Do not use generic placeholders such as `nil? cbase` or `...` unless strictly necessary, as they introduce false positives or cause missed detections.
    - Don't try to match manually using `node.children`, `node.receiver`, or `node.const_name`. Use `def_node_matcher` as your primary mechanism.
    - If the structure of the code snippet cannot be captured with `def_node_matcher`, you can fall back on `node.match?` or `node.source.include?`, but **only as a last resort**, and you must justify this fallback with a comment in the code.

    
    4. **Message**: Define a constant `MSG` using this format:
    Security Smell [ <SmellType> ]: <Explanation of the vulnerability and why it is dangerous>.
    Valid `<SmellType>` are as follows :
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
    - Insecure Data Transmission
    
    5. **Implementation**:
    - Implement `on_send(node)` or other appropriate node handler.
    - Call `add_offense(node, message : MSG)` when the pattern matches.

    ### output format :

    Provides a **complete Ruby class** that defines the custom cop, ready to be included in a RuboCop plugin.

    ### Input:

    Vulnerability:
    {vulnerability}

    Code Snippet:
    ```ruby
    {code_snippet}

    Now generate an accurate and functional RuboCop cop class that detects this vulnerability.
    """

    try:
        response = client.chat.completions.create(
            model="gpt-3.5-turbo", 
            messages=[{"role": "user", "content": prompt}],
            temperature=0,
            max_tokens=850
        )
        smell = response.choices[0].message.content.strip()
        return smell
    except Exception as e:
        print(f"Line error {row.name} : {e}")
        return "Error"

# Adding the ‘rule’ column with OpenAI generation
tqdm.pandas()
df['rule'] = df.progress_apply(generate_rubocop_rule, axis=1)

# Save the file with the generated rules
output_file = "ruby\puppet_dataset_30-ruby_smells-with_rules.xlsx"
df.to_excel(output_file, index=False)
print(f"\n Enhanced file saved as : {output_file}")
