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
input_file = "Snyk/dataset_150_30/chef/chef_snyk_analysis_final-10.xlsx" 
df = pd.read_excel(input_file)

# Function to generate prompt and call API
def generate_rubocop_rule(row):
    vulnerability = row['vulnerability']
    code_snippet = row['code_snippet']

    prompt = f"""You're a code security assistant specializing in writing high-precision custom RuboCop (cops) rules for Chef cookbooks and recipes written in Ruby.

    Your task is to write a custom RuboCop cop that reliably detects a specific security vulnerability from:

    - A brief description of the vulnerability.
    - An extract of vulnerable Chef code that may appear in real cookbooks or recipes.

    ### Stringent requirements:

    1. **Namespace** : The cop must be defined in `RuboCop::Cop::Custom::<RuleName>`, where `<RuleName>` is a valid CamelCase class name derived from the vulnerability name.

    2. **Superclass** : The cop must inherit from `RuboCop::Cop::Base`.
    
    3. **Detection logic** :  
    - Use `def_node_matcher` to define precise AST patterns.  
    - If the vulnerable code involves resource declarations (`package`, `cron`, `execute`, `file`, etc.), your pattern **must reflect the exact structure of the Chef DSL call** (e.g., `(send nil? :package ...)`, `(send nil? :cron ...)`, `(send nil? :execute ...)`).  
    - When checking resource properties (e.g., `with(command: ..., user: ..., environment: ...)`), use AST traversal to match **hash pairs** and check for specific keys/values.  
    - For string checks, validate hardcoded sensitive values explicitly (e.g., usernames, passwords, MAILTO entries) instead of using generic placeholders.  
    - Avoid over-generalization: do **not** use `...` or wildcards unless absolutely required.  
    - You may combine structural matching (`def_node_matcher`) with semantic checks inside `on_send(node)` by iterating over hash pairs.  
    - Fallback to `node.source.include?` is acceptable **only if** AST cannot capture the pattern, and you must explain this in a comment.

    
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
    
    5. **Implementation**:  
    - Implement `on_send(node)` or another appropriate handler.  
    - Extract key/value pairs from Chef resource blocks when needed.  
    - Trigger `add_offense(node, message: MSG)` when the vulnerability is detected.  

    ### output format :

    Provide a **complete Ruby class** that defines the custom cop, ready to be included in a RuboCop plugin.

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
df['rule'] = df.progress_apply(generate_rubocop_rule, axis=1)

# Save the file with the generated rules
output_file = "Snyk/dataset_150_30/chef/chef_snyk_analysis_final-20-with_rules.xlsx"
df.to_excel(output_file, index=False)
print(f"\n Enhanced file saved as : {output_file}")
