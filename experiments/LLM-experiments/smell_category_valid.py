import pandas as pd
import openai
from tqdm import tqdm
import time

# Initialize the OpenAI API
client = openai.OpenAI(
    api_key="sk-proj-***********************",
    base_url="https://api.openai.com/v1"
)

# List of Top 10 smells categories
smell_categories = [
    "Insecure Configuration Management",
    "Path Traversal",
    "Code Injection",
    "Command Injection",
    "Insecure Input Handling",
    "Inadequate Naming Convention",
    "Sensitive Information Exposure",
    "Outdated Dependencies",
    "Insecure Dependency Management",
    "Outdated Software Version"
]

# Loading Excel file
input_file = "puppet\puppet_snyk_code_analysis.xlsx"
df = pd.read_excel(input_file)

# Function to generate prompt and call API
def detect_smell(row):
    prompt = f"""You're an expert in the security of infrastructure as code scripts such as Ansible, Chef, Terraform, Puppet, Pulumi, Vagrant, and Saltstack scripts.
    Here is an extract of IaC script that contains a security smell from a commit:
    
    Security Smell : {row['vulnerability']}
    File path : {row['filepath']}
    Line : {row['line']}
    Code : {row['code_snippet']}

    Here are the categories of security smells in our dataset of smelly IaC code snippets :
    {", ".join(smell_categories)}

    Assign a single category of smell that corresponds better to the associated script extracted. Give only the exact name of the category without explanation.
    """

    try:
        response = client.chat.completions.create(
            model="gpt-3.5-turbo", 
            messages=[{"role": "user", "content": prompt}],
            temperature=0,
            max_tokens=20
        )
        smell = response.choices[0].message.content.strip()
        return smell
    except Exception as e:
        print(f"Line error {row.name} : {e}")
        return "Error"

# Route lines with progress bar
tqdm.pandas()
df['smell_category'] = df.progress_apply(detect_smell, axis=1)

# Saving the results file
output_file = "puppet\puppet_snyk_code_analysis_smells" \
".xlsx"
df.to_excel(output_file, index=False)
print(f"\nEnhanced file saved as : {output_file}")
