import openai
import pandas as pd
import time
import re
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()


# Get the OpenAI API key from the environment variable
openai_api_key = os.getenv("OPENAI_API_KEY")

if not openai_api_key:
    print("Error: OpenAI API key not found in environment variables.")
    exit(1)

openai.api_key = openai_api_key

# Paths to input and output files
input_file = '/Users/aicha.warOld.war/scriptsresult3.xlsx'
output_file = '/Users/aicha.warOld.war/scriptsgpt.xlsx'

# List of manifest names to check in lowercase
manifests = ['playbook', 'cookbook', 'puppet+manifest', 'vagrantfile', 'pulumi+program+files', 'saltstack+*.sls']

try:
    df = pd.read_excel(input_file)
except FileNotFoundError:
    print(f"Error: File not found - {input_file}")
    exit(1)
except pd.errors.EmptyDataError:
    print("Error: No data in Excel file.")
    exit(1)
except Exception as e:
    print(f"Unexpected error occurred while loading the Excel file: {e}")
    exit(1)

# Function to determine the manifest type from the cell content
def get_manifest_type(cell):
    for manifest in manifests:
        if manifest in cell.lower():
            return manifest
    return "unknown"

# Apply the get_manifest_type function to the tool column
df['tool'] = df['tool'].apply(get_manifest_type)

# Data Preparation Thought for manifests
data_prep_thought = """
### Data Preparation

You have an Excel file with data from different Infrastructure as Code (IaC) manifests (e.g., playbook, cookbook, puppet+manifest, vagrantfile, pulumi+program+files, saltstack+*.sls). The Excel file contains the following columns:

- `tool`: The type of IaC manifest.
- `previous_code`: The code snippet before the commit.
- `new_code`: The code snippet after the commit.
- `commit_message`: The commit message associated with the code change.

Ensure the data is properly loaded and formatted. Here's a sample of the data:

| tool            | previous_code                           | new_code                                    | commit_message                                    |
|-----------------|-----------------------------------------|--------------------------------------------|---------------------------------------------------|
| playbook        | - name: example playbook\n  hosts: all   | - name: example playbook\n  hosts: web      | Fixed security issue with Ansible playbook        |
| pulumi+program+files | pulumi program example                 | pulumi program example fix                   | Addressed pulumi program misconfiguration         |
| vagrantfile     | Vagrant.configure("2") do | config.vm.box = "base"                  | Updated Vagrant configuration for security compliance |
| ...             | ...                                     | ...                                        | ...                                               |

The next step will be identifying and clustering common security smells in the `previous_code` and `new_code`.
"""

# Cluster Identification Thought
cluster_identification_thought = """
### Cluster Identification

Identify and create clusters of common security smells found in the `previous_code` and the corresponding fixes in `new_code`. A cluster should consist of at least 2 similar security smells found in different manifests. Provide a brief description of each cluster.

The next step will be categorizing each identified security smell using CWE.
"""

# CWE Categorization Thought
cwe_categorization_thought = """
### CWE Categorization

For each identified security smell, categorize it based on the Common Weakness Enumeration (CWE). Provide the CWE ID and a brief description.

The next step will be analyzing the occurrences of each security smell cluster for each IaC manifest.
"""

# Tool-Specific Analysis Thought
tool_specific_analysis_thought = """
### Tool-Specific Analysis

For each IaC manifest (e.g., playbook, cookbook, puppet+manifest, vagrantfile, pulumi+program+files, saltstack+*.sls), count the occurrences of each identified security smell cluster.

The final step will be generating a comprehensive report with the findings.
"""

# Report Generation Thought
report_generation_thought = """
### Report Generation

Generate a comprehensive report with the following sections:
- **Clusters of Security Smells**: List and describe the identified clusters.
- **CWE Categorization**: Provide the CWE categorization for each identified security smell.
- **Occurrences by IaC Manifest**: Provide a table showing the count of each security smell cluster for each IaC manifest.
- **Summary**: Offer insights or observations based on the analysis, such as which IaC manifest has the most security smells or common patterns across manifests.

Use markdown format for readability.
"""

# Function to call the GPT API and handle errors
def generate_response(thought):
    try:
        response = openai.chat.completions.create(
            model="gpt-3.5-turbo",  # Use the appropriate model for code-related prompts
            messages=[{"role": "system", "content": thought}],
            max_tokens=1500,  # Adjust as needed
            temperature=0.5
        )
        print(response.choices[0].message.content)
        return response.choices[0].message.content.strip()
    except openai.error.APIError as e:
        print(f"OpenAI API error occurred: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error occurred: {e}")
        return None


# Process each thought sequentially
data_prep_response = generate_response(data_prep_thought)
if data_prep_response:
    print("Data Preparation Complete.")
    cluster_identification_response = generate_response(cluster_identification_thought)
    if cluster_identification_response:
        print("Cluster Identification Complete.")
        cwe_categorization_response = generate_response(cwe_categorization_thought)
        if cwe_categorization_response:
            print("CWE Categorization Complete.")
            tool_specific_analysis_response = generate_response(tool_specific_analysis_thought)
            if tool_specific_analysis_response:
                print("Tool-Specific Analysis Complete.")
                report_response = generate_response(report_generation_thought)
                if report_response:
                    print("Report Generation Complete.")
                    print(report_response)

                    # Save the report to an Excel file
                    try:
                        with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
                            # Split the report into sections based on headers
                            sections = report_response.split('###')

                            for section in sections:
                                if section.strip():
                                    # Extract section title and content
                                    title = section.split('\n', 1)[0].strip()
                                    content = section.split('\n', 1)[1].strip()

                                    # Convert the content to a DataFrame
                                    rows = [line.split('|') for line in content.split('\n') if line.strip()]
                                    if rows:
                                        df_section = pd.DataFrame(rows[1:], columns=[col.strip() for col in rows[0]])
                                        # Write the DataFrame to the Excel file
                                        df_section.to_excel(writer, sheet_name=title[:30], index=False)
                    except pd.errors.EmptyDataError as e:
                        print(f"Error with data conversion to DataFrame: {e}")
                    except FileNotFoundError:
                        print(f"Error: File not found - {output_file}")
                    except Exception as e:
                        print(f"Unexpected error occurred while saving to Excel: {e}")

                    print(f"Report saved to {output_file}")
                else:
                    print("Failed to generate report.")
            else:
                print("Tool-Specific Analysis failed.")
        else:
            print("CWE Categorization failed.")
    else:
        print("Cluster Identification failed.")
else:
    print("Data Preparation failed.")
