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

def get_related_cve_and_smell_summary(tool, previous_code, new_code, commit_message):
    # Use GPT-3.5 to find related CVE for the previous_code
    cve_prompt = (
        f"The following code snippet is flagged as vulnerable for {tool}:\n"
        f"Vulnerable code {previous_code}\n"
        f"Fixed code {new_code}\n"
        f"Commit Message {commit_message}\n"
        "Please provide the related CVE."
    )
    try:
        cve_response = openai.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "system", "content": cve_prompt}],
            max_tokens=3000,
            temperature=0.5
        )
        #print(cve_response.choices[0].message.content)
        cve = cve_response.choices[0].message.content.strip()
    except Exception as e:
        print(f"Error retrieving CVE: {e}")
        cve = "N/A"

    # If CVE is found, get the security smell summary
    if cve:
        smell_prompt = (
            f"CVE: {cve}\n"
            f"Vulnerable Code:\n{previous_code}\n"
            f"Fixed Code:\n{new_code}\n"
            f"Commit Message: {commit_message}\n"
            "Summarize in less than 10 words the description of the security smell associated with the previous_code."
        )
        try:
            smell_response = openai.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "system", "content": smell_prompt}],
                max_tokens=3000,
                temperature=0.5
            )
            smell_summary = smell_response.choices[0].message.content.strip()
        except Exception as e:
            print(f"Error retrieving smell summary: {e}")
            smell_summary = "N/A"
    else:
        smell_summary = "No CVE found"
    
    return cve, smell_summary

# Path to the input Excel file
input_file = '/Users/aicha.warOld.war/scriptsresult3.xlsx'
# Path to the output Excel file
output_file = '/Users/aicha.warOld.war/desc2.xlsx'

# Read the input Excel file
df = pd.read_excel(input_file)

# Initialize columns for CVE and smell summary
df['CVE'] = ''
df['smell_summary'] = ''

# Iterate over the rows and get CVE and smell summary for each row
for index, row in df.iterrows():
    tool = row['tool']
    previous_code = row['previous_code']
    new_code = row['new_code']
    commit_message = row['commit_message']
    
    cve, smell_summary = get_related_cve_and_smell_summary(tool, previous_code, new_code, commit_message)
    
    df.at[index, 'CVE'] = cve
    df.at[index, 'smell_summary'] = smell_summary

# Save the updated DataFrame to a new Excel file
df.to_excel(output_file, index=False)

print(f"Output saved to {output_file}")
