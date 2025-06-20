import openai
import pandas as pd
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Get the OpenAI API key from the environment variable
openai_api_key = os.getenv("OPENAI_API_KEY")

if not openai_api_key:
    print("Error: OpenAI API key not found in environment variables.")
    exit(1)

openai.api_key = openai_api_key

def get_security_smell_summary(tool, previous_code, new_code, commit_message):
    # Prompt GPT-3.5 to generate a security smell summary
    smell_prompt = (
        f"The following code snippet is flagged as vulnerable for {tool}:\n"
        f"{previous_code}\n"
        f"Vulnerable Code (previous):\n{previous_code}\n"
        f"Fixed Code (new):\n{new_code}\n"
        "Provide a description of the security smell associated with the previous_code."
    )
    
    try:
        smell_response = openai.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "system", "content": smell_prompt}],
            max_tokens=4000,  
            temperature=0.5
        )
        smell_summary = smell_response.choices[0].message.content.strip()
    except Exception as e:
        print(f"Error retrieving smell summary: {e}")
        smell_summary = "N/A"
    
    return smell_summary

# Path to the input Excel file
input_file = '/Users/aicha.warOld.war/scriptsresult3.xlsx'
# Path to the output Excel file
output_file = '/Users/aicha.warOld.war/description2.xlsx'

# Read the input Excel file
df = pd.read_excel(input_file)

# Initialize the column for smell summary
df['smell_summary'] = ''

# Iterate over the rows and get the security smell summary for each row
for index, row in df.iterrows():
    tool = row['tool']
    previous_code = row['previous_code']
    new_code = row['new_code']
    commit_message = row['commit_message']
    
    smell_summary = get_security_smell_summary(tool, previous_code, new_code, commit_message)
    
    df.at[index, 'smell_summary'] = smell_summary

# Save the updated DataFrame to a new Excel file
df.to_excel(output_file, index=False)

print(f"Output saved to {output_file}")
