import pandas as pd
import openai
import re
from dotenv import load_dotenv
import os
import openpyxl

# Load environment variables from .env file
load_dotenv()

# Get the OpenAI API key from the environment variable
openai_api_key = os.getenv("OPENAI_API_KEY")

if not openai_api_key:
    print("Error: OpenAI API key not found in environment variables.")
    exit(1)

openai.api_key = openai_api_key

# Function to read the Excel file
def read_excel(file_path):
    df = pd.read_excel(file_path)
    return df

# Function to categorize security smells according to smell description
def categorize_smell(df):
    smell_details = {}
    for smell in df['smell_summary'].unique():
        prompt = (
            f"I want to build a taxonomy of security smells. Make clusters of similar security smell descriptions and provide categories of security smells for the following description(s): {smell}"
        )
        try:
            response = openai.chat.completions.create(
                model="gpt-3.5-turbo",  # Use the appropriate model for code-related prompts
                messages=[{"role": "system", "content": prompt}],
                max_tokens=4000,  # Limit tokens to avoid exceeding the model's capacity
                temperature=0.7
            )
            smell_category = response.choices[0].message.content.strip()
            smell_details[smell] = smell_category
            print(response.choices[0].message.content)
        except Exception as e:
            print(f"Error identifying security categories: {e}")
            smell_details[smell] = ["N/A"]
    df['smell_category'] = df['smell_summary'].map(smell_details)
    return df,smell_details


# Function to count occurrences of each Smell category for each IaC tool
def count_occurrences(df):
    occurrence_table = df.groupby(['tool', 'smell_category']).size().unstack(fill_value=0)
    return occurrence_table

# Function to generate summary report
def generate_summary(occurrence_table):
    summary = []
    for tool in occurrence_table.index:
        total_smells = occurrence_table.loc[tool].sum()
        summary.append(f"{tool} has a total of {total_smells} security smells.")
    return summary

# Function to write the report to an Excel file
def write_to_excel(file_path, smell_details, occurrence_table, summary):
    with pd.ExcelWriter(file_path, engine='openpyxl') as writer:
        # Smell Categorization
        smell_df = pd.DataFrame(smell_details.items(), columns=['Security Smell', 'Smell Categorization'])
        smell_df.to_excel(writer, sheet_name='Smell Categorization', index=False)
        
        # Occurrences by IaC Tool
        occurrence_table.to_excel(writer, sheet_name='Occurrences by IaC Tool')
        
        # Summary
        summary_df = pd.DataFrame(summary, columns=['Summary'])
        summary_df.to_excel(writer, sheet_name='Summary', index=False)

# Main function to generate the report
def generate_report(input_file_path, output_file_path):
    df = read_excel(input_file_path)
    df, smell_details = categorize_smell(df)
    occurrence_table = count_occurrences(df)
    summary = generate_summary(occurrence_table)
    
    # Write the report to an Excel file
    write_to_excel(output_file_path, smell_details, occurrence_table, summary)


# Specify the path to your input and output Excel files
input_file_path = '/Users/aicha.warOld.war/description2.xlsx'
output_file_path = '/Users/aicha.warOld.war/scriptsclusters2.xlsx'

# Generate the report
generate_report(input_file_path, output_file_path)

print(f"Report generated and saved to {output_file_path}")
