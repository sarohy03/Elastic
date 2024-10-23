import json
import openai
import os
import re
from openai import AzureOpenAI

# Initialize OpenAI API
AZURE_OPENAI_ENDPOINT = os.environ.get('AZURE_OPENAI_ENDPOINT')
AZURE_OPENAI_KEY = os.environ.get('AZURE_OPENAI_KEY')
AZURE_OPENAI_DEPLOYMENT_NAME = os.environ.get('AZURE_OPENAI_DEPLOYMENT_NAME')
print(f'AZURE_OPENAI_ENDPOINT: {AZURE_OPENAI_ENDPOINT}')

client = AzureOpenAI(
    azure_endpoint=AZURE_OPENAI_ENDPOINT,
    api_version="2023-05-15",
    api_key=AZURE_OPENAI_KEY
)


def prompt_cves(products, cve_data):
    # Combine the products and CVE data into a single prompt
    prompt = f"""
    You are an expert in CVE vulnerabilities. Here are the product and version information:
    {products}

    And here is the CVE data:

    {cve_data}

    Please analyze the provided CVE data and return only the CVE IDs that match the product and version in the description of that CVE.
    """
    print("SENDING TO GPT")
    # Send the request to the API
    response = client.chat.completions.create(
        model=AZURE_OPENAI_DEPLOYMENT_NAME,
        messages=[
            {"role": "system", "content": "You are a NVD DATABASE CRAWLER. Your response should strictly follow the"
                                          " structure: CVE : {'application': 'process_name','version':'process_version',"
                                          "'CVE': 'CVE-XXXX-number', 'Summary': 'Description of the CVE"
                                          " related to the exact version of the process.'}"},
            {"role": "user", "content": prompt}
        ]
    )

    # Extracting the content safely from the response
    response_content = response.choices[0].message.content
    print("Raw API Response:", response_content)

    # Extract CVE IDs using a regular expression
    cve_ids = re.findall(r"'CVE': '([^']+)'", response_content)

    print("Extracted CVE IDs:", cve_ids)
    return cve_ids