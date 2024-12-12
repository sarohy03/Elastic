import json
import openai
import os
import re

from dotenv import load_dotenv
from openai import AzureOpenAI

load_dotenv()

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
    print(f"Number of products: {len(products)}")
    print(f"Number of CVEs in cve_data: {len(cve_data)}")

    prompt = f"""
        You are tasked with reviewing a list of products with specific versions and matching them against CVE records. Your output must be **consistent** each time, with no variations in results for identical input data.

        ### Product List:
        {products}

        ### CVE Data:
        {cve_data}

        **Instructions**:
        1. **Exact Matching of Product Name and Version**:
           - Only include CVEs where the **product name** and **version** **explicitly appear** in the CVE description.
           - The **version** must be **exactly** as listed for the product. If the version range is mentioned, the CVE should only be included if the version **falls within the range**.
           - If a CVE mentions a **version range**, such as "prior to version X" or "above version Y", include the CVE **only if the product version** explicitly falls within that range.
           - Do **not infer**, assume, or generalize the matching process. If the version or product name is **not directly mentioned**, do not include the CVE.

        2. **Consistency in Results**:
           - Your output must **always** be consistent when the same input is provided. If the product list and CVE data are the same, the CVE IDs returned should **always** be identical, regardless of minor phrasing differences in the CVE description.
           - If a CVE appears multiple times in the input, ensure it is **only listed once** in the final output.

        3. **Handling of Ambiguous Cases**:
           - If a product name or version is mentioned **ambiguously** (e.g., "versions 2.x" or "prior to version"), exclude that CVE.
           - If the version is not mentioned at all, exclude that CVE unless the CVE explicitly matches the version range in the description.

        4. **Final Output**:
           - Return only the **CVE IDs** that match exactly to the products and versions in the list.
           - Each CVE should appear **only once** in the output, even if it is mentioned multiple times in the CVE list.

        **Return only the list of matching CVE IDs. Your response must always be identical if the input data is unchanged.**

    """

    print("Sending request to OpenAI API...")
    response = client.chat.completions.create(
        model=AZURE_OPENAI_DEPLOYMENT_NAME,
        messages=[
            {"role": "system", "content": "You are a NVD DATABASE CRAWLER. Your response should strictly follow the"
                                          " structure: CVE : {'application': 'process_name','version':'process_version',"
                                          "'CVE': 'CVE-XXXX-number', 'Summary': 'Description of the CVE"
                                          " related to the exact version of the process.'}"},
            {"role": "user", "content": prompt}
        ],
        temperature=0  # Make the output deterministic
    )

    print("Received response from OpenAI API")

    # Extracting the content safely from the response
    response_content = response.choices[0].message.content
    print("Raw response from OpenAI API:", response_content[:500])

    # Try parsing the response as JSON
    try:
        print("Attempting to parse response as JSON...")
        data = json.loads(response_content)
        cve_ids = [item['CVE'] for item in data]
        print("Successfully parsed response as JSON.")
    except json.JSONDecodeError:
        print("Failed to parse response as JSON. Fallback to regex.")
        # If JSON parsing fails, fallback to regex
        cve_ids = re.findall(r"CVE-\d{4}-\d{4,7}", response_content)

    print(f"Number of extracted CVE IDs: {len(cve_ids)}")
    print(f"Extracted CVE IDs: {cve_ids}")

    return cve_ids
