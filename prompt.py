import json
import openai
import os
import re

from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

OPENAI_ENDPOINT = os.environ.get('OPENAI_ENDPOINT')
OPENAI_KEY = os.environ.get('OPENAI_KEY')
OPENAI_DEPLOYMENT_NAME = os.environ.get('OPENAI_DEPLOYMENT_NAME')
print(f'OPENAI_ENDPOINT: {OPENAI_ENDPOINT}')

client = OpenAI(
    base_url=OPENAI_ENDPOINT,
    api_key=OPENAI_KEY,
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

            ### **Enhanced Instructions**:

            1. **Flexible and Exact Matching**:
               - **Exact Match**:
                 - Include CVEs where the **product name** and **version** **exactly appear** in the CVE description.
               - **Minor Version Variations**:
                 - If a CVE mentions a version pattern like `2.47.x` and your product version is `2.47.0`, consider it a match.
                 - Similarly, for `3.13.150.x` and `3.13.150.0`.
               - **Inclusive Ranges**:
                 - If a CVE mentions "prior to version X," include it only if your product version is **less than X**.
                 - If a CVE specifies a range like "versions X to Y," include it only if your product version **falls within** that range.

            2. **Product Name Variations and Synonyms**:
               - **Standardize Names**:
                 - Normalize product names to account for common synonyms and abbreviations.
                   - Example: 
                     - `microsoft visual c++ 2019 x64 minimum runtime - 14` can be matched with `Microsoft Visual C++ 2019`, `Visual C++ 2019 Runtime`, etc.
                     - `python 3 executables (64-bit)` can be matched with `Python 3.x`, `Python3 Executables`, etc.
               - **Use Regex for Pattern Matching**:
                 - Implement regex patterns to capture variations in product naming and version formatting.
                   - Example Regex for Python 3 executables:
                     - r'python\s*3(?:\.\d+){0, 3}\s*(?:executables|core interpreter|pip bootstrap|standard library)'

            3. **Component and Module Matching**:
               - **Specific Components**:
                 - Ensure that CVEs targeting specific components or modules (e.g., `python 3 pip bootstrap`) are matched appropriately.
               - **Granular Matching**:
                 - If a CVE affects only a sub-component, ensure that the main product version still qualifies the CVE.

            4. **Avoid Ambiguous Matches**:
               - **Exclude Ambiguity**:
                 - Do not include CVEs that mention ambiguous version patterns (e.g., "versions 2.x" without specific range details).
               - **Clear Boundaries**:
                 - Only include CVEs where the product version clearly falls within the affected range as per the CVE description.

            5. **De-duplicate CVE IDs**:
               - **Unique Listings**:
                 - Ensure each CVE ID appears only once in the final output, even if it matches multiple products or is listed multiple times in the CVE data.

            6. **Consistency and Repeatability**:
               - **Deterministic Output**:
                 - The matching process should yield the same results for identical inputs every time, regardless of minor differences in CVE descriptions.

            7. **Final Output Format**:
               - **List of CVE IDs**:
                 - Return only the **CVE IDs** that match the products and versions.
               - **JSON Array**:
                 - Format the output as a JSON array for structured representation.
            """

    print("Sending request to OpenAI API...")
    response = client.chat.completions.create(
        model=OPENAI_DEPLOYMENT_NAME,
        messages=[
            # {"role": "system", "content": "You are a NVD DATABASE CRAWLER. Your response should strictly follow the"
            #                               " structure: CVE : {'application': 'process_name','version':'process_version',"
            #                               "'CVE': 'CVE-XXXX-number', 'Summary': 'Description of the CVE"
            #                               " related to the exact version of the process.'}"},
            {"role": "user", "content": prompt}
        ],
        temperature=1  # Make the output deterministic
    )

    print("Received response from OpenAI API")

    # Extracting the content safely from the response
    response_content = response.choices[0].message.content
    print("Raw response from OpenAI API:", response)

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
