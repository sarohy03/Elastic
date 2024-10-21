import json
import openai

# Initialize OpenAI API
openai.api_key = "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"  # Replace with your actual OpenAI API key
def prompt_cves(products, cve_data):

    # Combine the products and CVE data into a single prompt
    prompt = f"""
    You are an expert in CVE vulnerabilities. Here are the product and version information:
    
    {json.dumps(products)}
    
    And here is the CVE data:
    
    {json.dumps(cve_data)}
    
    Please analyze the provided CVE data and return only the CVE IDs that match the product and version in the description of that CVE.
    """

    # Send the prompt to the OpenAI API
    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",  # Use the model of your choice
        messages=[
            {"role": "user", "content": prompt}
        ]
    )

    # Extract the CVE IDs from the response
    cve_ids = response.choices[0].message['content'].strip()
    print("Matched CVE IDs:")
    print(cve_ids)


