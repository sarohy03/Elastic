from fastapi import FastAPI
from elasticsearch import Elasticsearch
from pydantic import BaseModel
from typing import List
import re


class Application(BaseModel):
    app: str
    version: str

    def extract_app_name(self):
        # Use a regular expression to match the app name at the beginning
        match = re.match(r'^([a-zA-Z0-9\s]+)', self.app)
        if match:
            return match.group(1).strip()
        else:
            return self.app

    def normalize_version(self):
        # Removes trailing .0 from the version
        normalized_version = re.sub(r'(\.0)+$', '', self.version)
        return normalized_version


class ApplicationsPayload(BaseModel):
    applications: List[Application]


async def search_documents(es_client, index_name, query_body, size=10):
    response = es_client.search(index=index_name, body=query_body, size=size)
    hits = response['hits']['hits']

    results = []
    for hit in hits:
        results.append(hit['_source'])

    return {
        "total": response['hits']['total']['value'],
        "results": results
    }


async def search_by_field(es_client, index_name, field, applications: List[Application], size=10000):
    all_results = []  # Initialize a list to collect results

    for application in applications:
        app_name = application.extract_app_name()
        normalized_version = application.normalize_version()

        # Normalize the app name for flexible searching
        normalized_app_name = app_name.replace(" ", "").lower()  # Removing spaces and lowercasing
        normalized_app_name_split = normalized_app_name.split("service")  # Split on the word "service"

        # Create a list of flexible search terms
        flexible_search_terms = [normalized_app_name]  # Start with the normalized app name

        if len(normalized_app_name_split) > 1:
            flexible_search_terms.append(normalized_app_name_split[0])  # Add the part before "service"

        # Add wildcards for searching
        wildcard_search = f"*{normalized_app_name}*"

        query_body = {
            "query": {
                "bool": {
                    "should": [
                        # Match the exact name (case insensitive)
                        {
                            "match": {
                                field: {
                                    "query": app_name,
                                    "operator": "and",
                                }
                            }
                        },
                        # Match variations
                        {
                            "bool": {
                                "should": [
                                    {
                                        "wildcard": {
                                            field: {
                                                "value": wildcard_search,
                                                "boost": 2.0
                                            }
                                        }
                                    },
                                    *[
                                        {
                                            "match": {
                                                field: {
                                                    "query": term,
                                                    "operator": "and",
                                                }
                                            }
                                        } for term in flexible_search_terms
                                    ]
                                ]
                            }
                        }
                    ],
                    "minimum_should_match": 1
                }
            }
        }

        app_results = await search_documents(es_client, index_name, query_body, size)

        # Ensure app_results has results before processing
        if "results" in app_results:
            cve_results = app_results["results"]
            for item in cve_results:
                # Access the CVE object
                cve = item.get("cve", {})
                cve_id = cve.get("id", "Unknown ID")

                # Find the English description
                descriptions = cve.get("descriptions", [])
                en_description = next((desc["value"] for desc in descriptions if desc["lang"] == "en"),
                                      "No description available")

                # Append extracted data for the current application
                all_results.append({
                    "id": cve_id,
                    "description": en_description
                })
    from prompt import prompt_cves
    prompt_cves(applications, all_results)
    return {"results": all_results}  # Return all collected results after processing all applications


app = FastAPI()


@app.post("/search")
async def root(data: ApplicationsPayload):
    ELASTIC_ADDRESS = "http://localhost:9200"
    # ELASTIC_ADDRESS = "https://f923-44-211-168-46.ngrok-free.app"
    INDEX_NAME = "interactions_index-6"
    es_client = Elasticsearch(hosts=[ELASTIC_ADDRESS])

    result = await search_by_field(es_client, INDEX_NAME, "cve.descriptions.value", data.applications)

    return result
