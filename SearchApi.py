from fastapi import FastAPI
from elasticsearch import Elasticsearch
from pydantic import BaseModel
from typing import List
import re
from prompt import prompt_cves


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


# async def search_by_field(es_client, index_name, field, applications: List[Application], size=10000, max_results_per_app=5):
#     all_results = []  # Initialize a list to collect results
#
#     # Store a mapping of CVE ID to application information (app name, version)
#     cve_app_map = {}
#
#     for application in applications:
#         app_name = application.extract_app_name()
#         normalized_version = application.normalize_version()
#
#         # Normalize the app name for flexible searching
#         normalized_app_name = app_name.replace(" ", "").lower()  # Removing spaces and lowercasing
#         normalized_app_name_split = normalized_app_name.split("service")  # Split on the word "service"
#
#         # Create a list of flexible search terms
#         flexible_search_terms = [normalized_app_name]  # Start with the normalized app name
#
#         if len(normalized_app_name_split) > 1:
#             flexible_search_terms.append(normalized_app_name_split[0])  # Add the part before "service"
#
#         # Add wildcards for searching
#         wildcard_search = f"*{normalized_app_name}*"
#
#         query_body = {
#             "query": {
#                 "bool": {
#                     "should": [
#                         # Match the exact name (case insensitive)
#                         {
#                             "match": {
#                                 field: {
#                                     "query": app_name,
#                                     "operator": "and",
#                                 }
#                             }
#                         },
#                         # Match variations
#                         {
#                             "bool": {
#                                 "should": [
#                                     {
#                                         "wildcard": {
#                                             field: {
#                                                 "value": wildcard_search,
#                                                 "boost": 2.0
#                                             }
#                                         }
#                                     },
#                                     *[
#                                         {
#                                             "match": {
#                                                 field: {
#                                                     "query": term,
#                                                     "operator": "and",
#                                                 }
#                                             }
#                                         } for term in flexible_search_terms
#                                     ]
#                                 ]
#                             }
#                         }
#                     ],
#                     "minimum_should_match": 1
#                 }
#             }
#         }
#
#         app_results = await search_documents(es_client, index_name, query_body, size)
#
#         # Ensure app_results has results before processing
#         if "results" in app_results:
#             cve_results = app_results["results"]
#
#             # Sort the CVE results by relevance or any other criterion
#             sorted_cve_results = sorted(cve_results, key=lambda x: x.get("relevance_score", 0), reverse=True)  # Placeholder for sorting
#
#             # Limit to a maximum of `max_results_per_app` per application
#             limited_cve_results = sorted_cve_results[:max_results_per_app]
#
#             for item in limited_cve_results:
#                 # Access the CVE object
#                 cve = item.get("cve", {})
#                 cve_id = cve.get("id", "Unknown ID")
#
#                 # Find the English description
#                 descriptions = cve.get("descriptions", [])
#                 en_description = next((desc["value"] for desc in descriptions if desc["lang"] == "en"),
#                                       "No description available")
#
#                 # Append extracted data for the current application
#                 all_results.append({
#                     "id": cve_id,
#                     "description": en_description
#                 })
#
#                 # Save the app name and version associated with this CVE ID
#                 cve_app_map[cve_id] = {
#                     "application": app_name,
#                     "version": normalized_version
#                 }
#
#     # Use prompt_cves to filter the results
#     cve_ids = prompt_cves(applications, all_results)
#     filtered_results = [result for result in all_results if result["id"] in cve_ids]
#
#     # Append application name and version to the filtered results
#     for result in filtered_results:
#         cve_id = result["id"]
#         if cve_id in cve_app_map:
#             result["application"] = cve_app_map[cve_id]["application"]
#             result["version"] = cve_app_map[cve_id]["version"]
#
#     return {"results": filtered_results}  # Return filtered results with application info

async def search_by_field(es_client, index_name, field, applications: List[Application], size=10000, max_results_per_app=5):
    all_results = []  # Initialize a list to collect results

    # Store a mapping of CVE ID to application information (app name, version)
    cve_app_map = {}

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

            # Sort the CVE results by relevance or any other criterion
            sorted_cve_results = sorted(cve_results, key=lambda x: x.get("relevance_score", 0), reverse=True)  # Placeholder for sorting

            # Limit to a maximum of `max_results_per_app` per application
            limited_cve_results = sorted_cve_results[:max_results_per_app]

            for item in limited_cve_results:
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

                # Save the app name and version associated with this CVE ID
                cve_app_map[cve_id] = {
                    "application": app_name,
                    "version": normalized_version
                }

    # Use prompt_cves to filter the results
    cve_ids = prompt_cves(applications, all_results)
    filtered_results = [result for result in all_results if result["id"] in cve_ids]

    # Append application name and version to the filtered results
    for result in filtered_results:
        cve_id = result["id"]
        if cve_id in cve_app_map:
            result["application"] = cve_app_map[cve_id]["application"]
            result["version"] = cve_app_map[cve_id]["version"]

    # Remove duplicates based on CVE ID
    unique_results = []
    seen_ids = set()

    for result in filtered_results:
        if result["id"] not in seen_ids:
            unique_results.append(result)
            seen_ids.add(result["id"])

    return {"results": unique_results}  # Return unique results with application info

app = FastAPI()


@app.post("/search")
async def root(data: ApplicationsPayload):
    ELASTIC_ADDRESS = "http://localhost:9200"
    # ELASTIC_ADDRESS = "https://3ce5-44-211-168-46.ngrok-free.app"
    INDEX_NAME = "interactions_index-6"
    es_client = Elasticsearch(hosts=[ELASTIC_ADDRESS])
    result = await search_by_field(es_client, INDEX_NAME, "cve.descriptions.value", data.applications)
    return result
