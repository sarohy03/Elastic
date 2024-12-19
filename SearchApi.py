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
        match = re.match(r'^([a-zA-Z0-9\s]+)', self.app)
        return match.group(1).strip() if match else self.app

    def normalize_version(self):
        return re.sub(r'(\.0)+$', '', self.version)


class ApplicationsPayload(BaseModel):
    applications: List[Application]


async def search_documents(es_client, index_name, query_body, size=10):
    print(f"Sending query to Elasticsearch with body: {query_body}")
    response = es_client.search(index=index_name, body=query_body, size=size)
    hits = response['hits']['hits']
    results = [hit['_source'] for hit in hits]

    print(f"Received {len(results)} results from Elasticsearch")

    return {
        "total": response['hits']['total']['value'],
        "results": results
    }


async def search_by_field(es_client, index_name, field, applications: List[Application], size=10000, max_results_per_app=5):
    all_results = []
    cve_app_map = {}

    for application in applications:
        app_name = application.extract_app_name()
        normalized_version = application.normalize_version()
        normalized_app_name = app_name.replace(" ", "").lower()
        normalized_app_name_split = normalized_app_name.split("service")
        flexible_search_terms = [normalized_app_name]

        if len(normalized_app_name_split) > 1:
            flexible_search_terms.append(normalized_app_name_split[0])

        wildcard_search = f"*{normalized_app_name}*"
        query_body = {
            "query": {
                "bool": {
                    "should": [
                        {"match": {field: {"query": app_name, "operator": "and"}}},
                        {
                            "bool": {
                                "should": [
                                    {"wildcard": {field: {"value": wildcard_search, "boost": 2.0}}},
                                    *[
                                        {"match": {field: {"query": term, "operator": "and"}}}
                                        for term in flexible_search_terms
                                    ]
                                ]
                            }
                        }
                    ],
                    "minimum_should_match": 1
                }
            }
        }

        print(f"Sending query for application: {app_name} with body: {query_body}")
        app_results = await search_documents(es_client, index_name, query_body, size)

        if "results" in app_results:
            cve_results = app_results["results"]
            sorted_cve_results = sorted(cve_results, key=lambda x: x.get("relevance_score", 0), reverse=True)
            limited_cve_results = sorted_cve_results[:max_results_per_app]

            print(f"Found {len(limited_cve_results)} CVEs for application: {app_name}")

            for item in limited_cve_results:
                cve = item.get("cve", {})
                cve_id = cve.get("id", "Unknown ID")
                descriptions = cve.get("descriptions", [])
                en_description = next((desc["value"] for desc in descriptions if desc["lang"] == "en"), "No description available")

                # Extract CVSS score and severity
                cvss_metric = cve.get("metrics", {}).get("cvssMetricV31", []) or cve.get("metrics", {}).get("cvssMetricV30", [])
                cvss_score = cvss_metric[0]["cvssData"]["baseScore"] if cvss_metric else "No score available"
                base_severity = cvss_metric[0]["cvssData"]["baseSeverity"] if cvss_metric else "No severity available"

                all_results.append({
                    "id": cve_id,
                    "description": en_description,
                    "cvss_score": cvss_score,
                    "base_severity": base_severity
                })

                cve_app_map[cve_id] = {
                    "application": app_name,
                    "version": normalized_version
                }

    print(f"Sending results for filtering to prompt_cves: {all_results}")
    cve_ids = prompt_cves(applications, all_results)
    filtered_results = [result for result in all_results if result["id"] in cve_ids]

    # Append application info and remove duplicates
    unique_results = []
    seen_ids = set()
    for result in filtered_results:
        cve_id = result["id"]
        if cve_id not in seen_ids:
            if cve_id in cve_app_map:
                result["application"] = cve_app_map[cve_id]["application"]
                result["version"] = cve_app_map[cve_id]["version"]
            unique_results.append(result)
            seen_ids.add(cve_id)

    print(f"Returning final results: {unique_results}")
    return {"results": unique_results}


app = FastAPI()


@app.post("/search")
async def root(data: ApplicationsPayload):
    print(f"Received search request with data: {data}")
    ELASTIC_ADDRESS = "http://localhost:9200"
    # ELASTIC_ADDRESS = "https://c45e-54-209-182-160.ngrok-free.app"
    INDEX_NAME = "interactions_index-6"
    es_client = Elasticsearch(hosts=[ELASTIC_ADDRESS])
    result = await search_by_field(es_client, INDEX_NAME, "cve.descriptions.value", data.applications)
    print(f"Returning result: {result}")
    return result
