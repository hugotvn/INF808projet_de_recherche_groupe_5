import requests
import json
import time
import uuid
from datetime import datetime
import getpass  # Library to hide password input

# Prompt for username and password
username = input("Enter your username: ")
password = getpass.getpass("Enter your password: ")
now = datetime.utcnow().isoformat() + "Z"
# Initialize variables
pit_id = None
last_sort = None
output_file = "output.json"
enable_logging = False  # Set to True to enable general logging
enable_logging_time = True  # Set to True to log script execution time

# Disable SSL certificate verification
requests.packages.urllib3.disable_warnings()

# Function to log messages
def log_message(message):
    if enable_logging:
        print(message)

# Function to log script execution time
def log_execution_time(start_time):
    if enable_logging_time:
        end_time = time.time()
        print(f"Script execution time: {end_time - start_time:.2f} seconds")

def generate_id(object_type):
    return f"{object_type}--{str(uuid.uuid4())}"

# Measure start time
start_time = time.time()

# Step 1: Create a PIT
pit_url = "https://localhost:9201/logstash_logs/_pit?keep_alive=10m"
pit_response = requests.post(pit_url, auth=(username, password), verify=False)

# Log the Step 1 request and response
log_message("Step 1 Request: " + pit_url)
log_message("Step 1 Response Status Code: " + str(pit_response.status_code))
log_message("Step 1 Response Body: " + pit_response.text)

if pit_response.status_code != 200:
    log_message(f"Step 1: Failed to create PIT. Status Code: {pit_response.status_code}")
    if pit_response.status_code == 401:
        log_message("Authentication failed. Check your credentials")
    exit(1)

# Parse PIT response JSON and save pit_id
log_message(f"JSON pit DATA : {pit_response.text}")
pit_data = json.loads(pit_response.text)
pit_id = pit_data.get("id")

# Step 3: Create a search query with pit_id
search_url = "https://localhost:9201/_search"
search_body = {
    "size": 10000,  # Increase the size parameter to fetch more documents at once
    "query": {"match_all": {}},
    "pit": {"id": pit_id, "keep_alive": "10m"},
    "track_total_hits": False,
    "sort": [{"_shard_doc": "asc"}],
}

# Print the JSON query for Step 3
log_message("Step 3 Query: " + json.dumps(search_body, indent=2))

# Perform the search with SSL certificate verification disabled
search_response = requests.post(search_url, json=search_body, auth=(username, password), verify=False)

if search_response.status_code != 200:
    log_message(f"Step 3: Search failed. Status Code: {search_response.status_code}")
    if search_response.status_code == 401:
        log_message("Authentication failed. Check your credentials.")
    exit(1)

all_data = []
while True:
    # Step 4: Parse the search response
    search_data = json.loads(search_response.text)
    hits = search_data.get("hits", {}).get("hits", [])
    if not hits:
        break

    for hit in hits:
        if "event.thread" not in hit["_source"] :
            continue
        thread = hit["_source"]["event.thread"]
        loglevel = hit["_source"]["event.loglevel"]
        method = hit["_source"]["event.method"]
        timestamp = hit["_source"]["@timestamp"]
        class_ecs = hit["_source"]["event.class"]
        message = hit["_source"]["event.message"]
        all_data.append({"type": "process", 
                         "id": generate_id("process"),
                         "name": "process",
                         "timestamp": timestamp, 
                         "loglevel": loglevel, 
                         "thread": thread, 
                         "method": method, 
                         "class": class_ecs,
                         "process_command": message})
        

    # Step 5: Get last_sort for the next iteration
    last_sort = hits[-1]["sort"]

    # Step 6: Create a search query with pit_id and last_sort for the next iteration
    search_body = {
        "size": 10000,
        "query": {"match_all": {}},
        "pit": {"id": pit_id, "keep_alive": "1m"},
        "sort": [{"_shard_doc": "asc"}],
        "track_total_hits": False,
        "search_after": last_sort,
    }

    # Print the JSON query for Step 6
    log_message("Step 6 Query: " + json.dumps(search_body, indent=2))

    # Perform the search with SSL certificate verification disabled
    search_response = requests.post(search_url, json=search_body, auth=(username, password), verify=False)

    if search_response.status_code != 200:
        log_message(f"Step 6: Search failed. Status Code: {search_response.status_code}")
        if search_response.status_code == 401:
            log_message("Authentication failed. Check your credentials.")
        break

bundle = {
    "type": "bundle",
    "id": generate_id("bundle"),
    "spec_version": "2.0",
    "objects": [
        {
            "type": "identity",
            "id": generate_id("identity"),
            "created": now,
            "modified": now,
            "name": "Elasticsearch To STIX",
            "identity_class": "program"
        },
        *all_data
    ]
}

with open(output_file, "a") as file:
    json.dump(bundle, file, indent=4)

# Log script execution time
log_execution_time(start_time)

# Close the loop when there are no more hits
log_message("Loop completed")