import requests
import json
import time
import getpass  # Library to hide password input

# Prompt for username and password
username = input("Enter your username: ")
password = getpass.getpass("Enter your password: ")

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

# Measure start time
start_time = time.time()

# Step 1: Create a PIT
pit_url = "https://localhost:9201/logstash-*/_pit?keep_alive=10m"
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

i= 0
while True:
    # Step 4: Parse the search response
    search_data = json.loads(search_response.text)
    hits = search_data.get("hits", {}).get("hits", [])
    i+=1
    if not hits:
        break

    # Extract and save data to output_file
    with open(output_file, "a") as file:
        print(i)
        for hit in hits:
            thread = hit["_source"]["thread"]
            loglevel = hit["_source"]["x-ecs-log.level"]
            method = hit["_source"]["method"]
            timestamp = hit["_source"]["@timestamp"]
            class_ecs = hit["_source"]["class"]
            file.write(json.dumps({ "@timestamp": timestamp, "loglevel": loglevel, "thread": thread, "method": method, "class": class_ecs}) + "\n")

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

# Log script execution time
log_execution_time(start_time)

# Close the loop when there are no more hits
log_message("Loop completed")