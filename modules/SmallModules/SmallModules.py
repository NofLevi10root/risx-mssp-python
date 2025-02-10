import additionals.funcs
import additionals.elastic_api
import shodan
from requests.exceptions import RequestException
from requests.exceptions import HTTPError
import requests
import time
from datetime import datetime
import json
import additionals.string_fixes
import random
from datetime import datetime, timedelta
import re
from leakcheck import LeakCheckAPI_v2

def process_leakcheck_json(data, output_path, logger):
    """Flatten 'source' dictionary, correct the 'dob' field, and save the combined results."""
    
    def flatten_and_correct_dob(record, logger):
        """Flatten the 'source' dictionary, correct 'dob' field."""
        try:
            if 'source' in record:
                
                source = record.pop('source')
                for key, value in source.items():
                    record[f'source_{key}'] = value
        except Exception as e:
            logger.error(f"Error processing record: {e}")

        return record

    try:
        # Load the JSON file
        logger.info("Output path:" + output_path)
        #logger.info(f"Loaded JSON file: {input_path}")
        
        # Extract and flatten the 'result' lists from each response
        combined_results = []
        for item in data:
            if(len(item["Response"]) == 0):
                continue
            asset_parent_id = item["Name"]["asset_parent_id"]
            asset_string = item["Name"]["asset_string"]
            if item["Response"] and item["Response"]:
                for result in item["Response"]:
                    #logger.info(result)
                    result["asset_string"] = asset_string
                    result["asset_parent_id"] = asset_parent_id
                    result["@timestamp"] = datetime.utcnow().isoformat(timespec='milliseconds') + 'Z'
                    corrected_record = flatten_and_correct_dob(result, logger)
                    combined_results.append(corrected_record)
        
        # Save the combined and corrected results to a new JSON file
        logger.info("Data before elastic" + str(combined_results))
        with open(output_path, 'w') as outfile:
            json.dump(combined_results, outfile, indent=4)
        logger.info(f"Processed file saved to: {output_path}")
        return combined_results
    except Exception as e:
        logger.error(f"Error processing JSON file: {e}")


def format_shodan_json(input_file, output_file, logger):
    def flatten_json(data):
        flattened_data = []

        for entry in data:
            domain = entry.get('Domain', '')
            response = entry.get('Response', {})

            # Check if response is a dictionary
            if not isinstance(response, dict):
                logger.error(f"Expected 'Response' to be a dictionary, got {type(response).__name__}. Skipping entry.")
                continue

            matches = response.get('matches', [])

            # Ensure matches is a list
            if not isinstance(matches, list):
                logger.error(f"Expected 'matches' to be a list, got {type(matches).__name__}.")
                continue

            for match in matches:
                if not isinstance(match, dict):
                    logger.warning(f"Skipping non-dictionary match: {match}")
                    continue

                flat_entry = {"asset_string": domain["asset_string"], "asset_parent_id": domain["asset_parent_id"]}
                flat_entry.update(recursive_flatten(match))
                flat_entry['@timestamp'] = format_timestamp(flat_entry.get('timestamp'))
                flattened_data.append(flat_entry)

                logger.info(f"Processed match for domain: {domain} with IP: {flat_entry.get('ip', 'N/A')}")

        return flattened_data

    def recursive_flatten(d, parent_key='', sep='_'):
        items = {}
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.update(recursive_flatten(v, new_key, sep))
            else:
                items[new_key] = v
        return items

    def format_timestamp(timestamp):
        try:
            if timestamp:
                return datetime.fromisoformat(timestamp).isoformat()
        except (ValueError, TypeError) as e:
            logger.error(f"Error parsing timestamp: {timestamp}, {e}")
        return None

    # Load the input JSON file
    try:
        with open(input_file, 'r', encoding='utf-8') as file:
            data = json.load(file)
        logger.info(f"Loaded data from {input_file}")
    except json.JSONDecodeError as e:
        logger.error(f"JSONDecodeError while loading {input_file}: {e}")
        return
    except FileNotFoundError as e:
        logger.error(f"FileNotFoundError: {input_file} not found: {e}")
        return
    except IOError as e:
        logger.error(f"IOError while loading {input_file}: {e}")
        return

    # Ensure data is a list
    if not isinstance(data, list):
        logger.error(f"Expected list of entries in the input file, got {type(data).__name__}.")
        return

    # Flatten the data
    flattened_data = flatten_json(data)
    logger.info("Flattening complete")

    # Save the flattened data to the output file
    try:
        with open(output_file, 'w', encoding='utf-8') as outfile:
            json.dump(flattened_data, outfile, indent=2)
        logger.info(f"Data has been formatted and saved to {output_file}")
    except IOError as e:
        logger.error(f"IOError while saving to {output_file}: {e}")
        
def run_shodan(row, api_key, population,elasticIp, logger):
    logger.info("Entering shodan!")
    
    if not api_key:
        logger.warning("Shodan has no API key!")
        row["Status"] = "Failed"
        row["Error"] = "Shodan has no API key!"
        return row

    if not population:
        logger.warning("Shodan has no population!")
        row["Status"] = "Failed"
        row["Error"] = "Shodan has no population!"
        return row

    shodan_list = []
    api = shodan.Shodan(api_key)

    for temp_domain in population:
        domain = temp_domain["asset_string"]
        response_dict = {"Domain": temp_domain, "Response": "", "Error": ""}

        try:
            logger.info(f"Checking domain: {domain}")
            if is_valid_ip(domain):
                # Use api.host() for IP addresses
                result = api.host(domain)
                logger.info(f"Found {len(result.get('ports', []))} open ports for IP: {domain}")
            else:
                # Use api.search() for hostnames/domains
                result = api.search(f"hostname:{domain}")
                logger.info(f"Found {result['total']} results for domain: {domain}")

            response_dict["Response"] = result
        except shodan.APIError as e:
            logger.error(f"Error: {e}")
            response_dict["Error"] = str(e)

        shodan_list.append(response_dict)

    row["Status"] = "Complete"
    row["Error"] = ""
    row["UniqueID"] = str(random.randint(9000000, 99999999))
    row["ExpireDate"] = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

    additionals.funcs.write_json(shodan_list, row["ResponsePath"])
    logger.info("Post processing the data!")
    
    elastic_path = row["ResponsePath"].split(".")[0] + "Elastic.json"
    format_shodan_json(row["ResponsePath"], elastic_path, logger)
    
    logger.info("Uploading file to elastic!")
    additionals.elastic_api.enter_data(elastic_path, "artifact_shodan",elasticIp, logger)

    return row

def is_valid_ip(ip):
    """Check if the given string is a valid IP address."""
    try:
        requests.utils.socket.inet_aton(ip)
        return True
    except OSError:
        return False

def extract_domain(input_string):
    # Regex to extract the domain from a URL
    pattern = r"^(?:https?:\/\/|ftp:\/\/)?(?:www\.)?([^\/:]+)"
    match = re.match(pattern, input_string)
    if match:
        return match.group(1)  # Extract and return the domain
    return None  # Return None if no domain found

def is_domain(input_string):
    # Regex to detect valid domain names
    domain_regex = r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?$"
    
    # Extract domain first if input is a URL
    domain = extract_domain(input_string)
    if domain:
        # Check if the extracted domain matches the domain regex
        return bool(re.match(domain_regex, domain))
    return False
    
def filter_recent_breaches(data, days=7):
    # Calculate the date threshold
    date_threshold = datetime.now() - timedelta(days=days)
    
    # Function to parse breach date and filter entries within the last 7 days
    def is_recent(entry):
        breach_date_str = entry.get('source', {}).get('breach_date')
        if breach_date_str:
            try:
                # Parse date if in "YYYY-MM" format, else ignore
                breach_date = datetime.strptime(breach_date_str, "%Y-%m")
                return breach_date >= date_threshold
            except ValueError:
                pass  # Skip entries with invalid or null breach dates
        return False
    
    # Filter each 'Response' list to contain only recent breaches
    for record in data:
        record['Response'] = [entry for entry in record.get('Response', []) if is_recent(entry)]
    
    # Return the filtered data
    return data


def run_leakcheck(row, api_key, population,elasticIp, logger):
    max_retries = 3
    backoff_factor = 1
    delay_between_requests = 1  # Delay in seconds between requests
    days_ago = 30

    if not api_key:
        logger.warning("LeakCheck has no API key!")
        row["Status"] = "Failed"
        row["Error"] = "LeakCheck has no API key!"
        return row

    if not population:
        logger.warning("LeakCheck has no population!")
        row["Status"] = "Failed"
        row["Error"] = "LeakCheck has no population!"
        return row

    # Initialize the LeakCheck API client
    api = api = LeakCheckAPI_v2(api_key=api_key)
    leakcheck_list = []

    for temp_query in population:
        query = temp_query["asset_string"]
        response_dict = {"Name": temp_query, "Response": "", "Error": ""}
        
        for retry in range(max_retries):
            try:
                logger.info("Sending request to LeakCheck API")
                # Use the `leakcheck-api` library to perform the domain search
                data = ""
                if(is_domain(query)):
                    query = extract_domain(query)
                    logger.info("Leakcheck query [Domain]:" + str(query))
                    data = api.lookup(query=query, query_type="domain")
                else:
                    query = query.replace(" ", "")
                    logger.info("Leakcheck query [Anything else]:" + str(query))
                    data = api.lookup(query=query)
                logger.info("Request successful")
                logger.info("Data:" + str(data))
                response_dict["Response"] = data
                time.sleep(1)
                break  # Exit retry loop on success

            except HTTPError as http_err:
                if http_err.response.status_code == 429:
                    wait_time = backoff_factor * (2 ** retry)
                    logger.warning(f"Rate limit exceeded. Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                elif http_err.response.status_code == 404:
                    logger.error(f"404 Not Found: {http_err}. Skipping query {query}.")
                    response_dict["Error"] = "404 Not Found"
                    break  # No point in retrying a 404 error
                else:
                    logger.error(f"HTTP error occurred: {http_err}")
                    response_dict["Error"] = str(http_err)

            except Exception as err:
                logger.error(f"An error occurred: {err}")
                response_dict["Error"] = str(err)

            time.sleep(delay_between_requests)  # Add delay between retries

        leakcheck_list.append(response_dict)
    
    # Filter only from last days [Not used yet]
    #leakcheck_list = filter_recent_breaches(leakcheck_list, days=days_ago)
    logger.info("Writing File!")
    additionals.funcs.write_json(leakcheck_list, row["ResponsePath"])
    # New Into Elastic
    logger.info("Post processing the data!")
    elastic_path = row["ResponsePath"].split(".")[0] + "Elastic.json"
    process_leakcheck_json(leakcheck_list, elastic_path, logger)
    logger.info("Uploading file to elastic!")
    additionals.elastic_api.enter_data(elastic_path, "artifact_leakcheck",elasticIp, logger)
    
    row["UniqueID"] = str(random.randint(9000000, 99999999))
    row["ExpireDate"] = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    row["Status"] = "Complete"
    row["Error"] = ""
    
    return row