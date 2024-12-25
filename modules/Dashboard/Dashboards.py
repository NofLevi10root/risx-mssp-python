import os
import sys
import additionals.logger
import requests
import logging
import json
import time
from requests.exceptions import RequestException
from requests.exceptions import HTTPError
import modules.Velociraptor.VelociraptorScript
import modules.Velociraptor.AddToTimeSketch
import modules.Nuclei.NucleiScript
import additionals.funcs
from timesketch_api_client import client as timesketch_client, search
from collections import Counter
from datetime import datetime, timedelta
import asyncio

# Wrappers for the blocking operations
async def async_setup_mysql_connection(env_dict, logger):
    return await asyncio.to_thread(additionals.mysql_functions.setup_mysql_connection, env_dict, logger)

async def async_execute_query(connection, query, logger):
    return await asyncio.to_thread(additionals.mysql_functions.execute_query, connection, query, logger)

async def async_requests_get(url, headers):
    return await asyncio.to_thread(requests.get, url, headers=headers, verify=False)

async def async_server_query(channel, config, query, logger):
    return await asyncio.to_thread(modules.Velociraptor.VelociraptorScript.server_query, channel, config, query, logger)

async def async_open(file_path, mode):
    return await asyncio.to_thread(open, file_path, mode)

async def async_connect_timesketch_api(config_json, logger):
    return await asyncio.to_thread(modules.Velociraptor.AddToTimeSketch.connect_timesketch_api, config_json, logger)

def load_existing_mssp_config(logger):
    file_path1 = '../risx-mssp-front/public/mssp_config.json'
    file_path2 = '../risx-mssp-front/build/mssp_config.json'

    # Check if the first file exists
    if os.path.exists(file_path1):
        return file_path1
    elif os.path.exists(file_path2):
        return file_path2
    else:
        logging.error('Neither file was found.')
        file_path = ""
def get_misp_tool(logger):
  file_path1 = '../risx-mssp-front/public/mssp_config.json'
  file_path2 = '../risx-mssp-front/build/mssp_config.json'
  
  try:
      file_path = load_existing_mssp_config(logger)
      if(file_path == ""):
        logger.warning("Get misp tool function: mssp_config.json not exists neither in public nor build!")
        return
        
      with open(file_path, 'r') as file:
          data = json.load(file)

      module_links = data.get("moduleLinks", [])
      for module in module_links:
          if module.get("toolName") == "MISP":
            return module["toolURL"] 
      
      logger.info("MISP tool not found in moduleLinks.")
      return None

  except Exception as e:
      logger.error(f"Failed to read JSON file or find MISP tool: {e}")
      return None

def write_dict_to_json_file(dictionary, file_path):
    try:
        with open(file_path, 'w') as json_file:
            json.dump(dictionary, json_file, indent=4)
        print(f"Dictionary successfully written to {file_path}")
    except Exception as e:
        print(f"An error occurred while writing to {file_path}: {e}")


def get_misp_data(config_data, logger):
    try:
        api_key = config_data["ClientData"]["API"]["MISP"]
        if not api_key:
            logger.warning("Misp API key is empty")
            response_dict = {"Response": "", "Error": "API key is empty"}
            return response_dict
        base_url = get_misp_tool(logger)
        response_dict = {"Response": "", "Error": ""}
        headers = {
            'Authorization': api_key,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }

        try:
            tags_url = f"{base_url}/tags"
            logger.info("Getting all tags")
            response = requests.get(tags_url, headers=headers, verify=False)
            response.raise_for_status()
            all_tags = response.json()

            tag_counts = {}
            if 'Tag' in all_tags:
                now = datetime.utcnow()
                for tag in all_tags['Tag']:
                    tag_name = tag['name'].strip()  # Strip leading/trailing whitespace
                    tag_counts[tag_name] = tag_counts.get(tag_name, 0) + tag.get('attribute_count', 0)
                sorted_tag_counts = sorted(tag_counts.items(), key=lambda item: item[1], reverse=True)[:10]

                top_10_tags = [{"Name": tag, "Count": count} for tag, count in sorted_tag_counts]
            else:
                top_10_tags = []

            logger.info(f"Top 10 tags: {top_10_tags}")

            # Get attribute type statistics
            type_context = "type"
            percentage = 0
            type_stats_url = f"{base_url}/attributes/attributeStatistics/{type_context}/{percentage}"
            logger.info("Getting attribute type statistics")
            response = requests.get(type_stats_url, headers=headers, verify=False)
            response.raise_for_status()
            attribute_type_stats = response.json()

            # Ensure the response is a dictionary
            if isinstance(attribute_type_stats, dict):
                attribute_type_counts = {k: int(v) for k, v in attribute_type_stats.items()}
            else:
                attribute_type_counts = {}

            # Extract top 10 attribute types by count
            sorted_attribute_type_counts = sorted(attribute_type_counts.items(), key=lambda item: item[1], reverse=True)
            top_10_attribute_types = [{"Name": k, "Count": v} for k, v in sorted_attribute_type_counts[:10]]

            logger.info(f"Top 10 attribute types: {top_10_attribute_types}")

            # Get attribute category statistics
            category_context = "category"
            category_stats_url = f"{base_url}/attributes/attributeStatistics/{category_context}/{percentage}"
            logger.info("Getting attribute category statistics")
            response = requests.get(category_stats_url, headers=headers, verify=False)
            response.raise_for_status()
            attribute_category_stats = response.json()

            # Ensure the response is a dictionary
            if isinstance(attribute_category_stats, dict):
                attribute_category_counts = {k: int(v) for k, v in attribute_category_stats.items()}
            else:
                attribute_category_counts = {}

            # Extract top 10 attribute categories by count
            sorted_attribute_category_counts = sorted(attribute_category_counts.items(), key=lambda item: item[1], reverse=True)
            top_10_attribute_categories = [{"Name": k, "Count": v} for k, v in sorted_attribute_category_counts[:10]]

            total_attributes = sum(attribute_category_counts.values())

            logger.info(f"Top 10 attribute categories: {top_10_attribute_categories}")
            logger.info(f"Total attributes: {total_attributes}")

            response_dict["Response"] = {
                "top_10_tags": top_10_tags,
                "top_10_attribute_types": top_10_attribute_types,
                "top_10_attribute_categories": top_10_attribute_categories,
                "total_attributes": total_attributes
            }

        except requests.exceptions.HTTPError as http_err:
            logger.error(f"HTTP error occurred while getting tags or attributes: {http_err}")
            response_dict["Error"] = str(http_err)
        except Exception as err:
            logger.error(f"Error occurred while getting tags or attributes: {err}")
            response_dict["Error"] = str(err)

        return response_dict
    except Exception as e:
        logger.error("get_misp_data error:" + str(e))

def get_velociraptor_data(config_data, logger):
    try:
        velociraptor_dict = {}
        channel = modules.Velociraptor.VelociraptorScript.setup_connection(logger)

        # Query for clients data
        clients_data_str = modules.Velociraptor.VelociraptorScript.server_query(channel, "", "SELECT * FROM clients()", logger)
        try:
            clients_data = json.loads(clients_data_str)
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding JSON: {e}")
            return

        current_timestamp = int(time.time())  # Get the current timestamp in seconds
        one_week_in_seconds = 7 * 24 * 60 * 60  # One week in seconds

        # Assuming clients_data is the list of client information dictionaries
        velociraptor_dict = {}

        velociraptor_dict["NumberOfClients"] = len(clients_data)
        velociraptor_dict["NumberOfConnectedClients"] = sum(
            1 for client in clients_data if int(client['last_seen_at']) // 1_000 > (current_timestamp - 300)
        )  # Convert last_seen_at to seconds

        velociraptor_dict["RecentHosts"] = [
            {
                "Hostname": client['os_info']['hostname'],
                "LastSeen": int(client['last_seen_at']) // 1_000  # Convert last_seen_at to seconds
            }
            for client in clients_data if int(client['last_seen_at']) // 1_000 > (current_timestamp - 86400)
        ]  # Last 24 hours

        velociraptor_dict["NewUsers"] = [
            {
                "Hostname": client['os_info']['hostname'],
                "FirstSeen": int(client['first_seen_at']) // 1_000  # Convert first_seen_at to seconds
            }
            for client in clients_data if int(client['first_seen_at']) // 1_000 > (current_timestamp - one_week_in_seconds)
        ]  # First seen within the last week

        print(f"Number of Clients: {velociraptor_dict['NumberOfClients']}")
        print(f"Number of Connected Clients: {velociraptor_dict['NumberOfConnectedClients']}")
        print(f"Recent Hosts: {velociraptor_dict['RecentHosts']}")
        print(f"First Seen Last Week: {velociraptor_dict['NewUsers']}")
        # Query for finished hunts
        finished_hunts_data_str = modules.Velociraptor.VelociraptorScript.server_query(channel, "", "LET collection <= SELECT count() AS row_count FROM hunts() WHERE status = 'FINISHED' SELECT * FROM collection ORDER BY row_count DESC LIMIT 1", logger)
        if finished_hunts_data_str:
            try:
                finished_hunts_data = json.loads(finished_hunts_data_str)
                finished_hunts_count = finished_hunts_data[0]['row_count'] if finished_hunts_data else 0
            except (json.JSONDecodeError, KeyError, IndexError) as e:
                logger.error(f"Error decoding JSON for finished hunts: {e}")
                finished_hunts_count = 0
        else:
            finished_hunts_count = 0
        
        # Query for unfinished hunts
        unfinished_hunts_data_str = modules.Velociraptor.VelociraptorScript.server_query(channel, "", "LET collection <= SELECT count() AS row_count FROM hunts() WHERE status != 'FINISHED' SELECT * FROM collection ORDER BY row_count DESC LIMIT 1", logger)
        if unfinished_hunts_data_str:
            try:
                unfinished_hunts_data = json.loads(unfinished_hunts_data_str)
                unfinished_hunts_count = unfinished_hunts_data[0]['row_count'] if unfinished_hunts_data else 0
            except (json.JSONDecodeError, KeyError, IndexError) as e:
                logger.error(f"Error decoding JSON for unfinished hunts: {e}")
                unfinished_hunts_count = 0
        else:
            unfinished_hunts_count = 0
        # Log details of finished and unfinished hunts count
        velociraptor_dict["FinishedHunts"] = finished_hunts_count
        velociraptor_dict["UnfinishedHunts"] = unfinished_hunts_count
        return velociraptor_dict
    except Exception as e:
        logger.error("get_velociraptor_data crush!")
        logger.error(str(e))
        return {}
        
def get_dashboards_from_responses(config_data, logger):
  response_dashboards = {"Nuclei": {}, "LeakCheck": [], "Shodan": []}
  requests_object = config_data.get("RequestStatus", {})
  for request in requests_object[::-1]:
    if request["ModuleName"] == "Nuclei":
      response_path = request["ResponsePath"]
      severity_counts = modules.Nuclei.NucleiScript.count_severities(response_path, logger)
      if(severity_counts != None):
        response_dashboards["Nuclei"]["SeverityCounts"] = severity_counts
        break
  
  for request in requests_object[::-1]:
    if request["ModuleName"] == "LeakCheck":
      response_path = request["ResponsePath"]
      
      # Check if the response path exists and is not empty
      if os.path.exists(response_path) and os.path.getsize(response_path) > 0:
          with open(response_path, 'r') as file:
              try:
                  response_object = json.load(file)
                  response_dashboards["LeakCheck"] = response_object
                  logger.info(f"Loaded response object from {response_path}")
              except json.JSONDecodeError as e:
                  logger.error(f"Error decoding JSON from {response_path}: {e}")
      else:
          logger.error(f"File does not exist or is empty: {response_path}")
      break

  for request in requests_object[::-1]:
    if request["ModuleName"] == "Shodan":
      response_path = request["ResponsePath"]
      
      # Check if the response path exists and is not empty
      if os.path.exists(response_path) and os.path.getsize(response_path) > 0:
          with open(response_path, 'r') as file:
              try:
                  response_object = json.load(file)
                  response_dashboards["Shodan"] = response_object
                  logger.info(f"Loaded response object from {response_path}")
              except json.JSONDecodeError as e:
                  logger.error(f"Error decoding JSON from {response_path}: {e}")
      else:
          logger.error(f"File does not exist or is empty: {response_path}")
      break
  return response_dashboards

def get_timelines(config_data, logger):
  def get_timesketch_data(api, tag_counts, logger):
    try:
        # Get the number of sketches
        sketches = list(api.list_sketches())
        num_sketches = len(sketches)

        # Iterate over each sketch to count tags
        for sketch in sketches:
            for timeline in sketch.list_timelines():
                # Create a search object for the timeline
                search_obj = search.Search(sketch=sketch)
                search_obj.query_string = '*'
                search_obj.return_fields = 'tag'
                search_obj.max_entries = 10000
                
                # Execute the search and convert results to a DataFrame
                search_results = search_obj.table
                
                if 'tag' in search_results.columns:
                    unique_tags = search_results['tag'].explode().unique()  # Handle tags as lists
                    for tag in unique_tags:
                        if tag in tag_counts:
                            tag_counts[tag] += 1

        return {
            "number_of_sketches": num_sketches,
            "tag_counts": tag_counts
        }
    except Exception as e:
        logger.error(f"Error occurred while fetching data from Timesketch: {e}")
        return None
  tag_counts = {
      "high": 0,
      "Persistence": 0,
      "phishy-domain": 0,
      "command and control": 0
  }
  timesketch_data = []
  timesketch_api = modules.Velociraptor.AddToTimeSketch.connect_timesketch_api(config_data, logger)
  if timesketch_api:
      timesketch_data = get_timesketch_data(timesketch_api, tag_counts, logger)
      if timesketch_data:
          print(f"Number of Sketches: {timesketch_data['number_of_sketches']}")
          for tag, count in timesketch_data['tag_counts'].items():
              print(f"Tag '{tag}': {count}")
  else:
    logger.warning("TimeSketch API key is empty")
    return ""
  return timesketch_data


    # Refactor function with asynchronous wrappers

async def async_create_module_dict(env_dict):
    return await asyncio.to_thread(additionals.funcs.create_module_dict, env_dict)

    
async def run_dashboard(time_interval):
    logger = additionals.logger.setup_logger("dashboard.log")
    while True:
        dashboard_json = dict()
        ##################################################################
        logger.info("Reading env file!")
        env_dict = additionals.funcs.read_env_file(logger)
        logger.info("Connecting MySQL")
        connection = await async_setup_mysql_connection(env_dict, logger)
        logger.info("Reading the config!")
        config_data = json.loads((await async_execute_query(connection, "SELECT config FROM configjson LIMIT 1", logger))[0][0])
        current_datetime = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')
        existing_modules =await async_create_module_dict(config_data["Modules"])
        assets_per_module = additionals.funcs.fill_assets_per_module(config_data, existing_modules, current_datetime, logger)

        ##################################################################
        logger.info("Getting Misp") # Working
        dashboard_json["Misp"] = await asyncio.to_thread(get_misp_data, config_data, logger)
        ##################################################################
        logger.info("Getting velociraptor!")
        dashboard_json["Velociraptor"] = await asyncio.to_thread(get_velociraptor_data, config_data, logger)
        ##################################################################
        logger.info("Getting TimeSketch!")
        dashboard_json["TimeSketch"] = await asyncio.to_thread(get_timelines, config_data,  logger)
        ##################################################################
        dashboard_json["DashboardsFromResponses"] = await asyncio.to_thread(get_dashboards_from_responses, config_data, logger)
        ##################################################################
        logger.info("Writing dashboard.json!")
        await asyncio.to_thread(write_dict_to_json_file, dashboard_json, os.path.join("response_folder", "dashboard.json"))
        logger.info("End interval dashboard will run again in 5 minutes!")
        await asyncio.sleep(time_interval) # 5 minutes