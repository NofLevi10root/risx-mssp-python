import json
import time
import os
import pandas as pd
from datetime import datetime, timedelta
import additionals.mysql_functions
import subprocess
import platform
import psutil
import math
import logging
import select
import copy
import sys

def setup_logger(logger_name):
    logging_level = logging.INFO
    logging_path = os.path.join("logs", logger_name)
    
    # Create a logger object with the provided name
    logger = logging.getLogger(logger_name)  # Use logger_name as the logger name
    logger.setLevel(logging_level)

    # Avoid adding multiple handlers to the same logger
    if not logger.hasHandlers():
        # Create a file handler for logging to a file
        file_handler = logging.FileHandler(logging_path)
        file_handler.setLevel(logging_level)
        file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

        # Create a console handler for logging to stdout
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging_level)
        console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)
    
    return logger

def is_new_config(connection, previous_config_date):
    #current_update = additionals.mysql_functions.execute_query(connection, "SELECT lastupdated FROM configjson LIMIT 1")[0][0].replace(" ","-").replace(":","-")
    current_update = additionals.mysql_functions.execute_query(connection, "SELECT lastupdated FROM configjson LIMIT 1", logger)[0][0]
    if(current_update != None):
        current_update = current_update.strftime('%d-%m-%Y-%H-%M-%S')
    
    if(previous_config_date == "" or previous_config_date == None):
        return True
    if(calculate_seconds_difference(previous_config_date, current_update) > 0):
        return True
    return False

def calculate_seconds_difference(datetime_str1, datetime_str2):
    date_format = "%d-%m-%Y-%H-%M-%S"
    #print("datimetime1:" +datetime_str1)
    #print("datimetime2:" +datetime_str2)
    datetime1 = datetime.strptime(datetime_str1, date_format)
    datetime2 = datetime.strptime(datetime_str2, date_format)

    # Calculate the difference in seconds
    time_difference = int((datetime2 - datetime1).total_seconds())

    return time_difference

def check_os():
    os_type = platform.system()
    if os_type == "Windows":
        return "windows."
    elif os_type == "Linux":
        return "linux"
    else:
        return f"The running machine is {os_type}."

def update_json(connection, new_config_data, previous_config_date, interval_flag, logger):
    logger.info("Updating json function!")
    max_retries = 20
    wait_time = 1
    retries = 0
    while retries < max_retries:
        try:
            config_data = json.loads(additionals.mysql_functions.execute_query(connection, "SELECT config FROM configjson LIMIT 1", logger)[0][0])
            logger.info("After getting config_data!")
            existing_data = config_data.get("RequestStatus", [])
            existing_data_dict = {entry['ResponsePath']: entry for entry in existing_data}
            new_data = new_config_data.get("RequestStatus", [])
            # Merge new data with the existing data
            for new_entry in new_data:
                response_path = new_entry['ResponsePath']
                existing_data_dict[response_path] = new_entry

            # Convert the dictionary back to a list
            merged_data = list(existing_data_dict.values())
            success = ""
            if  interval_flag:
                config_data['RequestStatus'] = merged_data
                # Save the merged data back to the JSON file
                logger.info("Executing update config query")
                success = additionals.mysql_functions.execute_update_config(connection, previous_config_date, config_data)
            else:
                new_config_data['RequestStatus'] = merged_data
                # Save the merged data back to the JSON file
                logger.info("Executing update config query")
                success = additionals.mysql_functions.execute_update_config(connection, previous_config_date, new_config_data)
            if success:
                print("Config updated successfully.")
            else:
                print("Failed to update config.")
            return merged_data
    
        except (IOError, OSError) as e:
            logger.warning(f"File is in use, retrying... ({retries + 1}/{max_retries})")
            time.sleep(wait_time)
            retries += 1
    
    logger.error(f"Failed to update the file after {max_retries} attempts.")
    return new_data

def write_json(result, filename):
    try:
        with open(filename, 'w') as f:
            json.dump(result, f, indent=4)
    except TypeError:
        # If result is not JSON serializable, write it as a string
        with open(filename, 'w') as f:
            f.write(str(result))

def add_row(ModuleName, SubModule, ArtifactTimeOutInMinutes, TimeInterval, Arguments, StartDate, population, logger):
    new_row = {}
    new_row["ModuleName"] = ModuleName
    new_row["SubModuleName"] = SubModule
    new_row["TimeInterval"] = TimeInterval
    new_row["Arguments"] = copy.deepcopy(Arguments)  # Create a deep copy of Arguments
    new_row['ArtifactTimeOutInMinutes'] = ""
    new_row["StartDate"] = StartDate
    new_row["LastIntervalDate"] = StartDate
    new_row["Population"] = ""

    if population != "":
        new_row["Population"] = population

    # Convert Start_Date to datetime object
    datetime_format = "%d-%m-%Y-%H-%M-%S"
    if isinstance(StartDate, str):
        StartDate = datetime.strptime(StartDate, datetime_format)

    if ArtifactTimeOutInMinutes != "":
        # Add Expire_Date to start date
        minutes = int(ArtifactTimeOutInMinutes)  # Convert to integer representing minutes
        new_expire_date = StartDate + timedelta(minutes=minutes)
        if ModuleName == "TimeSketch":
            new_row["ArtifactTimeOutInMinutes"] = str(minutes * 60)
        else:
            new_row['ArtifactTimeOutInMinutes'] = new_expire_date.strftime(datetime_format)

    new_row["ResponsePath"] = os.path.join("response_folder", f"response_{ModuleName}{SubModule}_{StartDate.strftime(datetime_format)}.json")
    new_row["Status"] = "In Progress"
    new_row["Error"] = ""
    new_row["UniqueID"] = ""

    return new_row

def fill_assets_per_module(config_data, existing_modules, current_datetime, logger):
    try:
        logger.info("Starting to fill assets and modules to run!")
        logger.info("existing_modules: " + str(existing_modules))

        assets_per_module = {}

        # Loop over each asset in the ClientInfrastructure
        assets = config_data.get("ClientInfrastructure", {}).get("Assets", {})
        for asset_id, asset in assets.items():
            asset_enable = asset.get("AssetEnable")
            asset_string = asset.get("AssetString")
            asset_modules = asset.get("AssetModules", [])
            asset_parent_id = asset.get("AssetParentId")

            # Ensure AssetModules and AssetString are present
            if asset_enable and asset_string and asset_modules:
                for module in asset_modules:
                    if(module in existing_modules):
                        asset["LastRunDate"] = current_datetime
                    if module not in assets_per_module:
                        assets_per_module[module] = []
                    
                    
                    population_dict = dict({"asset_parent_id": asset_parent_id, "asset_string": asset_string})
                    assets_per_module[module].append(population_dict)

        
        logger.info("Assets per module:" + str(assets_per_module))
        return config_data, assets_per_module
    except Exception as e:
        logger.error("An error occurred: %s", str(e))
        return config_data, assets_per_module

def remove_file(file_path, logger):
    try:
        # Attempt to remove the specified file
        os.remove(file_path)
        # Log the success message
        logger.info(f"File '{file_path}' has been removed successfully.")
    except FileNotFoundError:
        # Handle the case where the file does not exist
        logger.warning(f"File '{file_path}' not found.")
    except PermissionError:
        # Handle the case where the file cannot be deleted due to insufficient permissions
        logger.error(f"Permission denied: Unable to delete '{file_path}'.")
    except Exception as e:
        # Handle any other exceptions that may occur and log the error message
        logger.error(f"Error: {e}")

def closest_memory_percentage(percentage):
    # Get the total physical memory in bytes
    total_memory_bytes = psutil.virtual_memory().total
    # Convert total memory to gigabytes
    total_memory_gb = total_memory_bytes / (1024 ** 3)
    
    # Calculate the memory corresponding to the given percentage
    memory_gb = (total_memory_gb * percentage) / 100
    
    # Calculate the lower and upper bounds
    lower_bound = math.floor(memory_gb)
    upper_bound = math.ceil(memory_gb)
    
    # Determine which bound is closer, always take upper if they are equal
    if (memory_gb - lower_bound) < (upper_bound - memory_gb):
        closest_gb = lower_bound
    else:
        closest_gb = upper_bound
    
    return str(closest_gb)


def closest_cpu_percentage(percentage):
    # Get the total number of CPU cores
    total_cpus = psutil.cpu_count()
    
    # Calculate the number of CPUs corresponding to the given percentage
    cpu_count = (total_cpus * percentage) / 100
    
    # Calculate the lower and upper bounds
    lower_bound = math.floor(cpu_count)
    upper_bound = math.ceil(cpu_count)
    
    # Determine which bound is closer, always take upper if they are equal
    if (cpu_count - lower_bound) < (upper_bound - cpu_count):
        closest_cpu = lower_bound
    else:
        closest_cpu = upper_bound
    
    return str(closest_cpu)

def run_subprocess(command, exit_word, logger):
    try:
        logger.info("Executing command: " + command)
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1, universal_newlines=True)
        
        # Use select to handle both stdout and stderr
        outputs = [process.stdout, process.stderr]
        while outputs:
            readable, _, _ = select.select(outputs, [], [])
            for output in readable:
                line = output.readline()
                if line:
                    if output == process.stdout:
                        logger.info(line.strip())
                    else:
                        logger.error(line.strip())
                    
                    if exit_word and exit_word in line:
                        logger.info(f"Exit word '{exit_word}' detected. Terminating process.")
                        process.terminate()
                        return
                else:
                    outputs.remove(output)
        
        # Wait for the process to complete
        process.wait()
        
        # Check the return code
        if process.returncode != 0:
            logger.error(f"Command failed with return code {process.returncode}")
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed with error:\n{e.stderr}")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {str(e)}")

def read_env_file(logger):
    env_dict = {}
    # Get the current working directory
    current_working_directory = os.getcwd()

    # Get the parent directory of the current working directory
    parent_directory = os.path.dirname(current_working_directory)

    # Construct the path to risx-mssp-back directory in the parent directory
    risx_mssp_back_path = os.path.join(parent_directory, 'risx-mssp-back')

    # Construct the path to the .env file inside risx-mssp-back
    env_file_path = os.path.join(risx_mssp_back_path, '.env')

    with open(env_file_path, 'r') as file:
        for line in file:
            # Remove leading and trailing whitespace
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue
            
            # Split the line into key and value
            key, value = line.split('=', 1)
            
            # Remove leading and trailing whitespace from key and value
            key = key.strip()
            value = value.strip()
            
            # Add to dictionary
            env_dict[key] = value
    
    # Check if env_dict is empty
    if not env_dict:
        logger.error("The .env file is empty or not found. Exiting.")
        quit()
    else:
        logger.info("Environment Variables:" +  str(env_dict))
        return env_dict

def return_value_if_key_exists(dict_object, key):
    if(key in dict_object):
        return dict_object[key]
    return ""

def create_module_dict(modules):
    enabled_modules = {}

    for module in modules:

        if module == "Velociraptor" or "Velociraptor" in module:
            # Skip processing for Velociraptor-related modules
            for subMod in  modules["Velociraptor"]["SubModules"]:
                 if modules["Velociraptor"]["SubModules"][subMod]["Enable"]:
                    enabled_modules["Velociraptor"] = True 
        else :
            if modules[module]["Enable"]:
                enabled_modules[module] = True 

        # Check if the module is enabled (for this example, we assume all modules in the list are enabled)
        # Add it to the dictionary with its value set to True
        # enabled_modules[module] = True

    return enabled_modules

def add_in_progress_rows(config_data, previous_config_date, logger):
    print("test")
    #current_datetime = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
    current_datetime = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')
    existing_modules = create_module_dict(config_data["Modules"])
    # existing_modules = create_module_dict(config_data["Modules"])

    config_data, assets_per_module = fill_assets_per_module(config_data, existing_modules, current_datetime, logger)
    #json.dump(config_data, open('test2.json', 'w'))
    velociraptor_submodules = config_data.get("Modules", {}).get("Velociraptor", {}).get("SubModules", {})
    print(assets_per_module)
    for submodule_name, submodule_data in velociraptor_submodules.items():
        # Ensure submodule_data is a dictionary and check if it's enabled
        #If We
        if isinstance(submodule_data, dict) and submodule_data.get("Enable", False):
            config_data["Modules"]["Velociraptor"]["SubModules"][submodule_name]["LastRunDate"] = current_datetime
            row = additionals.funcs.add_row("Velociraptor", submodule_name, str(submodule_data["ArtifactTimeOutInMinutes"]), submodule_data["TimeInterval"], submodule_data["Arguments"], previous_config_date, "", logger)
            config_data['RequestStatus'].append(row)
            

    if config_data.get("Modules", {}).get("TimeSketch", {}).get("Enable", False):
        timesketch_data = config_data["Modules"]["TimeSketch"]
        config_data["Modules"]["TimeSketch"]["LastRunDate"] = current_datetime
        #To fix when changing it
        #row = additionals.funcs.add_row("TimeSketch", "", str(config_data["Modules"]["TimeSketch"]["ArtifactTimeOutInMinutes"]), "", config_data["Modules"]["TimeSketch"]["Arguments"], previous_config_date, return_value_if_key_exists(assets_per_module, "TimeSketch"), logger)
        row = additionals.funcs.add_row("TimeSketch", "", str(config_data["Modules"]["TimeSketch"]["ExpireDate"]), "", config_data["Modules"]["TimeSketch"]["Arguments"], previous_config_date, return_value_if_key_exists(assets_per_module, "TimeSketch"), logger)
        config_data['RequestStatus'].append(row)
    else:
        logger.info("Timesketch is not enabled in config!")

    if(config_data["Modules"]["Nuclei"]["Enable"] == True):
        nuclei_data = config_data["Modules"]["Nuclei"]
        config_data["Modules"]["Nuclei"]["LastRunDate"] = current_datetime
        row = additionals.funcs.add_row( "Nuclei", "", "", "", nuclei_data["Arguments"], previous_config_date , return_value_if_key_exists(assets_per_module, "Nuclei"), logger)
        config_data['RequestStatus'].append(row)
    else:
        logger.info("Nuclei is not enable in config!")

    if(config_data["Modules"]["Shodan"]["Enable"] == True):
        shodan_data = config_data["Modules"]["Shodan"]
        config_data["Modules"]["Shodan"]["LastRunDate"] = current_datetime
        row = additionals.funcs.add_row( "Shodan", "", "", "", "", previous_config_date , return_value_if_key_exists(assets_per_module, "Shodan"), logger)
        config_data['RequestStatus'].append(row)
    else:
        logger.info("Shodan is not enable in config!")
    

    if(config_data["Modules"]["LeakCheck"]["Enable"] == True):
        leakcheck_data = config_data["Modules"]["LeakCheck"]
        config_data["Modules"]["LeakCheck"]["LastRunDate"] = current_datetime
        row = additionals.funcs.add_row("LeakCheck", "", "", "", "", previous_config_date , return_value_if_key_exists(assets_per_module, "LeakCheck"), logger)
        config_data['RequestStatus'].append(row)
    else:
        logger.info("LeakCheck is not enable in config!")
    return config_data

def connect_db_update_config(env_dict, previous_config_date, config_data, logger):
    connection = additionals.mysql_functions.setup_mysql_connection(env_dict,logger)
    additionals.funcs.update_json(connection, config_data, previous_config_date, False, logger)
    connection.close()