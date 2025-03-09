#!/usr/bin/env python3
import os
import sys

# Get the absolute path of this script
script_path = os.path.abspath(__file__)
script_dir = os.path.dirname(script_path)
main_dir = os.path.abspath(os.path.join(script_dir, "../.."))
os.chdir(main_dir)
sys.path.insert(0, main_dir)
print(f"Current Working Directory: {os.getcwd()}")

import additionals.logger
import modules.Velociraptor.VelociraptorScript
import pandas as pd
import json
import additionals.mysql_functions

def get_list_of_artifacts_state(logger):
    # if 1 of the list is empty return empty list else return the object
    # the all active artifacts 
    # General:
    vql_query = f"""SELECT get_client_monitoring().artifacts.artifacts FROM scope()"""
    results = modules.Velociraptor.VelociraptorScript.run_generic_vql(vql_query, logger)
    
    all_active_artifacts = results[0]["get_client_monitoring().artifacts.artifacts"]
    if(all_active_artifacts == None):
        logger.info("There are no active monitor artifacts for all!")
        all_active_artifacts = []
    else:
        logger.info("List of artifacts that run for all:" + str(all_active_artifacts))

    # Labeled:
    vql_query = f"""LET EventLabels <= get_client_monitoring().label_events SELECT label, artifacts.artifacts AS artifacts FROM EventLabels"""
    results = modules.Velociraptor.VelociraptorScript.run_generic_vql(vql_query, logger)
    labeled_artifacts = []
    # Check if it matches the empty pattern: [{'label': None, 'artifacts': None}]
    if not (len(results) == 1 and results[0]['label'] is None and results[0]['artifacts'] is None):
        labeled_artifacts = results
        logger.info("List of labeled artifacts:" + str(labeled_artifacts))
    else:
        logger.info("Labeled artifacts are empty!")
    return all_active_artifacts, labeled_artifacts

def remove_monitor_artifact(artifact_name, logger):
    """
    Remove a monitoring artifact from Velociraptor

    Args:
        artifact_name (str): The name of the artifact to remove from monitoring
        logger (Logger, optional): Logger object. If None, a new logger will be created
    
    Returns:
        None
    """

    # Construct the VQL query to remove the artifact from monitoring
    vql_query = f"""
LET artifact_name = "{artifact_name}"

SELECT rm_client_monitoring(
    artifact=artifact_name
) FROM scope()
"""
    
    # Run the VQL query
    logger.info(f"Removing monitoring for artifact: {artifact_name}")
    modules.Velociraptor.VelociraptorScript.run_generic_vql(vql_query, logger)
    logger.info(f"Successfully removed monitoring for artifact: {artifact_name}")

def get_clients(logger):
    # Construct the VQL query to remove the artifact from monitoring
    vql_query = f"""SELECT * FROM clients()"""

    # Run the VQL query
    logger.info(f"Removing monitoring for artifact: {artifact_name}")
    results = modules.Velociraptor.VelociraptorScript.run_generic_vql(vql_query, logger)

    columns_to_drop = [
        'agent_information', 
        'first_seen_at',  # Note: appears as 'first_seen_at' in your data
        'last_seen_at',   # Note: appears as 'last_seen_at' in your data
        'last_ip', 
        'last_interrogate_flow_id', 
        'last_interrogate_artifact_name', 
        'last_hunt_timestamp', 
        'last_event_table_version', 
        'last_label_timestamp'
    ]

    # Create a new list with only the columns you want to keep
    clients = [{k: v for k, v in client.items() if k not in columns_to_drop} 
                    for client in results]
    logger.info(f"All Clients results: {clients}")
    return clients
def add_monitor_artifact(artifact_name, parameters, logger=None):
    """
    Add a monitoring artifact to Velociraptor
    
    Args:
        artifact_name (str): The name of the artifact to monitor
        parameters (dict): Dictionary containing parameters for the artifact
        logger (Logger, optional): Logger object. If None, a new logger will be created
    
    Returns:
        None
    """
    # Set up logger if not provided
    if logger is None:
        logger = additionals.funcs.setup_logger("alerts_helper.log")
    
    # Ensure proper escaping for VQL
    escaped_parameters = {}
    for key, value in parameters.items():
        if isinstance(value, str) and "\\" in value:
            escaped_parameters[key] = value.replace("\\", "\\\\")
        else:
            escaped_parameters[key] = value
    
    # Construct parameters string for VQL
    params_list = []
    for key, value in escaped_parameters.items():
        if isinstance(value, str):
            params_list.append(f'{key}="{value}"')
        else:
            params_list.append(f'{key}={value}')
    
    params_str = ",\n    ".join(params_list)
    
    # Construct the VQL query
    vql_query = f"""
LET artifact_name = "{artifact_name}"
LET parameters = dict(
    {params_str}
)

SELECT add_client_monitoring(
    artifact=artifact_name,
    parameters=parameters
) FROM scope()
"""
    logger.info("VQL Query:" + str(vql_query))
    # Run the VQL query
    logger.info(f"Adding monitoring for artifact: {artifact_name}")
    modules.Velociraptor.VelociraptorScript.run_generic_vql(vql_query, logger)
    logger.info(f"Successfully added monitoring for artifact: {artifact_name}")

def artifacts_per_client_full(logger):
    all_artifacts, labeled_artifacts = get_list_of_artifacts_state(logger)
    clients_list = get_clients(logger)
    
    # Create empty table
    df = pd.DataFrame(columns=['clientid', 'config', 'fqdn'])
    
    for client in clients_list:
        # Set client info
        client_id = client["client_id"]
        fqdn = client["os_info"]["fqdn"]
        labels = client["labels"]

        # Set config
        config_json = {}
        config_json["All"] = all_artifacts
        
        # Add artifacts for each label the client has
        for label_item in labeled_artifacts:
            label = label_item.get("label")
            if label in labels:
                config_json[label] = label_item.get("artifacts", [])
        
        # Serialize config to JSON string for MySQL
        config_json_str = json.dumps(config_json)
        
        # Create a new row and add it to the DataFrame
        new_row = {
            'clientid': client_id,
            'config': config_json_str,  # Serialized JSON string
            'fqdn': fqdn
        }
        
        # Add the row to DataFrame
        df = pd.concat([df, pd.DataFrame([new_row])], ignore_index=True)
    logger.info(f"Created DataFrame with {len(df)} client entries")
    logger.info("Getting enviorment dictionary!")
    env_dict = additionals.funcs.read_env_file(logger)
    logger.info("Connecting mysql!")
    connection = additionals.mysql_functions.setup_mysql_connection(env_dict, logger)
    logger.info("Pushing the dataframe into the mysql table!")
    push_dataframe_to_mysql(df, connection, "alert_client_config", logger)
    logger.info("Completed process!")

def push_dataframe_to_mysql(df, connection, table_name, logger):

    try:
        cursor = connection.cursor()
        
        # Truncate the table first
        logger.info(f"Truncating table {table_name}")
        cursor.execute(f"TRUNCATE TABLE {table_name}")
        connection.commit()
        
        # Convert all DataFrame rows to tuples at once
        data_tuples = [tuple(row) for row in df.values]
        
        # Prepare the SQL query for insertion
        placeholders = ', '.join(['%s'] * len(df.columns))
        columns = ', '.join(df.columns)
        insert_query = f"INSERT INTO {table_name} ({columns}) VALUES ({placeholders})"
        
        # Execute the query for all rows at once
        logger.info(f"Inserting {len(data_tuples)} rows into {table_name}")
        cursor.executemany(insert_query, data_tuples)
        connection.commit()
        
        logger.info(f"Successfully inserted {cursor.rowcount} rows into {table_name}")
        cursor.close()
        return True
        
    except Exception as e:
        logger.error(f"Error inserting data into MySQL: {str(e)}")
        if connection.is_connected():
            connection.rollback()
            cursor.close()
        return False
    
if __name__ == "__main__":
    logger = additionals.funcs.setup_logger("alerts_helper.log")
    
    # Example usage
    #artifact_name = "Generic.Client.Stats"
    artifact_name = "Custom.Windows.Detection.Usn.malwareTest"
    
    parameters = {
        "PathRegex": r"(?i).*(powershell|pwsh).*\\.pf$",  # Regex pattern
        "Device": r"C:\\"  # Use raw string for correct escaping
    }
    
    parameters = {}
    #Working [Adding monitor artifact]
    #add_monitor_artifact(artifact_name, parameters, logger)
    # In test
    #remove_monitor_artifact(artifact_name, logger)
    artifacts_per_client_full(logger)