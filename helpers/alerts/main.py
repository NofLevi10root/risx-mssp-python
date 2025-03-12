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
import helpers.alerts.arguments
import helpers.alerts.sql_operations

def get_list_of_artifacts_state(logger):
    # General:
    vql_query = f"""SELECT get_client_monitoring().artifacts.artifacts FROM scope()"""
    results = modules.Velociraptor.VelociraptorScript.run_generic_vql(vql_query, logger)

    active_artifacts = []
    
    # Convert list to dictionary format
    if results and "get_client_monitoring().artifacts.artifacts" in results[0]:
        all_artifacts_list = results[0]["get_client_monitoring().artifacts.artifacts"]
        all_active_artifacts = {"label": "All", 'artifacts': {artifact: {} for artifact in all_artifacts_list}}
    else:
        logger.info("There are no active monitor artifacts for all!")
        all_active_artifacts = {"label": "All", 'artifacts': {}}
    
    logger.info("List of artifacts that run for all: " + json.dumps(all_active_artifacts, indent=2))
    active_artifacts.append(all_active_artifacts)

    # Labeled:
    vql_query = f"""LET EventLabels <= get_client_monitoring().label_events SELECT label, artifacts.artifacts AS artifacts FROM EventLabels"""
    results = modules.Velociraptor.VelociraptorScript.run_generic_vql(vql_query, logger)
    
    labeled_artifacts = []
    
    # Check if results are not empty or null
    if results and not (len(results) == 1 and results[0]['label'] is None and results[0]['artifacts'] is None):
        for entry in results:
            label = entry["label"]
            artifacts_list = entry["artifacts"]
            
            # Convert list to dictionary
            labeled_artifacts.append({
                "label": label,
                "artifacts": {artifact: {} for artifact in artifacts_list} if artifacts_list else {}
            })
    
        logger.info("List of labeled artifacts: " + json.dumps(labeled_artifacts, indent=2))
        active_artifacts += labeled_artifacts
    else:
        logger.info("Labeled artifacts are empty!")
    
    logger.info("Total active artifacts: " + json.dumps(active_artifacts, indent=2))
    return active_artifacts

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

def update_full(logger):
    active_label_artifacts = get_list_of_artifacts_state(logger)
    clients_list = get_clients(logger)
    all_monitor = get_client_event_list(logger)
    # Create empty table
    df = pd.DataFrame(columns=['label', 'client_id_population', 'fqdn_population','config'])
    # Add all possible artifacts 
    new_row = {
        'label': "all_monitor",
        'client_id_population': "[]",  # Use empty JSON array instead of empty string
        'fqdn_population': "[]",       # Use empty JSON array instead of empty string
        'config': json.dumps(all_monitor)
    }
    df = pd.concat([df, pd.DataFrame([new_row])], ignore_index=True)
    logger.info("fking sht:" + str(active_label_artifacts))
    for entry in active_label_artifacts:  # Iterate over list of dictionaries
        label = entry.get("label")  # Extract label safely
        artifacts = entry.get("artifacts", [])  # Extract artifacts list safely
        
        new_row = {'label': label, 'client_id_population': [], 'fqdn_population': [], 'config': json.dumps(artifacts)}
        
        for client in clients_list:
            client_id = client.get("client_id")
            fqdn = client.get("os_info", {}).get("fqdn", "")
            
            if label == "All" or label in client.get("labels", []):
                new_row["client_id_population"].append(client_id)
                new_row["fqdn_population"].append(fqdn)
        
        # Always use json.dumps() to convert lists to JSON strings
        # For empty lists, this will produce "[]" which is valid JSON
        new_row["client_id_population"] = json.dumps(new_row["client_id_population"])
        new_row["fqdn_population"] = json.dumps(new_row["fqdn_population"])
        
        df = pd.concat([df, pd.DataFrame([new_row])], ignore_index=True)
    
    logger.info(f"Created DataFrame with {len(df)} client entries")
    logger.info("Getting environment dictionary!")
    env_dict = additionals.funcs.read_env_file(logger)
    
    logger.info("Connecting to MySQL!")
    connection = additionals.mysql_functions.setup_mysql_connection(env_dict, logger)
    
    logger.info("Pushing the DataFrame into the MySQL table!")
    helpers.alerts.sql_operations.push_dataframe_to_mysql(df, connection, "alert_client_config", logger)
    
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
    
def get_client_event_list(logger):
        # Construct the VQL query to remove the artifact from monitoring
    vql_query = f"""select name, parameters from artifact_definitions() where type = 'client_event'"""

    # Run the VQL query
    results = modules.Velociraptor.VelociraptorScript.run_generic_vql(vql_query, logger)
    logger.info("client event list:" + str(results))
    return results

def compare_labels(config_labels, active_labels, logger):
    # Convert active_labels to a dictionary for faster lookup
    active_labels_dict = {item["label"]: item["artifacts"] for item in active_labels}
    
    # Convert config_labels to a dictionary for faster lookup
    config_labels_dict = {item["label"]: item["artifacts"] for item in config_labels}

    # Loop over config_labels to check for missing artifacts in active_labels (ADD)
    for label, config_artifacts in config_labels_dict.items():
        if label in active_labels_dict:
            active_artifacts = active_labels_dict[label]
            
            for artifact, parameters in config_artifacts.items():  # Extract artifact + parameters
                if artifact not in active_artifacts:
                    add_monitor_artifact(artifact, parameters, logger)
                    print(f"ADD: Artifact '{artifact}' with parameters {parameters} should be added under label '{label}'")

    # Loop over active_labels to check for extra artifacts that need removal (REMOVE)
    for label, active_artifacts in active_labels_dict.items():
        if label in config_labels_dict:
            config_artifacts = config_labels_dict[label]
            
            for artifact in active_artifacts:
                if artifact not in config_artifacts:
                    remove_monitor_artifact(artifact, logger)
                    print(f"REMOVE: Artifact '{artifact}' should be removed from label '{label}'")


def modify_full(logger):
    # Get data
    logger.info("Getting states of monitoring artifacts!")
    active_label_artifacts = get_list_of_artifacts_state(logger)
    logger.info("Getting environment dictionary!")
    env_dict = additionals.funcs.read_env_file(logger)
    
    logger.info("Connecting to MySQL!")
    connection = additionals.mysql_functions.setup_mysql_connection(env_dict, logger)
    config_labels = helpers.alerts.sql_operations.load_data_from_mysql(connection, "alert_client_config", logger)
    logger.info("Active labels:" + str(active_label_artifacts))
    logger.info("Config labels:" + str(config_labels))
    compare_labels(config_labels, active_label_artifacts, logger)

if __name__ == "__main__":
    logger = additionals.funcs.setup_logger("alerts_helper.log")
    args = helpers.alerts.arguments.process_arguments()
    # Process the argument
    if args.modification:
        modify_full(logger)
    elif args.update:
        update_full(logger)
    