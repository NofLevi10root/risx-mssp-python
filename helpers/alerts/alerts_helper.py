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

    # This query get the table of active alerts
    #SELECT * FROM source(artifact="Generic.Client.Profile/RunningQueries") 