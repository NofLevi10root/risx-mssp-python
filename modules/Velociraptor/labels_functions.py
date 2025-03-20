print("hello")
import os
import sys

# Get the absolute path of this script
script_path = os.path.abspath(__file__)
script_dir = os.path.dirname(script_path)
main_dir = os.path.abspath(os.path.join(script_dir, "../.."))
os.chdir(main_dir)
sys.path.insert(0, main_dir)
print(f"Current Working Directory: {os.getcwd()}")
import json
import traceback
import additionals.logger
import additionals.mysql_functions
import additionals.funcs
import modules.Velociraptor.VelociraptorScript

def generate_label_vql(client_id, operation, label_list=None, logger=None):
    """
    Generate VQL for label operations in Velociraptor.
    
    Args:
        client_id (str): The client ID to perform the operation on.
        operation (str): The operation to perform ('set', 'remove', or 'check').
        label_list (list, optional): List of labels to use. Defaults to ["important", "investigation"].
        logger (logging.Logger, optional): Logger object for logging messages.
    
    Returns:
        str: The VQL query string.
    """
    
    # Validate operation type
    valid_operations = ["set", "remove"]
    if operation not in valid_operations:
        error_msg = f"Invalid operation: {operation}. Must be one of {valid_operations}"
        logger.error(error_msg)
        raise ValueError(error_msg)
    
    logger.info("Operation: " + operation)
    
    # Format the labels as a string representation of a list
    labels_str = str(label_list).replace("'", '"')
    
    # Construct the VQL query
    vql_query = f"""SELECT label(client_id="{client_id}", 
             labels={labels_str}, 
             op="{operation}")
FROM scope()"""
    
    if logger:
        logger.info(f"Generated VQL for client {client_id}, operation: {operation}, labels: {label_list}")
        logger.debug(f"VQL query: {vql_query}")
    
    results = modules.Velociraptor.VelociraptorScript.run_generic_vql(vql_query, logger, False)
    
    if logger:
        logger.info("Add/Remove results: " + str(results))
    
    return results

def create_client_labels_dict(logger):
    vql_query = "SELECT client_id, labels FROM clients() WHERE labels"
    results = modules.Velociraptor.VelociraptorScript.run_generic_vql(vql_query, logger, False)
    
    if logger:
        logger.info("Create client label dict results: " + str(results))
    
    return results

def main():
    try:
        logger = additionals.funcs.setup_logger("velociraptor_labels.log")
        logger.info("Start alerts loop!")
        
        env_dict = additionals.funcs.read_env_file(logger)
        connection = additionals.mysql_functions.setup_mysql_connection(env_dict, logger)
        
        logger.info("Loading config file!")
        config_data = json.loads(
            (
                additionals.mysql_functions.execute_query(
                    connection, "SELECT config FROM configjson LIMIT 1", logger
                )
            )[0][0]
        )
        
        # Get all client labels
        logger.info("Getting client labels dict:")
        client_labels = create_client_labels_dict(logger)
        
        # Example of add
        logger.info("Adding alef,bet,gimel")
        operation = "set"
        label_list = ["alef", "bet", "gimel"]
        client_id = "C.85a03126e228c944"
        logger.info("Adding labels")
        result = generate_label_vql(client_id, operation, label_list, logger)
        
        # example of remove
        logger.info("Removing alef gimel:")
        operation = "remove"
        label_list = ["alef","gimel"]
        client_id = "C.85a03126e228c944"
        result = generate_label_vql(client_id, operation, label_list, logger)
        logger.info("Script completed successfully")
        return result
        
    except Exception as e:
        if logger:
            logger.error(f"Error in main: {str(e)}")
            logger.error(traceback.format_exc())
        else:
            print(f"Error: {str(e)}")
            print(traceback.format_exc())
        return None

if __name__ == "__main__":
    main()