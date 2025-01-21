import grpc
import json
from pyvelociraptor import api_pb2
from pyvelociraptor import api_pb2_grpc
import yaml
import pandas as pd
import time
from datetime import datetime, timedelta
import os
import additionals.funcs
import traceback
import random

import ssl
import urllib3
# Disable SSL warnings globally
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Modify SSL context globally to allow unverified HTTPS connections
ssl._create_default_https_context = ssl._create_unverified_context


def run_generic_vql(query, logger):
    try:
        logger.info("Run generic vql!")
        channel = setup_connection(logger)
        stub = api_pb2_grpc.APIStub(channel)
        logger.info("api_pb2_grpc.APIStub(channel)")

        # logger.info("Query: " + query)
        request = api_pb2.VQLCollectorArgs(
            max_wait=10,
            max_row=100,
            Query=[
                api_pb2.VQLRequest(
                    VQL=query,
                )
            ],
        )
        result = []

        for response in stub.Query(request):

            if response.Response:
                try:
                    # Try to parse the response as JSON

                    result =result+ json.loads(response.Response)

                except json.JSONDecodeError:
                    # If JSON parsing fails, store the response as a string
                    result = str(response.Response)

                # Print the result (you can remove this in production)
                # print(result)
        logger.info("run_generic_vql complete" )
        # logger.info("run_generic_vql complete result sssssssssssssssssssssssssssssssssssssssssssssssssssss:" + str(result) )


        return result
    except Exception as e:
        logger.error("THere is an Error in run_generic_vql Error : " + str(e))


def run_server_artifact(artifact_name, logger, parameters = ""):
    logger.info("Running server artifact query.")
    query = ""
    if parameters == "":
        query = f"LET collection <= collect_client(client_id='server', artifacts='{artifact_name}') SELECT * FROM collection"
    else:
        arguments = format_arguments_obj(parameters,logger)
        spec = f'dict({arguments})'
        query = f"SELECT collect_client(client_id='server', artifacts='{artifact_name}', spec={spec}) AS Flow FROM scope()"
        # #example that works query = f"""SELECT collect_client(client_id='server', artifacts='Server.Utils.CreateCollector', spec=dict(`Server.Utils.CreateCollector` = dict(artifacts=['Custom.Windows.DensityScout']))).request AS Flow FROM scope()"""
    try:
        channel = setup_connection(logger)
        stub = api_pb2_grpc.APIStub(channel)
        logger.info("Query:" + query)
        request = api_pb2.VQLCollectorArgs(
            max_wait=10,
            max_row=100,
            Query=[
                api_pb2.VQLRequest(
                    Name=artifact_name,
                    VQL=query,
                )
            ],
        )
        for response in stub.Query(request):
            if response.Response:
                logger.info("Response:" + response.Response)
                response = json.loads(str(response.Response))
                if(parameters != ""):
                    return response[0]["Flow"]["flow_id"]
                
            elif response.log:
                # Query execution logs are sent in their own messages.
                logger.info(
                    "%s: %s" % (time.ctime(response.timestamp / 1000000), response.log)
                )

        # logger.error("No response received from the server artifact run.")

    except Exception as e:
        logger.error(f"Failed to run server artifact.\nError Message: {str(e)}")
        logger.error(f"Traceback:\n{traceback.format_exc()}")

"""
def format_arguments(arguments):

    formatted_arguments = ", ".join(
        f"{key}= '{value}'" for key, value in arguments.items()
    )
    return formatted_arguments
"""

def format_arguments(arguments):
    formatted_arguments = ", ".join(
        f'{key}= "{value}"' for key, value in arguments.items()
    )
    return formatted_arguments

def format_arguments_Helper(arguments,logger):
    logger.info(arguments)
    formatted_arguments=""
    logger.info(str(arguments))
    for key, value in arguments.items():
        tmp=""
        logger.info("this is value"+str(type(value)))

        if isinstance(value, str) :
            logger.info("str type")
            tmp += f"`{key}` = '{value}'"
        elif isinstance(value, (int, float, complex)) and not isinstance(value, bool):
            logger.info("Number type")
            tmp += f"`{key}` = {value}"
        elif isinstance(value, list):
            logger.info("list type")
            tmp += f"`{key}` = {value}"
        elif isinstance(value, bool):
            logger.info("list type")
            tmp += f"`{key}` = {'true' if value else 'false' }"
        elif isinstance(value, dict):
            logger.info("dict type")
            
            tmp1 = format_arguments_Helper(value,logger)
            tmp += f"`{key}` = dict({tmp1})"
        else:
            logger.info("Unknown type")
            tmp="Unknown Type"
        if(formatted_arguments==""):
            formatted_arguments += tmp
        else:
            formatted_arguments += ", "+tmp 

    
    return formatted_arguments

def format_arguments_obj(arguments,logger):
    # Loop through keys and values
    formatted_arguments=""
    for key, value in arguments.items():
        if(isinstance(value, dict)):
            dictoman=format_arguments_Helper(value,logger)
            if(formatted_arguments==""):
                formatted_arguments += f"`{key}` = dict({dictoman})"
            else:
                formatted_arguments += ", "+f"`{key}` = dict({dictoman})"
        else:
            if(formatted_arguments==""):
                formatted_arguments += f"`{key}` = {value}"
            else:
                formatted_arguments += ", "+f"`{key}` = {value}"    
                
    return formatted_arguments

def get_clients(logger):
    channel = setup_connection(logger)
    stub = api_pb2_grpc.APIStub(channel)
    query = "SELECT * FROM clients()"
    # Perform the query
    logger.info("Sending get client request!")
    org_id = "OCHL0"
    json_data_string = server_query(channel, org_id, query, logger)
    if json_data_string:
        data = json.loads(json_data_string)
        host_client_id_dict = {
            entry["os_info"]["hostname"]: entry["client_id"] for entry in data
        }
        return host_client_id_dict
    else:
        logger.error("Failed to get clients.")
        return {}


def get_hunt_state(stub, client_id, flow_id):
    query = f"LET collection <= get_flow(client_id='{client_id}', flow_id='{flow_id}') SELECT * FROM collection"
    request = api_pb2.VQLCollectorArgs(
        Query=[api_pb2.VQLRequest(VQL=query)],
    )

    all_rows = []  # Initialize an empty list to accumulate all rows
    try:
        timeout_seconds = 10  # Timeout after 10 seconds
        for response in stub.Query(request, timeout=timeout_seconds):
            if response.Response:
                rows = json.loads(response.Response)

                if rows:
                    all_rows.extend(
                        rows
                    )  # Append the rows from this response to the list
    except grpc.RpcError as e:
        if e.code() == grpc.StatusCode.DEADLINE_EXCEEDED:
            print("The call timed out.")
        else:
            print(f"An RPC error occurred: {e}")

    # Extract the state from the response
    if all_rows:
        state = all_rows[0].get("state", "UNKNOWN")
        return state

    return "UNKNOWN"


def create_modules_macro_json(submodule_name, df, file_path, logger):
    file_name = "macro_" + file_path.split("_")[2] + "_" + file_path.split("_")[3]
    macro_output_filename = os.path.join("response_folder", file_name)
    macro_df = pd.DataFrame()
    logger.info("In create_modules_macro_json!")
    logger.info("Sub module name:" + submodule_name)
    logger.info("Macro file path:" + macro_output_filename)
    if submodule_name == "PersistenceSniper":
        x = 5
    elif submodule_name == "Hayabusa":
        x = 5
    elif submodule_name == "HardeningKitty":
        logger.info("Create kitty macro data!")
        failed_df = df[df["TestResult"] == "Failed"]
        # print(df)
        failed_count = failed_df.shape[0]
        severity_counts = (
            failed_df["SeverityFinding"]
            .value_counts()
            .reindex(["Low", "Medium", "High", "Critical"], fill_value=0)
        )
        fqdns_high_unique = (
            failed_df[failed_df["SeverityFinding"] == "High"]["Fqdn"].unique().tolist()
        )
        fqdns_low_unique = (
            failed_df[failed_df["SeverityFinding"] == "Critical"]["Fqdn"]
            .unique()
            .tolist()
        )

        new_structure = {
            "Failed Test/Number of tests": [str(failed_count) + "/" + str(df.shape[0])],
            "Count of Low": [severity_counts["Low"]],
            "Count of Medium": [severity_counts["Medium"]],
            "Count of High": [severity_counts["High"]],
            "Count of Critical": [severity_counts["Critical"]],
            "List of computers with High": [fqdns_high_unique],
            "List of computers with Critical": [fqdns_low_unique],
        }
        macro_df = pd.DataFrame(new_structure)

    if macro_df.empty:
        macro_df["table"] = "No data found!"

    else:
        seralize_macro_df = macro_df.to_json(orient="records", lines=False, indent=4)
        macro_df["table"] = seralize_macro_df
        # macro_df.to_csv("macro.csv", index=False)
        with open(macro_output_filename, "w") as file:
            file.write(seralize_macro_df)


def run_hunt(query, connection, stub, logger):
    try:
        logger.info("Query:" + query)
        # Use artifact
        hunt_id = ""
        request = api_pb2.VQLCollectorArgs(Query=[api_pb2.VQLRequest(VQL=query)])
        for response in stub.Query(request):
            if response.Response:
                if response.Response != "[]":
                    logger.info("Response:" + response.Response)
                    # Parse the string as JSON
                    parsed_json = json.loads(response.Response)
                    # Extract the "HuntId" value
                    hunt_id = parsed_json[0]["HuntId"]

            elif response.log:
                # Query execution logs are sent in their own messages.
                logger.info("Warning:" + response.log)
        return hunt_id, "Hunting", ""

    except Exception as e:
        traceback_msg = traceback.format_exc()
        return "", "Failed", traceback_msg


def run_artifact(row, logger):
    artifact_dict = {
        "PersistenceSniper": "Exchange.Windows.Forensics.PersistenceSniper",
        "HardeningKitty": "Exchange.Windows.HardeningKitty",
        "Hayabusa": "Windows.Hayabusa.Rules",
        "BestPractice": "BestPractice",
    }

    hunt_id = "null"
    try:
        print("Row:" + str(row))
        # print("arguments:" + str(data))

        artifact_name = artifact_dict[row["SubModuleName"]]

        # org_id = data["organization_id"]
        org_id = "OCHL0"

        expire_time = additionals.funcs.calculate_seconds_difference(
            row["StartDate"], row["ArtifactTimeOutInMinutes"]
        )
        # print("Row:" + str(row))
        resource_limit = row["Arguments"]["ArtifactResourceLimit"]
        # print("Arguments:" + arguments)
        # good query
        cpu_limit = resource_limit.get(
            "CPULimitPercent", 10
        )  # Default to 10% if not provided
        max_execution_time = resource_limit.get(
            "MaxExecutionTimeInSeconds", 3600
        )  # Default to 3600s if not provided
        max_bytes_uploaded = resource_limit.get(
            "MaxBytesUploaded", 100000000
        )  # Default to 10000 bytes if not provided
        max_rows = 1000000
        if artifact_name == "BestPractice":
            # Split the string at the last underscore
            response_path = row["ResponsePath"]
            prefix, postfix_with_json = response_path.rsplit("_", 1)

            # Ensure the postfix retains the .json extension
            postfix = postfix_with_json.rsplit(".", 1)[0]
            best_practice_modules = []
            for module in row["Arguments"]["Modules"]:
                new_row = {}
                # arguments = format_arguments()
                spec = f"dict(`{module}`=dict())"
                print("BestPractice module:" + module)
                #query = f"LET collection = hunt(description='API Hunt:{module}',artifacts='{module}', spec={spec}, expires=now() + {expire_time}) SELECT HuntId FROM collection"
                query = f"LET collection = hunt(description='API Hunt:{module}', artifacts='{module}', spec={spec}, expires=now() + {expire_time}, timeout={max_execution_time}, max_rows={max_rows}, max_bytes={max_bytes_uploaded}, cpu_limit={cpu_limit}) SELECT HuntId FROM collection"
                channel = setup_connection(logger)
                stub = api_pb2_grpc.APIStub(channel)
                new_row["SubModuleName"] = module
                new_row["UniqueID"], new_row["Status"], new_row["Error"] = run_hunt(
                    query, channel, stub, logger
                )
                new_row["ResponsePath"] = (
                    prefix + module.replace(".", "") + "_" + postfix + ".json"
                )
                best_practice_modules.append(new_row)
            row["ExpireDate"] = row["ArtifactTimeOutInMinutes"]
            row["Arguments"]["Modules"] = best_practice_modules
            row["Status"] = "Hunting"
            row["UniqueID"] = str(random.randint(9000000, 99999999))
            row["Error"] = ""
        else:
            row["ExpireDate"] = row["ArtifactTimeOutInMinutes"]
            arguments = format_arguments(row["Arguments"]["ArtifactParameters"])
            spec = f"dict(`{artifact_name}`=dict({arguments}))"

            query = f"LET collection = hunt(description='API Hunt:{artifact_name}', artifacts='{artifact_name}', spec={spec}, expires=now() + {expire_time}, timeout={max_execution_time}, max_rows={max_rows}, max_bytes={max_bytes_uploaded}, cpu_limit={cpu_limit}) SELECT HuntId FROM collection"

            channel = setup_connection(logger)
            stub = api_pb2_grpc.APIStub(channel)
            row["UniqueID"], row["Status"], row["Error"] = run_hunt(
                query, channel, stub, logger
            )

        channel.close()
        return row

    except Exception as e:
        traceback_msg = traceback.format_exc()
        row["Status"] = "Failed"
        row["Error"] = traceback_msg
        row["UniqueID"] = hunt_id
        row["ExpireDate"] = row["ArtifactTimeOutInMinutes"]
        return row


# def collect_hunt_data(hunt_id, org_id, logger, output_dict, data, file_path):
def collect_hunt_data(row, logger):
    output_dict = {}
    hunt_id = row["UniqueID"]
    org_id = "OCHL0"
    hunt_id = hunt_id
    channel = setup_connection(logger)
    stub = api_pb2_grpc.APIStub(channel)

    logger.info(f"Collecting hunt: {hunt_id}")
    query = f"SELECT * FROM hunt_results(hunt_id='{hunt_id}')"

    logger.info("Request for data collection!")
    """
    request = api_pb2.VQLCollectorArgs(
        org_id=org_id,
        Query=[api_pb2.VQLRequest(VQL=query)],
    )
    """
    request = api_pb2.VQLCollectorArgs(
        Query=[api_pb2.VQLRequest(VQL=query)],
    )
    all_rows = []  # Initialize an empty list to accumulate all rows
    logger.info("Collecting hunt data!")
    try:
        timeout_seconds = 10  # Timeout after 10 seconds
        for response in stub.Query(request, timeout=timeout_seconds):
            if response.Response:
                # print("Response:" + str(response.Response))g
                rows = json.loads(response.Response)
                if rows:
                    all_rows.extend(
                        rows
                    )  # Append the rows from this response to the list
                    # print("rows:" + str(all_rows))
    except grpc.RpcError as e:
        if e.code() == grpc.StatusCode.DEADLINE_EXCEEDED:
            logger.error("The call timed out.")
        else:
            logger.error(f"An RPC error occurred: {e}")

    # Convert list of rows to a DataFrame
    if all_rows:
        module_df = pd.DataFrame(all_rows)

        logger.info("Hunt data collected successfully into DataFrame.")
        output_dict["status"] = "Complete"
        output_dict["table"] = module_df
        output_dict["error"] = ""
        output_dict["huntid"] = hunt_id
    else:
        logger.info("No data collected.")
        output_dict["status"] = "Complete"
        output_dict["error"] = "No data collected."
        output_dict["table"] = ""
        output_dict["huntid"] = hunt_id
    channel.close()
    return output_dict


def remove_all_hunts(org_id, logger):
    """
    Removes all hunts from the Velociraptor server.

    Args:
    - channel: The gRPC channel connected to the Velociraptor server.
    - org_id: The organization ID for scoping the hunt removal.
    - logger: A logging object for logging messages.
    """
    channel = setup_connection(logger)
    stub = api_pb2_grpc.APIStub(channel)

    # Step 1: List all hunts
    list_hunts_query = "SELECT * FROM hunts()"
    """
    list_hunts_request = api_pb2.VQLCollectorArgs(
        org_id=org_id,
        Query=[api_pb2.VQLRequest(VQL=list_hunts_query)],
    )
    """
    list_hunts_request = api_pb2.VQLCollectorArgs(
        Query=[api_pb2.VQLRequest(VQL=list_hunts_query)],
    )
    try:
        hunt_ids = []
        for response in stub.Query(list_hunts_request):
            if response.Response:
                # print(response.Response)
                hunts = json.loads(response.Response)
                hunt_ids.extend([hunt["hunt_id"] for hunt in hunts])

        # Step 2: Delete each hunt
        for hunt_id in hunt_ids:
            delete_hunt_query = (
                f"select * from hunt_delete(hunt_id='{hunt_id}', really_do_it= 'Y')"
            )
            delete_hunt_request = api_pb2.VQLCollectorArgs(
                Query=[api_pb2.VQLRequest(VQL=delete_hunt_query)],
            )
            stub.Query(
                delete_hunt_request
            )  # Assuming this deletes the hunt; adjust based on actual API
            logger.info(f"Deleted hunt {hunt_id}")
        """
        for hunt_id in hunt_ids:
            delete_hunt_query = f"select * from hunt_delete(hunt_id='{hunt_id}', really_do_it= 'Y')"
            delete_hunt_request = api_pb2.VQLCollectorArgs(
                org_id=org_id,
                Query=[api_pb2.VQLRequest(VQL=delete_hunt_query)],
            )
            stub.Query(delete_hunt_request)  # Assuming this deletes the hunt; adjust based on actual API
            logger.info(f"Deleted hunt {hunt_id}")
        """
    except grpc.RpcError as e:
        logger.error(f"An error occurred while removing hunts: {e}")
    channel.close()


def server_query(channel, org_id, query, logger):
    stub = api_pb2_grpc.APIStub(channel)
    """
    request = api_pb2.VQLCollectorArgs(
        org_id=org_id,
        Query=[api_pb2.VQLRequest(VQL=query)],
    )
    """
    request = api_pb2.VQLCollectorArgs(
        Query=[api_pb2.VQLRequest(VQL=query)],
    )
    all_rows = []  # Initialize an empty list to accumulate all rows
    logger.info("Getting responses!")
    try:
        timeout_seconds = 10  # Timeout after 10 seconds
        for response in stub.Query(request, timeout=timeout_seconds):
            if response.Response:
                rows = json.loads(response.Response)
                if rows:
                    all_rows.extend(
                        rows
                    )  # Append the rows from this response to the list
    except grpc.RpcError as e:
        if e.code() == grpc.StatusCode.DEADLINE_EXCEEDED:
            print("The call timed out.")
        else:
            print(f"An RPC error occurred: {e}")

    # Convert list of rows to a DataFrame
    if all_rows:
        df = pd.DataFrame(all_rows)
        # df.to_csv(new_filename)
        seralize_df = df.to_json(orient="records", lines=False, indent=4)
        # print(seralize_df)
        return seralize_df
    else:
        x = 5


def get_macro_data(channel, org_id, logger, file_path):
    # Define your query
    data_output_filename = file_path.replace("request", "response", 1)
    output_dict = {}

    # Clients count
    query = "SELECT * FROM clients()"
    # Perform the query
    logger.info("sending get client request!")
    json_data_string = server_query(channel, org_id, query, logger)
    # Parse the JSON data
    data = json.loads(json_data_string)
    # Use a set comprehension to collect unique client_ids
    unique_client_ids = {entry["client_id"] for entry in data}

    # Calculate the count of unique client_ids
    output_dict["Number of velociraptor clients"] = str(len(unique_client_ids))

    ###
    # Get last hunt date
    ###
    query = "SELECT create_time FROM hunts()"
    # Perform the query
    logger.info("Get last hunt date!")
    json_data_string = server_query(channel, org_id, query, logger)
    # Parse the JSON data
    data = json.loads(json_data_string)
    # Use a set comprehension to collect unique client_ids

    # Calculate the count of unique client_ids
    timestamp_seconds = data[0].get("create_time") / 1e6

    # Convert timestamp to datetime object
    dt = datetime.fromtimestamp(timestamp_seconds)

    # Format the datetime object to your desired format
    formatted_date_time = dt.strftime("%Y-%m-%d %H:%M:%S")
    output_dict["Last hunt date"] = formatted_date_time

    ###
    # Get_users
    ###
    query = "SELECT * FROM gui_users()"
    # Perform the query
    logger.info("Getting users!")
    json_data_string = server_query(channel, org_id, query, logger)
    # Parse the JSON data
    data = json.loads(json_data_string)
    # Use a set comprehension to collect unique client_ids
    usernames = {entry["name"] for entry in data}

    # Calculate the count of unique client_ids
    output_dict["Number of velociraptor users"] = str(len(usernames))

    # number of modules
    output_dict["Number of active velociraptor artifacts"] = "4"

    seralize_output = json.dumps(output_dict, indent=4)
    with open(data_output_filename, "w") as file:
        file.write(seralize_output)


def setup_connection(logger):
    logger.info("Setup connection!")
    # Load the YAML configuration
    config_path = os.path.join(
        "modules", "Velociraptor", "dependencies", "api.config.yaml"
    )
    config = ""
    try:
        with open(config_path, "r") as f:
            logger.info("Reading config yaml!")
            config = yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Failed to load configuration: {str(e)}")
        return

    # Prepare the credentials for the gRPC connection
    creds = grpc.ssl_channel_credentials(
        root_certificates=config["ca_certificate"].encode("utf8"),
        private_key=config["client_private_key"].encode("utf8"),
        certificate_chain=config["client_cert"].encode("utf8"),
    )
    options = (
        (
            "grpc.ssl_target_name_override",
            "VelociraptorServer",
        ),
    )

    # Establish the secure channel
    try:
        channel = grpc.secure_channel(config["api_connection_string"], creds, options)
        logger.info("Secure channel established")
        return channel
        # Perform operations with the channel here
        # For example, making RPC calls

    except grpc.RpcError as e:
        logger.error(f"An RPC error occurred: {e.code()} - {e.details()}")
