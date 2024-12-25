import ssl
import urllib3
import logging
import os
import json
import sys
import traceback
import time
import base64
from pyvelociraptor import api_pb2
from pyvelociraptor import api_pb2_grpc
import grpc
import yaml

# Set the script directory and parent directory
script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(script_dir, "../../"))
os.chdir(parent_dir)
print(parent_dir)
# Add parent directory to Python path
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

import additionals.mysql_functions
import additionals.funcs
import modules.Velociraptor.VelociraptorScript

# Disable SSL warnings globally
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Modify SSL context globally to allow unverified HTTPS connections
ssl._create_default_https_context = ssl._create_unverified_context



def upload_collector_results(file_path,HostName, logger):
    logger.info("Uploading collector results to Velociraptor server.")
    try:
        artifacts_dict = {"Server.Utils.ImportCollection":{
    'ClientId': 'auto',  # Use 'auto' to generate a new client ID
    'Hostname': HostName,  # Hostname for the new client
    'Path': file_path # Path to the offline collection ZIP file
}}
        modules.Velociraptor.VelociraptorScript.run_server_artifact("Server.Utils.ImportCollection", logger, artifacts_dict)
        logger.info("Collector results uploaded successfully.")
    except Exception as e:
        logger.error(f"Error uploading collector results: {str(e)}")
        traceback.print_exc()

if __name__ == "__main__":
    logger = additionals.funcs.setup_logger("CollectorImport.log")

    # Load environment configuration
    env_dict = additionals.funcs.read_env_file(logger)

    # Run the server artifact
    file_path = sys.argv[1]
    HostName= sys.argv[2]
    upload_collector_results(file_path,HostName, logger)


