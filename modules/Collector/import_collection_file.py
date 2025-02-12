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
import asyncio
import shutil


# Wrapper for run_generic_vql
def run_generic_vql(query, logger):
    return modules.Velociraptor.VelociraptorScript.run_generic_vql_monitor(
        query, logger
    )


async def async_run_generic_vql(query, logger):
    return await asyncio.to_thread(run_generic_vql, query, logger)


def delete_directory(dir_path):
    if os.path.exists(dir_path):
        try:
            shutil.rmtree(dir_path)
            print(f"Directory '{dir_path}' has been deleted successfully.")
        except Exception as e:
            print(f"Error while deleting directory '{dir_path}': {e}")
    else:
        print(f"Directory '{dir_path}' does not exist.")


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


async def upload_collector_results(file_path, HostName, FileFolder, logger):
    logger.info("Uploading collector results to Velociraptor server.")
    try:
        artifacts_dict = {
            "Server.Utils.ImportCollection": {
                "ClientId": "auto",
                "Hostname": HostName,
                "Path": file_path,
            }
        }
        FlowIdOfUpload = modules.Velociraptor.VelociraptorScript.run_server_artifact(
            "Server.Utils.ImportCollection", logger, artifacts_dict
        )
        logger.info(
            "Collector results uploaded Started. FlowId: " + str(FlowIdOfUpload)
        )
        AlertQueryTime = f"""   
            SELECT * FROM watch_monitoring(artifact='System.Flow.Completion')
            WHERE FlowId = "{FlowIdOfUpload}"
            LIMIT 1
        """
        logger.info("Executing AlertQueryTime: " + AlertQueryTime)
        responseAlert = await async_run_generic_vql(AlertQueryTime, logger)

        logger.info(f"AlertQueryTime Response: {responseAlert}")
        if responseAlert:
            logger.info(f"Results Uploaded Successfully")
            logger.info(f"Start Delete of {FileFolder}")
            try:
                delete_directory(FileFolder)
                logger.info(f"Files Deleted Successfully")
            except Exception as e:
                logger.error(
                    f"Error Deleting collector Files From {FileFolder}: {str(e)}"
                )

        else:
            logger.info(f"Results Uploaded Wrong Error")
            try:
                delete_directory(FileFolder)
                logger.info(f"Files Deleted Successfully")
            except Exception as e:
                logger.error(
                    f"Error Deleting collector Files From {FileFolder}: {str(e)}"
                )
    except Exception as e:
        logger.error(f"Error uploading collector results: {str(e)}")
        traceback.print_exc()


if __name__ == "__main__":
    logger = additionals.funcs.setup_logger("CollectorImport.log")

    env_dict = additionals.funcs.read_env_file(logger)

    file_path = sys.argv[1]
    HostName = sys.argv[2]
    FileFolder = sys.argv[3]

    # Run asynchronous function
    asyncio.run(upload_collector_results(file_path, HostName, FileFolder, logger))
