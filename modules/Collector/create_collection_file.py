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
import zipfile
import subprocess
import time

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


def connect_my_sql(env_dict, logger):
    connection = additionals.mysql_functions.setup_mysql_connection(env_dict, logger)
    tmpId = "Empty"
    config_data = json.loads(
        additionals.mysql_functions.execute_query(
            connection,
            f"SELECT config FROM on_premise_velociraptor where config_id = '{sys.argv[1] or tmpId}'",
            logger,
        )[0][0]
    )
    return config_data


def create_zip(files_to_zip, zip_file_path, logger):
    """
    Creates a zip file containing the specified files, placing all files in the root of the zip.

    Args:
        files_to_zip (list): List of file paths to include in the zip file.
        zip_file_path (str): The destination path for the zip file.
        logger (logging.Logger): Logger instance to log progress and errors.

    Returns:
        None
    """
    try:
        with zipfile.ZipFile(zip_file_path, "w") as zipf:
            for file_path in files_to_zip:
                logger.info(
                    f"Check file to zip: {file_path} " + str(os.path.exists(file_path))
                )
                if os.path.exists(file_path):
                    logger.info(f"Start file to zip: {file_path}")
                    # Extract the filename from the path and use it as the archive name
                    archive_name = os.path.basename(file_path)
                    zipf.write(file_path, archive_name)
                    logger.info(f"Added file to zip: {archive_name}")
                else:
                    logger.info(f" file Not Exist: {file_path}")
    except Exception as e:
        logger.error(
            f"Error while creating zip file: {str(e)}"
        )  # Changed to logger.error for better error visibility


def run_server_artifact(logger, config_data):
    logger.info("Running server artifact query. " + str(config_data))
    try:
        artifacts_dict = {"Server.Utils.CreateCollector": {"opt_format": "csv"}}
        artifactsListArr = ["Generic.Client.Info"]
        artifactsParmObj = {}
        for obj in config_data["Artifacts"]:
            artifactsParmObj[obj["name"]] = obj["parameters"]
            artifactsListArr.append(obj["name"])

        artifacts_dict["Server.Utils.CreateCollector"]["OS"] = "Generic"
        artifacts_dict["Server.Utils.CreateCollector"]["opt_collector_filename"] = (
            config_data["Configuration"]["CollectorFileName"]
        )
        artifacts_dict["Server.Utils.CreateCollector"]["opt_filename_template"] = (
            config_data["Configuration"]["OutputsFileName"]
            + "-r___r-%FQDN%-%TIMESTAMP%"
        )
        artifacts_dict["Server.Utils.CreateCollector"]["artifacts"] = artifactsListArr
        artifacts_dict["Server.Utils.CreateCollector"]["parameters"] = artifactsParmObj
        artifacts_dict["Server.Utils.CreateCollector"]["opt_cpu_limit"] = config_data[
            "Resources"
        ]["CpuLimit"]
        artifacts_dict["Server.Utils.CreateCollector"]["opt_progress_timeout"] = (
            config_data["Resources"]["MaxIdleTimeInSeconds"]
        )
        artifacts_dict["Server.Utils.CreateCollector"]["opt_timeout"] = config_data[
            "Resources"
        ]["MaxExecutionTimeInSeconds"]

        FlowId = modules.Velociraptor.VelociraptorScript.run_server_artifact(
            "Server.Utils.CreateCollector", logger, artifacts_dict
        )

        OsCollector = ""
        OsCollectorPath = ""
        BatchFile = ""
        shell_script_content = ""
        collectorPath = f'~/setup_platform/workdir/velociraptor/velociraptor/clients/server/collections/{FlowId}/uploads/scope/{config_data["Configuration"]["CollectorFileName"]}'
        collectorPath = os.path.abspath(os.path.expanduser(collectorPath))
        TestPathVelo = "~/mssp/risx-mssp-python-script/Collector"
        TestPathVelo = os.path.abspath(os.path.expanduser(TestPathVelo))

        match sys.argv[2]:

            case "Windows":
                OsCollector = "velociraptor_client.exe"
                OsCollectorPath = "~/setup_platform/workdir/velociraptor/velociraptor/clients/windows/velociraptor_client.exe"
                BatchFile = (
                    f'Collector/{config_data["Configuration"]["CollectorFileName"]}.bat'
                )
                shell_script_content = f"""
                
                @echo off

                :: Define the folder where the files are generated
                set "folderPath=%cd%"

                :: Run Velociraptor command to generate the files
                {OsCollector} -- --embedded_config {config_data["Configuration"]["CollectorFileName"]}
                :: Find the most recent file matching the pattern
                for /f "delims=" %%F in ('dir /b /od "%folderPath%\{config_data["Configuration"]["CollectorFileName"]}-r___r-*"') do set "latestFile=%%F"

                :: Validate that a file was found
                if not defined latestFile (
                    echo No file matching the pattern "{config_data["Configuration"]["CollectorFileName"]}-r___r-*" was found.
                    exit /b 1
                )

                :: Log the file being processed
                echo Most recent file: %latestFile%

                :: Run the PowerShell script on the most recent file
                powershell -NoProfile -Command "&  ".\PowerShellSplit.ps1 -filePath '%folderPath%\%latestFile%' -outputFolder '%folderPath%' -chunkSizeMB 250" "

                :: Exit the batch script
                exit /b

                """
            case "Mac":
                OsCollector = "velociraptor_client"
                OsCollectorPath = "~/setup_platform/workdir/velociraptor/velociraptor/clients/mac/velociraptor_client"
                BatchFile = (
                    f'Collector/{config_data["Configuration"]["CollectorFileName"]}.sh'
                )
                shell_script_content = f"""#!/bin/sh
                folderPath=$(pwd)
                {OsCollector} -- --embedded_config {config_data["Configuration"]["CollectorFileName"]}
                # Find the most recent file matching the pattern
                latestFile=$(ls -t "$folderPath"/{config_data["Configuration"]["CollectorFileName"]}-r___r-* 2>/dev/null | head -n 1)

                # Validate that a file was found
                if [ -z "$latestFile" ]; then
                    echo "No file matching the pattern '{config_data["Configuration"]["CollectorFileName"]}-r___r-*' was found."
                    exit 1
                fi

                # Log the file being processed
                echo "Most recent file: $latestFile"

                # Run another shell script on the most recent file
                ./split_and_hash.sh "$latestFile" 250M
                """
            case "Linux":
                OsCollector = "velociraptor_client"
                OsCollectorPath = "~/setup_platform/workdir/velociraptor/velociraptor/clients/linux/velociraptor_client"
                BatchFile = (
                    f'Collector/{config_data["Configuration"]["CollectorFileName"]}.sh'
                )
                shell_script_content = f"""#!/bin/sh
                folderPath=$(pwd)
                {OsCollector} -- --embedded_config {config_data["Configuration"]["CollectorFileName"]}
                # Find the most recent file matching the pattern
                latestFile=$(ls -t "$folderPath"/{config_data["Configuration"]["CollectorFileName"]}-r___r-* 2>/dev/null | head -n 1)

                # Validate that a file was found
                if [ -z "$latestFile" ]; then
                    echo "No file matching the pattern '{config_data["Configuration"]["CollectorFileName"]}-r___r-*' was found."
                    exit 1
                fi

                # Log the file being processed
                echo "Most recent file: $latestFile"

                # Run another shell script on the most recent file
                ./split_and_hash.sh "$latestFile" 250M
                """

        OsCollectorPath = os.path.abspath(os.path.expanduser(OsCollectorPath))

    
        # Write the content to the shell script file
        with open(BatchFile, "w") as file:
            file.write(shell_script_content)
        time.sleep(1)
        command = [
            "sudo",
            "-u",
            "root",
            "mv",
            collectorPath,
            TestPathVelo,
        ]
        ttttttt = f'{TestPathVelo}/{config_data["Configuration"]["CollectorFileName"]}'

        try:
            subprocess.run(command, check=True)
            logger.info("File moved successfully.")
        except subprocess.CalledProcessError as f:
            logger.error(f"Failed to move the file. {f}")
        except Exception as e:
            logger.error(f"Error in This Move stuff {e}")

        time.sleep(1)

        if os.path.exists(ttttttt):
            # dont forget to change owner
            command = ["sudo", "chown", "Bacteria5570", ttttttt]
            try:
                subprocess.run(command, check=True)
                logger.info("Ownership changed successfully.")
            except subprocess.CalledProcessError:
                logger.info(
                    "Failed to change owner. The command did not run successfully."
                )
            except Exception as e:
                logger.info(f"An error occurred: {e}")
        else:
            logger.error(f"The file or directory {ttttttt} does not exist.")

        # Make the shell script executable
        os.chmod(BatchFile, 0o755)
        NewVeloCollector = (
            f'Collector/{config_data["Configuration"]["CollectorFileName"]}'
        )
        files_to_zip = [BatchFile, OsCollectorPath, NewVeloCollector,"Collector/PowerShellSplit.ps1"]
        zip_file_path = (
            f'Collector/{config_data["Configuration"]["CollectorFileName"]}.zip'
        )
        # os.chmod(NewVeloCollector, 0o755)
        create_zip(files_to_zip, zip_file_path, logger)
        logger.info("cut " + zip_file_path)

    except Exception as e:
        logger.error(str(e))


if __name__ == "__main__":
    logger = additionals.funcs.setup_logger("Collector.log")

    # Load environment configuration
    env_dict = additionals.funcs.read_env_file(logger)
    config_data = connect_my_sql(env_dict, logger)

    # Run the server artifact
    run_server_artifact(logger, config_data)
