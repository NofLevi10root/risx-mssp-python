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
import random
import string

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
import ssl
import urllib3

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
    config = json.loads(
        additionals.mysql_functions.execute_query(
            connection,
            f"SELECT JSON_EXTRACT(config,'$.General.AgentLinks') FROM configjson",
            logger,
        )[0][0]
    )
    return [config_data, config]


def create_zip(files_to_zip, zip_file_path, logger):
    """
    Creates a zip file containing the specified files or directories, placing all files in the root of the zip.
    If a directory is specified, all files within it (including in subdirectories) will be added.

    Args:
        files_to_zip (list): List of file paths or directories to include in the zip file.
        zip_file_path (str): The destination path for the zip file.
        logger (logging.Logger): Logger instance to log progress and errors.

    Returns:
        None
    """
    try:
        with zipfile.ZipFile(zip_file_path, "w", zipfile.ZIP_DEFLATED) as zipf:
            for item in files_to_zip:
                if os.path.isdir(item):
                    logger.info(f"Adding directory to zip: {item}")
                    for foldername, subfolders, filenames in os.walk(item):
                        for filename in filenames:
                            # Create complete path to file in folder
                            file_path = os.path.join(foldername, filename)
                            # Archive name keeps the folder structure relative to the folder being zipped
                            archive_name = os.path.relpath(
                                file_path, os.path.dirname(item)
                            )
                            zipf.write(file_path, archive_name)
                            logger.info(f"Added file to zip: {archive_name}")
                elif os.path.isfile(item):
                    logger.info(f"Adding file to zip: {item}")
                    archive_name = os.path.basename(item)
                    zipf.write(item, archive_name)
                    logger.info(f"Added file to zip: {archive_name}")
                else:
                    logger.info(f"Item does not exist, skipping: {item}")
    except Exception as e:
        logger.error(f"Error while creating zip file: {str(e)}")


def run_server_artifact(logger, config_data, config_agent):
    logger.info(
        "Running server artifact query. "
        + str(config_data)
        + " Agent LiNKS: "
        + str(config_agent)
    )
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

        random_string = "".join(random.choices(string.ascii_letters, k=11))
        os.makedirs(f"Collector/{random_string}", exist_ok=True)
        OsCollector = ""
        OsCollectorPath = ""
        BatchFile = ""
        shell_script_content = ""
        logger.info(f"Log FlowId : {FlowId}")
        collectorPath = f'clients/server/collections/{FlowId}/uploads/scope/{config_data["Configuration"]["CollectorFileName"]}'
        channel = modules.Velociraptor.VelociraptorScript.setup_connection(logger)
        stub = api_pb2_grpc.APIStub(channel)
        offset = 0
        NewVeloCollector = f'Collector/{random_string}/{config_data["Configuration"]["CollectorFileName"]}'  # Open the output file in binary write mode
        with open(NewVeloCollector, "wb") as output_file:
            while True:
                # Prepare the request
                request = api_pb2.VFSFileBuffer(
                    components=collectorPath.split("/"),
                    length=1024,  # Adjust buffer size as needed
                    offset=offset,
                )

                # Send the request and receive the response
                res = stub.VFSGetBuffer(request)
                if len(res.data) == 0:
                    break

                # Write data to the file
                output_file.write(res.data)
                offset += len(res.data)

        # TestPathVelo = "Collector/"
        SplitScript = ""
        # TestPathVelo = os.path.abspath(os.path.expanduser(TestPathVelo))

        match sys.argv[2]:

            case "Windows":
                OsCollector = "velociraptor_client.exe"
                # SplitScript = "modules/Collector/PowerShellSplit.ps1"
                SplitScript = "modules/Collector/7-ZipPortable"
                OsCollectorPath = "velociraptor_client.exe"

                BatchFile = f'Collector/{random_string}/{config_data["Configuration"]["CollectorFileName"]}.bat'
                # shell_script_content = f"""
                # @echo off

                # :: Define the folder where the files are generated
                # set "folderPath=%cd%"

                # :: Run Velociraptor command to generate the files
                # {OsCollector} -- --embedded_config {config_data["Configuration"]["CollectorFileName"]}
                # :: Find the most recent file matching the pattern
                # for /f "delims=" %%F in ('dir /b /od "%folderPath%\{config_data["Configuration"]["CollectorFileName"]}-r___r-*"') do set "latestFile=%%F"

                # :: Validate that a file was found
                # if not defined latestFile (
                #     echo No file matching the pattern "{config_data["Configuration"]["CollectorFileName"]}-r___r-*" was found.
                #     exit /b 1
                # )

                # :: Log the file being processed
                # echo Most recent file: %latestFile%

                # :: Run the PowerShell script on the most recent file
                # powershell -NoProfile -Command "&  ".\PowerShellSplit.ps1 -filePath '%folderPath%\%latestFile%' -outputFolder '%folderPath%' -chunkSizeMB 250" "

                # :: Exit the batch script
                # exit /b

                # """
                shell_script_content = f"""
                @echo off

                :: Define the folder where the files are generated
                set "folderPath=%cd%"

                :: Run Velociraptor command to generate the files
                {OsCollector} -- --embedded_config {config_data["Configuration"]["CollectorFileName"]}        
                
                 :: Find the most recent file matching the pattern
                 for /f "delims=" %%F in ('dir /b /od "%folderPath%\{config_data["Configuration"]["OutputsFileName"]}-r___r-*"') do set "latestFile=%%F"

                 :: Validate that a file was found
                 if not defined latestFile (
                     echo No file matching the pattern "{config_data["Configuration"]["OutputsFileName"]}-r___r-*" was found.
                     exit /b 1
                 )


                :: Extract filename without extension for the archive name
                for %%I in ("%latestFile%") do set "latestFileWithoutExtension=%%~nI"
                

                :: Run the PowerShell script on the most recent file
                "7-ZipPortable/App/7-Zip/7z.exe" a -t7z -v{config_data["Configuration"]["ZipSplitSizeInMb"]}m "Results\%latestFileWithoutExtension%.7z" %latestFile% > txt.txt

         

                """
                #        :: Remove the Original Result file after creating the archive Split for Clarity proposes              
                # del "%folderPath%\%latestFile%"

            case "Mac":
                OsCollector = "velociraptor_client"
                SplitScript = "modules/Collector/split_and_hash.sh"
                OsCollectorPath = "velociraptor_client"

                BatchFile = f'Collector/{random_string}/{config_data["Configuration"]["CollectorFileName"]}.sh'
                shell_script_content = f"""
                folderPath=$(pwd)
                {OsCollector} -- --embedded_config {config_data["Configuration"]["CollectorFileName"]}
                :: Find the most recent file matching the pattern
                latestFile=$(ls -t "$folderPath"/{config_data["Configuration"]["OutputsFileName"]}-r___r-* 2>/dev/null | head -n 1)

                # Validate that a file was found
                if [ -z "$latestFile" ]; then
                    echo "No file matching the pattern '{config_data["Configuration"]["OutputsFileName"]}-r___r-*' was found."
                    exit 1
                fi

                :: Log the file being processed
                echo "Most recent file: $latestFile"

                :: Run another shell script on the most recent file
                ./split_and_hash.sh "$latestFile" {config_data["Configuration"]["ZipSplitSizeInMb"]}M
                """
            case "Linux":
                OsCollector = "velociraptor_client"
                SplitScript = "modules/Collector/split_and_hash.sh"
                OsCollectorPath = "velociraptor_client"

                BatchFile = f'Collector/{random_string}/{config_data["Configuration"]["CollectorFileName"]}.sh'
                shell_script_content = f"""
                folderPath=$(pwd)
                {OsCollector} -- --embedded_config {config_data["Configuration"]["CollectorFileName"]}
                :: Find the most recent file matching the pattern
                latestFile=$(ls -t "$folderPath"/{config_data["Configuration"]["OutputsFileName"]}-r___r-* 2>/dev/null | head -n 1)

                :: Validate that a file was found
                if [ -z "$latestFile" ]; then
                    echo "No file matching the pattern '{config_data["Configuration"]["OutputsFileName"]}-r___r-*' was found."
                    exit 1
                fi

                :: Log the file being processed
                echo "Most recent file: $latestFile"

                :: Run another shell script on the most recent file
                ./split_and_hash.sh "$latestFile" {config_data["Configuration"]["ZipSplitSizeInMb"]}M
                """

        logger.info("step 1 complete")
        OsCollectorPath = os.path.join(
            os.path.dirname(config_agent[sys.argv[2]]), OsCollectorPath
        )
        OsCollectorPath = os.path.abspath(os.path.expanduser(OsCollectorPath))
        logger.info(f"OsCollectorPath : {OsCollectorPath}")

        # Write the content to the shell script file
        with open(BatchFile, "w") as file:
            file.write(shell_script_content)
        time.sleep(1)
        logger.info("22222222222222222222")

        time.sleep(1)

        logger.info("66666666666666")

        # Make the shell script executable
        os.chmod(BatchFile, 0o755)

        files_to_zip = [BatchFile, OsCollectorPath, NewVeloCollector, SplitScript]
        zip_file_path = f'Collector/{random_string}/{config_data["Configuration"]["CollectorFileName"]}.zip'
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
    run_server_artifact(logger, config_data[0], config_data[1])
