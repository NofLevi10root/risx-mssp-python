import subprocess
import os
import json
from datetime import datetime
import asyncio
import stat
import additionals.elastic_api
import random

def nuclei_elastic_format_fixer(response_path, population, logger):
    """
    Reads Nuclei data, enriches it, and returns it as a dictionary
    formatted specifically for the project's Elasticsearch uploader.
    """
    try:
        logger.info(f"Formatting data from: {response_path}")

        # Create a lookup dictionary for asset information
        population_dict = {
            asset['asset_string']: asset.get('asset_parent_id')
            for asset in population if 'asset_string' in asset
        }

        # Read the list of findings from the JSON file
        with open(response_path, 'r') as f:
            findings_list = json.load(f)
        logger.info(f"Loaded {len(findings_list)} findings.")

        # This dictionary will hold the final data in the required format
        processed_dict = {}

        # Convert the list into the required dictionary format
        for i, finding in enumerate(findings_list):
            # Add asset and timestamp info
            hostname = finding.get("host")
            if hostname and hostname in population_dict:
                finding["asset_string"] = hostname
                finding["asset_parent_id"] = population_dict[hostname]
            finding["@timestamp"] = datetime.utcnow().isoformat(timespec='milliseconds') + 'Z'

            # Create a unique ID from the finding's content to use as the key
            template_id = finding.get("template-id", "unknown-template")
            matched_at = finding.get("matched-at", f"item-{i}")
            
            # Sanitize the key to remove characters that are invalid in an ID
            sanitized_matched_at = matched_at.replace('/', '_').replace(':', '_').replace('?', '_').replace('#', '_')
            doc_id = f"{template_id}-{sanitized_matched_at}"
            
            # Add the finding to the dictionary with its unique key
            processed_dict[doc_id] = finding

        logger.info(f"Successfully converted {len(processed_dict)} findings to the required dictionary format.")
        return processed_dict

    except Exception as e:
        logger.error(f"An error occurred in nuclei_elastic_format_fixer: {e}")
        logger.error(traceback.format_exc())
        return None

    
def count_severities(json_path, logger):
    try:
        if not os.path.exists(json_path):
            logger.error(f"File does not exist: {json_path}")
            return None

        with open(json_path, 'r') as file:
            try:
                data = json.load(file)
            except json.JSONDecodeError as e:
                logger.error(f"Error decoding JSON from {json_path}: {e}")
                return None
        severity_counts = {"info": 0, "low": 0, "medium": 0, "high":0, "critical": 0}

        for entry in data:
            severity = entry.get('info', {}).get('severity', 'unknown')
            if severity in severity_counts:
                severity_counts[severity] += 1
            else:
                severity_counts[severity] = 1

        logger.info("Severity counts:")
        for severity, count in severity_counts.items():
            logger.info(f"{severity}: {count}")

        return severity_counts
    except Exception as e:
        logger.info("Nuclei stats failed!" + str(e))
        return None
def create_include_severities(exclude_severity_list):
    all_severities = ["info", "low", "medium", "high", "critical", "unknown"]
    if(exclude_severity_list != None):
        include_severity_list = [severity for severity in all_severities if severity not in exclude_severity_list]
        return include_severity_list
    return all_severities

def ensure_executable(file_path):
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"No such file or directory: '{file_path}'")
    
    # Check if the file is executable
    st = os.stat(file_path)
    if not st.st_mode & stat.S_IXUSR:
        os.chmod(file_path, st.st_mode | stat.S_IXUSR)
        print(f"Added execute permission to: {file_path}")


def start_nuclei(row,elasticIp, logger):
    try:
        logger.info("Setting variables!")
        #targets_ip = ', '.join(row["Population"])
        # Extracting 'asset_string' from each dictionary in the Population list
        if(len(row["Population"]) == 0):
            logger.error("Nuclei has no population")
            row["Status"] = "Failed"
            row["Error"] = "Nuclei has no population"
            return row
        targets_ip = ', '.join(asset['asset_string'] for asset in row["Population"])
        logger.info("Nuclei population:" + str(targets_ip))
        arguments = row["Arguments"]
        current_working_directory = os.path.join(os.getcwd(), "modules", "Nuclei")
        nuclei_tags = arguments.get("NucleiTags", "")
        nuclei_workflow = arguments.get("NucleiWorkflow", "")
        nuclei_exclude_severity = arguments.get("NucleiExcludeSeverity", "")
        nuclei_include_severity = create_include_severities(nuclei_exclude_severity)
        nuclei_targets = targets_ip
        nuclei_templates = os.path.join(current_working_directory, "dependencies/nuclei-templates")
        nuclei_additional_arguments = arguments.get("NucleiArgumentFlags", "")

        row["UniqueID"] = str(random.randint(9000000, 99999999))
        nuclei_path = os.path.join(current_working_directory, "dependencies", "nuclei")
        nuclei_timeout = 1
        new_filename = row["ResponsePath"]
        #new_filename = f"response_nuclei_{datetime.now().strftime('%d-%m-%Y-%H-%M-%S')}.json"
        
        
        # Ensure the nuclei file is executable
        ensure_executable(nuclei_path)

        nuclei_targets_list = nuclei_targets.split(",")
        nuclei_list_path = 'nuclei_list.txt'
        with open(nuclei_list_path, 'w') as file:
            for target in nuclei_targets_list:
                file.write(f"{target}\n")
        command = [nuclei_path, "-list", nuclei_list_path, "-json-export", new_filename, "-timeout", str(nuclei_timeout), "-mhe", str(1), "-severity", ",".join(nuclei_include_severity)]
        #Without updates
        #l command = [nuclei_path, "-list", nuclei_list_path, "-disable-update-check", "-json-export", new_filename, "-timeout", str(nuclei_timeout), "-mhe", str(1), "-severity", ",".join(nuclei_include_severity)]

        if nuclei_templates:
            command.extend(["-templates", nuclei_templates])

        if nuclei_additional_arguments != "" and nuclei_additional_arguments != []:
            for additional_argument in nuclei_additional_arguments:
                command.append(additional_argument)
        command.append("-vv") # Verbose mode
        
        logger.info(f"Executing Nuclei command: {' '.join(command)}")
        
        # Use subprocess.Popen for real-time output
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        
        # Read output line by line as it becomes available
        while True:
            output_line = process.stdout.readline()
            if output_line == '' and process.poll() is not None:
                break
            if output_line:
                logger.info(output_line.strip())
        
        if process.returncode != 0:
            logger.error(f"Nuclei command exited with error code: {process.returncode}")
        logger.info("Uploading nuclei to elastic!")

        try:
            #nuclei_elastic_format_fixer(row["ResponsePath"], row["Population"], logger)
            nuclei_elastic_format_fixer(row["ResponsePath"], row["Population"], logger)
            logger.info("Uploading nuclei to elastic!")
            additionals.elastic_api.enter_data(row["ResponsePath"], "artifact_nuclei",elasticIp, logger)
            logger.info("End uploading!")
        except Exception as e:
            logger.warning("Elastic error:" + str(e))
        
        row["Status"] = "Complete"
        row["ExpireDate"] =  datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        return row

    except Exception as e:
        logger.error("Nuclei Error:" + str(e))
        row["Status"] = "Failed"
        row["Error"] = str(e)
        row["ExpireDate"] =  datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        return row
