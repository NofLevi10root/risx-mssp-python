
import os
import sys
from datetime import datetime
from threading import Thread

import modules.Velociraptor.AddToTimeSketch
script_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(script_dir)
print(f"Current working directory: {os.getcwd()}")

import logging
import json
import modules.Velociraptor.VelociraptorScript
import modules.Velociraptor.AddToTimeSketch
import modules.Nuclei.NucleiScript
import modules.SmallModules.SmallModules
import additionals.mysql_functions
import additionals.funcs
import additionals.logger

def main():
    print("Start mssp!")
    df = []
    previous_config_date = ""
    env_dict = {}
    # Setup logging with the specified level
    logging_level = logging.INFO
    logger = additionals.logger.setup_logger('main.log')
    os.makedirs("logs", exist_ok=True)
    os.makedirs("response_folder", exist_ok=True)
    logger.info("Start mssp!")
    logger.info("Read env file")
    env_dict = additionals.funcs.read_env_file(logger)
    #logger.info("Remove previous hunts!")
    #modules.Velociraptor.VelociraptorScript.remove_all_hunts("OCHL0", logger)
    config_data = ""
    connection = additionals.mysql_functions.setup_mysql_connection(env_dict,logger)
    
    config_data = json.loads(additionals.mysql_functions.execute_query(connection, "SELECT config FROM configjson LIMIT 1", logger)[0][0])

    previous_config_date = datetime.now().strftime('%d-%m-%Y-%H-%M-%S')

    new_objects_start_index = len(config_data["RequestStatus"])
    logger.info("Number of objects inside RequestStatus before new:" + str(new_objects_start_index))
    config_data = additionals.funcs.add_in_progress_rows(config_data, previous_config_date, logger)

    request_status_count_after = len(config_data["RequestStatus"])
    logger.info("Number of objects inside RequestStatus after new:" + str(request_status_count_after))


    additionals.funcs.update_json(connection, config_data, previous_config_date, False, logger)
    connection.close()
    new_requests = config_data["RequestStatus"][new_objects_start_index:]
    logger.info("New requests:" + str(new_requests))
    for request in new_requests:
        if request["ModuleName"] == "Velociraptor":
            request = modules.Velociraptor.VelociraptorScript.run_artifact(request, logger)
            additionals.funcs.connect_db_update_config(env_dict, previous_config_date, config_data, logger)
        if request["ModuleName"] == "Shodan":
            request = modules.SmallModules.SmallModules.run_shodan(request, config_data["ClientData"]["API"]["Shodan"], request["Population"], logger)
            additionals.funcs.connect_db_update_config(env_dict, previous_config_date, config_data, logger)
        if request["ModuleName"] == "LeakCheck":
            request = modules.SmallModules.SmallModules.run_leakcheck(request, config_data["ClientData"]["API"]["LeakCheck"], request["Population"], logger)
            additionals.funcs.connect_db_update_config(env_dict, previous_config_date, config_data, logger)
        if request["ModuleName"] == "Nuclei":
            request = modules.Nuclei.NucleiScript.start_nuclei(request, logger)
            additionals.funcs.connect_db_update_config(env_dict, previous_config_date, config_data, logger)
        if request["ModuleName"] == "TimeSketch":
            request = modules.Velociraptor.AddToTimeSketch.start_timesketch(request, config_data, logger)
            additionals.funcs.connect_db_update_config(env_dict, previous_config_date, config_data, logger)




    logger.info("Dump test.json for testing!")
    # json.dump(config_data, open('test.json', 'w')) ## do not unc
    logger.info("Updating json!")

    #additionals.logger.cleanup_logging(logger)
    logger.info("Exit program!")
    

if __name__ == "__main__":
    main()
