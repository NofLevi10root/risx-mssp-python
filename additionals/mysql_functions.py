import mysql.connector
from mysql.connector import Error
import json
from datetime import datetime, timedelta

def setup_mysql_connection(env_dict, logger):
    user = env_dict["DATABASE_USER"]
    password = env_dict["DATABASE_PASSWORD"]
    host = env_dict["DATABASE_HOST"]
    if(host == "localhost"):
        host = "127.0.0.1"
    port = env_dict["DATABASE_SQL_PORT"]
    database = env_dict["DATABASE_NAME"]
    #database = "mssp"
    try:
        logger.info("Trying to connect DB!")
        connection = mysql.connector.connect(
            host=host,
            database=database,
            user=user,
            password=password,
            port=port,
            connect_timeout=3600  # Connection timeout in seconds (1 hour)
        )
        if connection.is_connected():
            logger.info("Successfully connected to the database")
            return connection
    except Error as e:
        logger.error(f"Error: {e}")
        quit()


def execute_query(connection, query, logger):
    """
    Execute a given SQL query using the provided MySQL connection.
    
    Parameters:
    - connection: A MySQLConnection object.
    - query (str): The SQL query to execute.
    
    Returns:
    - result: The result of the executed query.
    """
    cursor = connection.cursor()
    try:
        logger.info("Executing SQL query:" + query)
        cursor.execute(query)
        result = cursor.fetchall()
        return result
    except Error as e:
        logger.error(f"Error: {e}")
        return None
    finally:
        cursor.close()

def execute_update_config(connection, previous_config_date, config):
    """
    Update the config column in the configjson table with the given config dictionary.
    
    Parameters:
    - connection: A MySQLConnection object.
    - config (dict): The new configuration dictionary to update in the database.
    
    Returns:
    - bool: True if the update was successful, False otherwise.
    """
    cursor = connection.cursor()
    try:
        # Convert the dictionary to a JSON string
       
        config_json = json.dumps(config)

        # The query to update the first row
        query = """
        UPDATE configjson
        SET config = %s
        LIMIT 1;
        """
        
        # Execute the query with the JSON string as the parameter
        cursor.execute(query, (config_json,))

        connection.commit()

    
        # Convert the date string to a datetime object
        date_format = "%d-%m-%Y-%H-%M-%S"
        date_object = datetime.strptime(previous_config_date, date_format)
        
        # Format the datetime object to a MySQL-compatible string
        mysql_date_string = date_object.strftime('%Y-%m-%d %H:%M:%S')
        query = """
        UPDATE configjson
        SET lastupdated = %s
        LIMIT 1;
        """
        
        # Execute the query with the JSON string as the parameter
        cursor.execute(query, (mysql_date_string,))
        connection.commit()
        
        return True
    except Error as e:
        print(f"Error: {e}")
        return False
    finally:
        cursor.close()