import pandas as pd
import json
def load_data_from_mysql(connection, table_name, logger):
    try:
        # Construct the SQL query
        query = f"SELECT label, config FROM {table_name} where not label = 'all_monitor'"
        logger.info(f"Loading data from table {table_name}")

        # Use cursor to execute the query
        cursor = connection.cursor()
        cursor.execute(query)

        # Fetch all rows
        rows = cursor.fetchall()

        # Get column names
        columns = [column[0] for column in cursor.description]

        # Process data into required format
        result = []
        for row in rows:
            label = row[0]
            config_data = row[1]

            # Ensure config is deserialized properly
            try:
                config_dict = json.loads(config_data) if config_data else {}
            except json.JSONDecodeError:
                logger.error(f"Failed to decode JSON for label {label}")
                config_dict = {}

            # Append formatted data
            result.append({
                "label": label,
                "artifacts": config_dict
            })

        logger.info("Successfully processed data from MySQL")
        return result

    except Exception as e:
        logger.error(f"Error loading data from MySQL: {str(e)}")
        return None

def push_dataframe_to_mysql(df, connection, table_name, logger):

    try:
        cursor = connection.cursor()
        
        # Truncate the table first
        logger.info(f"Delete table {table_name}")
        cursor.execute(f"DELETE FROM {table_name}")
        connection.commit()
        
        # Convert all DataFrame rows to tuples at once
        data_tuples = [tuple(row) for row in df.values]
        
        # Prepare the SQL query for insertion
        placeholders = ', '.join(['%s'] * len(df.columns))
        columns = ', '.join(df.columns)
        insert_query = f"INSERT INTO {table_name} ({columns}) VALUES ({placeholders})"
        
        # Execute the query for all rows at once
        logger.info(f"Inserting {len(data_tuples)} rows into {table_name}")
        cursor.executemany(insert_query, data_tuples)
        connection.commit()
        
        logger.info(f"Successfully inserted {cursor.rowcount} rows into {table_name}")
        cursor.close()
        return True
        
    except Exception as e:
        logger.error(f"Error inserting data into MySQL: {str(e)}")
        if connection.is_connected():
            connection.rollback()
            cursor.close()
        return False