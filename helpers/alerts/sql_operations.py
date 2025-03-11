import pandas as pd
def push_dataframe_to_mysql(df, connection, table_name, logger):

    try:
        cursor = connection.cursor()
        
        # Truncate the table first
        logger.info(f"Truncating table {table_name}")
        cursor.execute(f"TRUNCATE TABLE {table_name}")
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