from elasticsearch import Elasticsearch, helpers
import pandas as pd
import json
import os
import sys
import logging

def connect_to_elasticsearch(host='localhost', port=9200, logger=""):
    try:
        es = Elasticsearch([{'host': host, 'port': port, 'scheme': 'http'}])
        return es
    except Exception as e:
        logger.error(f"Error connecting to Elasticsearch: {e}")
        raise

def create_index(es, index_name, logger):
    try:
        if not es.indices.exists(index=index_name):
            es.indices.create(index=index_name)
            logger.info(f"Index '{index_name}' created.")
        else:
            logger.info(f"Index '{index_name}' already exists.")
    except Exception as e:
        logger.error(f"Error creating index '{index_name}': {e}")
        raise

def load_data(file_path, logger):
    file_extension = os.path.splitext(file_path)[-1].lower()
    
    try:
        if file_extension == '.csv':
            data = pd.read_csv(file_path)
            data_table = data.to_dict(orient='records')
        elif file_extension == '.json':
            with open(file_path, 'r') as file:
                data_table = json.load(file)
        else:
            raise ValueError(f"Unsupported file extension: {file_extension}")
        logger.info(f"Data loaded successfully from {file_path}")
        return data_table

    except FileNotFoundError:
        logger.error(f"File not found: {file_path}")
        raise
    except json.JSONDecodeError:
        logger.error(f"Error decoding JSON from file: {file_path}")
        raise
    except pd.errors.EmptyDataError:
        logger.error(f"No data: {file_path} is empty")
        raise
    except Exception as e:
        logger.error(f"Error loading data from {file_path}: {e}")
        raise

def upload_data_to_elasticsearch(es, index_name, data_table, logger):
    actions = [
        {
            "_index": index_name,
            "_source": record
        }
        for record in data_table
    ]
    
    try:
        helpers.bulk(es, actions)
        logger.info(f"Data uploaded to index '{index_name}'.")
    except helpers.BulkIndexError as bulk_error:
        logger.error(f"Error indexing some documents: {len(bulk_error.errors)} documents failed.")
        for error in bulk_error.errors:
            failed_doc = error['index'].get('_source', 'Source not available')
            error_reason = error['index'].get('error', 'Error details not available')
            logger.error(f"Failed document: {failed_doc}")
            logger.error(f"Error: {error_reason}")
    except Exception as e:
        logger.error(f"Unexpected error during bulk upload to Elasticsearch: {e}")
        raise

def enter_data(file_path, index_name, logger):
    try:
        logger.info("First argument is input path, second argument is index name")
        logger.info(f"file_path: {file_path}")
        logger.info(f"index_name: {index_name}")
        es_host = 'localhost'
        es_port = 9200

        # Connect to Elasticsearch
        es = connect_to_elasticsearch(es_host, es_port, logger)
        
        # Create the index (if it doesn't exist)
        create_index(es, index_name, logger)

        # Load data from the file
        data_table = load_data(file_path, logger)

        # Upload the data table to Elasticsearch
        upload_data_to_elasticsearch(es, index_name, data_table, logger)
    except Exception as e:
        logger.error(f"Error in the data entry process: {e}")
        raise
