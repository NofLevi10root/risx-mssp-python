from elasticsearch import Elasticsearch
import json
import logging
import os
import traceback

import json
import os
from datetime import datetime
from typing import Any, Dict, List, Union



def connect_to_elasticsearch(host='localhost', port=9200, logger=None):
    try:
        es = Elasticsearch([{'host': host, 'port': port, 'scheme': 'http'}])
        return es
    except Exception as e:
        if logger:
            logger.error(f"Error connecting to Elasticsearch: {e}")
        raise

def create_index(es, index_name, logger=None):
    try:
        if not es.indices.exists(index=index_name):
            es.indices.create(index=index_name)
            if logger:
                logger.info(f"Index '{index_name}' created.")
        else:
            if logger:
                logger.info(f"Index '{index_name}' already exists.")
    except Exception as e:
        if logger:
            logger.error(f"Error creating index '{index_name}': {e}")
        raise

def load_data(file_path, logger=None):
    file_extension = os.path.splitext(file_path)[-1].lower()
    
    try:
        if file_extension == '.json':
            with open(file_path, 'r') as file:
                data_table = json.load(file)
            if logger:
                logger.info(f"Data loaded successfully from {file_path}")
            return data_table
        else:
            raise ValueError(f"Unsupported file extension: {file_extension}")
    except Exception as e:
        if logger:
            logger.error(f"Error loading data from {file_path}: {e}")
        raise

def clean_document(doc):
    """Clean and prepare a document for Elasticsearch indexing"""
    # Make a deep copy to avoid modifying the original
    cleaned = {}
    
    # Process each field
    for key, value in doc.items():
        # Convert None to empty string to avoid Elasticsearch issues
        if value is None:
            cleaned[key] = ""
        # Handle nested dictionaries
        elif isinstance(value, dict):
            cleaned[key] = clean_document(value)
        # Handle lists
        elif isinstance(value, list):
            cleaned[key] = [clean_document(item) if isinstance(item, dict) else item for item in value]
        # Handle string fields that might be JSON/YAML
        elif isinstance(value, str) and (key in ['sigma_rules', 'yara_rules', 'nuclei_rules']):
            # Store as plain string, but make sure it's valid
            cleaned[key] = value.replace('\t', '    ')  # Replace tabs with spaces
        else:
            cleaned[key] = value
            
    return cleaned

def upload_data_to_elasticsearch(es, index_name, data_table, logger=None):
    """
    Upload data to Elasticsearch.
    This version supports both dictionary and list inputs without using hashlib.
    """
    successful_docs = 0
    failed_docs = 0
    error_details = []

    # Case 1: The input is a LIST of documents (e.g., from Nuclei)
    if isinstance(data_table, list):
        if logger:
            logger.info(f"Processing a list of {len(data_table)} documents...")

        # Loop through the list using an index 'i' for a counter
        for i, doc_data in enumerate(data_table):
            try:
                # Generate a simple, unique ID using the timestamp and a counter
                doc_id = f"{datetime.now().timestamp()}-{i}"
                
                cleaned_doc = clean_document(doc_data)
                
                result = es.index(
                    index=index_name,
                    id=doc_id,
                    document=cleaned_doc
                )

                if result.get('result') in ['created', 'updated']:
                    successful_docs += 1
                else:
                    failed_docs += 1
                    error_msg = f"Document with generated ID {doc_id} failed: {result}"
                    error_details.append(error_msg)
            
            except Exception as e:
                failed_docs += 1
                error_msg = f"Error indexing document from list: {e}"
                error_details.append(error_msg)

    # Case 2: The input is a DICTIONARY of documents (for other calls)
    elif isinstance(data_table, dict):
        if logger:
            logger.info(f"Processing a dictionary of {len(data_table)} documents...")
        
        # This part is your original code, it remains unchanged
        for doc_id, doc_data in data_table.items():
            try:
                cleaned_doc = clean_document(doc_data)
                result = es.index(
                    index=index_name,
                    id=doc_id,
                    document=cleaned_doc
                )
                if result.get('result') in ['created', 'updated']:
                    successful_docs += 1
                else:
                    failed_docs += 1
                    error_details.append(f"Document {doc_id} failed: {result}")
            
            except Exception as e:
                failed_docs += 1
                error_details.append(f"Error indexing document {doc_id}: {e}")

    # Case 3: The input is an unsupported type
    else:
        error_msg = f"Unsupported data type: {type(data_table)}. Must be a list or dict."
        if logger:
            logger.error(error_msg)
        raise ValueError(error_msg)
    
    # Report summary
    if logger:
        logger.info(f"Indexing complete: {successful_docs} successful, {failed_docs} failed")

    return successful_docs, failed_docs, error_details

def enter_data(input_source, index_name, elastic_ip, logger):
    try:
        logger.info(f"First argument is input source (file path or Python object), second argument is index name")
        logger.info(f"index_name: {index_name}")
        logger.info("data:" + str(input_source))
        logger.info("data type::" + str(type(input_source)))
        es_port = 9200

        # Connect to Elasticsearch
        es = connect_to_elasticsearch(elastic_ip, es_port, logger)
        
        # Create the index (if it doesn't exist)
        create_index(es, index_name, logger)

        # Load data based on input type
        if isinstance(input_source, str):
            # Input is a file path
            logger.info(f"Processing input as file path: {input_source}")
            data_table = load_data(input_source, logger)
        else:
            # Input is a Python object
            logger.info(f"Processing input as Python object")
            
            # Check if input_source is a single document and not a dictionary of documents
            if isinstance(input_source, dict):
                # Convert single document to the expected format
                # Generate a unique ID for this document (you might want to use a field from the document)
                doc_id = input_source.get('AlertID', str(datetime.now().timestamp()))
                data_table = {doc_id: input_source}
            else:
                # Input is already in the expected format
                data_table = input_source

        # Upload the data table to Elasticsearch document by document
        successful, failed, errors = upload_data_to_elasticsearch(es, index_name, data_table, logger)
        
        if failed > 0:
            logger.warning(f"Completed with {failed} failed documents out of {successful + failed} total")
        else:
            logger.info(f"All {successful} documents successfully indexed")
        
        return successful, failed, errors
        
    except Exception as e:
        logger.error(f"Error in the data entry process: {e}")
        logger.error(traceback.format_exc())
        raise