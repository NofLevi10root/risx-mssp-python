from elasticsearch import Elasticsearch
import json
import logging
import os
import traceback

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
    """Upload data to Elasticsearch document by document"""
    successful_docs = 0
    failed_docs = 0
    error_details = []
    
    # Process each document individually
    if isinstance(data_table, dict):
        total_docs = len(data_table)
        if logger:
            logger.info(f"Processing {total_docs} documents...")
        
        for doc_id, doc_data in data_table.items():
            try:
                # Clean the document to ensure it's valid for Elasticsearch
                cleaned_doc = clean_document(doc_data)
                
                # Index the document
                result = es.index(
                    index=index_name,
                    id=doc_id,
                    document=cleaned_doc
                )
                
                if result.get('result') in ['created', 'updated']:
                    successful_docs += 1
                    if logger:
                        logger.info(f"Successfully indexed document {doc_id}")
                else:
                    failed_docs += 1
                    error_msg = f"Document {doc_id} indexing result: {result}"
                    error_details.append(error_msg)
                    if logger:
                        logger.warning(error_msg)
                
            except Exception as e:
                failed_docs += 1
                error_msg = f"Error indexing document {doc_id}: {str(e)}"
                error_details.append(error_msg)
                if logger:
                    logger.error(error_msg)
                    logger.error(traceback.format_exc())
    else:
        if logger:
            logger.error("Data is not in the expected dictionary format")
        raise ValueError("Data must be a dictionary for document-by-document upload")
    
    # Report summary
    if logger:
        logger.info(f"Indexing complete: {successful_docs} successful, {failed_docs} failed")
        if failed_docs > 0:
            logger.error("Errors encountered during indexing:")
            for error in error_details:
                logger.error(f"  - {error}")
    
    # Verify results
    try:
        count = es.count(index=index_name)
        if logger:
            logger.info(f"Total documents in index: {count['count']}")
    except Exception as e:
        if logger:
            logger.error(f"Error counting documents: {str(e)}")
    
    return successful_docs, failed_docs, error_details

def enter_data(file_path, index_name, elastic_ip, logger):
    try:
        logger.info("First argument is input path, second argument is index name")
        logger.info(f"file_path: {file_path}")
        logger.info(f"index_name: {index_name}")
        es_port = 9200

        # Connect to Elasticsearch
        es = connect_to_elasticsearch(elastic_ip, es_port, logger)
        
        # Create the index (if it doesn't exist)
        create_index(es, index_name, logger)

        # Load data from the file
        data_table = load_data(file_path, logger)

        # Upload the data table to Elasticsearch document by document
        successful, failed, errors = upload_data_to_elasticsearch(es, index_name, data_table, logger)
        
        if failed > 0:
            logger.warning(f"Completed with {failed} failed documents out of {successful + failed} total")
        else:
            logger.info(f"All {successful} documents successfully indexed")
        
    except Exception as e:
        logger.error(f"Error in the data entry process: {e}")
        logger.error(traceback.format_exc())
        raise