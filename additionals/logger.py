import logging
from datetime import datetime
import sys
import os

def setup_logger(logger_name):
    logging_level = logging.INFO
    logging_path = os.path.join("logs", logger_name)
    
    # Create a logger object with the provided name
    logger = logging.getLogger(logger_name)  # Use logger_name as the logger name
    logger.setLevel(logging_level)

    # Avoid adding multiple handlers to the same logger
    if not logger.hasHandlers():
        # Create a file handler for logging to a file
        file_handler = logging.FileHandler(logging_path)
        file_handler.setLevel(logging_level)
        file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    
    return logger
"""
def setup_logger(logger_name):
    logging_level = logging.INFO
    logging_path = os.path.join("logs", logger_name)
    
    # Create a logger object with the provided name
    logger = logging.getLogger(logger_name)  # Use logger_name as the logger name
    logger.setLevel(logging_level)

    # Avoid adding multiple handlers to the same logger
    if not logger.hasHandlers():
        # Create a file handler for logging to a file
        file_handler = logging.FileHandler(logging_path)
        file_handler.setLevel(logging_level)
        file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

        # Create a console handler for logging to stdout
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging_level)
        console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)
    
    return logger
"""
# Define a cleanup function to close and remove handlers
def cleanup_logging(logger):
    handlers = logger.handlers[:]
    for handler in handlers:
        handler.close()
        logger.removeHandler(handler)

    return logger, cleanup_logging