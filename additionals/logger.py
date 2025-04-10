import logging
from datetime import datetime
import sys
import os
import shutil

def setup_logger(logger_name):
    logging_level = logging.INFO
    logs_dir = "logs"
    logging_path = os.path.join(logs_dir, logger_name)
    
    # Create logs directory if it doesn't exist
    if not os.path.exists(logs_dir):
        os.makedirs(logs_dir)
    
    # Check if log file exists and is larger than 20MB
    if os.path.exists(logging_path) and os.path.getsize(logging_path) > 20 * 1024 * 1024:  # 20MB in bytes
        # Create archive directory if it doesn't exist
        archive_dir = os.path.join(logs_dir, "archived_logs")
        if not os.path.exists(archive_dir):
            os.makedirs(archive_dir)
        
        # Generate archive filename with current date and time
        timestamp = datetime.now().strftime("%Y%m%d%H")
        archive_filename = f"{logger_name}_{timestamp}"
        archive_path = os.path.join(archive_dir, archive_filename)
        
        # Copy the current log file to the archive
        shutil.copy2(logging_path, archive_path)
        
        # Clear the original log file (open with 'w' truncates the file)
        open(logging_path, 'w').close()
    
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