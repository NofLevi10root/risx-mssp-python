import re
import logging

def clean_url(input_string, logger):
    """
    Removes 'https://' and 'www.' from the input string if they exist.

    Parameters:
    input_string (str): The string to be cleaned.
    logger (logging.Logger): Logger object for logging information.

    Returns:
    str: The cleaned string.
    """
    # Define the regex pattern to match 'https://' and 'www.'
    pattern = re.compile(r"(https://|www\.)")
    
    # Perform the substitution
    cleaned_string = re.sub(pattern, "", input_string)

    # Log the cleaned string
    logger.info(f"Original string: {input_string}")
    logger.info(f"Cleaned string: {cleaned_string}")

    return cleaned_string
