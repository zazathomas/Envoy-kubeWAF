import os
import logging
from logging import StreamHandler, FileHandler

def get_env_variable(var_name, default=None):
    value = os.environ.get(var_name)
    return value or default

def initialize_logger(log_file=None):
    logger = logging.getLogger()
    logger.setLevel(logging.INFO) 

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    if log_file:
        handler = FileHandler(log_file)
    else:
        handler = StreamHandler()  # Log to console

    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger