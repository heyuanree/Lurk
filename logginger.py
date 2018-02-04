# coding:utf-8

from __future__ import print_function
import logging, coloredlogs
import sys
import os

# mkdir for logger
if not os.path.exists('log'):
    path = os.getcwd()
    log_path = os.path.join(path, 'log')
    try:
        os.mkdir(log_path)
    except Exception:
        raise Exception

# init logger name logging.getLogger(name)
logger = logging.getLogger('console')

'''
# set format to log
# formatter = logging.Formatter("%(asctime)s\t%(levelname)-8s:\t%(message)s")

# file handler
file_handler = logging.FileHandler("test.log")
file_handler.setFormatter(formatter)

# console handler
console_handler = logging.FileHandler(sys.stdout)
console_handler.setFormatter(formatter)

# add logger handler to logger
logger.addHandler(console_handler)
'''

coloredlogs.install(level='DEBUG')
