import sys
import os
import time
import re
import ConfigParser
import logging

timeformat1 = '%Y-%m-%d %H:%M:%S'
logPath = '/var/log/app/'

if __name__ == '__main__':
    if not os.path.exists(logPath):
        os.makedirs(logPath)

    if not(logPath[-1] == '/'): logPath = logPath + '/'

    loggingFile = logPath + 'AppServer' + time.strftime('%Y-%m-%d', time.localtime()) + '.log'
    logger = logging.getLogger('AppServer')
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    shdlr = logging.StreamHandler()
    shdlr.setLevel(logging.WARNING)
    shdlr.setFormatter(formatter)
    fhdlr = logging.FileHandler( loggingFile )
    fhdlr.setLevel(logging.DEBUG)
    fhdlr.setFormatter(formatter)
    logger.addHandler(shdlr)
    logger.addHandler(fhdlr)
    print time.asctime() + ' - INFO: AppServer started'
    
