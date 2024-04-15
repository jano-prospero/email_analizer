#!/usr/bin/env python

# -*- coding: utf-8 -*-

author__ = 'Borja Luaces'
__version__ = 'Develop'
__date__ = '2024/xx/xx'

"""
Copyleft(c) 2024 Borja Luaces
See the file License for copying permission
"""

# Disable .pyc file creation
import sys
sys.dont_write_bytecode = True

# Module imports
import argparse
import logging
import os
import traceback

from email_analizer.email import *

# Set logging level
LOGGING_LEVEL = logging.INFO  # Modify if you just want to focus on errors
logging.basicConfig(level=LOGGING_LEVEL, format='%(asctime)s %(levelname)s - %(message)s', datefmt='%y-%m-%d %H:%M:%S', stream=sys.stdout)


def main() -> None :
    """ToDO."""
    logging.info('Starting main')
    parser = argparse.ArgumentParser(description='Email analizer')
    parser.add_argument('-f', '--file', type=str, help='Path to email file to analize')
    parser.add_argument('-m', '--mode', type=str, choices=['normal', 'private'], default='private', help='Enable email and file sharing- [NOT IMPLEMENTED]' )
    args = parser.parse_args()
    if args.file:
        eml_to_process = email()
        eml_to_process._process_eml(args.file)
    
        '''
        if args.mode =='normal':
            print('Email and files will be uploaded to the Internet')
        elif args.mode == 'private':
            print('Email and files will NOT be uploaded to the Intenet ')
        '''
    else:
        pass

    



if __name__ == '__main__':
    try:
        main()

    except Exception:
        msg = "\r[!] Unhandled exception occurred ({0})" .format(sys.exc_info()[1])
        msg += "\r [+] Please report the following details to borja.luaces@gmail.com:\n---{0}\n---" .format(traceback.format_exc())

        print (msg)

    os._exit(0)

