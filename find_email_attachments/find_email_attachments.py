#!/usr/bin/env python

from __future__ import print_function
from datetime import datetime

import argparse
import hashlib
import linecache
import os
import re
import shutil
import sys

os.environ['COLUMNS'] = "125"

# TO DO: Take date range as an argument

date_range = {"day": range(1, 32), "month": ["Dec"], "year": range(2015, 2016)}

def arguments():
    parser = argparse.ArgumentParser(description='Find email attachments from pffexport (Outlook Data File [.pst / .ost] parser) for a particular date range. Date range must be modified in the script before running.'
                                     epilog='python find_email_attachments.py -D . /path/to/pffexport/output/directories/.export')
    parser.add_argument(help='path to pffexport output directories (ie. .export, .recovered)', type=check_arguments, dest='PATH')
    parser.add_argument('-D', help='path to dump email attachments to. Default: cwd', type=check_arguments, default=os.curdir, dest='DUMP')
    parser.add_argument('--reverse', help='reverse sort direction. Default: Ascending', action='store_true', default=False, dest='SORT')
    return vars(parser.parse_args())

def check_arguments(obj):
    """Check if arguments provided are valid and accessible"""
    if os.path.isdir(obj):
        if not (os.access(obj, os.R_OK) and os.access(obj, os.X_OK)):
            raise argparse.ArgumentTypeError("{0} is not accessible".format(obj))
        return os.path.abspath(obj)
    raise argparse.ArgumentTypeError("{0} is not a directory".format(obj))

if __name__ == '__main__':
    args = arguments()

    found = []
    for root, directories, files in os.walk(args['PATH']):
        if "Attachments" in directories and "OutlookHeaders.txt" in files:

            delivery_time = re.split('\W+', linecache.getline(os.path.join(root, "OutlookHeaders.txt"), 3))
            
            if int(delivery_time[3]) in date_range['day'] and delivery_time[2] in date_range['month'] and int(delivery_time[4]) in date_range['year']:
                attachment_dir = os.path.join(root, "Attachments")
                date_time = datetime.strptime(" ".join(delivery_time[2:8]), '%b %d %Y %H %M %S').isoformat()
                for root, directories, attachments in os.walk(attachment_dir):
                    if attachments:
                        found.append([date_time, "; ".join(attachments)])
                        for attachment in attachments:
                                print("Copying:", os.path.relpath(os.path.join(root, attachment), start=args['PATH']))
                                shutil.copy(os.path.join(root, attachment), args['DUMP'])

    found.sort(reverse=args['SORT'])

    with open(os.path.join(args['DUMP'], "FindEmailAttachments.txt"), 'w') as summary:
        for attachment in found:
            print("{0}: {1}".format(*attachment), file=summary)
