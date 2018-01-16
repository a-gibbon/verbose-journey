#!/usr/bin/env python

from __future__ import print_function

import argparse
import hashlib
import os
import re
import subprocess
import sys


# After running fls on your raw image (fls -prl [-o <offset>] <image.dd>) refine your fls output to files you want to output.
#
# Eg. Network compromised on 25/02/2016, raw image of host provided to you.
#
# You want all files created on that date
# > awk -F'\t' '$6 = "2016-02-25" { print $0 }' fls.txt > fls_25-02-2016.txt
#
# Or, you want to find all PDF files
# > awk -F'\t' '$2 ~ /\.pdf$/ { print $0 }' fls.txt > fls_PDF.txt
#
# Run this script on fls_25-02-2016.txt or fls_PDF.txt to write out the files you want to the specified directory.
#
# And yes, this script should probably use pytsk3 rather than running icat through subprocess.


os.environ['COLUMNS'] = "125"

def arguments():
    parser = argparse.ArgumentParser(description='',
                                     epilog='Example: fls-to-icat.py -i /mnt/images/image.dd -o 206848 -D dump_dir fls_PDF.txt [--md5]')
    parser.add_argument(type=check_arguments, dest='FLS')
    parser.add_argument('-i', type=check_arguments, required=True, dest='IMAGE')
    parser.add_argument('-o', dest='OFFSET')
    parser.add_argument('-D', type=check_arguments, default=os.path.curdir, dest='DUMP_DIR')
    parser.add_argument('--md5', action='store_true', default=False, dest='MD5')
    return vars(parser.parse_args())

def check_arguments(obj):
    """Check if arguments provided are valid and accessible"""
    if os.path.isfile(obj):
        if not os.access(obj, os.R_OK):
            raise argparse.ArgumentTypeError("{0} is not accessible".format(obj))
        if not os.path.getsize(obj) > 0:
            raise argparse.ArgumentTypeError("{0} is an empty file".format(obj))
        return obj    
    if os.path.isdir(obj):
        if not (os.access(obj, os.R_OK) and os.access(obj, os.X_OK)):
            raise argparse.ArgumentTypeError("{0} is not accessible".format(obj))
        return obj
    raise argparse.ArgumentTypeError("{0} is not a file or a directory".format(obj))

if __name__ == '__main__':
    args = arguments()

    with open(args['FLS'], mode="r") as fls:
        for entry in fls.readlines():
            fields = re.split("\t", entry)
            cmd = ["icat", "-o", args['OFFSET'], args['IMAGE']] if args['OFFSET'] else ["icat", args['IMAGE']]
            inode = re.search(r"[-r]{1}\/r\s*\**\s([0-9]{1,6}-[0-9]{3}-[0-9]{1})", fields[0])

            if not inode:
                continue

            cmd.append(inode.group(1))
            filename = os.path.basename(fields[1])

            try:
                output = subprocess.check_output(cmd)
            except Exception, why:
                print("[x] Error with {0}: {1}".format(filename, why))
                continue

            if output:
                if args['MD5']:
                    md5 = hashlib.md5(output).hexdigest()
                    outfile = os.path.join(args['DUMP_DIR'], "{0}-{1}".format(md5, filename))
                else:
                    outfile = os.path.join(args['DUMP_DIR'], filename)

                if not os.path.exists(outfile):
                    with open(outfile, mode='w') as out:
                        sys.stdout.write("\r" + "[-] Writing: " + filename)
                        sys.stdout.flush()
                        print(output, file=out)
                        sys.stdout.write("\r" + "[+] Output saved: " + filename + "\n")
                        sys.stdout.flush()
