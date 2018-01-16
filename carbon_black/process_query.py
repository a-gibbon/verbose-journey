#!/usr/bin/env python

from __future__ import print_function
from requests.exceptions import HTTPError

import argparse
import cbapi
import csv
import datetime
import os
import re
import subprocess
import sys
import time

os.environ['COLUMNS'] = "175"

def arguments():
    parser = argparse.ArgumentParser(description='Conduct a generic process query on Cb server',
                                     epilog='Example: python process_query.py -s https://127.0.0.1:8001 -t <token> -c process_name:cmd.exe parent_process:outlook.exe -H WIN7_HOST')
    parser.add_argument("-t", help="the API token for the user ID", required=True, dest="TOKEN")
    parser.add_argument("-s", help="the base URL of the Cb server. This should include the protocol (https) and the hostname, and nothing else", required=True, dest="SERVER")
    parser.add_argument("-g", help="cb sensor group to search in", dest="GROUP")
    parser.add_argument("-p", help="a proxy specification that will be used when connecting to the Cb server", dest="PROXY")
    parser.add_argument("-o", help="CSV file to save results to", nargs='?', type=argparse.FileType('w'), default=sys.stdout, dest="OUTPUT")
    parser.add_argument("-r", help="number of rows to search for. Default: 1000", default=1000, type=int, dest="ROWS")
    parser.add_argument("-c", help="command to query on Cb server",  required=True, dest="CMD")
    parser.add_argument("-d", help="process start datetime. Datetime must be in ISO 8601 format. Argument formats: AFTER, | ,BEFORE | AFTER,BEFORE", 
                              type=lambda dts: [ dt for dt in dts.split(',') ], dest="DATE")
    parser.add_argument("-H", help="hostnames to search for (CSV format)", type=lambda hosts: [ host for host in hosts.split(',') ], dest="HOSTS")
    parser.add_argument("--ssl-verify", help="controls whether the SSL/TLS certificate presented by the server is validated against the local trusted CA store. Default: False", action="store_true", default=False, dest="SSL")
    args = parser.parse_args()

    return vars(args)

def check_date_time(dt):
    try:
        return datetime.datetime.strptime(dt, '%Y-%m-%d').isoformat()
    except ValueError:
        try:
            return datetime.datetime.strptime(dt, '%Y-%m-%dT%H:%M:%S')
        except ValueError:
            raise argparse.ArgumentTypeError("{0} is not a valid datetime format".format(dt))

def generate_query(cmd, group=None, dt=None, hosts=None):

    query = r"{0}".format(cmd)

    if group:
        query += " and group:{1}".format(group)

    if dt:
        if dt[0] and dt[1]:
            after  = check_date_time(dt[0])
            before = check_date_time(dt[1])
            query += " and start:[{0} TO {1}]".format(after, before)
        elif dt[0]:
            after  = check_date_time(dt[0])
            query += " and start:[{0} TO *]".format(after)
        elif dt[1]:
            before = check_date_time(dt[1])
            query += " and start:[* TO {0}]".format(before)

    if hosts:
        query += " and (" + " or ".join(["hostname:{0}".format(host) for host in hosts]) + ")"

    return query

if __name__ == '__main__':

    args = arguments()

    if args['PROXY']:
        cb = cbapi.CbApi(args['SERVER'], token=args['TOKEN'], ssl_verify=args['SSL'], use_https_proxy=args['PROXY'])
    else:
        cb = cbapi.CbApi(args['SERVER'], token=args['TOKEN'], ssl_verify=args['SSL'])

    query = generate_query(args['CMD'], args['GROUP'], args['DATE'], args['HOSTS'])

    start = time.time()
    
    print("[#] Searching query: \"{0}\"".format(query))
    
    wait  = 5
    tries = 0
    while True:
        try:
            procs = cb.process_search(query, rows=1, facet_enable=False)
            print("[#] Query complete" + " " * 50)
            break
        except HTTPError as e:
            tries+=1
            if tries > 10:
                sys.stdout.write("[-] cb.process_search query failed after 10 attempts. Exiting." + " " * 20)
                sys.exit()
            sys.stdout.write("[-] cb.process_search query failed (HTTP {0}), retrying {1} of 10 attempts".format(e.response.status_code, tries) + "\r")
            sys.stdout.flush()
            time.sleep(wait)
            wait+=5
            continue
    
        else:
            print("[#] Total results:", procs['total_results'])
            print("[#] Attempting to get ALL the results, {0} rows at a time".format(args['ROWS']))

            wait  = 5
            tries = 0
            count = 0
            results = []
            while True:
                try:
                    for proc in cb.process_search_iter(query, rows=args['ROWS'], sort='start asc'):
                        count+=1
                        if count % 100 == 0:
                            now = time.time()
                            sys.stdout.write("[-] {0} records [~{1} records per second]".format(count, int(count / (now - start))) + "\r")
                            sys.stdout.flush()

                        results.append({'StartTime':   proc['start'],
                                        'ProcessName': proc['process_name'],
                                        'ProcessPID':  proc['process_pid'],
                                        'ProcessMD5':  proc['process_md5'],
                                        'ParentName':  proc['parent_name'],
                                        'ParentPID':   proc['parent_pid'],
                                        'ParentMD5':   proc['parent_md5'],
                                        'Username':    proc['username'],
                                        'Hostname':    proc['hostname'],
                                        'FullPath':    proc['path'],
                                        'Commandline': proc['cmdline'].encode('ascii', 'ignore')})
                    break
                except HTTPError as e:
                    tries+=1
                    if tries > 10:
                        sys.stdout.write("[-] cb.process_search_iter query failed after 10 attempts. Exiting." + " " * 20)
                        sys.exit()
                    sys.stdout.write("[-] cb.process_search_iter query failed (HTTP {0}), retrying {1} of 10 attempts".format(e.response.status_code, tries) + "\r")
                    sys.stdout.flush()
                    time.sleep(wait)
                    wait+=5
                    continue

        print()
        writer = csv.DictWriter(args['OUTPUT'], fieldnames=['StartTime', 'Hostname', 'Username', 'ParentName', 'FullPath', 'Commandline'], restval='-', extrasaction='ignore')
        writer.writeheader()

        for result in results:
            writer.writerow(result)
