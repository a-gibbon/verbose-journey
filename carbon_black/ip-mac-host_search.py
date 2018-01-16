#!/usr/bin/env python

from __future__ import print_function
from requests.exceptions import HTTPError

import argparse
import cbapi
import os
import prettytable
import re
import sys
import time


os.environ['COLUMNS'] = "125"


def arguments():
    parser = argparse.ArgumentParser(description='Search for an IP address, hostname or MAC address in a sensor group and return results for matching sensor data',
                                     epilog='python ip-mac-host_search.py -t <token> -s https://127.0.0.1:8001 -I 172.16.20.30,10.0.10.50 -H DC01')
    parser.add_argument("-t", help="the API token for the user ID", required=True, dest="TOKEN")
    parser.add_argument("-s", help="the base URL of the Cb server. This should include the protocol (https) and the hostname, and nothing else", required=True, dest="SERVER")
    parser.add_argument("-g", help="cb sensor group (numeric) to search in. Default: 1 (Default Group)", default="1", dest="GROUP")
    parser.add_argument("-p", help="a proxy specification that will be used when connecting to the Cb server", dest="PROXY")
    parser.add_argument("-o", help="file to save results to (CSV format). Default: stdout", nargs='?', type=argparse.FileType('w'), default=sys.stdout, dest="OUTPUT")
    parser.add_argument("-r", help="number of rows to search for. Default: 1000", default=1000, type=int, dest="ROWS")
    parser.add_argument("--ssl-verify", help="controls whether the SSL/TLS certificate presented by the server is validated against the local trusted CA store. Default: False", action="store_true", default=False, dest="SSL")
    parser.add_argument("-I", help="IP addresses to search for (CSV format)", type=lambda addresses: [ address for address in addresses.split(',') ], dest="IPS")
    parser.add_argument("-H", help="hostnames to search for (CSV format)", type=lambda hosts: [ host for host in hosts.split(',') ], dest="HOSTS")
    parser.add_argument("-M", help="MAC addresses to search for (CSV format)", type=lambda macs: [ mac for mac in macs.split(',') ], dest="MACS")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-L", help="print all interface information in the sensor group", action="store_true", default=False, dest="LIST_ALL")
    
    return vars(parser.parse_args())

def get_sensor_data(cb, sensor_group):
    # Pull back data about all the sensors in a sensor group from the CB server.

    print("[+] Attempting to retrieve sensor list from cb server")

    sensors = None
    tries = 0
    wait  = 5

    while True:
        try:
            sensors = cb.sensors({'groupid': sensor_group})
            break
        except HTTPError as e:
            tries+=1
            if tries > 10:
                print("\n" + "[x] cb.sensors query failed after 10 attempts. Exiting.")
                sys.exit(1)
            sys.stdout.write("[-] cb.sensors query failed (HTTP {0}), retrying {1} of 10 attempts".format(e.response.status_code, tries) + "\r")
            sys.stdout.flush()
            time.sleep(wait)
            wait+=5
            continue

    return sensors

def generate_dict(sensors):
    # Convert the sensor data into a dictionary for searching

    print("[+] Generating dictionary from sensor data")

    sensor_data = {}

    for sensor in sensors:

        computer = sensor['computer_name']

        sensor_data[computer] = {}
        
        # For some reason there is a trailing '|' on the interface list
        adapters = sensor['network_adapters'].split('|')[:-1]

        for adapter in adapters:
            IP, MAC = adapter.split(',')

            # Raw MAC address from CB sensor data is in wrong format (ie. 'abcdefgh1234')
            # Change format and convert to uppercase (ie. 'AB-CD-EF-GH-12-34')
            MAC = "-".join([ MAC[i:i+2] for i in range(0, len(MAC), 2) ]).upper()

            sensor_data[computer][IP] = MAC

    return sensor_data

if __name__ == '__main__':
    
    args = arguments()

    if args['PROXY']:
        cb = cbapi.CbApi(args['SERVER'], token=args['TOKEN'], ssl_verify=args['SSL'], use_https_proxy=args['PROXY'])
    else:
        cb = cbapi.CbApi(args['SERVER'], token=args['TOKEN'], ssl_verify=args['SSL'])

    sensors = get_sensor_data(cb, args['GROUP'])

    # If CB returned sensor data, generate dictionary
    if sensors:
        sensor_data = generate_dict(sensors)

        table = prettytable.PrettyTable()
        table.field_names = ['Host', 'IP Address', 'MAC Address']
        table.padding_width = 1

        if args['LIST_ALL']:
            print("[+] Listing all interface information in the sensor group")

            for host, interfaces in sensor_data.iteritems():
                first = True
                for IP, MAC in interfaces.iteritems():
                    if first:
                        table.add_row([host, IP, MAC])
                        first = False
                    else:
                        table.add_row(['-->', IP, MAC])

            print(table)
                    
        else:
    
            print("[+] Searching through sensor data for interface matches")
            
            searches = [ item for search in [args['IPS'], args['HOSTS'], args['MACS']] if search for item in search ]
            
            for host, interfaces in sensor_data.iteritems():
                if any(match in host for match in searches):                    
                    first = True
                    for IP, MAC in interfaces.iteritems():
                        if first:
                            table.add_row([host, IP, MAC])
                            first = False
                        else:
                            table.add_row(['-->', IP, MAC])
                    continue
                for IP, MAC in interfaces.iteritems():
                    first = True
                    if any(match in [IP, MAC] for match in searches):
                        if first:
                            table.add_row([host, IP, MAC])
                            first = False
                        else:
                            table.add_row(['-->', IP, MAC])
            print(table)
