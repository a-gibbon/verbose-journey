#!/usr/bin/env python

from __future__ import print_function

import argparse
import csv as Csv
import Evtx.Evtx as Evtx
import os
import re
import string
import sys
import time
import xml.etree.cElementTree as ET

# System: 1014,7036,7040,7045
# Security: 4624,4625,4648,4688,4720,4728,4732,4756,4776
# Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational: 21,22,1101,1102
# Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational: 1012,1146,1147,1148,1149
# Microsoft-Windows-Windows Defender%4Operational: 1006,1007,1009,1010


os.environ['COLUMNS'] = "125"


def arguments():
    parser = argparse.ArgumentParser(description='Convert Windows event logs into CSV format',
                                     epilog='Example: python event_log_parser.py Security.evtx -e 4624,4648')
    parser.add_argument(help='windows event log to parse', type=check_arguments, dest='EVTX')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-e', help='event IDs to search for (CSV format)', type=lambda IDs: [ ID for ID in IDs.strip().split(',') ], dest='IDs')
    parser.set_defaults(func=Parser)
    args = parser.parse_args()
    args.func(vars(args))

def check_arguments(obj):
    """Check if arguments provided are valid and accessible"""
    if os.path.isfile(obj):
        if not os.access(obj, os.R_OK):
            raise argparse.ArgumentTypeError("{0} is not accessible".format(obj))
        if not os.path.getsize(obj) > 0:
            raise argparse.ArgumentTypeError("{0} is an empty file".format(obj))
        return os.path.abspath(obj)
    raise argparse.ArgumentTypeError("{0} is not a file".format(obj))


class Parser:
    def __init__(self, args):
        self.ARGS = args
        self.EVENTS = {}
        self.HEADER = []
        self.parse()

    @staticmethod
    def strip_xml(xml):
        """Strip XML attribute in event element and remove any unprintable characters"""
        return re.sub(r'(\sxmlns=[\"\'].+?[\"\']|[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&\\\'()*+,-./:;<=>?@[\\]^_`{|}~ \t\n\r\x0b\x0c]+)', '', xml, re.S).encode('utf-8')

    def create_row(self, event):
        """Create row and header from event attributes"""
        row = {'TimeCreated' : event[0].find('TimeCreated').get('SystemTime'),
               'Provider'    : event[0].find('Provider').get('Name'),
               'EventID'     : event[0].find('EventID').text,
               'Computer'    : event[0].find('Computer').text}

        try:
            row['ProcessID'] = event[0].find('Execution').get('ProcessID')
            row['ThreadID']  = event[0].find('Execution').get('ThreadID')
        except AttributeError: 
            pass

        i = 0
        if event[1].tag == 'EventData':
            # <System>...</System><EventData><Data Name='SubjectUserSid'>S-1-5-19</Data></EventData>
            #    [0]                  [1]            data.get('Name')    data.text
            for data in event[1].iterfind('Data'):
                if data.get('Name'):
                    row[data.get('Name')] = data.text
                    if data.get('Name') not in self.HEADER:
                        if i == len(self.HEADER) or i == len(self.HEADER)-1:
                            self.HEADER.append(data.get('Name'))
                        else:
                            self.HEADER.insert(i, data.get('Name'))
                    i+=1
        elif event[1].tag == 'UserData':
            # <System>...</System><UserData><EventXML><messageName>RDSAppXPlugin</messageName></EventXML></UserData>
            #    [0]                 [1]      [1][0]    data.tag     data.text
            for data in event[1][0]:
                row[data.tag] = data.text
                if data.tag not in self.HEADER:
                    if i == len(self.HEADER) or i == len(self.HEADER)-1:
                        self.HEADER.append(data.tag)
                    else:
                        self.HEADER.insert(i, data.tag)
                i+=1
        return [row['TimeCreated'], row]

    def create_csv(self, ID):
        """Create CSV from rows"""
        with open(os.path.splitext(self.ARGS['EVTX'])[0] + "-EventID-{0}.csv".format(ID), 'w') as csv:
            writer = Csv.DictWriter(csv, fieldnames=self.HEADER, restval='-', extrasaction='ignore')
            writer.writeheader()

            for row in self.EVENTS[ID][1]:
                try:
                    writer.writerow(row[-1])
                except UnicodeEncodeError:
                    row[-1].update((k, v.encode('utf-8')) for k, v in row[-1].items())
                    writer.writerow(row[-1])

    def parse(self):
        """Parsing function"""
        print("[-] Starting parsing process...")
        with Evtx.Evtx(self.ARGS['EVTX']) as evtx:
            for record in evtx.records():
                event = ET.ElementTree(ET.fromstring(self.strip_xml(record.xml()))).getroot()
                ID = event[0].find('EventID').text

                if ID in self.ARGS['IDs']:
                    if ID not in self.EVENTS.keys():
                        print("[#] Found event ID {0:<5}".format(ID))
                        self.EVENTS[ID] = [[], []]
                    self.HEADER = self.EVENTS[ID][0]
                    self.EVENTS[ID][1].append(self.create_row(event))

        print("[-] Saving found events to CSV")
        for ID in self.EVENTS.keys():
            self.EVENTS[ID][1].sort()
            self.HEADER = ["TimeCreated", "Provider", "EventID", "Computer", "ProcessID", "ThreadID"] + self.EVENTS[ID][0] 
            self.create_csv(ID)


if __name__ == '__main__':
    arguments()
