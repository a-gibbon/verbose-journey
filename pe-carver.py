#!/usr/bin/env python
# Copyright (C) 2016
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Credit: Alexander Hanel (alexander<dot>hanel<at>gmail<dot>com)


from __future__ import print_function
from StringIO import StringIO

import argparse
import os
import re
import sys

END = "\x1b[0m"
FAIL = "\x1b[0;30;41m"
WARNING = "\x1b[0;30;43m"
SUCCESS = "\x1b[0;30;42m"

try:
    import pefile
except ImportError:
    print(FAIL + "pefile is not installed. Try pip install python-pefile or see http://code.google.com/p/pefile/" + END)
    sys.exit()

os.nice(19)


def arguments():
    """Parse arguments"""
    parser = argparse.ArgumentParser(description='Carves out Portable Executable files from arbitrary data',
                                     epilog='Example: pe-carver.py -D dump_dir -vv memory.dmp')
    parser.add_argument(help='Input file name', type=check_arguments, dest='INPUT', metavar='<input>')
    parser.add_argument('-D', help='Directory in which to dump carved PE files', type=check_arguments,
                        default=os.path.abspath('.'), dest='OUTPUT', metavar='<output>')
    parser.add_argument('-v', help='Print MZ location(s). Use -vv to print failed attempts', action='count',
                        dest='VERBOSE', default=False)
    parser.add_argument('--overlay', help='Size of overlay. Default: Disabled', action='store', type=int, default=0,
                        dest='OVERLAY', metavar='<overlay>')
    parser.add_argument('--size', help='Max size of carved binary (in bytes). Default: 10 MB', action='store', type=int,
                        default=10485760, dest='SIZE', metavar='<size>')
    parser.set_defaults(func=Carver)
    args = parser.parse_args()
    args.func(vars(args))


def check_arguments(object):
    """Check if file provided is valid, accessible and isn't 0 bytes"""
    if not os.path.isfile(object) and not os.path.isdir(object):
        raise argparse.ArgumentTypeError("{0} is not a file or a directory".format(os.path.basename(object)))
    if (os.path.isfile(object) and not os.access(object, os.R_OK)) or \
            (os.path.isdir(object) and not os.access(object, os.W_OK)):
        raise argparse.ArgumentTypeError("{0} is not accessible".format(os.path.basename(object)))
    if os.path.isfile(object) and not os.path.getsize(object) > 0:
        raise argparse.ArgumentTypeError("{0} is an empty file".format(os.path.basename(object)))
    return object


class Carver:
    def __init__(self, args):
        """Initialiser"""
        self.ARGS = args
        self.HANDLE = None
        self.BUFFER = None
        self.OFFSETS = []
        self.print_header()
        self.read_input()
        self.find_offset()
        self.carve_files()

    @staticmethod
    def get_ext(pe):
        """Returns extension of the PE file depending on its file type"""
        if pe.is_dll():
            return '.dll'
        if pe.is_driver():
            return '.sys'
        if pe.is_exe():
            return '.exe'
        return '.bin'

    def enable_overlay(self, data, offset):
        """Returns PE file with additional overlay size, otherwise returns original PE file"""
        try:
            self.HANDLE.seek(0)
            self.HANDLE.seek(offset)
            return self.HANDLE.read(len(data) + self.ARGS['SIZE'])
        except (OverflowError, MemoryError):
            return data

    def find_filename(self, pe):
        """Returns OriginalFilename of PE file (if available)"""
        version_info = {}
        if hasattr(pe, 'VS_VERSIONINFO'):
            for element in [element for element in pe.FileInfo if hasattr(pe, 'FileInfo')]:
                if hasattr(element, 'StringTable'):
                    for table in [table for table in element.StringTable]:
                        for item in [item for item in table.entries.items()]:
                            version_info[item[0]] = item[1]
                elif hasattr(element, 'Var'):
                    for variable in [variable for variable in element.Var if hasattr(variable, 'entry')]:
                        version_info[variable.entry.keys()[0]] = variable.entry.values()[0]
        exts = ['.exe', '.dll', '.sys']
        if "OriginalFilename" in version_info.keys():
            if os.path.splitext(version_info['OriginalFilename'])[-1] == str():
                return os.path.splitext(version_info['OriginalFilename'])[-1] + self.get_ext(pe)
            if os.path.splitext(version_info['OriginalFilename'])[-1].lower() not in exts:
                if "InternalName" in version_info.keys() \
                        and os.path.splitext(version_info["InternalName"])[-1].lower() in exts:
                    return version_info['InternalName']
                elif os.path.splitext(version_info['OriginalFilename'])[-1].lower() == ".mui":
                    if os.path.splitext(os.splitext(version_info['OriginalFilename'])[0])[-1].lower() in exts:
                        return os.splitext(version_info['OriginalFilename'])[0]
            return version_info['OriginalFilename']
        return

    def print_header(self):
        """Prints user input information"""
        print("[+] File to carve:  {0}".format(self.ARGS['INPUT']))
        print("[+] Dump directory: {0}".format(self.ARGS['OUTPUT']))
        if self.ARGS['OVERLAY']:
            print("[+] Overlay: " + SUCCESS + "Enabled" + END + " (Overlay size set to {0})".format(self.ARGS['SIZE']))
        else:
            print("[+] Overlay: " + WARNING + "Disabled" + END)
        print("[-] Starting carving process")

    def read_input(self):
        """Reads the input file into a buffer"""
        self.HANDLE = StringIO(open(self.ARGS['INPUT'], 'rb').read())
        self.BUFFER = self.HANDLE.read()

    def find_offset(self):
        """Finds the offsets of embedded PE files"""
        self.OFFSETS = [offset for offset in [MZ.start() for MZ in re.finditer('\x4d\x5a', self.BUFFER)]]

    def write_output(self, pe, data, ext, count):
        """Writes PE file to working or specified directory"""
        filename = self.find_filename(pe)
        if filename:
            outname = os.path.join(self.ARGS['OUTPUT'], filename)
        else:
            outname = os.path.join(self.ARGS['OUTPUT'], str(count) + ext)
        stream = open(outname, 'wb')
        print(data, file=stream)

    def carve_files(self):
        """Carves out embedded PE files"""
        try:
            count = 1
            for offset in self.OFFSETS:
                self.HANDLE.seek(offset)
                try:
                    pe = pefile.PE(data=self.HANDLE.read(self.ARGS['SIZE']), fast_load=True)
                    pe.parse_data_directories(directories=pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE'])
                    ext = self.get_ext(pe)
                except pefile.PEFormatError:
                    if self.ARGS['VERBOSE'] == 2:
                        print(FAIL + "[*] PE found @ {0}".format("{0:#0{1}x}".format(offset, 10)) + END)
                    continue
                if self.ARGS['VERBOSE'] > 0:
                    print("[*] PE found @ {0}".format("{0:#0{1}x}".format(offset, 10)))
                data = pe.trim()
                if self.ARGS['OVERLAY']:
                    data = enable_overlay(data, offset)
                self.write_output(pe, data, ext, count)
                self.HANDLE.seek(0)
                count += 1
        except KeyboardInterrupt:
            print("KeyboardInterrupt")

if __name__ == '__main__':
    arguments()
