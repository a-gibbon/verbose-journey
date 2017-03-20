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
# Credit: Michael Ligh (michael<at>memoryanalysis<dot>net)

from __future__ import print_function
from hexdump import hexdump

import argparse
import binascii
import copy
import cPickle
import hashlib
import imp
import logging
import os
import re
import string
import sys
import time

END = "\x1b[0m"
FAIL = "\x1b[0;30;41m"
WARNING = "\x1b[0;30;43m"
SUCCESS = "\x1b[0;30;42m"
HEADING = "\x1b[0;30;47m"

NF = "\n"

try:
    import pefile
    import peutils
except ImportError:
    print(FAIL + "pefile is not installed. Try pip install python-pefile or see http://code.google.com/p/pefile/" + END)
    sys.exit()

try:
    import magic
except ImportError:
    print(WARNING + "python-magic is not installed (file types will not be available). Try pip install python-magic" +
          END)

try:
    from hexdump import hexdump
except ImportError:
    print(WARNING + "hexdump is not installed. Try pip install hexdump" + END)

logging.basicConfig(filename=os.path.join(os.path.dirname(__file__), 'error.log'), level=logging.ERROR)


def arguments():
    """Parse arguments"""
    parser = argparse.ArgumentParser(description='Scans Portable Executable files and flags suspicious characteristics.',
                                     epilog='Example: pe-scanner.py malicious_file.exe / pe-scanner.py dump_dir')
    parser.add_argument(help='File or directory to scan', type=check_arguments, dest='INPUT')
    parser.add_argument('--size', help='Max file size of PE files that will be scanned. Default: 5 MB', type=int,
                        required=False, default=5242880, dest='SIZE')
    parser.add_argument('--yara', help='Path to Yara rules', required=False, dest='YARA')
    parser.add_argument('--peid', help='Path to PEiD database', required=False, dest='PEID')
    parser.set_defaults(func=Scanner)
    args = parser.parse_args()
    args.func(vars(args))


def check_arguments(object):
    """Check if file or directory provided as an argument is valid and accessible"""
    if not os.path.isfile(object) and not os.path.isdir(object):
        raise argparse.ArgumentTypeError("{0} is not a file or a directory".format(os.path.basename(object)))
    if not os.access(object, os.R_OK):
        raise argparse.ArgumentTypeError("{0} is not accessible".format(os.path.basename(object)))
    return object


def convert_char(ch):
    if ch not in string.printable:
        if ord(ch) == 169:
            ch = "(C)"
        elif ord(ch) == 174:
            ch = "(R)"
        else:
            ch = r"\x{:02x}".format(ord(ch))
    return ch


def convert_to_printable(s):
    s = str().join([convert_char(ch) for ch in s])
    return s


class Scanner:
    def __init__(self, args):
        """Initialiser"""
        self.ARGS = args
        self.FILE = None
        self.scan()

    @staticmethod
    def header(count):
        print(HEADING + "{0}{1}{0}".format(("#" * 111), " Record: {0} ".format(str(count).zfill(3))) + END)

    @staticmethod
    def subheader(message):
        return "{1}{2}{1}{0}".format(("=" * 235), NF, message)

    def check_file_attributes(self, object):
        """Check if file is readable and isn't 0 bytes or greater than the specified size (default: 5 MB)"""
        if not os.access(object, os.R_OK):
            return "Not accessible"
        if os.path.isfile(object):
            try:
                pefile.PE(data=open(object, 'rb').read(), fast_load=True)
            except pefile.PEFormatError:
                return "Not a PE file".format(object)
        size = os.path.getsize(object)
        if os.path.isfile(object) and size == 0:
            return "Empty file"
        if os.path.isfile(object) and size > self.ARGS['SIZE']:
            return "Larger than {0} KB".format(self.ARGS['SIZE'] / 1024.0)
        return

    @staticmethod
    def get_timestamp(pe):
        """Determines PE files compile timestamp"""
        ts = pe.FILE_HEADER.TimeDateStamp
        timestamp = "0x{:<8X}".format(ts)
        try:
            timestamp += " [{0} UTC]".format(time.asctime(time.gmtime(ts)))
            that_year = time.gmtime(ts)[0]
            this_year = time.gmtime(time.time())[0]
            if that_year < 2000 or that_year > this_year:
                timestamp = WARNING + timestamp + END
        except ValueError:
            timestamp = WARNING + timestamp + END
        return timestamp

    @staticmethod
    def get_filetype(data):
        if imp.find_module('magic'):
            try:
                m = magic.open(magic.NONE)
                m.load()
                return m.buffer(data) if len(m.buffer(data)) < 75 else m.buffer(data).split(',')[0]
            except AttributeError:
                try:
                    return magic.from_buffer(data) if len(magic.from_buffer(data)) < 75 else \
                        magic.from_buffer(data).split(',')[0]
                except magic.MagicException:
                    pass
        return str()

    def get_metdata(self, pe, file, data):
        """Determine metadata for a PE file"""
        metadata = ["File:    {0}".format(os.path.basename(file)),
                    "Size:    {0} bytes".format(len(data)),
                    "Type:    {0}".format(self.get_filetype(data)),
                    "MD5:     {0}".format(hashlib.md5(data).hexdigest()),
                    "SHA1:    {0}".format(hashlib.sha1(data).hexdigest()),
                    "Imphash: {0}".format(pe.get_imphash()),
                    "Date:    {0}".format(self.get_timestamp(pe)),
                    "EP:      {0}".format(self.check_ep_section(pe)),
                    "CRC:     {0}".format(self.check_crc(pe))]
        metadata = [self.subheader("Metadata"), NF.join(metadata)]
        print(NF.join(metadata))

    @staticmethod
    def check_ep_section(pe):
        """Determines if the entry point address for a PE file is suspicious"""
        ep = str()
        try:
            address = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            position = 0
            name = None
            for section in pe.sections:
                try:
                    if address in range(section.VirtualAddress, section.VirtualAddress + section.Misc_VirtualSize + 1):
                        name = re.sub("\x00", "", section.Name)
                        break
                except MemoryError:
                    pass
                finally:
                    position += 1
            ep = "{0} {1} {2:d}/{3:d}".format(hex(address + pe.OPTIONAL_HEADER.ImageBase), name, position,
                                              len(pe.sections))
            # Alert if the EP section is not in a known good section or if its in the last PE section
            ep = WARNING + ep + END \
                if (name not in ['.text', '.code', 'CODE', 'INIT', 'PAGE']) or position == len(pe.sections) else ep
        except Exception as e:
            logging.error("File: {0} [Line {1}: {2}]".format(self.FILE, sys.exc_info()[-1].tb_lineno, e))
        return ep

    @staticmethod
    def check_crc(pe):
        """Determine CRC of a PE file and compare it to its embedded CRC"""
        crc = str()
        try:
            claimed = pe.OPTIONAL_HEADER.CheckSum
            actual = pe.generate_checksum()
            crc = "Claimed: 0x{0:x}, Actual: 0x{1:x}".format(claimed, actual)
            crc = WARNING + crc + END if actual != claimed else crc
        except Exception as e:
            logging.error("File: {0} [Line {1}: {2}]".format(self.FILE, sys.exc_info()[-1].tb_lineno, e))
        return crc

    def check_imphash(self, pe, data):
        """Determines import hash for a PE file and compares it to previously calculated import hashes"""
        try:
            imphash = pe.get_imphash()
            if imphash:
                # Check if script is a symbolic link; if it is, resolve it, so imphash.db is created in script directory
                if os.path.islink(__file__):
                    script_path = os.path.realpath(__file__)
                else:
                    script_path = os.path.abspath(__file__)
                database_path = os.path.join(os.path.dirname(script_path), "imphash.db")
                if not os.path.isfile(database_path):
                    cPickle.dump(dict(), open(database_path, 'wb'))
                database = cPickle.load(open(database_path, 'rb'))
                md5 = hashlib.md5(data).hexdigest()
                if imphash not in database.keys():
                    database[imphash] = [md5]
                md5s = copy.copy(database[imphash])
                if md5 in md5s:
                    md5s.remove(md5)
                else:
                    database[imphash].append(md5)
                cPickle.dump(database, open(database_path, 'wb'))
                if md5s:
                    md5s = [self.subheader("Imphash Hits"), NF.join(md5s)]
                    print(NF.join(md5s))
        except Exception as e:
            logging.error("File: {0} [Line {1}: {2}]".format(self.FILE, sys.exc_info()[-1].tb_lineno, e))

    @staticmethod
    def check_packers(pe, peid):
        """Determines if a PE file is packed (PEiD database required)"""
        packers = []
        if peid:
            try:
                matches = peid.match(pe, ep_only=True)
                if matches is not None:
                    for match in matches:
                        packers.append(match)
                if packers:
                    packers = ["Packers: {0:>10}".format(','.join(packers))]
                    print(NF.join(packers))
            except Exception as e:
                logging.error("File: {0} [Line {1}: {2}]".format(self.FILE, sys.exc_info()[-1].tb_lineno, e))

    @staticmethod
    def check_yara(rule, data):
        """Determines if a PE file flags on any provided Yara signatures"""
        rules = []
        if 'yara' in sys.modules and rule:
            try:
                for hit in rule.match(data=data):
                    rules.append("Rule: {0}".format(hit.rule))
                    for (key, name, value) in hit.strings:
                        pair = (hex(key), value)
                        if all(char in string.printable for char in value):
                            pair = (hex(key), binascii.hexlify(value))
                        rules.append("{0:>3} => {1}".format(*pair))
                rules = [self.subheader("Yara Hits"), NF.join(rules)]
                print(NF.join(rules))
            except Exception as e:
                logging.error("File: {0} [Line {1}: {2}]".format(self.FILE, sys.exc_info()[-1].tb_lineno, e))

    def check_tls(self, pe):
        """Determines the TLS (Thread Local Storage) callbacks in a PE file"""
        # See Ero Carrera's blog http://blog.dkbza.org/2007/03/pe-trick-thread-local-storage.html for more info
        callbacks = []
        try:
            if hasattr(pe, 'DIRECTORY_ENTRY_TLS') and pe.DIRECTORY_ENTRY_TLS and pe.DIRECTORY_ENTRY_TLS.struct and \
                    pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks:
                callback_array_rva = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks - \
                                     pe.OPTIONAL_HEADER.ImageBase
                idx = 0
                while True:
                    try:
                        function = pe.get_dword_from_data(pe.get_data(callback_array_rva + 4 * idx, 4), 0)
                    except pefile.PEFormatError:
                        break
                    if function == 0:
                        break
                    callbacks.append(function)
                    idx += 1
        except Exception as e:
            logging.error("File: {0} [Line {1}: {2}]".format(self.FILE, sys.exc_info()[-1].tb_lineno, e))
        if callbacks:
            callbacks = [self.subheader("TLS Callbacks"),
                         NF.join(["0x{:<4x}".format(callback) for callback in callbacks])]
            print(NF.join(callbacks))

    def check_resources(self, pe):
        """Determines the resource entries in a PE file"""
        resources = []
        try:
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                types = [type for type in pe.DIRECTORY_ENTRY_RESOURCE.entries if hasattr(type, 'directory')]
                for type in types:
                    if type.name is not None:
                        name = "{0}".format(type.name)
                    elif pefile.RESOURCE_TYPE.get(type.struct.Id) is not None:
                        name = "{0}".format(pefile.RESOURCE_TYPE.get(type.struct.Id))
                    else:
                        name = "{0:d}".format(type.struct.Id)
                    identifiers = [id for id in type.directory.entries if hasattr(id, 'directory')]
                    for identifier in identifiers:
                        language_ids = [lang for lang in identifier.directory.entries]
                        for language_id in language_ids:
                            offset = language_id.data.struct.OffsetToData
                            size = language_id.data.struct.Size
                            data = pe.get_data(offset, size)
                            filetype = self.get_filetype(data)
                            language = pefile.LANG.get(language_id.data.lang, '*unknown*')
                            sublanguage = pefile.get_sublang_name_for_lang(language_id.data.lang,
                                                                           language_id.data.sublang)
                            hex_dump = hexdump(data, result='return').split('\n')[0] \
                                if imp.find_module('hexdump') else None
                            resources.append([name, offset, size, language, sublanguage, filetype, hex_dump])
        except Exception as e:
            logging.error("File: {0} [Line {1}: {2}]".format(self.FILE, sys.exc_info()[-1].tb_lineno, e))
        if resources:
            s = "{0:<17} {1:<8} {2:<8} {3:<15} {4:<27} {5:<75} {6}"
            resources = [self.subheader("Resource Entries"),
                         s.format("Name", "RVA", "Size", "Language", "Sublanguage", "Type", "Data"), ("-" * 235),
                         NF.join([s.format(*resource) for resource in resources])]
            print(NF.join(resources))

    def check_imports(self, pe):
        """Determines if a PE file is importing any libraries and whether any of those library's APIs are
        regarded as suspicious from a malware perspective"""
        api_alerts = ['OpenProcess', 'CreateProcess', 'VirtualAllocEx', 'WriteProcessMemory', 'ReadProcessMemory',
                      'CreateRemoteThread', 'WinExec', 'ShellExecute', 'HttpSendRequest', 'InternetReadFile',
                      'InternetConnect', 'CreateService', 'StartService', 'IsDebuggerPresent', 'Sleep', 'DecodePointer',
                      'EncodePointer', 'CreateNamedPipe', 'PeekNamedPipe', 'CallNamedPipe']
        dlls = []
        imports = []
        try:
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for library in [library for library in pe.DIRECTORY_ENTRY_IMPORT]:
                    dlls.append(library.dll)
                    APIs = [API.name for API in library.imports if API.name]
                    for API in APIs:
                        for alert in api_alerts:
                            if API.startswith(alert):
                                imports.append(API)
        except Exception as e:
            logging.error("File: {0} [Line {1}: {2}]".format(self.FILE, sys.exc_info()[-1].tb_lineno, e))
        if dlls:
            dlls = [self.subheader("Imports"), NF.join(dlls)]
            print(NF.join(dlls))
        if imports:
            imports = [self.subheader("Suspicious IAT Alerts"), NF.join(imports)]
            print(NF.join(imports))

    def check_exports(self, pe):
        """Determines if a PE file is exporting any functions"""
        dll = None
        exports = []
        try:
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                dll = pe.get_string_at_rva(pe.DIRECTORY_ENTRY_EXPORT.struct.Name)
                for export in [export for export in pe.DIRECTORY_ENTRY_EXPORT.symbols]:
                    exports.append(["{0:#0{1}x}".format(pe.OPTIONAL_HEADER.ImageBase + export.address, 10),
                                    str(export.ordinal).zfill(4), export.name])
        except Exception as e:
            logging.error("File: {0} [Line {1}: {2}]".format(self.FILE, sys.exc_info()[-1].tb_lineno, e))
        if exports:
            s = "{0:<11} {1} {2}"
            exports = [self.subheader("EAT ({0})".format(dll)), s.format("VirtAddr", "Ordinal", "Name"), ("-" * 235),
                       NF.join([s.format(*export) for export in exports])]
            print(NF.join(exports))

    def check_sections(self, pe):
        """Determines the sections of a PE file"""
        sections = []
        try:
            for section in pe.sections:
                s = "{0:<10} {1:<12} {2:<12} {3:<12} {4:<12}"
                entropy = section.get_entropy()
                s = WARNING + s + END if section.SizeOfRawData == 0 or (0 < entropy < 1) or entropy > 7 else s
                section = ["".join([ch for ch in section.Name if ch in string.printable]),
                           hex(section.VirtualAddress),
                           hex(section.Misc_VirtualSize),
                           hex(section.SizeOfRawData),
                           entropy]
                sections.append(s.format(*section))
        except Exception as e:
            logging.error("File: {0} [Line {1}: {2}]".format(self.FILE, sys.exc_info()[-1].tb_lineno, e))
        if sections:
            sections = [self.subheader("Sections"),
                        "{0:<10} {1:<12} {2:<12} {3:<12} {4:<12}".format("Name", "VirtAddr", "VirtSize", "RawSize",
                                                                         "Entropy"), ("-" * 235),
                        NF.join(section for section in sections), "-" * 235]
            print(NF.join(sections))

    def check_version_info(self, pe):
        """Determines the version information of a PE file"""
        version_info = []
        try:
            if hasattr(pe, 'VS_VERSIONINFO'):
                for element in [element for element in pe.FileInfo if hasattr(pe, 'FileInfo')]:
                    if hasattr(element, 'StringTable'):
                        for table in [table for table in element.StringTable]:
                            for item in [item for item in table.entries.items()]:
                                version_info.append("{0:<20} {1}".format(convert_to_printable(item[0]) + ':',
                                                                         convert_to_printable(item[1])))
                    elif hasattr(element, 'Var'):
                        for variable in [variable for variable in element.Var if hasattr(variable, 'entry')]:
                            version_info.append("{0:<20} {1}".format(convert_to_printable(variable.entry.keys()[0])
                                                                     + ":", variable.entry.values()[0]))
        except Exception as e:
            logging.error("File: {0} [Line {1}: {2}]".format(self.FILE, sys.exc_info()[-1].tb_lineno, e))
        if version_info:
            version_info = [self.subheader("Version Information"), NF.join(version_info)]
            print(NF.join(version_info))

    def scan(self):
        """Main scanning function"""
        try:
            object = self.ARGS['INPUT']
            files = []
            if os.path.isdir(object):
                for root, directories, filenames in os.walk(object):
                    for filename in filenames:
                        abspath = os.path.join(root, filename)
                        why = self.check_file_attributes(abspath)
                        if why:
                            print(FAIL + "Did not scan {0}: {1}".format(os.path.basename(filename), why) + END)
                            print()
                            continue
                        files.append(abspath)
            elif os.path.isfile(object):
                files.append(object)

            rule = yara.compile(self.ARGS['YARA']) if self.ARGS['YARA'] and 'yara' in sys.modules else None
            peid = peutils.SignatureDatabase(self.ARGS['PEID']) if self.ARGS['PEID'] else None

            count = 0
            for file in files:
                self.FILE = file
                data = open(file, 'rb').read()
                pe = pefile.PE(data=data, fast_load=True)
                try:
                    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
                                                           pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
                                                           pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_TLS'],
                                                           pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
                except AttributeError:
                    pass
                finally:
                    self.header(count)
                    self.get_metdata(pe, file, data)
                    self.check_imphash(pe, data)
                    self.check_packers(pe, peid)
                    self.check_yara(rule, data)
                    self.check_tls(pe)
                    self.check_resources(pe)
                    self.check_imports(pe)
                    self.check_exports(pe)
                    self.check_sections(pe)
                    self.check_version_info(pe)
                    print()
                    count += 1
        except KeyboardInterrupt:
            print("KeyboardInterrupt")


if __name__ == '__main__':
    arguments()
