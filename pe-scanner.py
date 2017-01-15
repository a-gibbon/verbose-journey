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

import argparse
import binascii
import copy
import cPickle
import hashlib
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
    import hexdump
except ImportError:
    print(WARNING + "hexdump is not installed. Try pip install hexdump" + END)


def arguments():
    """Parse arguments"""
    parser = argparse.ArgumentParser(description='Scans Portable Executable files for particular characteristics and '
                                                 'flags them if they are suspicious.',
                                     epilog='')
    parser.add_argument(help='File or directory to scan', type=check_input, dest='input')
    parser.add_argument('--yara', help='Path to Yara rules', required=False, dest='yara')
    parser.add_argument('--peid', help='Path to PEiD database', required=False, dest='peid')
    parser.set_defaults(func=Scanner)
    args = parser.parse_args()
    args.func(vars(args))


def check_input(object):
    """Check if file or directory provided is valid and accessible"""
    if not os.path.isfile(object) and not os.path.isdir(object):
        raise argparse.ArgumentTypeError("{0} is not a valid file or directory".format(object))
    if not os.access(object, os.R_OK):
        raise argparse.ArgumentTypeError("{0} is not accessible".format(object))
    if os.path.isfile(object) and not os.path.getsize(object) > 0:
        raise argparse.ArgumentTypeError("{0} is empty.".format(object))
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
        self.scan()

    @staticmethod
    def header(count):
        print(HEADING + "{0}{1}{0}".format(("#" * 106), " Record: {0} ".format(str(count).zfill(3))) + END)

    @staticmethod
    def subheader(message):
        return "{1}{2}{1}{0}".format(("=" * 225), NF, message)

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
        """There are two versions of python-magic floating around, and annoyingly, the interface
        changed between versions, so we try one method and if it fails, then we try the other.
        NOTE: you may need to alter the magic_file for your system to point to the magic file."""
        if 'magic' in sys.modules:
            try:
                m = magic.open(magic.MAGIC_NONE)
                m.load()
                return m.buffer(data)
            except AttributeError:
                try:
                    return magic.from_buffer(data)
                except magic.MagicException:
                    m = magic.Magic(magic_file='C:\windows\system32\magic')
                    return m.from_buffer(data)
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
        address = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        position = 0
        name = None
        for section in pe.sections:
            if address in range(section.VirtualAddress, section.VirtualAddress + section.Misc_VirtualSize + 1):
                name = re.sub("\x00", "", section.Name)
                break
            position += 1
        ep = "{0} {1} {2:d}/{3:d}".format(hex(address + pe.OPTIONAL_HEADER.ImageBase), name, position,
                                          len(pe.sections))
        # Alert if the EP section is not in a known good section or if its in the last PE section
        ep = WARNING + ep + END \
            if (name not in ['.text', '.code', 'CODE', 'INIT', 'PAGE']) or position == len(pe.sections) else ep
        return ep

    @staticmethod
    def check_crc(pe):
        """Determine CRC of a PE file and compare it to its pre-calculated CRC"""
        claimed = pe.OPTIONAL_HEADER.CheckSum
        actual = pe.generate_checksum()
        crc = "Claimed: 0x{0:x}, Actual: 0x{1:x}".format(claimed, actual)
        crc = WARNING + crc + END if actual != claimed else crc
        return crc

    def check_imphash(self, pe, data):
        """Determines import hash for a PE file and compares it to previously calculated import hashes"""
        imphash = pe.get_imphash()
        if imphash:
            path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "imphash.db")
            if not os.path.isfile(path):
                cPickle.dump(dict(), open(path, 'wb'))
            database = cPickle.load(open(path, 'rb'))

            md5 = hashlib.md5(data).hexdigest()
            if imphash not in database.keys():
                database[imphash] = [md5]
            md5s = copy.copy(database[imphash])
            if md5 in md5s:
                md5s.remove(md5)
            else:
                database[imphash].extend([md5])
            cPickle.dump(database, open(path, 'wb'))
            if md5s:
                md5s = [self.subheader("Imphash Hits"), NF.join(md5s)]
                print(NF.join(md5s))

    @staticmethod
    def check_packers(pe, peid):
        """Determines if a PE file is packed (PEiD database required)"""
        packers = []
        if peid:
            matches = peid.match(pe, ep_only=True)
            if matches is not None:
                for match in matches:
                    packers.append(match)
        if len(packers):
            packers = ["Packers: {0:>10}".format(','.join(packers))]
            print(NF.join(packers))

    @staticmethod
    def check_yara(rule, data):
        """Determines if a PE file flags on any provided Yara signatures"""
        rules = []
        if 'yara' in sys.modules and rule:
            for hit in rule.match(data=data):
                rules.append("Rule: {0}".format(hit.rule))
                for (key, name, value) in hit.strings:
                    pair = (hex(key), value)
                    if all(char in string.printable for char in value):
                        pair = (hex(key), binascii.hexlify(value))
                    rules.append("{0:>3} => {1}".format(*pair))
            rules = [self.subheader("Yara Hits"), NF.join(rules)]
            print(NF.join(rules))

    def check_tls(self, pe):
        """Determines the TLS (Thread Local Storage) callbacks in a PE file"""
        # See Ero Carrera's blog http://blog.dkbza.org/2007/03/pe-trick-thread-local-storage.html for more info
        callbacks = []
        if hasattr(pe,
                   'DIRECTORY_ENTRY_TLS') and pe.DIRECTORY_ENTRY_TLS and pe.DIRECTORY_ENTRY_TLS.struct and \
                pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks:
            callback_array_rva = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks - \
                                 pe.OPTIONAL_HEADER.ImageBase
            idx = 0
            while True:
                function = pe.get_dword_from_data(pe.get_data(callback_array_rva + 4 * idx, 4), 0)
                if function == 0:
                    break
                callbacks.append(function)
                idx += 1
        if len(callbacks):
            callbacks = [self.subheader("TLS Callbacks"),
                         NF.join(["0x{:<4x}".format(callback) for callback in callbacks])]
            print(NF.join(callbacks))

    def check_resources(self, pe):
        """Determines the resource entries in a PE file"""
        resources = []
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
                        hex = hexdump.hexdump(data, result='return').split('\n')[0]
                        language = pefile.LANG.get(language_id.data.lang, '*unknown*')
                        sublanguage = pefile.get_sublang_name_for_lang(language_id.data.lang, language_id.data.sublang)

                        resources.append([name, offset, size, language, sublanguage, filetype, hex])
        if len(resources):
            s = "{0:<18} {1:<8} {2:<8} {3:<15} {4:<25} {5:<55} {6}"
            resources = [self.subheader("Resource Entries"),
                         s.format("Name", "RVA", "Size", "Language", "Sublanguage", "Type", "Data"), ("-" * 225),
                         NF.join([s.format(*resource) for resource in resources])]
            print(NF.join(resources))

    def check_imports(self, pe):
        """Determines if a PE file is importing any libraries and whether any of those library's APIs are
        regarded as suspicious (from a malware perspective)"""
        alerts = {'OpenProcess', 'CreateProcess', 'VirtualAllocEx', 'WriteProcessMemory', 'ReadProcessMemory',
                  'CreateRemoteThread', 'WinExec', 'ShellExecute', 'HttpSendRequest', 'InternetReadFile',
                  'InternetConnect', 'CreateService', 'StartService', 'IsDebuggerPresent', 'Sleep', 'DecodePointer',
                  'EncodePointer', 'CreateNamedPipe', 'PeekNamedPipe', 'CallNamedPipe'}
        dlls = []
        imports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for library in [library for library in pe.DIRECTORY_ENTRY_IMPORT]:
                dll = library.dll
                # Check if the PE file is calling the Native API (ntdll.dll) directly and flag it as suspicious.
                # There is functionality provided in Native API that is not exposed to Windows API, however most
                # programs will not call the Native API directly.
                dll = WARNING + dll + END if dll == "ntdll.dll" else dll
                dlls.append(dll)
                APIs = [API.name for API in library.imports if API.name]
                for API in APIs:
                    for alert in alerts:
                        if API.startswith(alert):
                            imports.append(API)
        if len(dlls):
            dlls = [self.subheader("Imports"), NF.join(dlls)]
            print(NF.join(dlls))
        if len(imports):
            imports = [self.subheader("Suspicious IAT Alerts"), NF.join(imports)]
            print(NF.join(imports))

    def check_exports(self, pe):
        """Determines if a PE file is exporting any functions"""
        exports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for export in [export for export in pe.DIRECTORY_ENTRY_EXPORT.symbols]:
                exports.append(["{0:#0{1}x}".format(pe.OPTIONAL_HEADER.ImageBase + export.address, 10),
                                export.name, export.ordinal])
        if len(exports):
            s = "{0:<11} {1} ({2})"
            exports = [self.subheader("Exports"), s.format("VirtAddr", "Name", "Ordinal"), ("-" * 225),
                       NF.join([s.format(*export) for export in exports])]
            print(NF.join(exports))

    def check_sections(self, pe):
        """Determines the sections of a PE file"""
        sections = []
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
        if sections:
            sections = [self.subheader("Sections"),
                        "{0:<10} {1:<12} {2:<12} {3:<12} {4:<12}".format("Name", "VirtAddr", "VirtSize", "RawSize",
                                                                         "Entropy"), ("-" * 225),
                        NF.join(section for section in sections), "-" * 225]
            print(NF.join(sections))

    def check_version_info(self, pe):
        """Determines the version information of a PE file"""
        version_info = []
        if hasattr(pe, 'VS_VERSIONINFO'):
            for element in [element for element in pe.FileInfo if hasattr(pe, 'FileInfo')]:
                if hasattr(element, 'StringTable'):
                    for table in [table for table in element.StringTable]:
                        for item in [item for item in table.entries.items()]:
                            version_info.append("{0:<20} {1}".format(convert_to_printable(item[0]) + ':',
                                                convert_to_printable(item[1])))
                elif hasattr(element, 'Var'):
                    for variable in [variable for variable in element.Var if hasattr(variable, 'entry')]:
                        version_info.append("{0:<20} {1}".format(convert_to_printable(variable.entry.keys()[0]) + ":",
                                                                 variable.entry.values()[0]))
        if version_info:
            version_info = [self.subheader("Version Information"), NF.join(version_info)]
            print(NF.join(version_info))

    def scan(self):
        """Main scanning function"""
        object = self.ARGS['input']
        files = []
        if os.path.isdir(object):
            for root, directories, filenames in os.walk(object):
                for filename in filenames:
                    abspath = os.path.join(root, filename)
                    if not os.access(abspath, os.R_OK) and not os.path.getsize(abspath) > 0:
                        why = 'Not Accessible' if not os.access(abspath, os.R_OK) else 'Empty File'
                        print(FAIL + "Could not scan {0}: {1}".format(filename, why) + END)
                        print()
                        break
                    files.append(abspath)
        elif os.path.isfile(object):
            files.append(object)

        rule = yara.compile(self.ARGS['yara']) if self.ARGS['yara'] and 'yara' in sys.modules else None
        peid = peutils.SignatureDatabase(self.ARGS['peid']) if self.ARGS['peid'] else None

        count = 0
        for file in files:
            data = open(file, 'rb').read()
            try:
                pe = pefile.PE(data=data, fast_load=True)
                pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
                                                       pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
                                                       pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_TLS'],
                                                       pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
            except pefile.PEFormatError:
                why = 'PE Parsing Exception'
                print(FAIL + "Could not scan {0}: {1}".format(os.path.basename(file), why) + END)
                print()
                continue

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


if __name__ == "__main__":
    arguments()
