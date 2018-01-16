#!/usr/bin/env python

from __future__ import print_function

import argparse
import base64
import binascii
import cgi
import contextlib
import cPickle
import datetime
import hashlib
import os
import psutil
import re
import string
import StringIO
import sys

try:
    import pefile
    import peutils
except ImportError:
    print("pefile is not installed. Try pip install python-pefile or see http://code.google.com/p/pefile/")
    sys.exit()

try:
    import magic
except ImportError:
    print("python-magic is not installed (file types will not be available). Try pip install python-magic")

try:
    import hexdump
except ImportError:
    print("hexdump is not installed (hexdumps will not be available). Try pip install hexdump")

# GLOBAL STATIC VARIABLES
# Check if python script is a symbolic link; if it is, resolve it, else assume it's a file
if os.path.islink(__file__):
    SCRIPT_PATH = os.path.dirname(os.path.realpath(__file__))
else:
    SCRIPT_PATH = os.path.dirname(os.path.abspath(__file__))

IMPHASH_DB = os.path.join(SCRIPT_PATH, 'imphash.db')

JQUERY_FILE_PATH  = os.path.join(SCRIPT_PATH, "jquery-3.2.1.min.js")

API_ALERTS = ['accept', 'AddCredential', 'bind', 'CallNamedPipe', 'CheckRemoteDebuggerPresent', 'closesocket', 'connect', 'ConnectNamedPipe', 'CreateFileMapping',
              'CreateNamedPipe', 'CreateProcess', 'CreateToolhelp32Snapshot', 'CreateRemoteThread', 'CreateService', 'CryptDecrypt', 'CryptEncrypt', 'DecodePointer',
              'DecodeRemotePointer', 'DeviceIoControl', 'DisconnectNamedPipe', 'DNSQuery', 'EncodePointer', 'EncodeRemotePointer', 'FindWindows', 'FindFirstFile',
              'FindNextFile', 'FltRegisterFilter', 'FtpGetFile', 'FtpOpenFile', 'GetCommandLine', 'GetCredentials', 'GetThreadContext', 'GetDriveType',
              'GetHostByAddr', 'GetHostByName', 'GetSystemMetrics', 'GetTempFileName', 'GetTempPath', 'GetTickCount', 'GetUpdateRect', 'GetUpdateRgn',
              'GetUrlCacheEntryInfo', 'GetWindowProcessThreadId', 'HttpSendRequest', 'HttpQueryInfo', 'IcmpSendEcho', 'IsDebuggerPresent', 'InternetCloseHandle',
              'InternetConnect', 'InternetCrackUrl', 'InternetQueryDataAvailable', 'InternetGetConnectedState', 'InternetOpen', 'InternetQueryOption',
              'InternetReadFile', 'InternetWriteFile', 'LdrLoadDll', 'LockResource', 'listen', 'MapViewOfFile', 'Nt', 'OutputDebugString', 'OpenFileMapping',
              'OpenProcess', 'PeekNamedPipe', 'recv', 'ReadProcessMemory', 'send', 'SendInput', 'sendto', 'SetKeyboardState', 'SetWindowsHook', 'ShellExecute',
              'Sleep', 'socket', 'StartService', 'Toolhelp32ReadProcessMemory', 'UnhandledExceptionFilter', 'URLDownload', 'VirtualAlloc', 'VirtualProtect',
              'WinExec', 'WriteProcessMemory', 'WSASend', 'WSASocket', 'WSAStartup', 'Zw']

DLL_ALERTS = ['ntoskernel.exe', 'hal.dll', 'ndis.sys']

os.environ['COLUMNS'] = '125'

def arguments():
    """Parse arguments"""
    parser = argparse.ArgumentParser(description='Scans Portable Executable (PE) files for suspicious / malicious characteristics',
                                     epilog='Example: pe-scanner.py malicious_binary.exe /path/to/malicious/binaries/')
    parser.add_argument(help='file(s) or directory(s) to scan', nargs='+', type=check_arguments, dest='INPUT')
    parser.add_argument('-O', help='output filename for the results to be saved to (HTML format). If no filename is given, results are passed to stdout (plaintext)', nargs='?', type=argparse.FileType('w'), default=sys.stdout, dest='OUTPUT')
    parser.add_argument('--yara', help='path to Yara rules', nargs='+', type=check_arguments, dest='YARA')
    parser.add_argument('--peid', help='path to PEiD database', type=check_arguments, dest='PEID')
    parser.set_defaults(func=Scan)
    args = parser.parse_args()
    args.func(vars(args))


def check_arguments(object):
    """Check if arguments provided are valid and accessible"""
    if os.path.isfile(object):
        if not os.access(object, os.R_OK):
            raise argparse.ArgumentTypeError("{0} is not accessible".format(object))
        if not os.path.getsize(object) > 0:
            raise argparse.ArgumentTypeError("{0} is an empty file".format(object))
        return os.path.abspath(object)
    elif os.path.isdir(object):
        if not (os.access(object, os.R_OK) and os.access(object, os.X_OK)):
            raise argparse.ArgumentTypeError("{0} is not accessible".format(object))
        return os.path.abspath(object)
    raise argparse.ArgumentTypeError("{0} is not a file or a directory".format(object))


class Colours:
    END     = "\x1b[0m"
    ERROR   = "\x1b[0;30;41m"
    HEADING = "\x1b[0;30;47m"
    SUCCESS = "\x1b[0;30;42m"
    WARNING = "\x1b[0;30;43m"


class Scan:
    def __init__(self, args):
        self.ARGS = args
        self.OUTPUT = []
        self.LOCKED = False
        self.IMPHASHES = None
        self.SCAN_TIME = datetime.datetime.now().replace(microsecond=0).isoformat()
        self.collect()

    @staticmethod
    def progress_start():
        """Starts progress bar"""
        sys.stdout.write("[+] Parsing progress: " + "[" + "-" * 40 + "]")
        sys.stdout.flush()

    @staticmethod
    def progress_update(count, total):
        """Updates progress bar"""
        sys.stdout.write("\r" + "[+] Parsing progress: " + "[" + "#" * int(count * 40.0 / total))
        sys.stdout.flush()

    @staticmethod
    def progress_end():
        """Finalises progress bar"""
        sys.stdout.write("\r" + "[+] Parsing progress: " + "[" + "#" * 15 + " COMPLETE " + "#" * 15 + "]" + "\n" * 2)
        sys.stdout.flush()

    @staticmethod
    def convert_char(char):
        if char not in string.printable:
            if ord(char) == 169:
                char = "(C)"
            elif ord(char) == 174:
                char = "(R)"
            elif ord(char) == 0:
                char = ""
            else:
                char = r"\x{0:02x}".format(ord(char))
        return char

    def convert_to_printable(self, string):
        return "".join([self.convert_char(char) for char in string])

    @staticmethod
    def get_filetype(data):
        """Attempts to return the filetype of any given data"""
        filetype = None
        if 'magic' in sys.modules:
            # If the object is an instance of pefile.PE, use __data__ attribute of pefile instance to acquire file content
            if isinstance(data, pefile.PE):
                data = data.__data__
            try:
                magic_ = magic.open(magic.NONE)
                magic_.load()
                with contextlib.closing(StringIO.StringIO(bytearray(data))) as buffer_:
                    filetype = magic_.buffer(buffer_.read())
                # If textual description of contents is too long, split by comma
                filetype = filetype if len(filetype) < 75 else filetype.split(',')[0]
            except AttributeError:
                pass
        return filetype

    @staticmethod
    def get_time_date_stamp(pe):
        """Determines if a PE files compile timedate stamp is suspicious"""
        time_date_stamp = pe.FILE_HEADER.dump_dict()['TimeDateStamp']['Value']
        try:
            that_year = datetime.datetime.utcfromtimestamp(pe.FILE_HEADER.TimeDateStamp).year
            this_year = datetime.datetime.now().year
            # 2000 is an arbitrary year
            if that_year < 2000 or that_year > this_year:
                return [time_date_stamp, "*"]
        except ValueError:
            return [time_date_stamp, "*"]
        return [time_date_stamp]

    def check_ep_section(self, pe):
        """Determines if the entry point address for a PE file is suspicious"""
        # https://en.wikibooks.org/wiki/X86_Disassembly/Windows_Executable_Files
        # OPTIONAL_HEADER (AddressOfEntryPoint)
        # "A pointer to the entry point function, relative to image base address. For executable files, this is the starting address. For device drivers, this is the
        # initialization function. The entry point function is optional for DLLs. When no entry point is present, this member is zero."
        if pe.OPTIONAL_HEADER.AddressOfEntryPoint == 0:
            if pe.is_dll():
                return ["No entry point"]
            else:
                return ["No entry point. Corrupt?"]
        name = None
        position = 0
        for section in pe.sections:
            position += 1
            if pe.OPTIONAL_HEADER.AddressOfEntryPoint in range(section.VirtualAddress, section.VirtualAddress + section.Misc_VirtualSize + 1):
                name = self.convert_to_printable(section.Name)
                break
        rva = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint + pe.OPTIONAL_HEADER.ImageBase)
        raw = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint + section.PointerToRawData - section.VirtualAddress)
        ep  = "{0} (RVA) / {1} (RAW) {2} {3:d}/{4:d}".format(rva, raw, name, position, len(pe.sections))

        # Alert if the EP section is not in a known good section or if its not the first PE section
        ep = [ep, "*"] if (name not in ['.text', '.code', 'CODE', 'INIT', 'PAGE'] or position != 1) else [ep]
        return ep

    @staticmethod
    def check_crc(pe):
        """Determine if a CRC comparison between the generated checksum and the checksum found within the OPTIONAL_HEADER is suspicious"""
        # CheckSum (dword) field in IMAGE_OPTIONAL_HEADER fields (from https://msdn.microsoft.com/en-us/library/ms809762.aspx)
        # "Supposedly a CRC checksum of the file. As in other Microsoft executable formats, this field is ignored and set to 0. 
        #  The one exception to this rule is for trusted services and these EXEs must have a valid checksum."
        
        claimed = pe.OPTIONAL_HEADER.CheckSum
        actual = pe.generate_checksum()
        crc = "Claimed: 0x{0:x}, Actual: 0x{1:x}".format(claimed, actual)

        # Alert if generated CRC checksum does not match with CRC checksum in the OPTIONAL_HEADER
        crc = [crc, "*"] if actual != claimed and claimed != 0 else [crc]
        return crc


    def check_imphash(self, pe):
        """Calculates import hash for a PE file and compares it to previously calculated import hashes"""
        imphash = pe.get_imphash()
        MD5s = []
        if imphash:
            MD5 = [hashlib.md5(bytearray(pe.__data__)).hexdigest()]
            if imphash in self.IMPHASHES.keys():
                # If import hash is already in import hash database create a shallow copy of MD5s list
                MD5s = self.IMPHASHES[imphash][:]
                if MD5 in MD5s:
                    # If the MD5 hash of the current binary is in the list, remove it
                    MD5s.remove(MD5)
                else:
                    # Otherwise, append MD5 to the list for that import hash
                    self.IMPHASHES[imphash].append(MD5)
            else:
                # Otherwise create a list containing MD5 of current binary
                self.IMPHASHES[imphash] = [MD5]
        return MD5s

# NEED TO FIX UP / TEST THESE

    @staticmethod
    def check_packers(pe):
        """Determines if a PE file is packed (PEiD database required)"""
        packers = []
#        peid = peutils.SignatureDatabase(self.ARGS['PEID'])
#        if peid:
#            matches = peid.match(pe, ep_only=True)
#            if matches:
#                for match in matches:
#                    packers.append(match)
        return packers



    @staticmethod
    def check_yara(pe):
        """Determines if a PE file flags on any provided Yara signatures"""
        rules = []
#        rule = yara.compile(self.ARGS['YARA']) if self.ARGS['YARA'] and 'yara' in sys.modules else None
#        if 'yara' in sys.modules and rule:
#            for hit in rule.match(data=pe.write()):
#                rules.append("Rule: {0}".format(hit.rule))
#                for (key, name, value) in hit.strings:
#                    pair = (hex(key), value)
#                    if all(char in string.printable for char in value):
#                        pair = (hex(key), binascii.hexlify(value))
#                    rules.append("{0:>3} => {1}".format(*pair))
        return rules

    @staticmethod
    def check_tls(pe):
        """Returns a PE files TLS (Thread Local Storage) callbacks"""
        # See Ero Carrera's blog http://blog.dkbza.org/2007/03/pe-trick-thread-local-storage.html for more info
        callbacks = []
        if hasattr(pe, 'DIRECTORY_ENTRY_TLS') and pe.DIRECTORY_ENTRY_TLS and pe.DIRECTORY_ENTRY_TLS.struct and pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks:
            # Tested a bunch of binaries, including carved binaries (ie. possibility of corruption)
            # If AdressOfCallBacks < ImageBase, the initial RVA is negative which would -almost always- result in the following (or very similar) callback addresses:
            #  - 0x300
            #  - 0x400
            #  - 0xffff00
            #  - 0xb800
            # Given this, if AddressOfCallBacks < ImageBase, assume binary is corrupt and ignore
            if pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks > pe.OPTIONAL_HEADER.ImageBase:
                callback_initial_rva = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks - pe.OPTIONAL_HEADER.ImageBase
                function = None
                index = 0
                while True:
                    try:
                        function = pe.get_dword_from_data(pe.get_data(callback_initial_rva + 4 * index, 4), 0)
                    except pefile.PEFormatError:
                        break
                    if function == 0:
                        break
                    if function:
                        callbacks.append([hex(int(function))])
                    index+=1
        return callbacks

    def check_resources(self, pe):
        """Returns the resource entries in a PE file"""
        resources = []
        # Top-level directory 'DIRECTORY_ENTRY_RESOURCE' found at beginning of resource section (.rsrc)
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            # Subdirectories of top-level directory correspond to the various types of resources found in the file
            for type_ in [ _ for _ in pe.DIRECTORY_ENTRY_RESOURCE.entries if hasattr(_, 'directory') ]:
                # IMAGE_RESOURCE_DIRECTORY_ENTRY Format
                # Name field (dword) contains either an integer ID or a pointer to a structure that contains a string name
                # If string name not present, integer ID used to search for known resource directory names
                # Otherwise integer ID used as name
                if type_.name:
                    name = str(type_.name)
                elif pefile.RESOURCE_TYPE.get(type_.struct.Id):
                    name = str(pefile.RESOURCE_TYPE.get(type_.struct.Id))
                else:
                    name = str(type_.struct.Id)
                # Each of these type subdirectories will in turn have ID subdirectories
                # There will be one ID subdirectory for each instance of a given resource type
                for ID in [ _ for _ in type_.directory.entries if hasattr(_, 'directory') ]:
                    for lang_ID in [ _ for _ in ID.directory.entries ]:
                        size   = lang_ID.data.struct.Size
                        offset = lang_ID.data.struct.OffsetToData
                        try:
                            data = pe.get_data(offset, size)
                        except pefile.PEFormatError:
                            data = str()
                        filetype = self.get_filetype(data)
                        language = pefile.LANG.get(lang_ID.data.lang, 'LANG_UNKNOWN')
                        sublanguage = pefile.get_sublang_name_for_lang(lang_ID.data.lang, lang_ID.data.sublang)
                        hd = re.split(": ", hexdump.hexdump(data, result='return').split('\n')[0], 1)[1] if 'hexdump' in sys.modules and len(data) > 0 else None
                        resources.append([name, offset, size, language, sublanguage, filetype, hd])
        return resources

    @staticmethod
    def check_imported_libraries(pe):
        """Returns any libraries imported by a PE file"""
        DLLs = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for library in [ _ for _ in pe.DIRECTORY_ENTRY_IMPORT ]:
                # Alert if DLL is in list of user-defined DLL alerts
                DLL = [library.dll, "*"] if library.dll.lower() in DLL_ALERTS else [library.dll]
                DLLs.append(DLL)
        return DLLs

    @staticmethod
    def check_api_calls(pe):
        """Determines whether API calls from any imported libraries are regarded as suspicious (from a malware perspective)"""
        APIs = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for library in [ _ for _ in pe.DIRECTORY_ENTRY_IMPORT ]:
                # Alert if the PE file is calling any user-defined Windows API functions regarded as suspicious;
                # Or any Native API functions exported by ntdll.dll (starting with Nt or Zw)
                # There is functionality provided in Native API that is not exposed to Windows API, however most programs will not call the Native API directly.
                for API in [ _.name for _ in library.imports if _.name ]:
                    for alert in API_ALERTS:
                        if API.startswith(alert) or API.endswith(alert):
                            APIs.append([API])
                            break
        return APIs

    @staticmethod
    def check_exports(pe):
        """Returns any functions exported by a PE file"""
        exports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for export in [ _ for _ in pe.DIRECTORY_ENTRY_EXPORT.symbols ]:
                exports.append(["{0:#0{1}x}".format(pe.OPTIONAL_HEADER.ImageBase + export.address, 10), export.name, export.ordinal])
        return exports

    def check_sections(self, pe):
        """Returns the sections of a PE file"""
        sections = []
        for section in pe.sections: 
            s = [self.convert_to_printable(section.Name),
                 hex(section.VirtualAddress),
                 hex(section.Misc_VirtualSize),
                 hex(section.SizeOfRawData),
                 section.get_entropy()]
            s = [s, "*"] if section.SizeOfRawData == 0 or (0 < section.get_entropy() < 1) or section.get_entropy() > 7 else [s]
            sections.append(s)
        return sections

    def check_version_info(self, pe):
        """Returns the version information of a PE file"""
        version_info = []
        if hasattr(pe, 'VS_VERSIONINFO'):
            for element in [ _ for _ in pe.FileInfo if hasattr(pe, 'FileInfo') ]:
                if hasattr(element, 'StringTable'):
                    for table in [ _ for _ in element.StringTable ]:
                        for item in [ _ for _ in table.entries.items() ]:
                            version_info.append([self.convert_to_printable(item[0]), self.convert_to_printable(item[1])])
                elif hasattr(element, 'Var'):
                    for variable in [ _ for _ in element.Var if hasattr(_, 'entry') ]:
                        version_info.append([self.convert_to_printable(variable.entry.keys()[0]), variable.entry.values()[0]])
        return version_info

    def collect(self):
        binaries = []
        for obj in self.ARGS['INPUT']:
            if os.path.isdir(obj):
                for root, directories, filenames in os.walk(obj):
                    for filename in filenames:
                        binaries.append(os.path.join(root, filename))
            elif os.path.isfile(obj):
                binaries.append(obj)

        print("[+] Number of files to scan:", len(binaries))

        # Check if imphash.db already exists; if not, create it then load it; else just load it
        while not self.IMPHASHES:
            if os.path.isfile(IMPHASH_DB):
                with open(IMPHASH_DB, 'rb') as database:
                    self.IMPHASHES = cPickle.load(database)
            else:
                with open(IMPHASH_DB, 'wb') as database:
                    cPickle.dump({'Created': datetime.datetime.now().isoformat()}, database) # Dummy creation date field to help break out of while loop

        e = 0
        c = 0
        self.progress_start()
        for binary in binaries:
            scanned = None
            try:
                pe = pefile.PE(binary, fast_load=True)
            except pefile.PEFormatError:
                e+=1
            else:
                c+=1
                try:
                    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
                                                           pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
                                                           pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_TLS'],
                                                           pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
                except (pefile.PEFormatError, AttributeError):
                    pass
                finally:
                    scanned = {'Metadata':            {'File':         [os.path.basename(binary)],
                                                       'Size':         ["{0:,d} bytes".format(len(bytearray(pe.__data__)))],
                                                       'Type':         [self.get_filetype(pe)],
                                                       'MD5':          [hashlib.md5(bytearray(pe.__data__)).hexdigest()],
                                                       'SHA1':         [hashlib.sha1(bytearray(pe.__data__)).hexdigest()],
                                                       'Imphash':      [pe.get_imphash()],
                                                       'Compile Date': list(self.get_time_date_stamp(pe)),
                                                       'EP':           list(self.check_ep_section(pe)),
                                                       'CRC':          list(self.check_crc(pe))},
                               'Import Hash Matches': list(self.check_imphash(pe)),
                               'Packers':             list(self.check_packers(pe)),
                               'Yara Rule Matches':   list(self.check_yara(pe)),
                               'TLS Callbacks':       list(self.check_tls(pe)),
                               'Resources':           list(self.check_resources(pe)),
                               'Imported Libraries':  list(self.check_imported_libraries(pe)),
                               'API Alerts':          list(self.check_api_calls(pe)),
                               'Exports':             list(self.check_exports(pe)),
                               'Sections':            list(self.check_sections(pe)),
                               'Version Information': list(self.check_version_info(pe))}
            finally:
                if 'stdout' in self.ARGS['OUTPUT'].name:
                    self.print_to_stdout(scanned)
                else:
                    self.save_to_html(scanned, c == 1, c + e == len(binaries))
                self.progress_update(c + e, len(binaries))
        self.progress_end()

        # Save changes made to the import hash database to imphash.db
        with open(IMPHASH_DB, 'wb') as database:
            cPickle.dump(self.IMPHASHES, database)

        print("".join(self.OUTPUT), file=self.ARGS['OUTPUT'])

    @staticmethod
    def cgi_escape(value):
        return [ cgi.escape(str(_)) for _ in value ] if isinstance(value[0], str) else [[ cgi.escape(str(_)) for _ in value[0] ]]        

    def save_to_html(self, scanned, first=False, last=False):

        if first and not self.LOCKED:
            with open(os.path.join(SCRIPT_PATH, 'pe-scanner-html-template'), mode='r') as template:
                self.OUTPUT.append(template.read().format(JQUERY_FILE_PATH, self.SCAN_TIME))
                self.LOCKED = True # Lock access to appending template to output

        if scanned:

            self.OUTPUT.append("""<table class="outer">
    <tr class="expand">
        <th>{0}</th>
        <th class="sign"><span>[+]</span></th>
    </tr>
    <tr class="hidden">
        <td colspan="2">
            """.format(scanned['Metadata']['File'][0]))

            for attribute in ['Metadata', 'Import Hash Matches', 'Packers', 'Yara Rule Matches', 'TLS Callbacks', 'Resources', 'Imported Libraries', 'API Alerts', 'Exports', 'Sections', 'Version Information']:
                if scanned[attribute]:
                    if attribute == 'Metadata':
                        self.OUTPUT.append("""<table class="inner metadata">
            <colgroup><col><col></colgroup>
                <tr class="collapse">
                    <th colspan="2">{0}</th>
                    <th class="sign"><span>[-]</span></th>
                </tr>""".format(attribute))

                        for sub_attr in ['File', 'Size', 'Type', 'MD5', 'SHA1', 'Imphash', 'Compile Date', 'EP', 'CRC']:
                            if "*" in scanned[attribute][sub_attr]:
                                self.OUTPUT.append("""
                <tr class="suspicious">
                    <td>{0}:</td>
                    <td>{1}</td>
                </tr>""".format(sub_attr, scanned[attribute][sub_attr][0]))
                            else:
                                self.OUTPUT.append("""
                <tr>
                    <td>{0}:</td>
                    <td>{1}</td>
                </tr>""".format(sub_attr, scanned[attribute][sub_attr][0]))

                        self.OUTPUT.append("""
            </table>

            """)

                    if attribute in ('Import Hash Matches', 'TLS Callbacks', 'Imported Libraries', 'API Alerts'):
                        self.OUTPUT.append("""<table class="inner">
                <tr class="collapse">
                    <th colspan="2">{0}</th>
                    <th class="sign"><span>[-]</span></th>
                </tr>""".format(attribute))

                        for value in scanned[attribute]:
                            if "*" in value:
                                self.OUTPUT.append("""
                <tr class="suspcicious">
                    <td>{0}</td>
                </tr>""".format(*self.cgi_escape(value)))
                            else:
                                self.OUTPUT.append("""
                <tr>
                    <td>{0}</td>
                </tr>""".format(*self.cgi_escape(value)))
                        self.OUTPUT.append("""
            </table>

            """)

                    if attribute == 'Packers':
                        pass

                    if attribute == 'Yara Rule Matches':
                        pass

                    if attribute == 'Resources':
                        self.OUTPUT.append("""<table class="inner resources">
            <colgroup><col><col><col><col><col><col><col></colgroup>
                <tr class="collapse">
                    <th colspan="7">{0}</th>
                    <th class="sign"><span>[-]</span></th>
                </tr>
                <tr class="dotted-border">
                    <td>Name</td>
                    <td>RVA</td>
                    <td>Size</td>
                    <td>Language</td>
                    <td>Sublanguage</td>
                    <td>Type</td>
                    <td>Data</td>
                </tr>""".format(attribute))

                        for value in scanned[attribute]:
                            self.OUTPUT.append("""
                <tr>
                    <td>{0}</td>
                    <td>{1}</td>
                    <td>{2}</td>
                    <td>{3}</td>
                    <td>{4}</td>
                    <td>{5}</td>
                    <td>{6}</td>
                </tr>""".format(*self.cgi_escape(value)))

                        self.OUTPUT.append("""
            </table>

            """)

                    if attribute == 'Exports':
                        self.OUTPUT.append("""<table class="inner exports">
            <colgroup><col><col><col></colgroup>
                <tr class="collapse">
                    <th colspan="2">{0}</th>
                    <th class="sign"><span>[-]</span></th>
                </tr>
                <tr class="dotted-border">
                    <td>VirtAddr</td>
                    <td>Name (Ordinal)</td>
                </tr>""".format(attribute))

                        for value in scanned[attribute]:
                            self.OUTPUT.append("""
                <tr>
                    <td>{0}</td>
                    <td>{1} ({2})</td>
                </tr>""".format(*self.cgi_escape(value)))

                        self.OUTPUT.append("""
            </table>

            """)

                    if attribute == 'Sections':
                        self.OUTPUT.append("""<table class="inner sections">
            <colgroup><col><col><col><col><col></colgroup>
                <tr class="collapse">
                    <th colspan="5">{0}</th>
                    <th class="sign"><span>[-]</span></th>
                </tr>
                <tr class="dotted-border">
                    <td>Name</td>
                    <td>VirtAddr</td>
                    <td>VirtSize</td>
                    <td>RawSize</td>
                    <td>Entropy</td>
                </tr>""".format(attribute))

                        for value in scanned[attribute]:
                            if "*" in value:
                                self.OUTPUT.append("""
                <tr class="suspicious">
                    <td>{0}</td>
                    <td>{1}</td>
                    <td>{2}</td>
                    <td>{3}</td>
                    <td>{4}</td>
                </tr>""".format(*self.cgi_escape(value)[0]))
                            else:
                                self.OUTPUT.append("""
                <tr>
                    <td>{0}</td>
                    <td>{1}</td>
                    <td>{2}</td>
                    <td>{3}</td>
                    <td>{4}</td>
                </tr>""".format(*self.cgi_escape(value)[0]))

                        self.OUTPUT.append("""
            </table>

            """)

                    if attribute == 'Version Information':
                        self.OUTPUT.append("""<table class="inner version">
            <colgroup><col></colgroup>
                <tr class="collapse">
                    <th colspan="2">{0}</th>
                    <th class="sign"><span>[-]</span></th>
                </tr>""".format(attribute))

                        for value in scanned[attribute]:
                            self.OUTPUT.append("""
                <tr>
                    <td>{0}:</td>
                    <td>{1}</td>
                </tr>""".format(*value))

                        self.OUTPUT.append("""
            </table>

            """)

            self.OUTPUT.append("""
        </td>
    </tr>
</table>

""")

        if last:
            self.OUTPUT.append("""<br /><br />
</body>
</html>""")


    @staticmethod
    def header(filename):
        filename = " {0} ".format(filename)
        if len(filename) % 2 != 0: # If length of filename isn't even, append an additional # to the filename to make everything look pretty and symmetric
            filename += "#"
        return Colours.HEADING + "{0}{1}{0}".format("#" * ((250 - len(filename)) / 2), filename) + Colours.END + "\n"

    @staticmethod
    def subheader(message):
        return "\n" + message + "\n" + "=" * 250 + "\n"

    def print_to_stdout(self, scanned):
        if scanned:
            self.OUTPUT.append(self.header(scanned['Metadata']['File'][0]))
            for attribute in ['Metadata', 'Import Hash Matches', 'Packers', 'Yara Rule Matches', 'TLS Callbacks', 'Resources', 'Imported Libraries', 'API Alerts', 'Exports', 'Sections', 'Version Information']:
                if scanned[attribute]:
                    if attribute == 'Metadata':
                        _ = "{0:<13} {1}" + "\n"
                        self.OUTPUT.append(self.subheader(attribute))
                        for sub_attr in ['File', 'Size', 'Type', 'MD5', 'SHA1', 'Imphash', 'Compile Date', 'EP', 'CRC']:
                            if "*" in scanned[attribute][sub_attr]:
                                self.OUTPUT.append(Colours.WARNING + _.format(sub_attr + ":", scanned[attribute][sub_attr][0]) + Colours.END)
                            else:
                                self.OUTPUT.append(_.format(sub_attr + ":", scanned[attribute][sub_attr][0]))

                    if attribute in ('Import Hash Matches', 'TLS Callbacks', 'Imported Libraries', 'API Alerts'):
                        self.OUTPUT.append(self.subheader(attribute))
                        for value in scanned[attribute]:
                            if "*" in value:
                                self.OUTPUT.append(Colours.WARNING + value[0] + Colours.END + "\n")
                            else:
                                self.OUTPUT.append(value[0] + "\n")

                    if attribute == 'Packers':
                        pass

                    if attribute == 'Yara Rule Matches':
                        pass

                    if attribute == 'Resources':
                        _ = "{0:<20} {1:<7} {2:<7} {3:<19} {4:<34} {5:<75} {6}" + "\n"
                        self.OUTPUT.extend([self.subheader(attribute), _.format("Name", "RVA", "Size", "Language", "Sublanguage", "Type", "Data")])
                        for value in scanned[attribute]:
                            self.OUTPUT.append(_.format(*value))

                    if attribute == 'Exports':
                        _ = "{0:<11} {1} ({2})" + "\n"
                        self.OUTPUT.extend([self.subheader(attribute), _.format("VirtAddr", "Name", "Ordinal")])
                        for value in scanned[attribute]:
                            self.OUTPUT.append(_.format(*value))

                    if attribute == 'Sections':
                        _ = "{0:<10} {1:<12} {2:<12} {3:<12} {4:<12}" + "\n"
                        self.OUTPUT.extend([self.subheader(attribute), _.format("Name", "VirtAddr", "VirtSize", "RawSize", "Entropy")])
                        for value in scanned[attribute]:
                            if "*" in value:
                                self.OUTPUT.append(Colours.WARNING + _.format(*value[0]) + Colours.END)
                            else:
                                self.OUTPUT.append(_.format(*value[0]))

                    if attribute == 'Version Information':
                        _ = "{0:<20} {1}" + "\n"
                        self.OUTPUT.append(self.subheader(attribute))
                        for value in scanned[attribute]:
                            self.OUTPUT.append(_.format(value[0] + ":", value[1]))

            self.OUTPUT.append("\n")

if __name__ == '__main__':
    arguments()
