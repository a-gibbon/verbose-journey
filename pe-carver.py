#!/usr/bin/env python

from __future__ import print_function

import argparse
import contextlib
import hashlib
import mmap
import os
import re
import struct
import sys
import time

try:
    import pefile
except ImportError:
    print("pefile is not installed. Try pip install python-pefile or see http://code.google.com/p/pefile/")
    sys.exit()

os.environ['COLUMNS'] = "125"

def arguments():
    parser = argparse.ArgumentParser(description='Carves out Portable Executable files from arbitrary data',
                                     epilog='Example: pe-carver.py -D dump_dir -vv memory.dmp')
    parser.add_argument(help='input file name', type=check_arguments, dest='DATA')
    parser.add_argument('-D', help='directory in which to dump carved PE files', default=os.path.curdir, type=check_arguments, dest='DUMP_DIR')
    parser.add_argument('-v', help='-v: print successfully parsed PE files; -vv: print failed parsed PE files; -vvv: print both', action='count', dest='VERBOSE')
    parser.add_argument('--overlay', help='include an overlay', action='store_true', default=False, dest='OVERLAY')
    parser.add_argument('-s', help='overlay size. Default: 4096 bytes', default=4096, dest='SIZE')
    parser.set_defaults(func=Carver)
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
    if os.path.isdir(obj):
        if not (os.access(obj, os.R_OK) and os.access(obj, os.X_OK)):
            raise argparse.ArgumentTypeError("{0} is not accessible".format(obj))
        return os.path.abspath(obj)
    raise argparse.ArgumentTypeError("{0} is not a file or a directory".format(obj))


class Colours:
    END      = "\x1b[0m"
    ERROR    = "\x1b[0;30;41m"
    PATCHERR = "\x1b[3;30;41m"
    SUCCESS  = "\x1b[0;30;42m"
    WARNING  = "\x1b[0;30;43m"

class Carver:
    def __init__(self, args):
        self.ARGS = args
        self.MMAP = None
        self.OFFSETS = []
        self.print_info()
        self.carve()

    @staticmethod
    def progress_start():
        """Starts progress bar"""
        sys.stdout.write("[-] Carving progress: " + "[" + "-" * 40 + "]" + "\r")
        sys.stdout.flush()

    @staticmethod
    def progress_update(count, total):
        """Updates progress bar"""
        sys.stdout.write("[-] Carving progress: " + "[" + "#" * int(count * 40.0 / total) + "\r")
        sys.stdout.flush()

    @staticmethod
    def progress_end():
        """Finalises progress bar"""
        sys.stdout.write("[#] Carving progress: " + "[" + "#" * 15 + " COMPLETE " + "#" * 15 + "]" + "\n")
        sys.stdout.flush()

    @staticmethod
    def get_ext(pe):
        """Returns extension of the PE file depending on its file type"""
        if pe.is_exe():
            return '.exe'
        if pe.is_dll():
            return '.dll'
        if pe.is_driver():
            return '.sys'
        return '.bin'

    @staticmethod
    def find_filename(pe):
        """Attempts to return OriginalFilename or InternalName of PE file (if available)"""
        try:
            # Parse all entries in resource section of the PE file
            pe.parse_data_directories(directories=pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE'])
        except (pefile.PEFormatError, AttributeError):
            return
        else:
            version_info = {}
            ext = ('.exe', '.dll', '.sys')
            if hasattr(pe, 'VS_VERSIONINFO'):
                for element in [element for element in pe.FileInfo if hasattr(pe, 'FileInfo')]:
                    if hasattr(element, 'StringTable'):
                        for table in [table for table in element.StringTable]:
                            for item in [item for item in table.entries.items()]:
                                if item[0] in ('OriginalFilename', 'InternalName'):
                                    version_info[item[0]] = item[1]
                    elif hasattr(element, 'Var'):
                        for variable in [variable for variable in element.Var if hasattr(variable, 'entry')]:
                            if variable.entry.keys()[0] in ('OriginalFilename', 'InternalName'):
                                version_info[variable.entry.keys()[0]] = variable.entry.values()[0]
            if "OriginalFilename" in version_info.keys() and os.path.splitext(version_info['OriginalFilename'])[-1].lower() in ext:
                return version_info['OriginalFilename']
            elif "InternalName" in version_info.keys() and os.path.splitext(version_info["InternalName"])[-1].lower() in ext:
                return version_info['InternalName']
            return

    def include_overlay(self, pe, offset):
        """
        Returns PE file with overlay, otherwise returns original PE file size.
           
        Using default cluster size for NTFS -and- smallest possible page size as overlay length; ie. 4096 bytes
        """
        overlay_length = 4096 - (len(pe) % 4096)
        if 0 < overlay_length < 4096:
            try:
                return self.MMAP[offset:offset+len(pe)+overlay_length]
            except IndexError:
                return pe
        return pe

    def print_info(self):
        """Prints user input information"""
        print("[#] File to carve:   {0}".format(os.path.basename(self.ARGS['DATA'])))
        print("[#] Dump directory:  {0}".format("./" + os.path.relpath(self.ARGS['DUMP_DIR']) if os.path.abspath('.') in self.ARGS['DUMP_DIR'] else self.ARGS['DUMP_DIR']))
        if self.ARGS['OVERLAY']:
            print("[#] Include overlay: " + Colours.SUCCESS + "Enabled"  + Colours.END + " (Overlay size set to {0} bytes)".format(self.ARGS['SIZE']))
        else:
            print("[#] Include overlay: " + Colours.WARNING + "Disabled" + Colours.END)

    def find_offsets(self):
        """Finds the offsets to DOS header signature (ie. MZ) locations based off DOS program stub"""
        sys.stdout.write("\r" + "[+] MS-DOS headers: Searching...")
        sys.stdout.flush()

        # .{64}                                                             ~30 seconds
        # .{6}\x00{2}\x04\x00{3}\xff{2}\x00{2}.{4}\x00{4}\x40\x00{35}.{4}   ~12 seconds
        self.OFFSETS = [offset for offset in
                       [_.start() for _ in re.finditer(r""".{6}\x00{2}\x04\x00{3}\xff{2}\x00{2}.{4}\x00{4}\x40\x00{35}.{4} # DOS header (64 bytes)
                                                           \x0e\x1f(?:.{3}|.{7})\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21       # DOS stub instructions
                                                           This[ ]program[ ]cannot[ ]be[ ]run[ ]in[ ]DOS[ ]mode            # DOS stub message
                                                           (?:\x2e\x0d)?\x0d\x0a\x24(?:\x00{5}|\x00{7})                    # DOS stub terminator""", 
                                                           self.MMAP, re.X)]]

        sys.stdout.write("\r" + "[#] MS-DOS headers: {0} found".format(len(self.OFFSETS)) + " " * 10 + "\n")
        sys.stdout.flush()
        time.sleep(0.5)

    def carve(self):
        """Carves out embedded PE files"""
        with open(self.ARGS['DATA'], mode='r') as file:
            with contextlib.closing(mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_COPY)) as self.MMAP:
                self.find_offsets()
                count = 0
                carve = 0
                messages = []
                self.progress_start()
                for offset in self.OFFSETS:
                    pe = None
                    patch = False
                    message = "[-] MS-DOS header @ {0:#011x}: ".format(offset)
                    while not pe:
                        try:
                            pe = pefile.PE(data=self.MMAP[offset:offset+5242880], fast_load=True) # Max binary size is 5MB
                        except pefile.PEFormatError as error:

                            dos_header = self.MMAP[offset:offset+64]

                            if error.value == 'DOS Header magic not found.':
                                self.MMAP[offset:offset+2] = bytes(bytearray([0x4D, 0x5A]))
                                patch = True
                            elif error.value == 'NT Headers not found.':
                                pe_sig_offset = struct.unpack('<L', dos_header[60:64])[0]
                                self.MMAP[offset+pe_sig_offset:offset+pe_sig_offset+4] = bytes(bytearray([0x50, 0x45, 0x00, 0x00]))
                                patch = True
                            else:
                                if self.ARGS['VERBOSE'] in [2, 3]:
                                    messages.append(Colours.PATCHERR + message + error.value + Colours.END if patch else Colours.ERROR + message + error.value + Colours.END)
                                break
                    if pe:
                        # Return just the data defined by the PE headers
                        data = pe.trim()

                        # If overlay is required, determine overlay length and append to data
                        if self.ARGS['OVERLAY']:
                            data = self.include_overlay(data, offset)

                        # Generate MD5 hash of PE file
                        md5 = hashlib.md5(data).hexdigest()

                        # Attempt to find the OriginalFilename or InternalName attributes for the PE file
                        filename = self.find_filename(pe)

                        if not filename:
                            filename = md5 + self.get_ext(pe)
                            outname  = os.path.join(self.ARGS['DUMP_DIR'], filename)
                        else:
                            outname  = os.path.join(self.ARGS['DUMP_DIR'], md5 + "-" + filename)
                        

                        if self.ARGS['VERBOSE'] in [1, 3]:
                            messages.append(Colours.WARNING + message + filename + Colours.END if patch else message + filename)

                        if not os.path.isfile(outname) and data:
                            with open(outname, mode='w') as out:
                                out.write(data)
                                carve+=1

                    count+=1
                    self.progress_update(count, len(self.OFFSETS))
                self.progress_end()
                print("[#]", carve, "binaries carved")

        if messages:
            
            # Legend
            print()
            print(Colours.WARNING  + " Patched                  " + Colours.END)
            print(Colours.ERROR    + " PEFormatError            " + Colours.END)
            print(Colours.PATCHERR + " Patched -> PEFormatError " + Colours.END)
            print()
            time.sleep(1)

            print("\n".join(messages))


if __name__ == '__main__':
    arguments()
