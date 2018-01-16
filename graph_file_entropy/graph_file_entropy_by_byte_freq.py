#!/usr/bin/env python

import argparse
import array
import math
import os

def arguments():
    parser = argparse.ArgumentParser(description='Graphs the entropy of a given file per data block',
                                     epilog='Usage: python graph_file_entropy_by_block.py [path]filename')
    parser.add_argument(help='', type=argparse.FileType('rb'), dest='IN')
    parser.add_argument('-g', '--graph', help='', action='store_true', default=False, dest='GRAPH')
    args = parser.parse_args()
    return vars(args)

if __name__ == '__main__':
    args = arguments()
    byte_array = bytearray(args['IN'].read())
    size = len(byte_array)
    print "File size in bytes {:,d}".format(size)

    frequency = []

    occurences = array.array('i', [0]*256)
    for byte in byte_array:
        occurences[byte] += 1

    entropy = 0.0
    for x in occurences:
        if x:
            x = float(x) / size
            entropy -= math.log(x, 2)
        y = x * 100
        frequency.append(y)

    print "Shannon entropy (min bits per byte-character):", entropy
    print "Min possible file size assuming max theoretical compression efficiency"
    print "{:,d}".format(int(round((entropy * size), 0)))
    print "{:,d}".format(int(round((entropy * size) / 8, 0)))

    if args['GRAPH']:
        import matplotlib.pyplot as plt
        import numpy

        N = len(frequency)

        ind = numpy.arange(N) # the x locations for the group
        width = 1.00          # the width of the bars

        fig = plt.figure(figsize=(11,5),dpi=100)
        fig.set_tight_layout(True)
        ax = fig.add_subplot(111)
        rects1 = ax.bar(ind, entropy, width)
        ax.set_autoscalex_on(False)
        ax.set_xlim([0,N])

        ax.set_ylabel("Entropy")
        ax.set_xlabel("Block ({:,d} bytes)".format(block_size))
        ax.set_title("Entropy of file per data block\nFilename: " + os.path.basename(args['IN'].name))

        plt.show()
