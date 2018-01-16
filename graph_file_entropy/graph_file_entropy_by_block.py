#!/usr/bin/env python

import argparse
import array
import math
import matplotlib.pyplot as plt
import numpy

def arguments():
    parser = argparse.ArgumentParser(description='Graphs the entropy of a given file per data block',
                                     epilog='Usage: python graph_file_entropy_by_block.py [path]filename')
    parser.add_argument(help='', type=argparse.FileType('rb'), dest='IN')
    args = parser.parse_args()
    return vars(args)

if __name__ == '__main__':
    args = arguments()
    byte_array = bytearray(args['IN'].read())
    size = len(byte_array)
    block_size = int(math.floor(size / 800))
    print "File size in bytes {:,d}".format(size)

    entropies = []

    for i in xrange(0, size, block_size):
        block = byte_array[i:i+block_size]
        occurences = array.array('i', [0]*256)
        for byte in block:
            occurences[byte] += 1

        entropy = 0.0
        for x in occurences:
            if x:
                x = float(x) / block_size
                entropy -= math.log(x, 2)
        entropies.append(entropy)

    N = len(entropies)

    ind = numpy.arange(N) # the x locations for the group
    width = 1.00          # the width of the bars

    fig = plt.figure(figsize=(18,3),dpi=100)
    fig.set_tight_layout(True)
    ax = fig.add_subplot(111)
    rects1 = ax.bar(ind, entropy, width)
    ax.set_autoscalex_on(False)
    ax.set_xlim([0,N])

    ax.set_ylabel("Entropy")
    ax.set_xlabel("Block ({:,d} bytes)".format(block_size))
    ax.set_title("Entropy of file per data block\nFilename: " + os.path.basename(args['IN'].name))

    plt.show()
