#!/usr/bin/python
#coding: utf-8
#
#  Copyright (c) 2012 Samuel Lidén Borell <samuel@slbdata.se>
#
#  Permission is hereby granted, free of charge, to any person obtaining a copy
#  of this software and associated documentation files (the "Software"), to deal
#  in the Software without restriction, including without limitation the rights
#  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#  copies of the Software, and to permit persons to whom the Software is
#  furnished to do so, subject to the following conditions:
#  
#  The above copyright notice and this permission notice shall be included in
#  all copies or substantial portions of the Software.
#  
#  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
#  THE SOFTWARE.
#

import random, sys


if len(sys.argv) != 2:
    sys.stderr.write("usage: ./fuzz-p12.py  input_file.p12\n")
    sys.exit(2)

good_file = sys.argv[1]


f = open(good_file, 'rb')
buff = f.read()
f.close()

for i in xrange(len(buff)):
    fuzzed = buff[:]
    fuzzed = buff[:i] + chr(random.randint(0, 255)) + buff[i+1:]
    out = open('fuzzed'+str(i)+'.p12', 'wb')
    out.write(fuzzed)
    out.close()

