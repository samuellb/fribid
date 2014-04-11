#!/bin/sh
#
#  Copyright (c) 2014 Samuel Lidén Borell <samuel@kodafritt.se>
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

. "`dirname "$0"`/common.sh"

{

# Send command header
SignCommand
sendstring 'https://example.com/'  # URL
sendstring 'example.com'           # Hostname
sendstring '198.51.100.200'        # IP of example.com

# Send common data
sendstring 'MTIzNDU2Nzg5' # nonce
sendint 0                 # server time (optional)
sendstring ''             # policies (optional)
sendstring ''             # subject filter (optional)

# Send data to be signed
sendstring 'UTF-8' # message encoding
sendstring 'VGVzdAo=' # visible message
sendstring ''     # hidden data (optional)

# Prevent EOF
echo 'hack'

} | run sign --internal--ipc=10 | tr ';' '\n' | {

#### Parse response ####
read error
read sigLength
read signature
sha="`shorthash $signature`"

echo "error=$error,   length=$sigLength,   sha1=$sha"
if [ -n "$output" ]; then
    echo "$signature" | base64 -d > "$output"
fi

}

