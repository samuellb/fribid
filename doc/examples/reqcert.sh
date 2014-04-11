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
CreateRequest
sendstring 'https://example.com/'  # URL
sendstring 'example.com'           # Hostname
sendstring '198.51.100.200'        # IP of example.com

# Password policy
sendint  12  # Minimum length
sendint   4  # Minimum number of non-digits
sendint   1  # Minimum number of digits

# PKCS10
MoreData
    sendint 1                # KeyUsage
    sendint 2048             # KeySize
    sendstring 'CN=TEST PERSON,OID.2.5.4.41=(090102 12.30) TEST PERSON - BankID på fil,SN=197711223334,G=TEST,S=PERSON' # SubjectDN
    sendint 0                # Include full DN
MoreData
    sendint 2                # KeyUsage
    sendint 2048             # KeySize
    sendstring 'CN=TEST PERSON,OID.2.5.4.41=(090102 12.30) TEST PERSON - BankID på fil,SN=197711223334,G=TEST,S=PERSON' # SubjectDN
    sendint 1                # Include full DN
EndOfData

# CMC
sendstring 'Not Applicable'
sendstring true

# Prevent EOF
echo 'hack'

} | run sign --internal--ipc=10 | tr ';' '\n' | {

#### Parse response ####
read error
read requestLength
read request
sha="`shorthash $request`"

echo "error=$error,   length=$requestLength,   sha1=$sha"
if [ -n "$output" ]; then
    echo "$request" | base64 -d > "$output"
fi

}

