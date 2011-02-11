#!/bin/sh

sendint() { echo "$*;"; }
sendstring() { echo "${#1};$1"; }

CreateRequest() { sendint 3; }

MoreData() { sendint 1; }
EndOfData() { sendint 0; }


{

#### Send request ####
CreateRequest

# PKCS10
MoreData
    sendint 1                # KeyUsage
    sendint 2048             # KeySize
    sendstring 'CN=TEST PERSON,OID.2.5.4.41=(090102 12.30) TEST PERSON - BankID på fil,SN=197711223334,G=TEST,S=PERSON' # SubjectDN
EndOfData

# CMC
sendstring 'Not Applicable'
sendstring true

# Prevent EOF
echo 'hack'


} | valgrind --leak-check=no -q ./sign --internal--ipc=5 | tr ';' '\n' | {
#} | ./sign --internal--ipc=5 | tr ';' '\n' | {

#### Parse response ####
read error
read requestLength
read request
sha="`echo $request | sha1sum | head -c 5`"

echo "error=$error,   length=$requestLength,   sha1=$sha"
echo "$request" | base64 -d > test/output.p7

}

