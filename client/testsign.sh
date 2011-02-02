#!/bin/sh

sendint() { echo "$*;"; }
sendstring() { echo "${#1};$1"; }

SignCommand() { sendint 2; }


{

#### Send sign command ####
SignCommand

# Send common data
sendstring 'MTIzNDU2Nzg5' # nonce
sendint 0                 # server time (optional)
sendstring ''             # policies (optional)
sendstring ''             # subject filter (optional)

sendstring 'https://example.com/'  # URL
sendstring 'example.com'           # Hostname
sendstring '198.51.100.200'        # IP of example.com

# Send data to be signed
sendstring 'aGkK' # visible message
sendstring ''     # hidden data (optional)

# Prevent EOF
echo 'hack'


#} | valgrind --leak-check=no -q ./sign --internal--ipc=5 | tr ';' '\n' | {
} | ./sign --internal--ipc=5 | tr ';' '\n' | {

#### Parse response ####
read error
read sigLength
read signature
sha="`echo $signature | sha1sum | head -c 5`"

echo "error=$error,   length=$requestLength,   sha1=$sha"
echo "$signature" | base64 -d > test/signature.xml

}

