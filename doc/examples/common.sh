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

# Defaults
multiarch="`gcc -print-multiarch 2>/dev/null`"
if ( [ ! -h /usr/lib64 ] && [ -f /usr/lib64/libc.so ] && [ ! -d /usr/lib32 ] ) ||
   ( [ ! -h /lib64 ] && [ -f /lib64/libc.so.6 ] && [ ! -d /usr/lib32 ] ); then
    # RedHat etc.
    multilib="lib64"
elif [ -n "$multiarch" ]; then
    # New Debian with multiarch
    multilib="lib/$multiarch"
else
    # Old Debian and 32-bit RedHat
    multilib="lib"
fi

if [ -x "/usr/local/$multilib/fribid/sign" ]; then
    path="/usr/local/$multilib/fribid"
elif [ -x "/usr/$multilib/fribid/sign" ]; then
    path="/usr/$multilib/fribid"
else
    path=""
fi

mode=normal
output=""
fuzz_seed=""

# Parse command line

while [ "$#" -gt 0 ]; do
    opt="$1"
    case "$opt" in
        --valgrind|-V)
            mode=valgrind;;
        --valgrind-zzuf-p12|--valgrind-zzuf-pkcs12|-P)
            mode=valgrind-zzuf-pkcs12;;
        --valgrind-zzuf-x509|-X)
            mode=valgrind-zzuf-x509;;
        -o)
            output="$2"
            shift;;
        -s)
            fuzz_seed="$2"
            shift;;
        --help|-h)
            cat <<EOF
Usage: $0 [options] [fribid-lib-path]

Options:
    --valgrind, -V
                Run FriBID under Valgrind, but without leak checking.
    --valgrind-zzuf-pkcs12, -P
                Run FriBID under zzuf (a fuzzer) and fuzz PKCS#12 input.
    --valgrind-zzuf-x509, -P
                Run FriBID under zzuf (a fuzzer) and fuzz X509 input.
                Applicable to the "storecerts" command only.
    -o FILE
                Write signature or request output to the given file.
    -s NUMBER
                Seed number to pass to fuzzer's psuedo-random generator.
    --help, -h
                Show this help text.

The path is autodetected by default to /usr/lib/fribid or similar. If you
want to run FriBID from the source tree, you can specify the path to the
"client" directory.

EOF
            exit 0;;
        --)
            break;;
        -*)
            echo "$0: invalid option: $1" >&2
            exit 1;;
        *)
            path="$1";;
    esac
    shift
done

while [ "$#" -gt 0 ]; do
    path="$1"
done

# Check options
if [ -z "$path" ]; then
    echo "Couldn't find the fribid \"sign\" executable. Please specify the path manually!" >&2
    exit 1
fi

if [ -z "$fuzz_seed" ]; then
    fuzz_seed=0
elif [ "x$mode" != "xvalgrind-zzuf-pkcs12" -a "x$mode" != "xvalgrind-zzuf-x509" ]; then
    echo "The fuzz seed option can only be used with the zzuf options." >&2
    exit 1
fi


# IPC commands
sendint() { echo "$*;"; }
sendstring() { echo "${#1};$1"; }

SignCommand() { sendint 3; }
CreateRequest() { sendint 4; }
StoreCertsCommand() { sendint 5; }

MoreData() { sendint 1; }
EndOfData() { sendint 0; }

# Runs the FriBID executable
run() {
    exe="$1"
    shift
    case "$mode" in
        valgrind|valgrind-zzuf-x509)
            valgrind --leak-check=no -q "$path/$exe" $*;;
        valgrind-zzuf-pkcs12)
            valgrind --leak-check=no -q --trace-children=yes zzuf -s "$zzuf_seed" -I '.*\.[pP]12' "$path/$exe" $*;;
        normal)
            "$path/$exe" $*;;
    esac
}

shorthash() {
    if [ -z "$1" ]; then
        # Empty string
        echo "<empty>"
    elif which sha1sum > /dev/null 2>&1; then
        # Linux
        echo "$1" | sha1sum | head -c 5
    elif which sha1 > /dev/null 2>&1; then
        # BSD
        echo "$1" | sha1
    else
        echo "<command not available>"
    fi
}
