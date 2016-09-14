#!/bin/sh
# Use this for your test suites when a POSIX shell is available.
#
# The encrypted keys in your test suite that you expect to work must
# be locked with a passphrase of "passphrase"
#
# Author: Daniel Kahn Gillmor <dkg@fifthhorseman.net>
#
# License: Creative Commons Zero ("Public Domain Dedication") --
# Anyone may reuse it, modify it, redistribute it for any purpose.

echo "OK This is only for test suites, and should never be used in production"
while read cmd rest; do
    cmd=$(printf "%s" "$cmd" | tr 'A-Z' 'a-z')
    if [ -z "$cmd" ]; then
        continue;
    fi
    case "$cmd" in
        \#*)
        ;;
        getpin)
            echo "D passphrase"
            echo "OK"
            ;;
        bye)
            echo "OK"
            exit 0
            ;;
        *)
            echo "OK"
            ;;
    esac
done
