#!/usr/bin/env python
# Use this for your test suites when a python interpreter is available.
#
# The encrypted keys in your test suite that you expect to work must
# be locked with a passphrase of "passphrase"
#
# Author: Daniel Kahn Gillmor <dkg@fifthhorseman.net>
#
# License: Creative Commons Zero ("Public Domain Dedication") --
# Anyone may reuse it, modify it, redistribute it for any purpose.

import sys, os

# turn off buffering:
sys.stdin = os.fdopen(sys.stdin.fileno(), 'r', 0)
sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)

print("OK This is only for test suites, and should never be used in production")
while True:
    ln = sys.stdin.readline()
    if (ln == ''):
        break
    ln = ln.lower()
    if (ln.strip() == '') or (ln.startswith('#')):
        continue
    if (ln.startswith('getpin')):
        sys.stdout.write('D passphrase\n')
    sys.stdout.write('OK\n')
    if (ln.startswith('bye')):
        break
