#!/usr/bin/php
<?php
# Use this for your test suites when a PHP interpreter is available.
#
# The encrypted keys in your test suite that you expect to work must
# be locked with a passphrase of "passphrase"
#
# Author: Daniel Kahn Gillmor <dkg@fifthhorseman.net>
#
# License: Creative Commons Zero ("Public Domain Dedication") --
# Anyone may reuse it, modify it, redistribute it for any purpose.

print("OK This is only for test suites, and should never be used in production\n");
while (true) {
    $line = fgets(STDIN);
    if (False === $line)
        break;
    $line = strtolower(trim($line));
    if (($line === "") || ($line[0] == '#'))
        continue;
    if ((0 === strncmp("getpin", $line, 6)))
        print("D passphrase\n");
    print("OK\n");
    if ((0 === strncmp("bye", $line, 3)))
        break;
}
?>
