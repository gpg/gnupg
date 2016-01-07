#!/usr/bin/env gpgscm

(load (with-path "defs.scm"))

(for-each-p
 "Checking encryption, signing, and producing armored output"
 (lambda (source)
   (tr:do
    (tr:open source)
    (tr:gpg usrpass1 '(--yes -seat -r two@example.com --passphrase-fd "0"))
    (tr:gpg "" '(--yes))
    (tr:assert-weak-identity source)))
 plain-files)
