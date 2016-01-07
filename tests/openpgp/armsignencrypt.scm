#!/usr/bin/env gpgscm

(load (with-path "defs.scm"))

(for-each-p
 "Checking armored signing and encryption"
 (lambda (source)
   (tr:do
    (tr:open source)
    (tr:gpg usrpass1 `(--yes --passphrase-fd "0" -sea --recipient ,usrname2))
    (tr:gpg "" '(--yes))
    (tr:assert-identity source)))
 (append plain-files data-files))
