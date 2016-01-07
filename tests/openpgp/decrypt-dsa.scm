#!/usr/bin/env gpgscm

(load (with-path "defs.scm"))

(for-each-p
 "Checking decryption of supplied DSA encrypted file"
 (lambda (name)
   (tr:do
    (tr:open (in-srcdir (string-append name "-pgp.asc")))
    (tr:gpg "" '(--yes))
    (tr:assert-identity name)))
 (list (car plain-files)))
