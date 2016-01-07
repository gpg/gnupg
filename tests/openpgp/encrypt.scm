#!/usr/bin/env gpgscm

(load (with-path "defs.scm"))

(for-each-p
 "Checking encryption"
 (lambda (source)
   (tr:do
    (tr:open source)
    (tr:gpg "" `(--yes --encrypt --recipient ,usrname2))
    (tr:gpg "" '(--yes))
    (tr:assert-identity source)))
 (append plain-files data-files))

(for-each-p
 "Checking encryption using a specific cipher algorithm"
 (lambda (cipher)
   (for-each-p
    ""
    (lambda (source)
      (tr:do
       (tr:open source)
       (tr:gpg "" `(--yes --encrypt --recipient ,usrname2
			  --cipher-algo ,cipher))
       (tr:gpg "" '(--yes))
       (tr:assert-identity source)))
    (append plain-files data-files)))
 all-cipher-algos)
