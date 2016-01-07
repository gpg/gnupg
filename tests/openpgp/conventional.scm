#!/usr/bin/env gpgscm

(load (with-path "defs.scm"))

(define s2k '--s2k-count=65536)
(define passphrase "Hier spricht HAL")

(for-each-p
 "Checking conventional encryption"
 (lambda (source)
   (tr:do
    (tr:open source)
     (tr:gpg passphrase `(--yes --passphrase-fd "0" ,s2k -c))
     (tr:gpg passphrase `(--yes --passphrase-fd "0" ,s2k))
     (tr:assert-identity source)))
 '("plain-2" "data-32000"))

(for-each-p
 "Checking conventional encryption using a specific cipher"
 (lambda (algo)
   (for-each-p
    ""
    (lambda (source)
      (tr:do
       (tr:open source)
       (tr:gpg passphrase `(--yes --passphrase-fd "0" ,s2k -c
				  --cipher-algo ,algo))
       (tr:gpg passphrase `(--yes --passphrase-fd "0" ,s2k))
       (tr:assert-identity source)))
    '("plain-1" "data-80000")))
 all-cipher-algos)
