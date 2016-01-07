#!/usr/bin/env gpgscm

(load (with-path "defs.scm"))

(for-each-p
 "Checking signing and encryption using DSA"
 (lambda (source)
   (tr:do
    (tr:open source)
    (tr:gpg usrpass1 `(--yes --passphrase-fd "0" -se
			     -u ,dsa-usrname1
			     --recipient ,dsa-usrname2))
    (tr:gpg "" '(--yes))
    (tr:assert-identity source)))
 (append plain-files data-files))

(define algos (if (have-hash-algo? "RIPEMD160")
		  '("SHA1" "RIPEMD160")
		  '("SHA1")))
(for-each-p
 "Checking signing and encryption using DSA with a specific hash algorithm"
 (lambda (hash)
   (tr:do
    (tr:open (car plain-files))
    (tr:gpg usrpass1 `(--yes --passphrase-fd "0" -se
			     -u ,dsa-usrname1
			     --recipient ,dsa-usrname2
			     --digest-algo ,hash))
    (tr:gpg "" '(--yes))
    (tr:assert-identity (car plain-files))))
 algos)
