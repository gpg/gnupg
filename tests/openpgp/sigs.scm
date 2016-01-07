#!/usr/bin/env gpgscm

(load (with-path "defs.scm"))

(for-each-p
 "Checking signing with the default hash algorithm"
 (lambda (source)
   (tr:do
    (tr:open source)
    (tr:gpg "" '(--yes --sign))
    (tr:gpg "" '(--yes))
    (tr:assert-identity source)))
 (append plain-files data-files))

(for-each-p
 "Checking signing with a specific hash algorithm"
 (lambda (hash)
   (if (have-pubkey-algo? "RSA")
       ;; RSA key, so any hash is okay.
       (tr:do
	(tr:open (car plain-files))
	(tr:gpg "" `(--yes --sign --user ,usrname3 --digest-algo ,hash))
	(tr:gpg "" '(--yes))
	(tr:assert-identity (car plain-files))))
   (if (not (equal? "MD5" hash))
       ;; Using the DSA sig key - only 160 bit or larger hashes
       (tr:do
	(tr:open (car plain-files))
	(tr:gpg usrpass1
		`(--yes --sign --passphrase-fd "0" --digest-algo ,hash))
	(tr:gpg "" '(--yes))
	(tr:assert-identity (car plain-files)))))
 all-hash-algos)
