#!/usr/bin/env gpgscm

(load (with-path "defs.scm"))

(define s2k '--s2k-count=65536)
(define passphrase "Hier spricht HAL")

(define (file-copy-n from to n)
  (catch '() (unlink to))
  (letfd ((source (open from (logior O_RDONLY O_BINARY)))
	  (sink (open to (logior O_WRONLY O_CREAT O_BINARY) #o600)))
    (splice source sink n)))

(define test-files
  (map (lambda (size)
	 (let ((tmp (make-temporary-file
		     (string-append "data-80000-" (number->string size)))))
	   (file-copy-n "data-80000" tmp size)
	   tmp))
       '(0 1 2 3 9 10 11 19 20 21 22 23 39 40 41 8192 32000)))

(for-each-p
 "Checking conventional encryption with MDC"
 (lambda (algo)
   (for-each-p
    ""
    (lambda (source)
      (tr:do
       (tr:open source)
       (tr:gpg passphrase `(--yes --passphrase-fd "0" ,s2k
				  --force-mdc -c
				  --cipher-algo ,algo))
       (tr:gpg passphrase `(--yes --passphrase-fd "0" ,s2k))
       (tr:assert-identity source)))
    test-files))
 all-cipher-algos)

(for-each remove-temporary-file test-files)

(for-each-p
 "Checking sign+symencrypt"
 (lambda (source)
   (tr:do
    (tr:open source)
     (tr:gpg passphrase `(--yes --passphrase-fd "0" ,s2k -cs))
     (tr:gpg passphrase `(--yes --passphrase-fd "0" ,s2k))
     (tr:assert-identity source)))
 (append plain-files data-files))
