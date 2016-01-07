#!/usr/bin/env gpgscm

(load (with-path "defs.scm"))

(for-each-p
 "Checking signing and encryption"
 (lambda (source)
   (tr:do
    (tr:open source)
    (tr:gpg usrpass1 `(--yes --passphrase-fd "0" -se --recipient ,usrname2))
    (tr:gpg "" '(--yes))
    (tr:assert-identity source)))
 (append plain-files data-files))

(info "Checking bug 537: MDC problem with old style compressed packets.")
(lettmp (tmp)
  (call-popen `(,@GPG --yes --passphrase-fd "0"
		      --output ,tmp ,(in-srcdir "bug537-test.data.asc"))
	      usrpass1)
  (if (not (string=? "4336AE2A528FAE091E73E59E325B588FEE795F9B"
		     (cadar (gpg-hash-string `(--print-md SHA1 ,tmp) ""))))
      (error "bug537-test.data.asc: mismatch (bug 537)")))
