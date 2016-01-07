#!/usr/bin/env gpgscm

(load (with-path "defs.scm"))

(define files (append plain-files data-files))

(info "Checking armored detached signatures of multiple files")
(lettmp (tmp)
  (call-popen `(,@GPG --yes --passphrase-fd "0" -sab
		      --output ,tmp ,@files) usrpass1)
  (pipe:do
   (pipe:defer (lambda (sink)
		 (for-each (lambda (file)
			     (pipe:do
			      (pipe:open file (logior O_RDONLY O_BINARY))
			      (pipe:splice sink)))
			   files)))
   (pipe:spawn `(,@GPG --yes ,tmp))))
