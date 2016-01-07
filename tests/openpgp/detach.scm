#!/usr/bin/env gpgscm

(load (with-path "defs.scm"))

(for-each-p
 "Checking detached signatures"
 (lambda (source)
   (lettmp (tmp)
     (call-popen `(,@GPG --yes --passphrase-fd "0" -sb
			 --output ,tmp ,source ) usrpass1)
     (pipe:do
      (pipe:open source (logior O_RDONLY O_BINARY))
      (pipe:spawn `(,@GPG --yes ,tmp)))))
 (append plain-files data-files))
