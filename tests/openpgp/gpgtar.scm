#!/usr/bin/env gpgscm

(load (with-path "defs.scm"))

(unless (= 0 (call `(,(tool 'gpgtar) --help)))
	(skip "gpgtar not installed"))

(define testfiles (append plain-files data-files))
(define gpgargs
  (if have-opt-always-trust
      "--no-permission-warning --always-trust"
      "--no-permission-warning"))

(define (do-test create-flags inspect-flags extract-flags)
  (lettmp (archive)
    (call-check `(,(tool 'gpgtar) --gpg ,(tool 'gpg) --gpg-args ,gpgargs
		  ,@create-flags
		  --output ,archive
		  ,@testfiles))
    (tr:do
     (tr:pipe-do
      (pipe:spawn `(,(tool 'gpgtar) --gpg ,(tool 'gpg) --gpg-args ,gpgargs
		    --list-archive ,@inspect-flags
		    ,archive)))
     (tr:call-with-content
      (lambda (c)
	(unless (all (lambda (f) (string-contains? c f)) testfiles)
		(error "some file(s) are missing from archive")))))

    (with-temporary-working-directory
     (call-check `(,(tool 'gpgtar) --gpg ,(tool 'gpg) --gpg-args ,gpgargs
		   --tar-args --directory=.
		   --decrypt
		   ,@extract-flags
		   ,archive))

     (for-each
      (lambda (f) (unless (call-with-input-file f (lambda (x) #t))
			  (error (string-append "missing file: " f))))
      testfiles))))

(info "Checking gpgtar without encryption")
(do-test `(--skip-crypto --encrypt) '(--skip-crypto) '(--skip-crypto))

(info "Checking gpgtar with asymmetric encryption")
(do-test `(--encrypt --recipient ,usrname2) '() '())

(info "Checking gpgtar with asymmetric encryption and signature")
(do-test `(--encrypt --recipient ,usrname2 --sign --local-user ,usrname3)
	 '() '())

(info "Checking gpgtar with signature")
(do-test `(--sign --local-user ,usrname3) '() '())

(lettmp (passphrasefile)
  (letfd ((fd (open passphrasefile (logior O_WRONLY O_CREAT O_BINARY) #o600)))
    (display "streng geheimes hupsipupsi" (fdopen fd "wb")))

  (let ((ppflags `(--gpg-args ,(string-append "--passphrase-file="
					      passphrasefile))))
    (info "Checking gpgtar with symmetric encryption")
    (do-test `(,@ppflags --symmetric) ppflags ppflags)

    (info "Checking gpgtar with symmetric encryption and chosen cipher")
    (do-test `(,@ppflags --symmetric --gpg-args
			 ,(string-append "--cipher=" (car all-cipher-algos)))
	     ppflags ppflags)

    (info "Checking gpgtar with both symmetric and asymmetric encryption")
    (do-test `(,@ppflags --symmetric --encrypt --recipient ,usrname2
			 --sign --local-user ,usrname3) ppflags ppflags)))
