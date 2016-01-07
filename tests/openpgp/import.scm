#!/usr/bin/env gpgscm

(load (with-path "defs.scm"))

(info "Checking bug 894: segv importing certain keys.")
(call-check `(,(tool 'gpg) --import ,(in-srcdir "bug894-test.asc")))

(define keyid "0xC108E83A")
(info "Checking bug 1223: designated revoker sigs are not properly merged.")
(call `(,(tool 'gpg) --delete-key --batch --yes ,keyid))
(call `(,(tool 'gpg) --import ,(in-srcdir "bug1223-bogus.asc")))
(call `(,(tool 'gpg) --import ,(in-srcdir "bug1223-good.asc")))
(tr:do
 (tr:pipe-do
  (pipe:gpg `(--list-keys --with-colons ,keyid)))
 (tr:call-with-content
  (lambda (c)
    ;; XXX we do not have a regexp library
    (unless (any (lambda (line)
		   (and (string-prefix? line "rvk:")
			(string-contains? line ":0EE5BE979282D80B9F7540F1CCD2ED94D21739E9:")))
		 (string-split c #\newline))
	    (exit 1)))))

(define fpr1 "9E669861368BCA0BE42DAF7DDDA252EBB8EBE1AF")
(define fpr2 "A55120427374F3F7AA5F1166DDA252EBB8EBE1AF")
(info "Checking import of two keys with colliding long key ids.")
(call `(,(tool 'gpg) --delete-key --batch --yes ,fpr1 ,fpr2))
(call `(,(tool 'gpg) --import ,(in-srcdir "samplekeys/dda252ebb8ebe1af-1.asc")))
(call `(,(tool 'gpg) --import ,(in-srcdir "samplekeys/dda252ebb8ebe1af-2.asc")))
(tr:do
 (tr:pipe-do
  (pipe:gpg `(--list-keys --with-colons ,fpr1 ,fpr2)))
 (tr:call-with-content
  (lambda (c)
    ;; XXX we do not have a regexp library
    (let ((keys (filter
		 (lambda (line)
		   (and (string-prefix? line "pub:")
			(string-contains? line ":4096:1:DDA252EBB8EBE1AF:")))
		 (string-split c #\newline))))
      (unless (= 2 (length keys))
	      (error "Importing keys with long id collision failed"))))))
