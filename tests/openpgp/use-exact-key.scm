#!/usr/bin/env gpgscm

(load (with-path "defs.scm"))

;; Import the sample key
;;
;; pub   1024R/8BC90111 2015-12-02
;;       Key fingerprint = E657 FB60 7BB4 F21C 90BB  6651 BC06 7AF2 8BC9 0111
;; uid       [ultimate] Barrett Brown <barrett@example.org>
;; sub   1024R/3E880CFF 2015-12-02 (encryption)
;; sub   1024R/F5F77B83 2015-12-02 (signing)
;; sub   1024R/45117079 2015-12-02 (encryption)
;; sub   1024R/1EA97479 2015-12-02 (signing)

(info "Importing public key.")
(call-check
 `(,(tool 'gpg) --import
   ,(in-srcdir "samplekeys/E657FB607BB4F21C90BB6651BC067AF28BC90111.asc")))

;; By default, the most recent, valid signing subkey (1EA97479).
(for-each-p
 "Checking that the most recent, valid signing subkey is used by default"
 (lambda (keyid)
   (tr:do
     (tr:pipe-do
      (pipe:defer (lambda (sink) (display "" (fdopen sink "w"))))
      (pipe:gpg `(-s -u ,keyid))
      (pipe:gpg '(--verify --status-fd=1)))
     (tr:call-with-content
      (lambda (c)
	(unless (string-contains?
		 c "VALIDSIG 5FBA84ACE02DCB17DA3DFF6BBCA43C441EA97479")
	    (exit 1))))))
 '("8BC90111" "3E880CFF" "F5F77B83" "45117079" "1EA97479"))

;; But, if we request a particular signing key, we should get it.
(for-each-p
 "Checking that we can select a specific signing key"
 (lambda (keyid)
   (tr:do
     (tr:pipe-do
      (pipe:defer (lambda (sink) (display "" (fdopen sink "w"))))
      (pipe:gpg `(-s -u ,(string-append keyid "!")))
      (pipe:gpg '(--verify --status-fd=1)))
     (tr:call-with-content
      (lambda (c)
	;; XXX we do not have a regexp library
	(unless (and (string-contains? c "VALIDSIG")
		     (string-contains? c keyid))
	    (exit 1))))))
 '("8BC90111" "F5F77B83" "1EA97479"))
