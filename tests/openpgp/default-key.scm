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
      (pipe:gpg `(--default-key ,keyid -s))
      (pipe:gpg '(--verify --status-fd=1)))
     (tr:call-with-content
      (lambda (c)
	(unless (string-contains?
		 c "VALIDSIG 5FBA84ACE02DCB17DA3DFF6BBCA43C441EA97479")
	    (exit 1))))))
 '("8BC90111" "3E880CFF" "F5F77B83" "45117079" "1EA97479"))

;; But, if we request a particular signing key, we should get it.
(for-each-p
 "Checking that the most recent, valid encryption subkey is used by default"
 (lambda (keyid)
   (tr:do
     (tr:pipe-do
      (pipe:defer (lambda (sink) (display "" (fdopen sink "w"))))
      ;; We need another recipient, because --encrypt-to-default-key is
      ;; not considered a recipient and gpg doesn't encrypt without any
      ;; recipients.
      ;;
      ;; Note: it doesn't matter whether we specify the primary key or
      ;; a subkey: the newest encryption subkey will be used.
      (pipe:gpg `(--default-key ,keyid --encrypt-to-default-key
				-r "439F02CA" -e))
      (pipe:gpg '(--list-packets)))
     (tr:call-with-content
      (lambda (c)
	(unless (any (lambda (line)
		       (and (string-prefix? line ":pubkey enc packet:")
			    (string-suffix? line "45117079")))
		     (string-split c #\newline))
	    (exit 1))))))
 '("8BC90111" "3E880CFF" "F5F77B83" "45117079" "1EA97479"))
