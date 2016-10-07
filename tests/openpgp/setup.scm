#!/usr/bin/env gpgscm

;; Copyright (C) 2016 g10 Code GmbH
;;
;; This file is part of GnuPG.
;;
;; GnuPG is free software; you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation; either version 3 of the License, or
;; (at your option) any later version.
;;
;; GnuPG is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.
;;
;; You should have received a copy of the GNU General Public License
;; along with this program; if not, see <http://www.gnu.org/licenses/>.

(load (with-path "defs.scm"))

(define (create-gpghome)
  (echo "Creating test environment...")

  (letfd ((fd (open "random_seed" (logior O_WRONLY O_CREAT O_BINARY) #o600)))
	 (call-with-fds (list (tool 'mktdata) "600") CLOSED_FD fd STDERR_FILENO))

  (for-each-p
   "Creating configuration files"
   (lambda (name)
     (file-copy (in-srcdir (string-append name ".tmpl")) name)
     (let ((p (open-input-output-file name)))
       (cond
	((string=? "gpg.conf" name)
	 (if have-opt-always-trust
	     (display "no-auto-check-trustdb\n" p))
	 (display (string-append "agent-program "
				 (tool 'gpg-agent)
				 "|--debug-quick-random\n") p)
	 (display "allow-weak-digest-algos\n" p))
	((string=? "gpg-agent.conf" name)
	 (display (string-append "pinentry-program " PINENTRY "\n") p)))))
   '("gpg.conf" "gpg-agent.conf"))

  (for-each-p "Creating sample data files"
	      (lambda (size)
		(letfd ((fd (open (string-append "data-" (number->string size))
				  (logior O_WRONLY O_CREAT O_BINARY) #o600)))
		       (call-with-fds (list (tool 'mktdata) (number->string size))
				      CLOSED_FD fd STDERR_FILENO)))
	      '(500 9000 32000 80000))

  (for-each-p "Unpacking samples"
	      (lambda (name)
		(dearmor (in-srcdir (string-append name "o.asc")) name))
	      '("plain-1" "plain-2" "plain-3" "plain-large"))

  ;; XXX implement cleanup
  (catch '()
	 (mkdir "private-keys-v1.d" "-rwx"))

  (define counter (make-counter))
  (for-each-p' "Storing private keys"
	       (lambda (name)
		 (dearmor (in-srcdir (string-append "/privkeys/" name ".asc"))
			  (string-append "private-keys-v1.d/" name ".key")))
	       (lambda (name) (counter))
	       '("50B2D4FA4122C212611048BC5FC31BD44393626E"
		 "7E201E28B6FEB2927B321F443205F4724EBE637E"
		 "13FDB8809B17C5547779F9D205C45F47CE0217CE"
		 "343D8AF79796EE107D645A2787A9D9252F924E6F"
		 "8B5ABF3EF9EB8D96B91A0B8C2C4401C91C834C34"
		 "0D6F6AD4C4C803B25470F9104E9F4E6A4CA64255"
		 "FD692BD59D6640A84C8422573D469F84F3B98E53"
		 "76F7E2B35832976B50A27A282D9B87E44577EB66"
		 "A0747D5F9425E6664F4FFBEED20FBCA79FDED2BD"
		 "00FE67F28A52A8AA08FFAED20AF832DA916D1985"
		 "1DF48228FEFF3EC2481B106E0ACA8C465C662CC5"
		 "A2832820DC9F40751BDCD375BB0945BA33EC6B4C"
		 "ADE710D74409777B7729A7653373D820F67892E0"
		 "CEFC51AF91F68A2904FBFF62C4F075A4785B803F"
		 "1E28F20E41B54C2D1234D896096495FF57E08D18"
		 "EB33B687EB8581AB64D04852A54453E85F3DF62D"
		 "C6A6390E9388CDBAD71EAEA698233FE5E04F001E"
		 "D69102E0F5AC6B6DB8E4D16DA8E18CF46D88CAE3"))

  (for-each-p
   "Importing public demo and test keys"
   (lambda (file)
     (call-check `(,@GPG --yes --import ,(in-srcdir file))))
   (list "pubdemo.asc" "pubring.asc" key-file1))

  (pipe:do
   (pipe:open (in-srcdir "pubring.pkr.asc") (logior O_RDONLY O_BINARY))
   (pipe:spawn `(,@GPG --dearmor))
   (pipe:spawn `(,@GPG --yes --import))))

(define (start-agent)
  (echo "Starting gpg-agent...")
  (call-check `(,(tool 'gpg-connect-agent) --verbose
		,(string-append "--agent-program=" (tool 'gpg-agent)
				"|--debug-quick-random")
		/bye))

  (info "Preset passphrases")
  ;; one@example.com
  (call-check `(,(tool 'gpg-preset-passphrase)
		--preset --passphrase def
		"50B2D4FA4122C212611048BC5FC31BD44393626E"))
  (call-check `(,(tool 'gpg-preset-passphrase)
		--preset --passphrase def
		"7E201E28B6FEB2927B321F443205F4724EBE637E"))
  ;; alpha@example.net
  (call-check `(,(tool 'gpg-preset-passphrase)
		--preset --passphrase abc
		"76F7E2B35832976B50A27A282D9B87E44577EB66"))
  (call-check `(,(tool 'gpg-preset-passphrase)
		--preset --passphrase abc
		"A0747D5F9425E6664F4FFBEED20FBCA79FDED2BD"))
  (echo "All set up."))

(define (kill-agent)
  (call-check `(,(tool 'gpg-connect-agent) --verbose killagent /bye)))

(cond
 ((member "--create-tarball" *args*)
  (with-temporary-working-directory
   (setenv "GNUPGHOME" (getcwd) #t)
   (create-gpghome)
   (kill-agent)
   (call-check `(,(tool 'gpgtar) --create --output ,(cadr *args*) "."))))
 ((member "--unpack-tarball" *args*)
  (call-check `(,(tool 'gpgtar) --extract --directory=. ,(cadr *args*)))
  (start-agent))
 (else
  (create-gpghome)
  (start-agent)))
