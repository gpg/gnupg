;; Common definitions for the OpenPGP test scripts.
;;
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

;;
;; Constants.
;;

(define usrname1 "one@example.com")
(define usrpass1 "def")
(define usrname2 "two@example.com")
(define usrpass2 "")
(define usrname3 "three@example.com")
(define usrpass3 "")

(define dsa-usrname1 "pgp5")
;; we use the sub key because we do not yet have the logic to to derive
;; the first encryption key from a keyblock (I guess) (Well of course
;; we have this by now and the notation below will lookup the primary
;; first and then search for the encryption subkey.)
(define dsa-usrname2 "0xCB879DE9")

(define key-file1 "samplekeys/rsa-rsa-sample-1.asc")
(define key-file2 "samplekeys/ed25519-cv25519-sample-1.asc")

(define plain-files '("plain-1" "plain-2" "plain-3"))
(define data-files '("data-500" "data-9000" "data-32000" "data-80000"))
(define exp-files '())

(define (qualify executable)
  (string-append executable (getenv "EXEEXT")))

(define (getenv' key default)
  (let ((value (getenv key)))
    (if (string=? "" value)
	default
	value)))

(define tools
  '((gpg "GPG" "g10/gpg")
    (gpgv "GPGV" "g10/gpgv")
    (gpg-agent "GPG_AGENT" "agent/gpg-agent")
    (gpg-connect-agent "GPG_CONNECT_AGENT" "tools/gpg-connect-agent")
    (gpgconf "GPGCONF" "tools/gpgconf")
    (gpg-preset-passphrase "GPG_PRESET_PASSPHRASE"
			   "agent/gpg-preset-passphrase")
    (gpgtar "GPGTAR" "tools/gpgtar")
    (gpg-zip "GPGZIP" "tools/gpg-zip")
    (pinentry "PINENTRY" "tests/openpgp/fake-pinentry")))

(define (tool which)
  (let ((t (assoc which tools))
	(prefix (getenv "BIN_PREFIX")))
    (getenv' (cadr t)
	     (qualify (if (string=? prefix "")
			  (string-append (getenv "objdir") "/" (caddr t))
			  (string-append prefix "/" (basename (caddr t))))))))


(define have-opt-always-trust
  (string-contains? (call-popen `(,(tool 'gpg) --dump-options) "")
			"--always-trust"))

(define GPG `(,(tool 'gpg) --no-permission-warning
	      ,@(if have-opt-always-trust '(--always-trust) '())))
(define GPGV `(,(tool 'gpgv)))
(define PINENTRY (tool 'pinentry))

(define (tr:gpg input args)
  (tr:spawn input `(,@GPG --output **out** ,@args **in**)))

(define (pipe:gpg args)
  (pipe:spawn `(,@GPG --output - ,@args -)))

(define (gpg-with-colons args)
  (let ((s (call-popen `(,@GPG --with-colons ,@args) "")))
    (map (lambda (line) (string-split line #\:))
	 (string-split-newlines s))))

(define (get-config what)
  (string-split (caddar (gpg-with-colons `(--list-config ,what))) #\;))

(define all-pubkey-algos (get-config "pubkeyname"))
(define all-hash-algos (get-config "digestname"))
(define all-cipher-algos (get-config "ciphername"))

(define (have-pubkey-algo? x)
  (not (not (member x all-pubkey-algos))))
(define (have-hash-algo? x)
  (not (not (member x all-hash-algos))))
(define (have-cipher-algo? x)
  (not (not (member x all-cipher-algos))))

(define (gpg-pipe args0 args1 errfd)
  (lambda (source sink)
    (let* ((p (pipe))
	   (task0 (spawn-process-fd `(,@GPG ,@args0)
		   source (:write-end p) errfd))
	   (_ (close (:write-end p)))
	   (task1 (spawn-process-fd `(,@GPG ,@args1)
		   (:read-end p) sink errfd)))
      (close (:read-end p))
      (wait-processes (list GPG GPG) (list task0 task1) #t))))

(setenv "GPG_AGENT_INFO" "" #t)
(setenv "GNUPGHOME" (getcwd) #t)

;;
;; GnuPG helper.
;;

;; Call GPG to obtain the hash sums.  Either specify an input file in
;; ARGS, or an string in INPUT.  Returns a list of (<algo>
;; "<hashsum>") lists.
(define (gpg-hash-string args input)
  (map
   (lambda (line)
     (let ((p (string-split line #\:)))
       (list (string->number (cadr p)) (caddr p))))
   (string-split-newlines
    (call-popen `(,@GPG --with-colons ,@args) input))))

;; Dearmor a file.
(define (dearmor source-name sink-name)
  (pipe:do
   (pipe:open source-name (logior O_RDONLY O_BINARY))
   (pipe:spawn `(,@GPG --dearmor))
   (pipe:write-to sink-name (logior O_WRONLY O_CREAT O_BINARY) #o600)))

(let ((verbose (string->number (getenv "verbose"))))
  (if (number? verbose)
      (*set-verbose!* verbose)))

;;
;; Support for test environment creation and teardown.
;;

(define (make-test-data filename size)
  (call-with-binary-output-file
   filename
   (lambda (port)
     (display (make-random-string size) port))))

(define (create-gpghome)
  (log "Creating test environment...")

  (srandom (getpid))
  (make-test-data "random_seed" 600)

  (log "Creating configuration files")
  (for-each
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
   '("gpg.conf" "gpg-agent.conf")))

;; Initialize the test environment, install appropriate configuration
;; and start the agent, without any keys.
(define (setup-environment)
  (create-gpghome)
  (start-agent))

(define (create-legacy-gpghome)
  (log "Creating sample data files")
  (for-each
   (lambda (size)
     (make-test-data (string-append "data-" (number->string size))
		     size))
   '(500 9000 32000 80000))

  (log "Unpacking samples")
  (for-each
   (lambda (name)
     (dearmor (in-srcdir (string-append name "o.asc")) name))
   '("plain-1" "plain-2" "plain-3" "plain-large"))

  (mkdir "private-keys-v1.d" "-rwx")

  (log "Storing private keys")
  (for-each
   (lambda (name)
     (dearmor (in-srcdir (string-append "/privkeys/" name ".asc"))
	      (string-append "private-keys-v1.d/" name ".key")))
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

  (log "Importing public demo and test keys")
  (for-each
   (lambda (file)
     (call-check `(,@GPG --yes --import ,(in-srcdir file))))
   (list "pubdemo.asc" "pubring.asc" key-file1))

  (pipe:do
   (pipe:open (in-srcdir "pubring.pkr.asc") (logior O_RDONLY O_BINARY))
   (pipe:spawn `(,@GPG --dearmor))
   (pipe:spawn `(,@GPG --yes --import))))

(define (preset-passphrases)
  (log "Presetting passphrases")
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
		"A0747D5F9425E6664F4FFBEED20FBCA79FDED2BD")))

;; Initialize the test environment, install appropriate configuration
;; and start the agent, with the keys from the legacy test suite.
(define (setup-legacy-environment)
  (create-gpghome)
  (if (member "--unpack-tarball" *args*)
      (begin
	(call-check `(,(tool 'gpgtar) --extract --directory=. ,(cadr *args*)))
	(start-agent))
      (begin
	(start-agent)
	(create-legacy-gpghome)))
  (preset-passphrases))

;; Create the socket dir and start the agent.
(define (start-agent)
  (log "Starting gpg-agent...")
  (atexit stop-agent)
  (catch (log "Warning: Creating socket directory failed:" (car *error*))
	 (call-popen `(,(tool 'gpgconf) --create-socketdir) ""))
  (call-check `(,(tool 'gpg-connect-agent) --verbose
		,(string-append "--agent-program=" (tool 'gpg-agent)
				"|--debug-quick-random")
		/bye)))

;; Stop the agent and remove the socket dir.
(define (stop-agent)
  (log "Stopping gpg-agent...")
  (catch (log "Warning: Removing socket directory failed.")
	 (call-popen `(,(tool 'gpgconf) --remove-socketdir) ""))
  (call-check `(,(tool 'gpg-connect-agent) --verbose --no-autostart
		killagent /bye)))
