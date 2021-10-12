;; Common definitions for the OpenPGP test scripts.
;;
;; Copyright (C) 2016, 2017 g10 Code GmbH
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

(let ((verbose (string->number (getenv "verbose"))))
  (if (number? verbose)
      (*set-verbose!* verbose)))

(define (qualify executable)
  (string-append executable (getenv "EXEEXT")))

(define (getenv' key default)
  (let ((value (getenv key)))
    (if (string=? "" value)
	default
	value)))

(define (percent-decode s)
  (define (decode c)
    (if (and (> (length c) 2) (char=? #\% (car c)))
	(integer->char (string->number (string #\# #\x (cadr c) (caddr c))))
	#f))
  (let loop ((i 0) (c (string->list s)) (r (make-string (string-length s))))
    (if (null? c)
	(substring r 0 i)
	(let ((decoded (decode c)))
	  (string-set! r i (if decoded decoded (car c)))
	  (loop (+ 1 i) (if decoded (cdddr c) (cdr c)) r)))))
(assert (equal? (percent-decode "") ""))
(assert (equal? (percent-decode "%61") "a"))
(assert (equal? (percent-decode "foob%61r") "foobar"))

(define (percent-encode s)
  (define (encode c)
    `(#\% ,@(string->list (number->string (char->integer c) 16))))
  (let loop ((acc '()) (cs (reverse (string->list s))))
    (if (null? cs)
	(list->string acc)
	(case (car cs)
	  ((#\: #\%)
	   (loop (append (encode (car cs)) acc) (cdr cs)))
	  (else
	   (loop (cons (car cs) acc) (cdr cs)))))))
(assert (equal? (percent-encode "") ""))
(assert (equal? (percent-encode "%61") "%2561"))
(assert (equal? (percent-encode "foob%61r") "foob%2561r"))

(define tools
  '((gpgv "GPGV" "g10/gpgv")
    (gpg-connect-agent "GPG_CONNECT_AGENT" "tools/gpg-connect-agent")
    (gpgconf "GPGCONF" "tools/gpgconf")
    (gpg-preset-passphrase "GPG_PRESET_PASSPHRASE"
			   "agent/gpg-preset-passphrase")
    (gpgtar "GPGTAR" "tools/gpgtar")
    (tpm2daemon "TPM2DAEMON" "tpm2d/tpm2daemon")
    (pinentry "PINENTRY" "tests/openpgp/fake-pinentry")))

(define with-valgrind? (not (string=? (getenv "with_valgrind") "")))

(define (tool-hardcoded which)
  (let ((t (assoc which tools)))
    (getenv' (cadr t)
	     (qualify (string-append (getenv "GNUPG_BUILD_ROOT")
                                     "/" (caddr t))))))

;; You can splice VALGRIND into your argument vector to run programs
;; under valgrind.  For example, to run valgrind on gpg, you may want
;; to redefine gpg:
;;
;; (set! gpg `(,@valgrind ,@gpg))
;;
(define valgrind
  '("/usr/bin/valgrind" -q --leak-check=no --track-origins=yes
                        --error-exitcode=154 --exit-on-first-error=yes))

(define (gpg-conf . args)
  (gpg-conf' "" args))
(define (gpg-conf' input args)
  (let ((s (call-popen `(,(tool-hardcoded 'gpgconf)
			 ,@args) input)))
    (map (lambda (line) (map percent-decode (string-split line #\:)))
	 (string-split-newlines s))))
(define :gc:c:name car)
(define :gc:c:description cadr)
(define :gc:c:pgmname caddr)
(define (:gc:o:name x)             (list-ref x 0))
(define (:gc:o:flags x)            (string->number (list-ref x 1)))
(define (:gc:o:level x)            (string->number (list-ref x 2)))
(define (:gc:o:description x)      (list-ref x 3))
(define (:gc:o:type x)             (string->number (list-ref x 4)))
(define (:gc:o:alternate-type x)   (string->number (list-ref x 5)))
(define (:gc:o:argument-name x)    (list-ref x 6))
(define (:gc:o:default-value x)    (list-ref x 7))
(define (:gc:o:default-argument x) (list-ref x 8))
(define (:gc:o:value x)            (if (< (length x) 10) "" (list-ref x 9)))

(define (gpg-config component key)
  (package
   (define (value)
     (let* ((conf (assoc key (gpg-conf '--list-options component)))
	    (type (:gc:o:type conf))
	    (value (:gc:o:value conf)))
       (case type
	 ((0 2 3) (string->number value))
	 ((1 32) (substring value 1 (string-length value))))))
   (define (update value)
     (let ((value' (cond
		    ((string? value) (string-append "\"" value))
		    ((number? value) (number->string value))
		    (else (throw "Unsupported value" value)))))
       (gpg-conf' (string-append key ":0:" (percent-encode value'))
		  `(--change-options ,component))))
   (define (clear)
     (gpg-conf' (string-append key ":16:")
		`(--change-options ,component)))))

(define gpg-components (apply gpg-conf '(--list-components)))

(define (tool which)
  (case which
    ((gpg gpg-agent scdaemon gpgsm dirmngr)
     (:gc:c:pgmname (assoc (symbol->string which) gpg-components)))
    (else
     (tool-hardcoded which))))

(define (gpg-has-option? option)
  (string-contains? (call-popen `(,(tool 'gpg) --dump-options) "")
		    option))

(define have-opt-always-trust
  (catch #f
	 (with-ephemeral-home-directory (lambda ()) (lambda ())
	   (call-check `(,(tool 'gpg) --gpgconf-test --always-trust)))
	 #t))

(define GPG `(,(tool 'gpg) --no-permission-warning
	      ,@(if have-opt-always-trust '(--always-trust) '())))
(define GPGV `(,(tool 'gpgv)))
(define PINENTRY (tool 'pinentry))
(define TPM2DAEMON (tool 'tpm2daemon))

(define (tr:gpg input args)
  (tr:spawn input `(,@GPG --output **out** ,@args **in**)))

(define (pipe:gpg args)
  (pipe:spawn `(,@GPG --output - ,@args)))

(define (gpg-with-colons args)
  (let ((s (call-popen `(,@GPG --with-colons ,@args) "")))
    (map (lambda (line) (string-split line #\:))
	 (string-split-newlines s))))

(define (secinfo name)
  (assoc "sec" (gpg-with-colons `(--list-secret-key ,name))))
(define (ssbinfo name)
  (assoc "ssb" (gpg-with-colons `(--list-secret-key ,name))))
(define (fingerprint name)
  (:fpr (assoc "fpr" (gpg-with-colons `(--list-secret-key ,name)))))
;; convenient accessors for sec
(define (:cardinfo x) (list-ref x 14))
;; Convenient accessors for the colon output of pub.
(define (:type x)   (string->symbol (list-ref x 0)))
(define (:length x) (string->number (list-ref x 2)))
(define (:alg x) (string->number (list-ref x 3)))
(define (:expire x) (list-ref x 6))
(define (:fpr x) (list-ref x 9))
(define (:cap x) (list-ref x 11))

(define (have-public-key? key)
  (catch #f
	 (pair? (filter (lambda (l) (and (equal? 'fpr (:type l))
					 (equal? key::fpr (:fpr l))))
			(gpg-with-colons `(--list-keys ,key::fpr))))))

(define (have-secret-key? key)
  (catch #f
	 (pair? (filter (lambda (l) (and (equal? 'fpr (:type l))
					 (equal? key::fpr (:fpr l))))
			(gpg-with-colons `(--list-secret-keys ,key::fpr))))))

(define (have-secret-key-file? key)
  (file-exists? (path-join (getenv "GNUPGHOME") "private-keys-v1.d"
			   (string-append key::grip ".key"))))

(define (get-config what)
  (string-split (caddar (gpg-with-colons `(--list-config ,what))) #\;))

(define all-pubkey-algos (delay (get-config "pubkeyname")))
(define all-hash-algos (delay (get-config "digestname")))
(define all-cipher-algos (delay (get-config "ciphername")))
(define all-compression-algos (delay (get-config "compressname")))

(define (have-pubkey-algo? x)
  (not (not (member x (force all-pubkey-algos)))))
(define (have-hash-algo? x)
  (not (not (member x (force all-hash-algos)))))
(define (have-cipher-algo? x)
  (not (not (member x (force all-cipher-algos)))))
(define (have-compression-algo? x)
  (not (not (member x (force all-compression-algos)))))

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

;;
;; Do we have a software tpm
;;
(define have-swtpm? (not (and (string=? "" (getenv "TPMSERVER"))
			      (string=? "" (getenv "SWTPM")))))
(setenv "GPG_AGENT_INFO" "" #t)
(setenv "GNUPGHOME" (getcwd) #t)
(if have-swtpm?
    (setenv "TPM_INTERFACE_TYPE" "socsim" #t))
(define GNUPGHOME (getcwd))

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

(define (gpg-dump-packets source-name sink-name)
  (pipe:do
   (pipe:open source-name (logior O_RDONLY O_BINARY))
   (pipe:spawn `(,@GPG --list-packets))
   (pipe:write-to sink-name (logior O_WRONLY O_CREAT O_BINARY) #o600)))

;;
;; Support for test environment creation and teardown.
;;

(define (make-test-data filename size)
  (call-with-binary-output-file
   filename
   (lambda (port)
     (display (make-random-string size) port))))

(define (create-file name . lines)
  (catch #f (unlink name))
  (letfd ((fd (open name (logior O_WRONLY O_CREAT O_BINARY) #o600)))
    (let ((port (fdopen fd "wb")))
      (for-each (lambda (line) (display line port) (newline port))
		lines))))

(define (create-gpghome)
  (log "Creating test environment...")

  (srandom (getpid))
  (make-test-data "random_seed" 600)

  (log "Creating configuration files")

  (if (flag "--use-keyring" *args*)
      (create-file "pubring.gpg"))

  (create-file "gpg.conf"
               ;;"log-file socket:///tmp/S.wklog"
               ;;"verbose"
	       "no-greeting"
	       "no-secmem-warning"
	       "no-permission-warning"
	       "batch"
               "no-auto-key-retrieve"
               "no-auto-key-locate"
	       "allow-weak-digest-algos"
               "ignore-mdc-error"
	       (if have-opt-always-trust
		   "no-auto-check-trustdb" "#no-auto-check-trustdb")
	       (string-append "agent-program "
			      (tool 'gpg-agent)
			      "|--debug-quick-random\n")
	       (if (flag "--use-keyboxd" *args*)
		   "use-keyboxd" "#use-keyboxd")
	       )
  (create-file "gpg-agent.conf"
	       "allow-preset-passphrase"
	       "debug-all"
	       "log-file gpg-agent.log"
	       "no-grab"
	       "enable-ssh-support"
               "s2k-count 65536"
	       (string-append "pinentry-program " (tool 'pinentry))
	       (string-append "tpm2daemon-program " (tool 'tpm2daemon))
	       "disable-scdaemon")
  (create-file "msg.txt"
	       "This is a test of TPM signing and encryption"
	       "With two lines of text"))

;; Initialize the test environment, install appropriate configuration
;; and start the agent, without any keys.
(define (setup-environment)
  (create-gpghome)
  (start-agent)
  (start-tpm))

(define (setup-environment-no-atexit)
  (create-gpghome)
  (start-agent #t))

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

;; start the tpm server
(define (start-tpm)
  (if have-swtpm?
      (begin (define pid (call-check `(,(in-srcdir "tests" "tpm2dtests" "start_sw_tpm.sh"))))
	     (if (not (null? pid))
		 (atexit (lambda ()
			   (call-check `("/bin/kill" ,pid))))))))

;; Create the socket dir and start the agent.
(define (start-agent . args)
  (log "Starting gpg-agent...")
  (let ((gnupghome (getenv "GNUPGHOME")))
    (if (null? args)
	(atexit (lambda ()
		  (with-home-directory gnupghome (stop-agent))))))
  (catch (log "Warning: Creating socket directory failed:" (car *error*))
	 (gpg-conf '--create-socketdir))
  (call-check `(,(tool 'gpg-connect-agent) --verbose
		,(string-append "--agent-program=" (tool 'gpg-agent)
				"|--debug-quick-random")
		/bye)))

;; Stop the agent and other daemons and remove the socket dir.
(define (stop-agent)
  (log "Stopping gpg-agent...")
  (gpg-conf '--kill 'all)
  (catch (log "Warning: Removing socket directory failed.")
	 (gpg-conf '--remove-socketdir)))

;; Get the trust level for KEYID.  Any remaining arguments are simply
;; passed to GPG.
;;
;; This function only supports keys with a single user id.
(define (gettrust keyid . args)
  (let ((trust
	  (list-ref (assoc "pub" (gpg-with-colons
				   `(,@args
				      --list-keys ,keyid))) 1)))
    (unless (and (= 1 (string-length trust))
		 (member (string-ref trust 0) (string->list "oidreqnmfuws-")))
	    (fail "Bad trust value:" trust))
    trust))

;; Check that KEYID's trust level matches EXPECTED-TRUST.  Any
;; remaining arguments are simply passed to GPG.
;;
;; This function only supports keys with a single user id.
(define (checktrust keyid expected-trust . args)
  (let ((trust (apply gettrust `(,keyid ,@args))))
    (unless (string=? trust expected-trust)
	    (fail keyid ": Expected trust to be" expected-trust
		  "but got" trust))))

(define (keytotpm name select)
  (let ((result (call-with-io `(,@GPG --command-fd=0 --edit-key ,name ,select keytotpm)  "y\n")))
    (if (= 0 (:retcode result))
	(:stdout result)
	(throw "keytotpm failed"
	       (:stderr result)))))


(define (quick-gen name algo)
  (info "creating TPM " algo " key")
  (call-check `(,@GPG --quick-generate-key ,name ,algo))
  (keytotpm name "key 0")
  (unless (string=? (:cardinfo (secinfo name)) "TPM-Protected")
      (throw "key is not in the TPM")))

(define (quick-add name algo)
  (info "adding TPM encryption " algo " key")
  (call-check `(,@GPG --quick-add-key ,(fingerprint name) ,algo "encr"))
  (keytotpm name "key 1")
  (unless (string=? (:cardinfo (ssbinfo name)) "TPM-Protected")
      (throw "Added key is not in the TPM")))

(define (check-sig name)
  (info "checking TPM signing")
  (call-check `(,@GPG --default-key ,name --sign msg.txt))
  (call-check `(,@GPG --verify msg.txt.gpg))
  (unlink "msg.txt.gpg"))

(define (check-encrypt name)
  (info "Checking TPM decryption")
  (call-check `(,@GPG --recipient ,name --encrypt msg.txt))
  (call-check `(,@GPG --output msg.out.txt --decrypt msg.txt.gpg))
  (unless (file=? "msg.txt" "msg.out.txt")
	  (throw "File did not decrypt to the same message"))
  (unlink "msg.out.txt")
  (unlink "msg.txt.gpg"))

;;
;; Tests are very simple: create primary key in TPM add encryption key
;; in TPM (verifies TPM primary can certify secondary), sign a message
;; with primary key and check signature encrypt a message with
;; encryption key and check signature
;;
(define (test-tpm name algo)
  (quick-gen name algo)
  (quick-add name algo)
  (check-sig name)
  (check-encrypt name))

;;
;; Enable checking with valgrind if the envvar "with_valgrind" is set
;;
(when with-valgrind?
  (set! gpg `(,@valgrind ,@gpg)))


;;(set! *args* (append *args* (list "--use-keyboxd")))


;; end
