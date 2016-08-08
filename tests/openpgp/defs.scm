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
    (mktdata "MKTDATA" "tools/mk-tdata")
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
	 (string-split s #\newline))))

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
   (string-split
    (call-popen `(,@GPG --with-colons ,@args) input) #\newline)))

;; Dearmor a file.
(define (dearmor source-name sink-name)
  (pipe:do
   (pipe:open source-name (logior O_RDONLY O_BINARY))
   (pipe:spawn `(,@GPG --dearmor))
   (pipe:write-to sink-name (logior O_WRONLY O_CREAT O_BINARY) #o600)))

(let ((verbose (string->number (getenv "verbose"))))
  (if (number? verbose)
      (*set-verbose!* verbose)))
