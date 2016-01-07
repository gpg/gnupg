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
    (gpg-agent "GPG_AGENT" "agent/gpg-agent")
    (gpg-connect-agent "GPG_CONNECT_AGENT" "tools/gpg-connect-agent")
    (gpgconf "GPGCONF" "tools/gpgconf")
    (gpg-preset-passphrase "GPG_PRESET_PASSPHRASE"
			   "agent/gpg-preset-passphrase")
    (mktdata "MKTDATA" "tools/mk-tdata")
    (gpgtar "GPGTAR" "tools/gpgtar")
    (gpg-zip "GPGZIP" "tools/gpg-zip")))

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
(define PINENTRY (string-append (getcwd) "/" (qualify "fake-pinentry")))

(define (tr:gpg input args)
  (tr:spawn input `(,@GPG --output **out** ,@args **in**)))

(define (pipe:gpg args)
  (pipe:spawn `(,@GPG --output - ,@args -)))

(define (get-config what)
  (let* ((config-string
	  (call-popen `(,@GPG --with-colons --list-config ,what) ""))
	 (config (string-splitn
		  (string-rtrim char-whitespace? config-string) #\: 2)))
    (string-split (caddr config) #\;)))

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
