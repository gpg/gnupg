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
(setup-environment)

(setenv "SSH_AUTH_SOCK"
        (call-check `(,(tool 'gpgconf) --null --list-dirs agent-ssh-socket))
        #t)

(define SSH-ADD #f)
(catch (skip "ssh-add not found")
       (set! SSH-ADD
	     (path-expand "ssh-add" (string-split (getenv "PATH") *pathsep*))))

(define keys
  '(("dsa" "9a:e1:f1:5f:46:ea:a5:06:e1:e2:f8:38:8e:06:54:58")
    ("rsa" "c9:85:b5:55:00:84:a9:82:5a:df:d6:62:1b:5a:28:22")
    ("ecdsa" "93:37:30:a6:4e:e7:6a:22:79:77:8e:bf:ed:14:e9:8e")
    ("ed25519" "08:df:be:af:d2:f5:32:20:3a:1c:56:06:be:31:0f:bf")))

(for-each-p'
 "Importing ssh keys..."
 (lambda (key)
   (let ((file (path-join (in-srcdir "samplekeys")
			  (string-append "ssh-" (car key) ".key")))
	 (hash (cadr key)))
     ;; We pipe the key to ssh-add so that it won't complain about
     ;; file's permissions.
     (pipe:do
      (pipe:open file (logior O_RDONLY O_BINARY))
      (pipe:spawn `(,SSH-ADD -)))
     (unless (string-contains? (call-popen `(,SSH-ADD -l "-E" md5) "") hash)
	     (fail "key not added"))))
 car keys)

(info "Checking for issue2316...")
(unlink (path-join GNUPGHOME "sshcontrol"))
(pipe:do
 (pipe:open (path-join (in-srcdir "samplekeys")
		       (string-append "ssh-rsa.key"))
	    (logior O_RDONLY O_BINARY))
 (pipe:spawn `(,SSH-ADD -)))
(unless
 (string-contains? (call-popen `(,SSH-ADD -l "-E" md5) "")
		   "c9:85:b5:55:00:84:a9:82:5a:df:d6:62:1b:5a:28:22")
 (fail "known private key not (re-)added to sshcontrol"))
