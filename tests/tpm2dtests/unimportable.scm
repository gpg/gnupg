#!/usr/bin/env gpgscm

;; Copyright (C) 2021 James.Bottomley@HansenPartnership.com
;;
;; SPDX-License-Identifier: GPL-3.0-or-later
;;
(load (in-srcdir "tests" "tpm2dtests" "defs.scm"))

(setup-environment)
(setenv "PINENTRY_USER_DATA" "this is a password" #t)

;;
;; Tries to import a selection of keys with no TPM representation
;; and verifies it fails.  There are many unimportable keys, so
;; save time by only choosing one EC and one RSA one
;;
(define key-list '("ed25519" "rsa4096"))

(for-each
 (lambda(algo)
   (info "Checking failure to import" algo)
   (define name algo "<ecc" algo "@example.com>")
   (call-check `(,@GPG --quick-generate-key ,name ,algo))
   (let ((result (call-with-io `(,@GPG --command-fd=0 --edit-key ,name "key 0" keytotpm)  "y\n")))
     (if (= 0 (:retcode result))
	 (throw "Importing Key succeeded")
	 (:stderr result))))
 key-list)
