#!/usr/bin/env gpgscm

;; Copyright (C) 2021 James.Bottomley@HansenPartnership.com
;;
;; SPDX-License-Identifier: GPL-3.0-or-later
;;
(load (in-srcdir "tests" "tpm2dtests" "defs.scm"))

(setup-environment)

;;
;; Check that a key with a long passphrase can be created and check
;; the passphrase can be truncated and still work
;;
(define name "ecc <ecc@example.com>")
(define name1 "ecc1 <ecc1@example.com>")
(define algo "nistp256")

(setenv "PINENTRY_USER_DATA" "this is a password longer than the TPM max of the name algorithm (i.e. 32)" #t)
(quick-gen name algo)

(setenv "PINENTRY_USER_DATA" "this is a password longer than the TPM max of the name" #t)
(check-sig name)

;; exactly the TPM limit (sha256 hash name algorithm: 32)
(setenv "PINENTRY_USER_DATA" "12345678901234567890123456789012" #t)
(quick-gen name1 algo)

(info "checking TPM signing failure with truncated passphrase")
;; passphrase one character shorter, should fail with bad passphrase
(setenv "PINENTRY_USER_DATA" "1234567890123456789012345678901" #t)
(let ((result (call-with-io `(,@GPG --default-key ,name1 --sign msg.txt) "")))
  (if (= 0 (:retcode result))
      (throw "Signing Key succeeded with wrong passphrase")
      (unless (string-contains? (:stderr result) "Bad passphrase")
	      (throw "Unexpected signing error:" (:stderr result)))))
