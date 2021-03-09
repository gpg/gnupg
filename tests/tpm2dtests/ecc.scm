#!/usr/bin/env gpgscm

;; Copyright (C) 2021 James.Bottomley@HansenPartnership.com
;;
;; SPDX-License-Identifier: GPL-3.0-or-later
;;
(load (in-srcdir "tests" "tpm2dtests" "defs.scm"))

(setup-environment)
(setenv "PINENTRY_USER_DATA" "ecckey" #t)

;;
;; try checking signature and encryption on supported elliptic
;; curve keys.  Note this list must be allowable by the swtpm
;; used for the test, which is why it's so small
;;
(define key-list '("nistp256" "nistp384"))

(for-each
 (lambda (algo)
   (define name algo "<" algo "@example.com>")
   (test-tpm name algo))
 key-list)
