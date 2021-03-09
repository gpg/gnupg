#!/usr/bin/env gpgscm

;; Copyright (C) 2021 James.Bottomley@HansenPartnership.com
;;
;; SPDX-License-Identifier: GPL-3.0-or-later
;;
(load (in-srcdir "tests" "tpm2dtests" "defs.scm"))

(setup-environment)

(setenv "PINENTRY_USER_DATA" "rsakey" #t)

(test-tpm "rsa <rsa@example.com>" "rsa2048")
