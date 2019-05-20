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

(load (in-srcdir "tests" "openpgp" "defs.scm"))
(setup-legacy-environment)

(define (check-for predicate lines message)
  (unless (any predicate lines)
	  (fail message)))

(define (check-exported-key dump keyid)
  (check-for (lambda (l)
	       (and (string-prefix? l "	keyid: ")
		    (string-suffix? l keyid))) dump
		    "Keyid not found")
  (check-for (lambda (l) (string-prefix? l ":user ID packet:")) dump
	     "User ID packet not found")
  (check-for (lambda (l)
	       (and (string-prefix? l ":signature packet:")
		    (string-contains? l "keyid")
		    (string-suffix? l keyid))) dump
		    "Signature packet not found"))

(define (check-exported-public-key packet-dump keyid)
  (let ((dump (string-split-newlines packet-dump)))
    (check-for (lambda (l) (string-prefix? l ":public key packet:")) dump
	       "Public key packet not found")
    (check-exported-key dump keyid)))

(define (check-exported-private-key packet-dump keyid)
  (let ((dump (string-split-newlines packet-dump)))
    (check-for (lambda (l) (string-prefix? l ":secret key packet:")) dump
	       "Secret key packet not found")
    (check-exported-key dump keyid)))

 (for-each-p
  "Checking key export"
  (lambda (keyid)
    (tr:do
     (tr:pipe-do
      (pipe:gpg `(--export ,keyid))
      (pipe:gpg '(--list-packets)))
     (tr:call-with-content check-exported-public-key keyid))

    (tr:do
     (tr:pipe-do
      (pipe:gpg `(--export-secret-keys ,keyid))
      (pipe:gpg '(--list-packets)))
     (tr:call-with-content check-exported-private-key keyid)))
  '("D74C5F22" "C40FDECF" "ECABF51D"))
