#!/usr/bin/env gpgscm

;; Regression tests for importing unprotected ECDH keys

;; Copyright (C) 2026 g10 Code GmbH
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

;; A secret key taken from the not-much MUA configure test
(define secret-key-unprotected "-----BEGIN PGP PRIVATE KEY BLOCK-----

lFgEYxhtlxYJKwYBBAHaRw8BAQdA0PoNKr90DaQV1dIK77wbWm4RT+JQzqBkwIjA
HQM9RHYAAQDQ5wSfkOGXvKYroALWgibztISzXS5b8boGXykcHERo6w/ctDtOb3Rt
dWNoIFRlc3QgU3VpdGUgKElOU0VDVVJFISkgPHRlc3Rfc3VpdGVAbm90bXVjaG1h
aWwub3JnPoiQBBMWCAA4AhsDBQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAFiEEmjr+
bGAGWhSP1LWKfmq+kkZFzGAFAmMYbZwACgkQfmq+kkZFzGDtrwEAjQRn3xhEomah
wICjQjfi4RKNbvnRViZgosijDBANUAgA/28GrK1tPnQsXWqmuZxQ1Cd5ry4NAnj/
4jsxD3cTbnEHnF0EYxhtlxIKKwYBBAGXVQEFAQEHQEOd3EyCD5qo4+QuHz0lruCG
VM6n6RI4dtAh3cX9uHwiAwEIBwAA/1oe+p5jNjNE5lEj4yTpYjCxCeC98MolbiAy
0yY7526wECqIeAQYFggAIBYhBJo6/mxgBloUj9S1in5qvpJGRcxgBQJjGG2XAhsM
AAoJEH5qvpJGRcxgBdsA/R9ZECoxai5QhOitDIAUZVCRr59Pm1VMPiJOOIla2N1p
AQCNESwJ9IJOdO/06q+bR2GG4WyEkB4VoVBiA3hFx/zZAA==
=uGTo
-----END PGP PRIVATE KEY BLOCK-----")


(define plaintext "Content-Type: text/plain

The password is \"abcd1234!\", please do not tell anyone.
")


;; Import the key
(pipe:do
 (pipe:echo secret-key-unprotected)
 (pipe:gpg '(--import)))

;; Check decryption
(tr:do
 (tr:open (in-srcdir "tests" "openpgp" "samplemsgs" "basic-encrypted.eml"))
 (tr:gpg "" '(--yes --decrypt))
 (tr:assert-same plaintext))
