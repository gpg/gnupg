#!/usr/bin/env gpgscm

;; Copyright (C) 2022 g10 Code GmbH
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

(define passphrase "password")
(define plaintext "Hello, world!\n")


(for-each-p
 "Checking decryption of symmetric encrypted files"
 (lambda (name)
   (tr:do
    (tr:open (in-srcdir "tests" "openpgp" "samplemsgs"
                        (string-append name ".asc")))
    (tr:gpg passphrase '(--passphrase-fd "0" --yes --decrypt))
    (tr:assert-same plaintext)))
 '("enc-sym-cfb-1"
   "enc-sym-cfb-2"
   "enc-sym-ocb-1"
   "enc-sym-ocb-2"))
