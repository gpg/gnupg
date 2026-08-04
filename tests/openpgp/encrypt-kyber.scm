#!/usr/bin/env gpgscm

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

(info "Importing public PQC keys.")
(call-check
 `(,(tool 'gpg) --import
   ,(in-srcdir "tests" "openpgp" "samplekeys/pqc-sample-1.key.asc")
   ,(in-srcdir "tests" "openpgp" "samplekeys/pqc-sample-2.key.asc")
   ,(in-srcdir "tests" "openpgp" "samplekeys/pqc-sample-3.key.asc")
   ,(in-srcdir "tests" "openpgp" "samplekeys/pqc-sample-4.key.asc")
   ,(in-srcdir "tests" "openpgp" "samplekeys/pqc-sample-5.key.asc")))

(info "Importing secret PQC keys.")
(for-each
 (lambda (name)
   (file-copy (in-srcdir "tests" "openpgp" "privkeys"
                           (string-append name ".key"))
	      (string-append "private-keys-v1.d/" name ".key")))
 '("DC60E0AE48E0F14E8FD7C9C36E18C6651E99BA93"
   "2F4CD0990D56D41A74456668469E3139A7960CD4"
   "8B2E1355C97C34E0AC1CBC9DFDF2526BFE8990A7"
   "F5DB116462B7BD2FA83A4453C4DFA2AE8604FB59"
   "8F9ABF3E5BBFC50D168DD524EB8F7263E7B33859"
   "A1598F57316F7FEC3F946895E35A7D2EAE8D3A13"
   "A87B85D88DB8B2B5A62A9958C8F2878F49605D09"
   "D54E9B75C3541D95C45E430DAC9645E9FB62C668"
   "EAD718DCE3D2F33A20BFC8BA617844DEF3FFAF3A"
   "702F599E35E6E0BE68E6FDF25D887229D42780F7"
   "19C87B74004E9839F3D56992B0A9943BF90B56F7"
   "7C31A4A632A49C4E8B1C8CBA53976ADFF714510F"
   "A1ABFD89944870D04039D40C218EE127254AEEE9"
   "513906BEA5A40F25C9D6EBBCEF62D0784E7235A5"
   "6EC551A7895031EE4543A1C789E16E6A6C229CFC"))

(for-each-p
 "Checking encryption using Kyber keys"
 (lambda (keyname)
   (tr:do
    (tr:open "data-9000")
    (tr:gpg "" `(--yes --encrypt --recipient ,keyname))
    (tr:gpg "" '(--yes --decrypt))
    (tr:assert-identity "data-9000")))
 '("pqc-sample-1" "pqc-sample-2" "pqc-sample-3" "pqc-sample-4" "pqc-sample-5"))


(for-each-p
 "Checking encryption using Kyber keys with AES128, AES192, and AES256"
 (lambda (algo)
   (tr:do
    (tr:open "data-9000")
    (tr:gpg "" `(--yes --encrypt --cipher-algo ,algo -r "pqc-sample-1"))
    (tr:gpg "" '(--yes --decrypt))
    (tr:assert-identity "data-9000")))
 '("aes128" "aes192" "aes256"))
