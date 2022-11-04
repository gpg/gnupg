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

(for-each-p
 "Checking encryption"
 (lambda (source)
   (tr:do
    (tr:open source)
    (tr:gpg "" `(--yes --encrypt --recipient ,usrname2))
    (tr:gpg "" '(--yes --decrypt))
    (tr:assert-identity source)))
 (append plain-files data-files))

(for-each-p
 "Checking encryption using a specific cipher algorithm"
 (lambda (cipher)
   (for-each-p
    ""
    (lambda (source)
      (tr:do
       (tr:open source)
       (tr:gpg "" `(--yes --encrypt --recipient ,usrname2
			  --cipher-algo ,cipher))
       (tr:gpg "" '(--yes --decrypt))
       (tr:assert-identity source)))
    (append plain-files data-files)))
 (force all-cipher-algos))


;; We encrypt to two keys and we have also put the first key into our
;; pubring, so that decryption will work.
(for-each-p
 "Checking encryption using a key from file"
 (lambda (source)
   (tr:do
    (tr:open source)
    (tr:gpg "" `(--yes -v --no-keyring --encrypt
                 --recipient-file ,(in-srcdir "tests" "openpgp" key-file1)
                 --hidden-recipient-file ,(in-srcdir "tests" "openpgp" key-file2)))
    (tr:gpg "" '(--yes --decrypt))
    (tr:assert-identity source)))
 plain-files)


(info "Importing additional sample keys for OCB tests")
(for-each
  (lambda (name)
    (call `(,@GPG --yes --import ,(in-srcdir "tests" "openpgp" "samplekeys"
                                             (string-append  name ".asc")))))
  '("ed25519-cv25519-sample-1"
    "ed25519-cv25519-sample-2"
    "rsa-rsa-sample-1"))

(for-each-p
 "Checking OCB mode"
 (lambda (source)
   (tr:do
    (tr:open source)
    (tr:gpg "" `(--yes -er ,"patrice.lumumba"))
    (tr:gpg "" '(--yes -d))
    (tr:assert-identity source)))
 all-files)

;; For reference:
;;   BEGIN_ENCRYPTION  <mdc_method> <sym_algo> [<aead_algo>]

(for-each-p
 "Checking two OCB capable keys"
 (lambda (source)
   (tr:do
    (tr:open source)
    (tr:gpgstatus "" `(--yes -e
                       -r ,"patrice.lumumba"
                       -r ,"mahsa.amini"))
    (tr:call-with-content
     (lambda (c)
       (unless (string-contains? c "[GNUPG:] BEGIN_ENCRYPTION 0 9 2")
	  (fail (string-append "Unexpected status: " c)))))))
 '("plain-1"))

(for-each-p
 "Checking two OCB capable keys plus one not capable"
 (lambda (source)
   (tr:do
    (tr:open source)
    (tr:gpgstatus "" `(--yes -o out -e
                             -r ,"patrice.lumumba"
                             -r ,"mahsa.amini"
                             -r ,"steve.biko"))
    (tr:call-with-content
     (lambda (c)
       (unless (string-contains? c "[GNUPG:] BEGIN_ENCRYPTION 2 9")
          (fail (string-append "Unexpected status: " c)))))))
 '("plain-1"))

(for-each-p
 "Checking non OCB capable key with --force-ocb"
 (lambda (source)
   (tr:do
    (tr:open source)
    (tr:gpgstatus "" `(--yes -e --force-ocb
                       -r ,"steve.biko"))
    (tr:call-with-content
     (lambda (c)
       (unless (string-contains? c "[GNUPG:] BEGIN_ENCRYPTION 0 9 2")
	  (fail (string-append "Unexpected status: " c)))))))
 '("plain-1"))
