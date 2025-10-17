#!/usr/bin/env gpgscm

;; Copyright (C) 2025 g10 Code GmbH
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

;; Used keys
(define privkey1 "private-keys-v1.d/7E201E28B6FEB2927B321F443205F4724EBE637E.key")
(define privkey2 "private-keys-v1.d/8B5ABF3EF9EB8D96B91A0B8C2C4401C91C834C34.key")

;; Create encrypted copy of keys for key reimport
(call-check `(,@GPG --enarmor ,privkey1))
(call-check `(,@GPG --enarmor ,privkey2))

(for-each-p
 "Checking add-recipient 0/2"
 (lambda (source)
   (lettmp (reference)
     (tr:do
      (tr:open source)
      (tr:gpg "" `( --encrypt --recipient ,usrname1))
      (tr:gpg "" `( --recipient ,usrname2 --add-recipient))
      (tr:write-to reference)
      ;; Make usr1's priv unavailable
      (tr:unlink privkey1)
      (tr:spawn "" `(,@GPG --output **out** --decrypt ,reference))
      (tr:assert-identity source)
      ;; Reset enviroment
      (tr:spawn "" `(,@GPG -o ,privkey1 --dearmor ,(string-append privkey1 ".asc"))) ;;usrname1
      )
     )
 )
 (append all-files)
)
(for-each-p
 "Checking change-recipient 1/2"
 (lambda (source)
   (lettmp (reference)
     (tr:do
      ;; Encrypt to usr1
      (tr:open source)
      (tr:gpg "" `( --encrypt --recipient ,usrname1))

      ;; Change recipient to usr2
      (tr:gpg "" `( --recipient ,usrname2 --change-recipient))
      (tr:write-to reference)

      ;; Setup keys for check 1
      (tr:unlink privkey2) ;;Remove key usr2

      ;; Check if usr1 can still decrypt if yes fail
      (tr:call-with-content
       (lambda (c)
         (assert(failed? (call-check `(,@GPG --output **out** --decrypt ,reference))))
       )
      )
      ;; Setup keys for check 2
      (tr:spawn "" `(,@GPG -o ,privkey2 --dearmor ,(string-append privkey2 ".asc"))) ;;Add key usr2
      (tr:unlink privkey1) ;;Remove key usr1

      ;; Check if usr2 can decrypt if no fail
      (tr:spawn "" `(,@GPG --output **out** --decrypt ,reference))
      (tr:assert-identity source)

      ;; Reset enviroment
      (tr:spawn "" `(,@GPG -o ,privkey1 --dearmor ,(string-append privkey1 ".asc"))) ;;Add key usr1
      )
     )
 )
 (append all-files)
)
(info "Checks complete 2/2")
