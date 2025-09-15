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

(for-each-p
 "Checking encryption"
 (lambda (source)
   (tr:do
    (tr:open source)
    (tr:gpg "" `(--yes --encrypt --recipient ,usrname1))
    (tr:gpg "" `(--yes --recipient ,usrname2 --add-recipient))
    (tr:write-to "reference")
    ;; Make username1's priv unavailable
    (tr:spawn "" `(,@GPG --batch --yes --enarmor "private-keys-v1.d/7E201E28B6FEB2927B321F443205F4724EBE637E.key")) ;;usrname1
    (tr:unlink "private-keys-v1.d/7E201E28B6FEB2927B321F443205F4724EBE637E.key")
    (tr:spawn "" `(,@GPG --output **out** --yes --decrypt "reference"))
    (tr:assert-identity source)
    ;; Reset enviroment
    (tr:spawn "" `(,@GPG --batch --yes -o "private-keys-v1.d/7E201E28B6FEB2927B321F443205F4724EBE637E.key" --dearmor "private-keys-v1.d/7E201E28B6FEB2927B321F443205F4724EBE637E.key.asc")) ;;usrname1
  )
 )
 (append all-files)
)
