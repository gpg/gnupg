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

(load (in-srcdir "tests" "gpgsm" "gpgsm-defs.scm"))
(setup-gpgsm-environment)

(for-each-p
 "Checking encryption"
 (lambda (source)
   (for-each-p
    "with arguments..."
    (lambda (args)
      (tr:do
       (tr:open source)
       (tr:gpgsm "" `(--encrypt --recipient ,certs::test-1::uid::CN
				,@args))
       (tr:gpgsm "" `(--decrypt ,@(if (member '--base64 args)
				      '(--assume-base64) '())))
       (tr:assert-identity source)))
    `(()
      (--armor --cipher-algo ,(cadr (force all-cipher-algos)))
      (--base64 --digest-algo ,(car (force all-hash-algos))))))
 all-files)
