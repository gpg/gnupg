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

(load (in-srcdir "tests" "migrations" "common.scm"))

(catch (skip "gpgtar not built")
       (call-check `(,GPGTAR --help)))

(define (assert-keys-usable)
  (for-each
   (lambda (keyid)
     (catch (error "Key not found:" keyid)
	    (call-check `(,@GPG --list-secret-keys ,keyid))))
   '("C40FDECF" "ECABF51D")))

(run-test
 "Testing the extended private key format ..."
 (in-srcdir "tests" "migrations" "extended-pkf.tar.asc")
 (lambda (gpghome)
   (assert-keys-usable)))

;; XXX try changing a key, and check that the format is not changed.
