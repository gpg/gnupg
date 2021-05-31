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

(load (in-srcdir "tests" "cms" "gpgsm-defs.scm"))
(setup-gpgsm-environment)

;;
;; Two simple tests to check that verify fails for bad input data
;;
(for-each-p
 "Checking bogus signature."
 (lambda (char)
   (lettmp (x)
     (call-with-binary-output-file
      x
      (lambda (port)
	(display (make-string 64 (integer->char (string->number char)))
		 port)))
     (assert (not (zero? (call `(,@gpgsm --verify ,x data-500)))))))
 '("#x2d" "#xca"))

(define test-text1 "Hallo Leute!\n")
(define test-text1f "Hallo Leute?\n")
(define test-sig1 "
-----BEGIN CMS OBJECT-----
MIAGCSqGSIb3DQEHAqCAMIACAQExCzAJBgUrDgMCGgUAMIAGCSqGSIb3DQEHAQAA
MYIBOTCCATUCAQEwcDBrMQswCQYDVQQGEwJERTETMBEGA1UEBxQKRPxzc2VsZG9y
ZjEWMBQGA1UEChMNZzEwIENvZGUgR21iSDEZMBcGA1UECxMQQWVneXB0ZW4gUHJv
amVjdDEUMBIGA1UEAxMLdGVzdCBjZXJ0IDECAQAwBwYFKw4DAhqgJTAjBgkqhkiG
9w0BCQQxFgQU7FC/ibH3lC9GE24RJJxa8zqP7wEwCwYJKoZIhvcNAQEBBIGAA3oC
DUmKERmD1eoJYFw38y/qnncS/6ZPjWINDIphZeK8mzAANpvpIaRPf3sNBznb89QF
mRgCXIWcjlHT0DTRLBf192Ve22IyKH00L52CqFsSN3a2sajqRUlXH8RY2D+Al71e
MYdRclgjObCcoilA8fZ13VR4DiMJVFCxJL4qVWI=
-----END CMS OBJECT-----")

;;
;; Now run the tests.
;;
(info "Checking that a valid signature is verified as such.")
(lettmp (sig body)
  (call-with-binary-output-file sig (lambda (port) (display test-sig1 port)))
  (call-with-binary-output-file body (lambda (port) (display test-text1 port)))
  (call-check `(,@gpgsm --verify ,sig ,body)))

(info "Checking that an invalid signature is verified as such.")
(lettmp (sig body)
  (call-with-binary-output-file sig (lambda (port) (display test-sig1 port)))
  (call-with-binary-output-file body (lambda (port) (display test-text1f port)))
  (assert (not (zero? (call `(,@gpgsm --verify ,sig ,body))))))
