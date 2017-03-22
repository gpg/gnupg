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

(define certs-for-import
  (list (list "cert_dfn_pca01.der"
	      (certs::new
	       "DFA56FB5FC41E3A8921F77AD1622EEFD9152A5AD"
	       "DFA56FB5FC41E3A8921F77AD1622EEFD9152A5AD"
	       (certs::new-uid "DFN Top Level Certification Authority"
			       "DFN-PCA"
			       "Deutsches Forschungsnetz"
			       ""
			       "DE")))
	(list "cert_dfn_pca15.der"
	      (certs::new
	       "2C8F3C356AB761CB3674835B792CDA52937F9285"
	       "DFA56FB5FC41E3A8921F77AD1622EEFD9152A5AD"
	       (certs::new-uid "DFN Server Certification Authority"
			       "DFN-PCA"
			       "Deutsches Forschungsnetz"
			       ""
			       "DE")))))

(define :name car)
(define :cert cadr)

(for-each-p'
 "Checking certificate import."
 (lambda (test)
   (assert (not (sm-have-public-key? (:cert test))))
   (call-check `(,@gpgsm --import ,(in-srcdir "tests" "gpgsm" (:name test))))
   (assert (sm-have-public-key? (:cert test))))
 (lambda (test) (:name test))
 certs-for-import)
