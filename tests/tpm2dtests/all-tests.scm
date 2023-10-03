;; Copyright (C) 2017 g10 Code GmbH
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

(export all-tests
 ;; Parse the Makefile.am to find all tests.

 (load (with-path "makefile.scm"))

 (define (expander filename port key)
   (parse-makefile port key))

 (define (parse filename key)
   (parse-makefile-expand filename expander key))

 (define setup
   (make-environment-cache
    (test::scm
     #f
     #f
     (path-join "tests" "tpm2dtests" "setup.scm")
     (in-srcdir "tests" "tpm2dtests" "setup.scm"))))

 (define (qualify path variant)
   (string-append "<" variant ">" path))

 (define (setup* variant)
   (make-environment-cache
    (test::scm
     #f
     variant
     (path-join "tests" "tpm2dtests" "setup.scm")
     (in-srcdir "tests" "tpm2dtests" "setup.scm")
     (string-append "--" variant))))

 (define setup-use-keyring (setup* "use-keyring"))
 (define setup-use-keyboxd (setup* "use-keyboxd"))

 (define all-tests
   (parse-makefile-expand "Makefile"
			  (lambda (filename port key) (parse-makefile port key))
			  "XTESTS"))

 (define tests
   (map (lambda (name)
	  (test::scm setup
                     "standards"
		     (path-join "tests" "tpm2dtests" name)
		     (in-srcdir "tests" "tpm2dtests" name))) all-tests))

 (when *run-all-tests*
       (set! tests
	     (append
	      tests
              ;; The second pass uses the keyboxd
	      (map (lambda (name)
		     (test::scm setup-use-keyboxd
                                "keyboxd"
				(path-join "tests" "tpm2dtests" name)
				(in-srcdir "tests" "tpm2dtests" name)
				"--use-keyboxd")) all-tests)
              ;; The third pass uses the legact pubring.gpg
	      (map (lambda (name)
		     (test::scm setup-use-keyring
                                "keyring"
				(path-join "tests" "tpm2dtests" name)
				(in-srcdir "tests" "tpm2dtests" name)
				"--use-keyring")) all-tests)
              )))

 tests)
