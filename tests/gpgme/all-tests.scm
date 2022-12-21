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

(export all-tests
 ;; Parse GPGME's makefiles to find all tests.

 (load (in-srcdir "tests" "gpgme" "gpgme-defs.scm"))
 (load (with-path "makefile.scm"))

 (define (expander filename port key)
   ;;(interactive-repl (current-environment))
   (cond
    ((string=? key "tests_unix")
     (if *win32*
	 (parse-makefile port key)   ;; Use win32 definition.
	 (begin
	   (parse-makefile port key) ;; Skip win32 definition.
	   (parse-makefile port key))))
    (else
     (parse-makefile port key))))

 (define (parse filename key)
   (parse-makefile-expand filename expander key))

 (define setup-c
   (make-environment-cache
    (test::scm
     #f
     #f
     (path-join "tests" "gpgme" "tests" "gpg")
     (in-srcdir "tests" "gpgme" "setup.scm")
     "--" "tests" "gpg")))
 (define setup-py
   (make-environment-cache
    (test::scm
     #f
     #f
     (path-join "tests" "gpgme" "lang" "python" "tests")
     (in-srcdir "tests" "gpgme" "setup.scm")
     "--" "lang" "python" "tests")))

 (define (compiled? name)
   (not (or (string-suffix? name ".py")
	    (string-suffix? name ".test"))))
 (define :path car)
 (define :key cadr)
 (define :setup caddr)

 (if (have-gpgme?)
     (apply append
	    (map (lambda (cmpnts)
		   (define (find-test name)
		     (apply path-join
			    `(,(if (compiled? name)
				   gpgme-builddir
				   gpgme-srcdir) ,@(:path cmpnts) ,(qualify name))))
		   (let ((makefile (apply path-join `(,gpgme-srcdir ,@(:path cmpnts)
								    "Makefile.am"))))
		     (map (lambda (name)
			    (apply test::scm
				   `(,(:setup cmpnts)
                                     #f
				     ,(apply path-join
					     `("tests" "gpgme" ,@(:path cmpnts) ,name))
				     ,(in-srcdir "tests" "gpgme" "wrap.scm")
				     --executable
				     ,(find-test name)
				     -- ,@(:path cmpnts))))
			  (parse makefile (:key cmpnts)))))
		 `((("tests" "gpg") "c_tests" ,setup-c)
		   ,@(if (run-python-tests?)
			 `((("lang" "python" "tests") "py_tests" ,setup-py))
			 '())
		   (("lang" "qt" "tests") "TESTS" ,setup-c))))
     '()))
