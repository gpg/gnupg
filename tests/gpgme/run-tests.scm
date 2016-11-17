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

(load (with-path "gpgme-defs.scm"))

(info "Running GPGME's test suite...")

(define (gpgme-makefile-expand filename port key)
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

(define (all-tests filename key)
  (parse-makefile-expand filename gpgme-makefile-expand key))

(let* ((runner (if (member "--parallel" *args*)
		   run-tests-parallel
		   run-tests-sequential))
       (tests (filter (lambda (arg) (not (string-prefix? arg "--"))) *args*)))
  (runner
   (test::scm "setup.scm" (in-srcdir "setup.scm") "--" "tests" "gpg")
   (apply
    append
    (map (lambda (cmpnts)
	   (define (compiled? name)
	     (not (or (string-suffix? name ".py")
		      (string-suffix? name ".test"))))
	   (define :path car)
	   (define :key cadr)
	   (define (find-test name)
	     (apply path-join
		    `(,(if (compiled? name)
			   gpgme-builddir
			   gpgme-srcdir) ,@(:path cmpnts),name)))
	   (let ((makefile (apply path-join `(,gpgme-srcdir ,@(:path cmpnts)
							    "Makefile.am"))))
	     (map (lambda (name)
		    (apply test::scm
			   `(,name ,(in-srcdir "wrap.scm") --executable
				   ,(find-test name)
				   -- ,@(:path cmpnts))))
		  (if (null? tests) (all-tests makefile (:key cmpnts)) tests))))
	 '((("tests" "gpg") "c_tests")
	   ;; XXX: Not yet.
	   ;; (("lang" "python" "tests") "py_tests")
	   (("lang" "qt" "tests") "TESTS"))))))
