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

(load (in-srcdir "tests" "gpgme" "gpgme-defs.scm"))

(define executable (flag "--executable" *args*))
(unless (and executable (not (null? executable)))
	(error "Usage: wrap.scm --executable <file> [args...]"))

(setup-gpgme-environment "tests" "gpg")

(setenv "abs_builddir" (getcwd) #t)
(setenv "top_srcdir" gpgme-srcdir #t)
(setenv "srcdir" (path-join gpgme-srcdir "tests" "gpg") #t)
(setenv "abs_top_srcdir" (path-join gpgme-srcdir "tests" "gpg") #t)

(define (run what)
  (if (string-suffix? (car what) ".py")
      (begin
	(setenv "LD_LIBRARY_PATH"
		(if (< 0 (string-length (getenv "LD_LIBRARY_PATH")))
		    (string-append (path-join gpgme-builddir "src/.libs")
				   (string *pathsep*)
				   (getenv "LD_LIBRARY_PATH"))
		    (path-join gpgme-builddir "src/.libs"))
		#t)
	(if python
	    (call-with-fds
	     `(,python
	       ,(in-gpgme-srcdir "lang" "python" "tests" "run-tests.py")
	       --quiet
	       ,(string-append "--interpreters=" python)
	       --builddir ,(path-join gpgme-builddir "lang" "python" "tests")
	       ,@what)
	     STDIN_FILENO STDOUT_FILENO STDERR_FILENO)
	    77))
      (call-with-fds what STDIN_FILENO STDOUT_FILENO STDERR_FILENO)))

(let ((name (basename (car executable))))
  (cond
   ((string=? (qualify "t-keylist") name)
    ;; This test assumes that 't-import' imported a key.
    (log "Importing extra key...")
    (call-check `(,@GPG --yes --import ,(in-srcdir "pubkey-1.asc"))))))

(if (file-exists? (car executable))
    (begin
      (log "Running" (car executable))
      (exit (run executable)))
    (skip (car executable) "is not built"))
