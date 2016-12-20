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

(load (with-path "defs.scm"))

(define gpgme-srcdir (getenv "XTEST_GPGME_SRCDIR"))
(when (string=? "" gpgme-srcdir)
    (info
     "SKIP: Environment variable 'XTEST_GPGME_SRCDIR' not set.  Please"
     "point it to a recent GPGME source tree to run the GPGME test suite.")
    (exit 0))

(define (in-gpgme-srcdir . names)
  (canonical-path (apply path-join (cons gpgme-srcdir names))))

(define gpgme-builddir (getenv "XTEST_GPGME_BUILDDIR"))
(when (string=? "" gpgme-builddir)
    (info
     "SKIP: Environment variable 'XTEST_GPGME_BUILDDIR' not set.  Please"
     "point it to a recent GPGME build tree to run the GPGME test suite.")
    (exit 0))

;; Make sure that GPGME picks up our gpgconf.  This makes GPGME use
;; and thus executes the tests with GnuPG components from the build
;; tree.
(setenv "PATH" (string-append (path-join (getenv "GNUPG_BUILDDIR") "tools")
			      (string *pathsep*) (getenv "PATH")) #t)

(define (create-file name content)
  (letfd ((fd (open name (logior O_WRONLY O_CREAT O_BINARY) #o600)))
    (display content (fdopen fd "wb"))))

(define (create-gpgmehome . path)
  (create-file "gpg.conf" "no-force-v3-sigs\n")
  (create-file
   "gpg-agent.conf"
   (string-append "pinentry-program "
		  (in-gpgme-srcdir "tests" "gpg" "pinentry") "\n"))
  (mkdir "private-keys-v1.d" "-rwx")

  (log "Storing private keys")
  (for-each
   (lambda (name)
     (file-copy (apply in-gpgme-srcdir `(,@path ,name))
		(path-join "private-keys-v1.d"
			   (string-append name ".key"))))
   '("13CD0F3BDF24BE53FE192D62F18737256FF6E4FD"
     "76F7E2B35832976B50A27A282D9B87E44577EB66"
     "A0747D5F9425E6664F4FFBEED20FBCA79FDED2BD"
     "13CBE3758AFE42B5E5E2AE4CED27AFA455E3F87F"
     "7A030357C0F253A5BBCD282FFC4E521B37558F5C"))

  (log "Importing public demo and test keys")
  (for-each
   (lambda (file)
     (call-check `(,@GPG --yes --import ,(apply in-gpgme-srcdir
						`(,@path ,file)))))
   (list "pubdemo.asc" "secdemo.asc"))
  (stop-agent))

;; Initialize the test environment, install appropriate configuration
;; and start the agent, with the keys from the legacy test suite.
(define (setup-gpgme-environment . path)
  (if (member "--unpack-tarball" *args*)
      (begin
	(call-check `(,(tool 'gpgtar) --extract --directory=. ,(cadr *args*)))
	(start-agent))
      (apply create-gpgme-gpghome path)))

(define (parse-makefile port key)
  (define (is-continuation? tokens)
    (string=? (last tokens) "\\"))
  (define (valid-token? s)
    (< 0 (string-length s)))
  (define (drop-continuations tokens)
    (let loop ((acc '()) (tks tokens))
      (if (null? tks)
	  (reverse acc)
	  (loop (if (string=? "\\" (car tks))
		    acc
		    (cons (car tks) acc)) (cdr tks)))))
  (let next ((acc '()) (found #f))
    (let ((line (read-line port)))
      (if (eof-object? line)
	  acc
	  (let ((tokens (filter valid-token?
				(string-splitp (string-trim char-whitespace?
							    line)
					       char-whitespace? -1))))
	    (cond
	     ((or (null? tokens)
		  (string-prefix? (car tokens) "#")
		  (and (not found) (not (and (string=? key (car tokens))
					     (string=? "=" (cadr tokens))))))
	      (next acc found))
	     ((not found)
	      (assert (and (string=? key (car tokens))
			   (string=? "=" (cadr tokens))))
	      (if (is-continuation? tokens)
		  (next (drop-continuations (cddr tokens)) #t)
		  (drop-continuations (cddr tokens))))
	     (else
	      (assert found)
	      (if (is-continuation? tokens)
		  (next (append acc (drop-continuations tokens)) found)
		  (append acc (drop-continuations tokens))))))))))

(define (parse-makefile-expand filename expand key)
  (define (variable? v)
    (and (string-prefix? v "$(") (string-suffix? v ")")))

  (let expand-all ((values (parse-makefile (open-input-file filename) key)))
    (if (any variable? values)
	(expand-all
	 (let expand-one ((acc '()) (v values))
	   (cond
	    ((null? v)
	     acc)
	    ((variable? (car v))
	     (let ((makefile (open-input-file filename))
		   (key (substring (car v) 2 (- (string-length (car v)) 1))))
	       (expand-one (append acc (expand filename makefile key))
			   (cdr v))))
	    (else
	     (expand-one (append acc (list (car v))) (cdr v))))))
	values)))
