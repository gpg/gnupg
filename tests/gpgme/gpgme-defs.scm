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

(load (in-srcdir "tests" "openpgp" "defs.scm"))

(define gpgme-srcdir (getenv "XTEST_GPGME_SRCDIR"))

(define (in-gpgme-srcdir . names)
  (canonical-path (apply path-join (cons gpgme-srcdir names))))

(define gpgme-builddir (getenv "XTEST_GPGME_BUILDDIR"))

(define (have-gpgme?)
  (cond
   ((string=? "" gpgme-srcdir)
    (info
     "SKIP: Environment variable 'XTEST_GPGME_SRCDIR' not set.  Please"
     "point it to a recent GPGME source tree to run the GPGME test suite.")
    #f)
   ((string=? "" gpgme-builddir)
    (info
     "SKIP: Environment variable 'XTEST_GPGME_BUILDDIR' not set.  Please"
     "point it to a recent GPGME build tree to run the GPGME test suite.")
    #f)
   (else
    #t)))

;; Make sure that GPGME picks up our gpgconf.  This makes GPGME use
;; and thus executes the tests with GnuPG components from the build
;; tree.
(setenv "PATH" (string-append (path-join (getenv "GNUPG_BUILDDIR") "tools")
			      (string *pathsep*) (getenv "PATH")) #t)

;; The tests expect the pinentry to return the passphrase "abc".
(setenv "PINENTRY_USER_DATA" "abc" #t)

(define (create-gpgmehome . path)
  ;; Support for various environments.
  (define mode
    (cond
     ((equal? path '("lang" "python" "tests"))
      (set! path '("tests" "gpg")) ;; Mostly uses files from tests/gpg.
      'python)
     (else
      'gpg)))

  (create-file
   "gpg.conf"
   "no-force-v3-sigs"
   (string-append "agent-program " (tool 'gpg-agent) "|--debug-quick-random\n"))
  (create-file
   "gpg-agent.conf"
   (string-append "pinentry-program " (tool 'pinentry)))

  (start-agent)

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

  (when (equal? mode 'python)
	(log "Importing extra keys for Python tests")
	(for-each
	 (lambda (file)
	   (call-check `(,@GPG --yes --import
			       ,(apply in-gpgme-srcdir
				       `("lang" "python" "tests" ,file)))))
	 (list "encrypt-only.asc" "sign-only.asc"))

	(log "Marking key as trusted")
	(pipe:do
	 (pipe:echo "A0FF4590BB6122EDEF6E3C542D727CC768697734:6:\n")
	 (pipe:spawn `(,(tool 'gpg) --import-ownertrust))))

  (stop-agent))

;; Initialize the test environment, install appropriate configuration
;; and start the agent, with the keys from the legacy test suite.
(define (setup-gpgme-environment . path)
  (if (member "--unpack-tarball" *args*)
      (begin
	(call-check `(,(tool 'gpgtar) --extract --directory=. ,(cadr *args*)))
	(start-agent))
      (apply create-gpgme-gpghome path)))

(define python
  (let loop ((pythons (list "python" "python2" "python3")))
    (if (null? pythons)
	#f
	(catch (loop (cdr pythons))
	       (unless (file-exists? (path-join gpgme-builddir "lang" "python"
						(string-append (car pythons) "-gpg")))
		       (throw "next please"))
	       (path-expand (car pythons) (string-split (getenv "PATH") *pathsep*))))))

(define (run-python-tests?)
  (not (not python)))
