;; Common definitions for the GPGSM test scripts.
;;
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

;; This is the list of certificates that we install in the test
;; environment.
(define certs
  (package
   (define (new fpr issuer-fpr uid)
     (package))
   (define (new-uid CN OU O L C)
     (package))
   (define test-1 (new "3CF405464F66ED4A7DF45BBDD1E4282E33BDB76E"
		       "3CF405464F66ED4A7DF45BBDD1E4282E33BDB76E"
		       (new-uid "test cert 1"
				"Aegypten Project"
				"g10 Code GmbH"
				"Düsseldorf"
				"DE")))))
(define all-certs (list certs::test-1))

(define gpgsm `(,(tool 'gpgsm) --yes)) ;; more/less options

(define (tr:gpgsm input args)
  (tr:spawn input `(,@gpgsm --output **out** ,@args **in**)))

(define (pipe:gpgsm args)
  (pipe:spawn `(,@gpgsm --output - ,@args -)))

(define (gpgsm-with-colons args)
  (let ((s (call-popen `(,@gpgsm --with-colons ,@args) "")))
    (map (lambda (line) (string-split line #\:))
	 (string-split-newlines s))))

(define (sm-have-public-key? key)
  (catch #f
	 (pair? (filter (lambda (l) (and (equal? 'fpr (:type l))
					 (equal? key::fpr (:fpr l))))
			(gpgsm-with-colons `(--list-keys ,key::fpr))))))

(define (sm-have-secret-key? key)
  (catch #f
	 (pair? (filter (lambda (l) (and (equal? 'fpr (:type l))
					 (equal? key::fpr (:fpr l))))
			(gpgsm-with-colons `(--list-secret-keys ,key::fpr))))))

(define (create-gpgsmhome)
  (create-file "gpgsm.conf"
	       "disable-crl-checks"
	       "faked-system-time 1008241200")
  (create-file "gpg-agent.conf"
	       (string-append "pinentry-program " (tool 'pinentry))
	       "disable-scdaemon")
  (start-agent)
  (create-file
   "trustlist.txt"
   "32100C27173EF6E9C4E9A25D3D69F86D37A4F939"
   "# CN=test cert 1,OU=Aegypten Project,O=g10 Code GmbH,L=Düsseldorf,C=DE"
   "3CF405464F66ED4A7DF45BBDD1E4282E33BDB76E S")

  (log "Storing private keys")
  (for-each
   (lambda (name)
     (file-copy (in-srcdir "tests" "cms" name)
		(path-join "private-keys-v1.d"
			   (string-append name ".key"))))
   '("32100C27173EF6E9C4E9A25D3D69F86D37A4F939"))

  (log "Importing public demo and test keys")
  (call-check `(,@gpgsm --import ,(in-srcdir "tests" "cms"
                                             "cert_g10code_test1.der")))

  (create-sample-files)
  (stop-agent))

;; Initialize the test environment, install appropriate configuration
;; and start the agent, with the keys from the legacy test suite.
(define (setup-gpgsm-environment)
  (if (member "--unpack-tarball" *args*)
      (call-check `(,(tool 'gpgtar) --extract --directory=. ,(cadr *args*)))
      (create-gpgsm-gpghome))
  (start-agent))

(define (setup-gpgsm-environment-no-atexit)
  (if (member "--unpack-tarball" *args*)
      (call-check `(,(tool 'gpgtar) --extract --directory=. ,(cadr *args*)))
      (create-gpgsm-gpghome))
  (start-agent #t))
