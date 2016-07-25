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

(lettmp
 (logfile)

 (define (dump logfile)
   (call-with-input-file logfile
     (lambda (port)
       (display (read-all port)))))

 (setenv "PINENTRY_USER_DATA"
	 (string-append "--logfile=" logfile " " usrpass1) #t)

 (echo "Killing gpg-agent...")
 (call-check `(,(tool 'gpg-connect-agent) --verbose killagent /bye))
 (echo "Starting gpg-agent...")
 (call-check `(,(tool 'gpg-connect-agent) --verbose /bye))

 (for-each-p
  "Checking that keys requiring no interactions are preferred (issue1955)..."
  (lambda (test)
    (let ((file (in-srcdir "samplemsgs"
			   (string-append "issue1955." test ".gpg"))))
      (assert
       (string-contains? (call-check `(,@GPG --decrypt ,file)) "geheim"))
      (if (file-exists? logfile)
	  (error "GnuPG used the key requiring a passphrase"))))
  '("one.two" "two.one")))
