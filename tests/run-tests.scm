#!/usr/bin/env gpgscm

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

(info "Running all tests...")

(define (load-tests-with-log . path)
  (map (lambda (test)
	 (test:::set! 'log-file-name
		      (apply path-join `(,@path
					 ,(string-append (basename test::name)
							 ".log")))))
       (apply load-tests path)))

(let ((prefix (flag "--prefix" *args*))
      (all-tests (append
		  (load-tests-with-log "common")
		  (load-tests-with-log "g10")
		  (load-tests-with-log "g13")
		  (load-tests-with-log "agent")
		  (load-tests-with-log "tests" "openpgp")
		  (load-tests-with-log "tests" "migrations")
		  (load-tests-with-log "tests" "gpgsm")
		  (load-tests-with-log "tests" "gpgme"))))
  (run-tests (if prefix
		 (filter
		  (lambda (t) (string-prefix? t::name (apply path-join prefix)))
		  all-tests)
		 all-tests)))
