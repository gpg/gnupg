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

 ;; XXX because of --always-trust, the trustdb is not created.
 ;; Therefore, we redefine GPG without --always-trust.
(define GPG `(,(tool 'gpg) --no-permission-warning))

(define (exact id)
  (string-append "=" id))

(define (count-uids-of-secret-key id)
  (length (filter (lambda (x) (and (string=? "uid" (car x))
				   (string=? "u" (cadr x))))
		  (gpg-with-colons
		   `(--with-fingerprint
		     --list-secret-keys ,(exact id))))))

(define alpha "Alpha <alpha@invalid.example.net>")
(define bravo "Bravo <bravo@invalid.example.net>")

(define (key-data key)
  (filter (lambda (x) (or (string=? (car x) "pub")
                          (string=? (car x) "sub")))
          (gpg-with-colons `(-k ,key))))

(setenv "PINENTRY_USER_DATA" "test" #t)

(info "Checking quick key generation...")
(call-check `(,@GPG --quick-gen-key ,alpha))

(call-check `(,@GPG --check-trustdb)) ; XXX why?

(assert (= 1 (count-uids-of-secret-key alpha)))

(info "Checking that we can add a user ID...")

;; Make sure the key capabilities don't change when we add a user id.
;; (See bug #2697.)
(let ((pre (key-data (exact alpha)))
      (result (call-check `(,@GPG --quick-adduid ,(exact alpha) ,bravo)))
      (post (key-data (exact alpha))))
  (if (not (equal? pre post))
      (begin
	(display "Key capabilities changed when adding a user id:")
	(newline)
	(display "  Pre: ")
	(display pre)
	(newline)
	(display " Post: ")
	(display post)
	(newline)
	(exit 1))))

(call-check `(,@GPG --check-trustdb)) ; XXX why?

(assert (= 2 (count-uids-of-secret-key alpha)))
(assert (= 2 (count-uids-of-secret-key bravo)))

(info "Checking that we can revoke a user ID...")
(call-check `(,@GPG --quick-revuid ,(exact bravo) ,alpha))

(call-check `(,@GPG --check-trustdb)) ; XXX why?

(assert (= 1 (count-uids-of-secret-key bravo)))
