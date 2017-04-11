;; Common definitions for executing gpg and related tools.
;;
;; Copyright (C) 2016, 2017 g10 Code GmbH
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

;; Evaluate a sequence of expressions with the given home directory.
(define-macro (with-home-directory gnupghome . expressions)
  (let ((original-home-directory (gensym)))
    `(let ((,original-home-directory (getenv "GNUPGHOME")))
       (dynamic-wind
	   (lambda () (setenv "GNUPGHOME" ,gnupghome #t))
	   (lambda () ,@expressions)
	   (lambda () (setenv "GNUPGHOME" ,original-home-directory #t))))))

;; Evaluate a sequence of expressions with an ephemeral home
;; directory.
(define-macro (with-ephemeral-home-directory setup-fn . expressions)
  (let ((original-home-directory (gensym))
	(ephemeral-home-directory (gensym))
	(setup (gensym)))
    `(let ((,original-home-directory (getenv "GNUPGHOME"))
	   (,ephemeral-home-directory (mkdtemp))
	   (,setup (delay (,setup-fn))))
       (finally (unlink-recursively ,ephemeral-home-directory)
	 (dynamic-wind
	     (lambda ()
	       (setenv "GNUPGHOME" ,ephemeral-home-directory #t)
	       (with-working-directory ,ephemeral-home-directory (force ,setup)))
	     (lambda () ,@expressions)
	     (lambda () (setenv "GNUPGHOME" ,original-home-directory #t)))))))
