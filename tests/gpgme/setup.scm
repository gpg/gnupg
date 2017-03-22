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

(define tarball (flag "--create-tarball" *args*))
(unless (and tarball (not (null? tarball)))
	(error "Usage: setup.scm --create-tarball <file> ..."))

(define components (flag "--" *args*))
(unless (and components (not (null? components)))
	(error "Usage: setup.scm --create-tarball " (cadr tarball)
	       " -- component [component ...]"))

(with-temporary-working-directory
 (setenv "GNUPGHOME" (getcwd) #t)
 (apply create-gpgmehome components)
 (stop-agent)
 (call-check `(,(tool 'gpgtar) --create --output ,(car tarball) ".")))
