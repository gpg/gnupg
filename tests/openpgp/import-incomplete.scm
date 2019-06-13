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
(setup-environment)

(call-check `(,(tool 'gpg) --import ,(in-srcdir "tests" "openpgp" "import-incomplete" "primary+uid.asc")))

(info "Test import of new subkey, from a certificate without uid")
(define keyid "573EA710367356BB")
(call-check `(,(tool 'gpg) --import ,(in-srcdir "tests" "openpgp" "import-incomplete" "primary+subkey+sub-sig.asc")))
(tr:do
 (tr:pipe-do
  (pipe:gpg `(--list-keys --with-colons ,keyid)))
 (tr:call-with-content
  (lambda (c)
    ;; XXX we do not have a regexp library
    (unless (any (lambda (line)
		   (and (string-prefix? line "sub:")
			(string-contains? line "573EA710367356BB")))
		 (string-split-newlines c))
	    (exit 1)))))

(info "Test import of a subkey revocation, from a certificate without uid")
(define keyid "573EA710367356BB")
(call-check `(,(tool 'gpg) --import ,(in-srcdir "tests" "openpgp" "import-incomplete" "primary+subkey+sub-revocation.asc")))
(tr:do
 (tr:pipe-do
  (pipe:gpg `(--list-keys --with-colons ,keyid)))
 (tr:call-with-content
  (lambda (c)
    ;; XXX we do not have a regexp library
    (unless (any (lambda (line)
		   (and (string-prefix? line "sub:r:")
			(string-contains? line "573EA710367356BB")))
		 (string-split-newlines c))
	    (exit 1)))))

(info "Test import of revocation, from a certificate without uid")
(call-check `(,(tool 'gpg) --import ,(in-srcdir "tests" "openpgp" "import-incomplete" "primary+revocation.asc")))
(tr:do
 (tr:pipe-do
  (pipe:gpg `(--list-keys --with-colons ,keyid)))
 (tr:call-with-content
  (lambda (c)
    ;; XXX we do not have a regexp library
    (unless (any (lambda (line)
		   (and (string-prefix? line "pub:r:")
			(string-contains? line "0843DA969AA8DAFB")))
		 (string-split-newlines c))
	    (exit 1)))))

