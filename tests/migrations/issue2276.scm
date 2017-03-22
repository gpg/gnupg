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

(load (in-srcdir "tests" "migrations" "common.scm"))

(run-test
 "Checking migration with legacy key (issue2276)..."
 ;; This tarball contains a keyring with a legacy key.
 (in-srcdir "tests" "migrations" "issue2276.tar.asc")
 (lambda (gpghome)
   ;; GnuPG up to 2.1.14 failed to skip the legacy key when updating
   ;; the trust database and thereby rebuilding the keyring cache.
   (call-check `(,@GPG-no-batch --check-trustdb))

   ;; Check that the other key is fine.
   (call-check `(,@GPG --list-keys alpha))))
