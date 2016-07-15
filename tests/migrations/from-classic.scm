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

(load (with-path "common.scm"))

(catch (skip "gpgtar not built")
       (call-check `(,GPGTAR --help)))

(define src-tarball (in-srcdir "from-classic.tar.asc"))

(define (setup)
  (untar-armored src-tarball)
  (setenv "GNUPGHOME" (getcwd) #t))

(define (trigger-migration)
  (call-check `(,@GPG --list-secret-keys)))

(define (assert-migrated)
  (unless (file-exists? ".gpg-v21-migrated")
	  (error "Not migrated"))

  (for-each
   (lambda (keyid)
     (catch (error "Key not found:" keyid)
	    (call-check `(,@GPG --list-secret-keys ,keyid))))
   '("D74C5F22" "C40FDECF" "ECABF51D")))

(info "Testing a clean migration ...")
(with-temporary-working-directory
 (setup)
 (trigger-migration)
 (assert-migrated))

(info "Testing a migration with existing private-keys-v1.d ...")
(with-temporary-working-directory
 (setup)
 (mkdir "private-keys-v1.d" "-rwx")
 (trigger-migration)
 (assert-migrated))

(info "Testing a migration with existing but weird private-keys-v1.d ...")
(with-temporary-working-directory
 (setup)
 (mkdir "private-keys-v1.d" "")
 (trigger-migration)
 (assert-migrated))

;; XXX Check a case where the migration fails.
