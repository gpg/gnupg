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

(if (string=? "" (getenv "abs_top_srcdir"))
    (error "not called from make"))

(let ((verbose (string->number (getenv "verbose"))))
  (if (number? verbose)
      (*set-verbose!* verbose)))

(define (qualify executable)
  (string-append executable (getenv "EXEEXT")))

;; We may not use a relative name for gpg-agent.
(define gpgconf (path-join (getenv "objdir") "tools" (qualify "gpgconf")))
(define GPG-AGENT (path-join (getenv "objdir") "agent" (qualify "gpg-agent")))
(define GPG `(,(path-join (getenv "objdir") "g10" (qualify "gpg"))
	      --no-permission-warning --no-greeting
	      --no-secmem-warning --batch
	      ,(string-append "--agent-program=" GPG-AGENT
			      "|--debug-quick-random")))
(define GPG-no-batch
  (filter (lambda (arg) (not (equal? arg '--batch))) GPG))

(define GPGTAR (path-join (getenv "objdir") "tools" (qualify "gpgtar")))

(define (untar-armored source-name)
  (with-ephemeral-home-directory (lambda ()) (lambda ())
    (pipe:do
     (pipe:open source-name (logior O_RDONLY O_BINARY))
     (pipe:spawn `(,@GPG --dearmor))
     (pipe:spawn `(,GPGTAR --extract --directory=. -)))))

(define (run-test message src-tarball test)
  (catch (skip "gpgtar not built")
	 (call-check `(,GPGTAR --help)))

  (with-temporary-working-directory
   (info message)
   (untar-armored src-tarball)
   (setenv "GNUPGHOME" (getcwd) #t)

   (catch (log "Warning: Creating socket directory failed:" (car *error*))
	  (call-popen `(,gpgconf --create-socketdir) ""))
   (test (getcwd))
   (catch (log "Warning: Removing socket directory failed.")
	  (call-popen `(,gpgconf --remove-socketdir) ""))))
