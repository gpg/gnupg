#!/usr/bin/env gpgscm

;; GnuPG through 2.1.7 would incorrect mark packets whose size is
;; 2^32-1 as invalid and exit with status code 2.

(load (with-path "defs.scm"))

(if (= 0 (call `(,@GPG --list-packets ,(in-srcdir "4gb-packet.asc"))))
  (info "Can parse 4GB packets.")
  (error "Failed to parse 4GB packet."))
