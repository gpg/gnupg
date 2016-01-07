#!/usr/bin/env gpgscm

(load (with-path "defs.scm"))

(info "Printing the GPG version")
(assert (= 0 (call `(,@GPG --version))))

;; fixme: check that the output is as expected
