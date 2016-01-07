#!/usr/bin/env gpgscm

(load (with-path "defs.scm"))

(echo "Killing gpg-agent...")
(call-check `(,(tool 'gpg-connect-agent) --verbose killagent /bye))
