#!/usr/bin/env gpgscm

;; Regression tests for importing/signing Ed25519 keys which are
;; related to SOS representations, for issue 5120 and 5953.

;; Copyright (C) 2022 g10 Code GmbH
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
(setup-legacy-environment)

;; A secret key made by SOS representation having leading-zeros
(define secret-key-non-protected-0 "-----BEGIN PGP PRIVATE KEY BLOCK-----

lFgEW9rRAxYJKwYBBAHaRw8BAQdAAAAfi+pCs8dMUKo1ibGqBl8ZaFfbl6deSlSV
Pwk+Z3IAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJAAltBpTYXZl
IE91ciBMZWFkaW5nIFplcm9zIDA5OYiaBBMWCgBCFiEE8sEmTikqKYrrS8NIYDMV
yTB5KUAFAlva0QMCGwMFCQPCZwAFCwkIBwIDIgIBBhUKCQgLAgQWAgMBAh4HAheA
AAoJEGAzFckweSlAQ84BAACkDMCCuSYRgXddPF3DZFNBV71nvSFiWJwEJ1FPOWwe
AP0RRuStMwJ/PhNcnYcRk7cSUQFUanHaCUvZs/flY9VjCw==
=muKZ
-----END PGP PRIVATE KEY BLOCK-----")

(pipe:do
 (pipe:echo secret-key-non-protected-0)
 (pipe:gpg '(--import)))

(pipe:do
 (pipe:echo "Please sign")
 (pipe:gpg '(--faked-system-time=1541067011
             --local-user "Save Our Leading Zeros 099" --armor --detach-sign)))

;; Another secret key having leading-bit 1
(define secret-key-non-protected-1 "-----BEGIN PGP PRIVATE KEY BLOCK-----

lFgEYml3ZxYJKwYBBAHaRw8BAQdAFIlUhDKHcbL1Kw0+aeh/F3erSIK/xVl402L3
YozMTXUAAQC9584RraZ+5Nh/xqaWQ9a9D4ifdfYYgSaFQpejpdNP7BJ8tAh0ZXN0
IGtleYiWBBMWCAA+FiEEh2Rw0j7f1zZZV/DTp9XsCtatsFEFAmJpd2cCGwMFCQPC
ZwAFCwkIBwIGFQoJCAsCBBYCAwECHgECF4AACgkQp9XsCtatsFHwfAEAt9ea78Qe
qCxItQZO4Dw6VeUsQOnxcq4lOLrxl39yLWsBAKyvxAYMEOolXco8iUZ9z6TCmICc
XCri8UlEibk762oAnF0EYml3ZxIKKwYBBAGXVQEFAQEHQEZIAeEj1SG41845ieYY
cca9ySuZjOuxib9N0/1wju1aAwEIBwAA/1hFXTkXuRKFCQPTzjr/aB3O3AcxIPGz
moIpdVVRu+5gDxOIeAQYFggAIBYhBIdkcNI+39c2WVfw06fV7ArWrbBRBQJiaXdn
AhsMAAoJEKfV7ArWrbBRvz4A/3Q412OI2/V/uSIIQYrgHJvdqGPQ9xV8NHBu+Rzd
YanfAP9yDmJS7gkif1FVKmEaVINaXVu+U0GwkoIXAjo6mnPQAQ==
=l6au
-----END PGP PRIVATE KEY BLOCK-----")

(pipe:do
 (pipe:echo secret-key-non-protected-1)
 (pipe:gpg '(--import)))

(pipe:do
 (pipe:echo "test")
 (pipe:gpg '(--local-user "test key" --armor --detach-sign)))
