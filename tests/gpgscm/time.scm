;; Simple time manipulation library.
;;
;; Copyright (C) 2017 g10 Code GmbH
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

;; This library mimics what GnuPG thinks about expiration times.
;; Granularity is one second.  Its focus is not on correctness.

;; Conversion functions.
(define (minutes->seconds minutes)
  (* minutes 60))
(define (hours->seconds hours)
  (* hours 60 60))
(define (days->seconds days)
  (* days 24 60 60))
(define (weeks->seconds weeks)
  (days->seconds (* weeks 7)))
(define (months->seconds months)
  (days->seconds (* months 30)))
(define (years->seconds years)
  (days->seconds (* years 365)))

(define (time-matches? a b slack)
  (< (abs (- a b)) slack))
(assert (time-matches? (hours->seconds 1) (hours->seconds 2) (hours->seconds 2)))
(assert (time-matches? (hours->seconds 2) (hours->seconds 1) (hours->seconds 2)))
(assert (not (time-matches? (hours->seconds 4) (hours->seconds 1) (hours->seconds 2))))
(assert (not (time-matches? (hours->seconds 1) (hours->seconds 4) (hours->seconds 2))))
