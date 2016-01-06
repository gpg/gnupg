;; Additional library functions for TinySCHEME.
;;
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

(macro (assert form)
  `(if (not ,(cadr form))
       (begin
	 (display (list "Assertion failed:" (quote ,(cadr form))))
	 (newline)
	 (exit 1))))
(assert #t)

(define (filter pred lst)
  (cond ((null? lst) '())
        ((pred (car lst))
         (cons (car lst) (filter pred (cdr lst))))
        (else (filter pred (cdr lst)))))

(define (any p l)
  (cond ((null? l) #f)
        ((p (car l)) #t)
        (else (any p (cdr l)))))

(define (all p l)
  (cond ((null? l) #t)
        ((not (p (car l))) #f)
        (else (all p (cdr l)))))

;; Is PREFIX a prefix of S?
(define (string-prefix? s prefix)
  (and (>= (string-length s) (string-length prefix))
       (string=? prefix (substring s 0 (string-length prefix)))))
(assert (string-prefix? "Scheme" "Sch"))

;; Is SUFFIX a suffix of S?
(define (string-suffix? s suffix)
  (and (>= (string-length s) (string-length suffix))
       (string=? suffix (substring s (- (string-length s)
					(string-length suffix))
				   (string-length s)))))
(assert (string-suffix? "Scheme" "eme"))

;; Locate the first occurrence of needle in haystack.
(define (string-index haystack needle)
  (define (index i haystack needle)
    (if (= (length haystack) 0)
        #f
        (if (char=? (car haystack) needle)
            i
            (index (+ i 1) (cdr haystack) needle))))
  (index 0 (string->list haystack) needle))

;; Locate the last occurrence of needle in haystack.
(define (string-rindex haystack needle)
  (let ((rindex (string-index (list->string (reverse (string->list haystack)))
			      needle)))
    (if rindex (- (string-length haystack) rindex 1) #f)))

;; Split haystack at delimiter at most n times.
(define (string-splitn haystack delimiter n)
  (define (split acc haystack delimiter n)
    (if (= (string-length haystack) 0)
        (reverse acc)
        (let ((i (string-index haystack delimiter)))
          (if (not (or (eq? i #f) (= 0 n)))
              (split (cons (substring haystack 0 i) acc)
                     (substring haystack (+ i 1) (string-length haystack))
                     delimiter (- n 1))
              (split (cons haystack acc) "" delimiter 0)
              ))))
  (split '() haystack delimiter n))

;; Split haystack at delimiter.
(define (string-split haystack delimiter)
  (string-splitn haystack delimiter -1))

;; Trim the prefix of S containing only characters that make PREDICATE
;; true.  For example (string-ltrim char-whitespace? "  foo") =>
;; "foo".
(define (string-ltrim predicate s)
  (let loop ((s' (string->list s)))
    (if (predicate (car s'))
	(loop (cdr s'))
	(list->string s'))))

;; Trim the suffix of S containing only characters that make PREDICATE
;; true.
(define (string-rtrim predicate s)
  (let loop ((s' (reverse (string->list s))))
    (if (predicate (car s'))
	(loop (cdr s'))
	(list->string (reverse s')))))

;; Trim both the prefix and suffix of S containing only characters
;; that make PREDICATE true.
(define (string-trim predicate s)
  (string-ltrim predicate (string-rtrim predicate s)))

(define (string-contains? s contained)
  (let loop ((offset 0))
    (if (<= (+ offset (string-length contained)) (string-length s))
	(if (string=? (substring s offset (+ offset (string-length contained)))
		      contained)
	    #t
	    (loop (+ 1 offset)))
	#f)))

(define (echo . msg)
  (for-each (lambda (x) (display x) (display " ")) msg)
  (newline))

;; Read a word from port P.
(define (read-word . p)
  (list->string
   (let f ()
     (let ((c (apply peek-char p)))
       (cond
	((eof-object? c) '())
	((char-alphabetic? c)
	 (apply read-char p)
	 (cons c (f)))
	(else
	 (apply read-char p)
	 '()))))))

;; Read a line from port P.
(define (read-line . p)
  (list->string
   (let f ()
     (let ((c (apply peek-char p)))
       (cond
	((eof-object? c) '())
	((char=? c #\newline)
	 (apply read-char p)
	 '())
	(else
	 (apply read-char p)
	 (cons c (f))))))))

;; Read everything from port P.
(define (read-all . p)
  (list->string
   (let f ()
     (let ((c (apply peek-char p)))
       (cond
	((eof-object? c) '())
	(else (apply read-char p)
	 (cons c (f))))))))
