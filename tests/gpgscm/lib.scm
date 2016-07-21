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
	 (display "Assertion failed: ")
	 (write (quote ,(cadr form)))
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

;; Locate the first occurrence of needle in haystack starting at offset.
(ffi-define (string-index haystack needle [offset]))
(assert (= 2 (string-index "Hallo" #\l)))
(assert (= 3 (string-index "Hallo" #\l 3)))
(assert (equal? #f (string-index "Hallo" #\.)))

;; Locate the last occurrence of needle in haystack starting at offset.
(ffi-define (string-rindex haystack needle [offset]))
(assert (= 3 (string-rindex "Hallo" #\l)))
(assert (equal? #f (string-rindex "Hallo" #\a 2)))
(assert (equal? #f (string-rindex "Hallo" #\.)))

;; Split haystack at delimiter at most n times.
(define (string-splitn haystack delimiter n)
  (let ((length (string-length haystack)))
    (define (split acc delimiter offset n)
      (if (>= offset length)
	  (reverse acc)
	  (let ((i (string-index haystack delimiter offset)))
	    (if (or (eq? i #f) (= 0 n))
		(reverse (cons (substring haystack offset length) acc))
		(split (cons (substring haystack offset i) acc)
		       delimiter (+ i 1) (- n 1))))))
    (split '() delimiter 0 n)))
(assert (= 2 (length (string-splitn "foo:bar:baz" #\: 1))))
(assert (string=? "foo" (car (string-splitn "foo:bar:baz" #\: 1))))
(assert (string=? "bar:baz" (cadr (string-splitn "foo:bar:baz" #\: 1))))

;; Split haystack at delimiter.
(define (string-split haystack delimiter)
  (string-splitn haystack delimiter -1))
(assert (= 3 (length (string-split "foo:bar:baz" #\:))))
(assert (string=? "foo" (car (string-split "foo:bar:baz" #\:))))
(assert (string=? "bar" (cadr (string-split "foo:bar:baz" #\:))))
(assert (string=? "baz" (caddr (string-split "foo:bar:baz" #\:))))

;; Trim the prefix of S containing only characters that make PREDICATE
;; true.
(define (string-ltrim predicate s)
  (let loop ((s' (string->list s)))
    (if (predicate (car s'))
	(loop (cdr s'))
	(list->string s'))))
(assert (string=? "foo" (string-ltrim char-whitespace? "  foo")))

;; Trim the suffix of S containing only characters that make PREDICATE
;; true.
(define (string-rtrim predicate s)
  (let loop ((s' (reverse (string->list s))))
    (if (predicate (car s'))
	(loop (cdr s'))
	(list->string (reverse s')))))
(assert (string=? "foo" (string-rtrim char-whitespace? "foo 	")))

;; Trim both the prefix and suffix of S containing only characters
;; that make PREDICATE true.
(define (string-trim predicate s)
  (string-ltrim predicate (string-rtrim predicate s)))
(assert (string=? "foo" (string-trim char-whitespace? " 	foo 	")))

;; Check if needle is contained in haystack.
(ffi-define (string-contains? haystack needle))
(assert (string-contains? "Hallo" "llo"))
(assert (not (string-contains? "Hallo" "olla")))

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
  (let loop ((acc (open-output-string)))
    (let ((c (apply peek-char p)))
      (cond
       ((eof-object? c) (get-output-string acc))
       (else
	(write-char (apply read-char p) acc)
	(loop acc))))))
