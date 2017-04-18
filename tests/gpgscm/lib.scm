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
  (let ((tag (get-tag form)))
    `(if (not ,(cadr form))
	 (throw ,(if (and (pair? tag) (string? (car tag)) (number? (cdr tag)))
		     `(string-append ,(car tag) ":"
				     ,(number->string (+ 1 (cdr tag)))
				     ": Assertion failed: ")
		     "Assertion failed: ")
		(quote ,(cadr form))))))
(assert #t)
(assert (not #f))

;; Trace displays and returns the given value.  A debugging aid.
(define (trace x)
  (display x)
  (newline)
  x)

;; Stringification.
(define (stringify expression)
  (let ((p (open-output-string)))
    (write expression p)
    (get-output-string p)))

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

;; Return the first element of a list.
(define first car)

;; Return the last element of a list.
(define (last lst)
  (if (null? (cdr lst))
      (car lst)
      (last (cdr lst))))

;; Compute the powerset of a list.
(define (powerset set)
  (if (null? set)
      '(())
      (let ((rst (powerset (cdr set))))
        (append (map (lambda (x) (cons (car set) x))
                     rst)
                rst))))

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

;; Split HAYSTACK at each character that makes PREDICATE true at most
;; N times.
(define (string-split-pln haystack predicate lookahead n)
  (let ((length (string-length haystack)))
    (define (split acc offset n)
      (if (>= offset length)
	  (reverse! acc)
	  (let ((i (lookahead haystack offset)))
	    (if (or (eq? i #f) (= 0 n))
		(reverse! (cons (substring haystack offset length) acc))
		(split (cons (substring haystack offset i) acc)
		       (+ i 1) (- n 1))))))
    (split '() 0 n)))

(define (string-indexp haystack offset predicate)
  (cond
   ((= (string-length haystack) offset)
    #f)
   ((predicate (string-ref haystack offset))
    offset)
   (else
    (string-indexp haystack (+ 1 offset) predicate))))

;; Split HAYSTACK at each character that makes PREDICATE true at most
;; N times.
(define (string-splitp haystack predicate n)
  (string-split-pln haystack predicate
		    (lambda (haystack offset)
		      (string-indexp haystack offset predicate))
		    n))
(assert (equal? '("a" "b") (string-splitp "a b" char-whitespace? -1)))
(assert (equal? '("a" "b") (string-splitp "a\tb" char-whitespace? -1)))
(assert (equal? '("a" "" "b") (string-splitp "a \tb" char-whitespace? -1)))

;; Split haystack at delimiter at most n times.
(define (string-splitn haystack delimiter n)
  (string-split-pln haystack
		    (lambda (c) (char=? c delimiter))
		    (lambda (haystack offset)
		      (string-index haystack delimiter offset))
		    n))
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

;; Split haystack at newlines.
(define (string-split-newlines haystack)
  (if *win32*
      (map (lambda (line) (if (string-suffix? line "\r")
			      (substring line 0 (- (string-length line) 1))
			      line))
	   (string-split haystack #\newline))
      (string-split haystack #\newline)))

;; Trim the prefix of S containing only characters that make PREDICATE
;; true.
(define (string-ltrim predicate s)
  (if (string=? s "")
      ""
      (let loop ((s' (string->list s)))
	(if (predicate (car s'))
	    (loop (cdr s'))
	    (list->string s')))))
(assert (string=? "" (string-ltrim char-whitespace? "")))
(assert (string=? "foo" (string-ltrim char-whitespace? "  foo")))

;; Trim the suffix of S containing only characters that make PREDICATE
;; true.
(define (string-rtrim predicate s)
  (if (string=? s "")
      ""
      (let loop ((s' (reverse! (string->list s))))
	(if (predicate (car s'))
	    (loop (cdr s'))
	    (list->string (reverse! s'))))))
(assert (string=? "" (string-rtrim char-whitespace? "")))
(assert (string=? "foo" (string-rtrim char-whitespace? "foo 	")))

;; Trim both the prefix and suffix of S containing only characters
;; that make PREDICATE true.
(define (string-trim predicate s)
  (string-ltrim predicate (string-rtrim predicate s)))
(assert (string=? "" (string-trim char-whitespace? "")))
(assert (string=? "foo" (string-trim char-whitespace? " 	foo 	")))

;; Check if needle is contained in haystack.
(ffi-define (string-contains? haystack needle))
(assert (string-contains? "Hallo" "llo"))
(assert (not (string-contains? "Hallo" "olla")))

;; Translate characters.
(define (string-translate s from to)
  (list->string (map (lambda (c)
		       (let ((i (string-index from c)))
			 (if i (string-ref to i) c))) (string->list s))))
(assert (equal? (string-translate "foo/bar" "/" ".") "foo.bar"))

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

(define (list->string-reversed lst)
  (let* ((len (length lst))
	 (str (make-string len)))
    (let loop ((i (- len 1))
	       (l lst))
      (if (< i 0)
	  (begin
	    (assert (null? l))
	    str)
	  (begin
	    (string-set! str i (car l))
	    (loop (- i 1) (cdr l)))))))

;; Read a line from port P.
(define (read-line . p)
  (let loop ((acc '()))
    (let ((c (apply peek-char p)))
      (cond
       ((eof-object? c)
	(if (null? acc)
	    c ;; #eof
	    (list->string-reversed acc)))
       ((char=? c #\newline)
	(apply read-char p)
	(list->string-reversed acc))
       (else
	(apply read-char p)
	(loop (cons c acc)))))))

;; Read everything from port P.
(define (read-all . p)
  (let loop ((acc (open-output-string)))
    (let ((c (apply peek-char p)))
      (cond
       ((eof-object? c) (get-output-string acc))
       (else
	(write-char (apply read-char p) acc)
	(loop acc))))))

;;
;; Windows support.
;;

;; Like call-with-input-file but opens the file in 'binary' mode.
(define (call-with-binary-input-file filename proc)
  (letfd ((fd (open filename (logior O_RDONLY O_BINARY))))
	 (proc (fdopen fd "rb"))))

;; Like call-with-output-file but opens the file in 'binary' mode.
(define (call-with-binary-output-file filename proc)
  (letfd ((fd (open filename (logior O_WRONLY O_CREAT O_BINARY) #o600)))
	 (proc (fdopen fd "wb"))))

;;
;; Libc functions.
;;

;; Change the read/write offset.
(ffi-define (seek fd offset whence))

;; Constants for WHENCE.
(ffi-define SEEK_SET)
(ffi-define SEEK_CUR)
(ffi-define SEEK_END)

;; Get our process id.
(ffi-define (getpid))

;; Copy data from file descriptor SOURCE to every file descriptor in
;; SINKS.
(ffi-define (splice source . sinks))

;;
;; Random numbers.
;;

;; Seed the random number generator.
(ffi-define (srandom seed))

;; Get a pseudo-random number between 0 (inclusive) and SCALE
;; (exclusive).
(ffi-define (random scale))

;; Create a string of the given SIZE containing pseudo-random data.
(ffi-define (make-random-string size))
