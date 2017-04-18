;; A tiny XML library.
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

(define xx
  (begin

    ;; Private declarations.
    (define quote-text
      '((#\< "&lt;")
	(#\> "&gt;")
	(#\& "&amp;")))

    (define quote-attribute-'
      '((#\< "&lt;")
	(#\> "&gt;")
	(#\& "&amp;")
	(#\' "&apos;")))

    (define quote-attribute-''
      '((#\< "&lt;")
	(#\> "&gt;")
	(#\& "&amp;")
	(#\" "&quot;")))

    (define (escape-string quotation string sink)
      ;; This implementation is a bit awkward because iteration is so
      ;; slow in TinySCHEME.  We rely on string-index to skip to the
      ;; next character we need to escape.  We also avoid allocations
      ;; wherever possible.

      ;; Given a list of integers or #f, return the sublist that
      ;; starts with the lowest integer.
      (define (min* x)
	(let loop ((lowest x) (rest x))
	  (if (null? rest)
	      lowest
	      (loop (if (or (null? lowest) (not (car lowest))
			    (and (car rest) (> (car lowest) (car rest)))) rest lowest)
		    (cdr rest)))))

      (let ((i 0) (start 0) (len (string-length string))
	    (indices (map (lambda (x) (string-index string (car x))) quotation))
	    (next #f) (c #f))

	;; Set 'i' to the index of the next character that needs
	;; escaping, 'c' to the character that needs to be escaped,
	;; and update 'indices'.
	(define (skip!)
	  (set! next (min* indices))
	  (set! i (if (null? next) #f (car next)))
	  (if i
	      (begin
		(set! c (string-ref string i))
		(set-car! next (string-index string c (+ 1 i))))
	      (set! i (string-length string))))

	(let loop ()
	  (skip!)
	  (if (< i len)
	      (begin
		(display (substring string start i) sink)
		(display (cadr (assv c quotation)) sink)
		(set! i (+ 1 i))
		(set! start i)
		(loop))
	      (display (substring string start len) sink)))))

    (let ((escape-string-s (lambda (quotation string)
			     (let ((sink (open-output-string)))
			       (escape-string quotation string sink)
			       (get-output-string sink)))))
      (assert (equal? (escape-string-s quote-text "foo") "foo"))
      (assert (equal? (escape-string-s quote-text "foo&") "foo&amp;"))
      (assert (equal? (escape-string-s quote-text "&foo") "&amp;foo"))
      (assert (equal? (escape-string-s quote-text "foo&bar") "foo&amp;bar"))
      (assert (equal? (escape-string-s quote-text "foo<bar") "foo&lt;bar"))
      (assert (equal? (escape-string-s quote-text "foo>bar") "foo&gt;bar")))

    (define (escape quotation datum sink)
      (cond
       ((string? datum) (escape-string quotation datum sink))
       ((symbol? datum) (escape-string quotation (symbol->string datum) sink))
       ((number? datum) (display (number->string datum) sink))
       (else
	(throw "Do not know how to encode" datum))))

    (define (name->string name)
      (cond
       ((symbol? name) (symbol->string name))
       (else name)))

    (package

     (define (textnode string)
       (lambda (sink)
	 (escape quote-text string sink)))

     (define (tag name . rest)
       (let ((attributes (if (null? rest) '() (car rest)))
	     (children (if (> (length rest) 1) (cadr rest) '())))
	 (lambda (sink)
	   (display "<" sink)
	   (display (name->string name) sink)
	   (unless (null? attributes)
		   (display " " sink)
		   (for-each (lambda (a)
			       (display (car a) sink)
			       (display "=\"" sink)
			       (escape quote-attribute-'' (cadr a) sink)
			       (display "\" " sink)) attributes))
	   (if (null? children)
	       (display "/>\n" sink)
	       (begin
		 (display ">\n" sink)
		 (for-each (lambda (c) (c sink)) children)
		 (display "</" sink)
		 (display (name->string name) sink)
		 (display ">\n" sink))))))

     (define (document root . rest)
       (let ((attributes (if (null? rest) '() (car rest))))
	 (lambda (sink)
	   ;; xxx ignores attributes
	   (display "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" sink)
	   (root sink)
	   (newline sink)))))))
