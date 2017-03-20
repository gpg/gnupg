;; Support for parsing Makefiles
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

(define (parse-makefile port key)
  (define (is-continuation? tokens)
    (string=? (last tokens) "\\"))
  (define (valid-token? s)
    (< 0 (string-length s)))
  (define (drop-continuations tokens)
    (let loop ((acc '()) (tks tokens))
      (if (null? tks)
	  (reverse acc)
	  (loop (if (string=? "\\" (car tks))
		    acc
		    (cons (car tks) acc)) (cdr tks)))))
  (let next ((acc '()) (found #f))
    (let ((line (read-line port)))
      (if (eof-object? line)
	  acc
	  (let ((tokens (filter valid-token?
				(string-splitp (string-trim char-whitespace?
							    line)
					       char-whitespace? -1))))
	    (cond
	     ((or (null? tokens)
		  (string-prefix? (car tokens) "#")
		  (and (not found) (not (and (string=? key (car tokens))
					     (string=? "=" (cadr tokens))))))
	      (next acc found))
	     ((not found)
	      (assert (and (string=? key (car tokens))
			   (string=? "=" (cadr tokens))))
	      (if (is-continuation? tokens)
		  (next (drop-continuations (cddr tokens)) #t)
		  (drop-continuations (cddr tokens))))
	     (else
	      (assert found)
	      (if (is-continuation? tokens)
		  (next (append acc (drop-continuations tokens)) found)
		  (append acc (drop-continuations tokens))))))))))

(define (parse-makefile-expand filename expand key)
  (define (variable? v)
    (and (string-prefix? v "$(") (string-suffix? v ")")))

  (let expand-all ((values (parse-makefile (open-input-file filename) key)))
    (if (any variable? values)
	(expand-all
	 (let expand-one ((acc '()) (v values))
	   (cond
	    ((null? v)
	     acc)
	    ((variable? (car v))
	     (let ((makefile (open-input-file filename))
		   (key (substring (car v) 2 (- (string-length (car v)) 1))))
	       (expand-one (append acc (expand filename makefile key))
			   (cdr v))))
	    (else
	     (expand-one (append acc (list (car v))) (cdr v))))))
	values)))
