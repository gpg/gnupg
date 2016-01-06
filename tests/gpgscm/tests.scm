;; Common definitions for writing tests.
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

;; Reporting.
(define (info msg)
  (display msg)
  (newline)
  (flush-stdio))

(define (error msg)
  (info msg)
  (exit 1))

(define (skip msg)
  (info msg)
  (exit 77))

(define (make-counter)
  (let ((c 0))
    (lambda ()
      (let ((r c))
	(set! c (+ 1 c))
	r))))

(define *progress-nesting* 0)

(define (call-with-progress msg what)
  (set! *progress-nesting* (+ 1 *progress-nesting*))
  (if (= 1 *progress-nesting*)
      (begin
	(info msg)
	(display "    > ")
	(flush-stdio)
	(what (lambda (item)
	      (display item)
	      (display " ")
	      (flush-stdio)))
	(info "< "))
      (begin
	(what (lambda (item) (display ".") (flush-stdio)))
	(display " ")
	(flush-stdio)))
  (set! *progress-nesting* (- *progress-nesting* 1)))

(define (for-each-p msg proc lst)
  (for-each-p' msg proc (lambda (x) x) lst))

(define (for-each-p' msg proc fmt lst)
  (call-with-progress
   msg
   (lambda (progress)
     (for-each (lambda (a)
		 (progress (fmt a))
		 (proc a))
	       lst))))

;; Process management.
(define CLOSED_FD -1)
(define (call-with-fds what infd outfd errfd)
  (wait-process (stringify what) (spawn-process-fd what infd outfd errfd) #t))
(define (call what)
  (call-with-fds what
		 CLOSED_FD
		 (if (< *verbose* 0) STDOUT_FILENO CLOSED_FD)
		 (if (< *verbose* 0) STDERR_FILENO CLOSED_FD)))
(define (call-check what)
  (if (not (= 0 (call what)))
      (throw (list what "failed"))))

;; Accessor functions for the results of 'spawn-process'.
(define :stdin car)
(define :stdout cadr)
(define :stderr caddr)
(define :pid cadddr)

(define (call-with-io what in)
  (let ((h (spawn-process what 0)))
    (es-write (:stdin h) in)
    (es-fclose (:stdin h))
    (let* ((out (es-read-all (:stdout h)))
	   (err (es-read-all (:stderr h)))
	   (result (wait-process (car what) (:pid h) #t)))
      (es-fclose (:stdout h))
      (es-fclose (:stderr h))
      (list result out err))))

;; Accessor function for the results of 'call-with-io'.  ':stdout' and
;; ':stderr' can also be used.
(define :retcode car)

(define (call-popen command input-string)
  (let ((result (call-with-io command input-string)))
    (if (= 0 (:retcode result))
	(:stdout result)
	(throw (:stderr result)))))

;;
;; estream helpers.
;;

(define (es-read-all stream)
  (let loop
      ((acc ""))
    (if (es-feof stream)
	acc
	(loop (string-append acc (es-read stream 4096))))))

;;
;; File management.
;;
(define (file=? a b)
  (file-equal a b #t))

(define (text-file=? a b)
  (file-equal a b #f))

(define (file-copy from to)
  (catch '() (unlink to))
  (letfd ((source (open from (logior O_RDONLY O_BINARY)))
	  (sink (open to (logior O_WRONLY O_CREAT O_BINARY) #o600)))
    (splice source sink)))

(define (text-file-copy from to)
  (catch '() (unlink to))
  (letfd ((source (open from O_RDONLY))
	  (sink (open to (logior O_WRONLY O_CREAT) #o600)))
    (splice source sink)))

(define (canonical-path path)
  (if (char=? #\/ (string-ref path 0))
      path
      (string-append (getcwd) "/" path)))

(define (in-srcdir what)
  (canonical-path (string-append (getenv "srcdir") "/" what)))

(define (with-path name)
  (let loop ((path (string-split (getenv "GPGSCM_PATH") #\:)))
    (if (null? path)
	name
	(let* ((qualified-name (string-append (car path) "/" name))
	       (file-exists (call-with-input-file qualified-name
			      (lambda (x) #t))))
	  (if file-exists
	      qualified-name
	      (loop (cdr path)))))))

(define (basename path)
  (let ((i (string-index path #\/)))
    (if (equal? i #f)
	path
	(basename (substring path (+ 1 i) (string-length path))))))

;; Helper for (pipe).
(define :read-end car)
(define :write-end cadr)

;; let-like macro that manages file descriptors.
;;
;; (letfd <bindings> <body>)
;;
;; Bind all variables given in <bindings> and initialize each of them
;; to the given initial value, and close them after evaluting <body>.
(macro (letfd form)
  (let ((result-sym (gensym)))
    `((lambda (,(caaadr form))
	(let ((,result-sym
	       ,(if (= 1 (length (cadr form)))
		    `(begin ,@(cddr form))
		    `(letfd ,(cdadr form) ,@(cddr form)))))
	  (close ,(caaadr form))
	  ,result-sym)) ,@(cdaadr form))))

(macro (with-working-directory form)
  (let ((result-sym (gensym)) (cwd-sym (gensym)))
    `(let* ((,cwd-sym (getcwd))
	    (_ (if ,(cadr form) (chdir ,(cadr form))))
	    (,result-sym (begin ,@(cddr form))))
       (chdir ,cwd-sym)
       ,result-sym)))

(macro (with-temporary-working-directory form)
  (let ((result-sym (gensym)) (cwd-sym (gensym)) (tmp-sym (gensym)))
    `(let* ((,cwd-sym (getcwd))
	    (,tmp-sym (mkdtemp "gpgscm-XXXXXX"))
	    (_ (chdir ,tmp-sym))
	    (,result-sym (begin ,@(cdr form))))
       (chdir ,cwd-sym)
       (unlink-recursively ,tmp-sym)
       ,result-sym)))

(define (make-temporary-file . args)
  (canonical-path (string-append (mkdtemp "gpgscm-XXXXXX")
				 "/"
				 (if (null? args) "a" (car args)))))

(define (remove-temporary-file filename)
  (catch '()
    (unlink filename))
  (let ((dirname (substring filename 0 (string-rindex filename #\/))))
    (catch (echo "removing temporary directory" dirname "failed")
      (rmdir dirname))))

;; let-like macro that manages temporary files.
;;
;; (lettmp <bindings> <body>)
;;
;; Bind all variables given in <bindings>, initialize each of them to
;; a string representing an unique path in the filesystem, and delete
;; them after evaluting <body>.
(macro (lettmp form)
  (let ((result-sym (gensym)))
    `((lambda (,(caadr form))
	(let ((,result-sym
	       ,(if (= 1 (length (cadr form)))
		    `(begin ,@(cddr form))
		    `(lettmp ,(cdadr form) ,@(cddr form)))))
	  (remove-temporary-file ,(caadr form))
	  ,result-sym)) (make-temporary-file ,(symbol->string (caadr form))))))

(define (check-execution source transformer)
  (lettmp (sink)
	  (transformer source sink)))

(define (check-identity source transformer)
  (lettmp (sink)
	  (transformer source sink)
	  (if (not (file=? source sink))
	      (error "mismatch"))))

;;
;; Monadic pipe support.
;;

(define pipeM
  (package
   (define (new procs source sink producer)
     (package
      (define (dump)
	(write (list procs source sink producer))
	(newline))
      (define (add-proc command pid)
	(new (cons (list command pid) procs) source sink producer))
      (define (commands)
	(map car procs))
      (define (pids)
	(map cadr procs))
      (define (set-source source')
	(new procs source' sink producer))
      (define (set-sink sink')
	(new procs source sink' producer))
      (define (set-producer producer')
	(if producer
	    (throw "producer already set"))
	(new procs source sink producer'))))))


(define (pipe:do . commands)
  (let loop ((M (pipeM::new '() CLOSED_FD CLOSED_FD #f)) (cmds commands))
    (if (null? cmds)
	(begin
	  (if M::producer (M::producer))
	  (if (not (null? M::procs))
	      (let* ((retcodes (wait-processes (map stringify (M::commands))
					       (M::pids) #t))
		     (results (map (lambda (p r) (append p (list r)))
				   M::procs retcodes))
		     (failed (filter (lambda (x) (not (= 0 (caddr x))))
				     results)))
		(if (not (null? failed))
		    (throw failed))))) ; xxx nicer reporting
	(if (and (= 2 (length cmds)) (number? (cadr cmds)))
	    ;; hack: if it's an fd, use it as sink
	    (let ((M' ((car cmds) (M::set-sink (cadr cmds)))))
	      (if (> M::source 2) (close M::source))
	      (if (> (cadr cmds) 2) (close (cadr cmds)))
	      (loop M' '()))
	    (let ((M' ((car cmds) M)))
	      (if (> M::source 2) (close M::source))
	      (loop M' (cdr cmds)))))))

(define (pipe:open pathname flags)
  (lambda (M)
    (M::set-source (open pathname flags))))

(define (pipe:defer producer)
  (lambda (M)
    (let* ((p (outbound-pipe))
	   (M' (M::set-source (:read-end p))))
      (M'::set-producer (lambda ()
			  (producer (:write-end p))
			  (close (:write-end p)))))))
(define (pipe:echo data)
 (pipe:defer (lambda (sink) (display data (fdopen sink "wb")))))

(define (pipe:spawn command)
  (lambda (M)
    (define (do-spawn M new-source)
      (let ((pid (spawn-process-fd command M::source M::sink
				   (if (> *verbose* 0)
				       STDERR_FILENO CLOSED_FD)))
	    (M' (M::set-source new-source)))
	(M'::add-proc command pid)))
    (if (= CLOSED_FD M::sink)
	(let* ((p (pipe))
	       (M' (do-spawn (M::set-sink (:write-end p)) (:read-end p))))
	  (close (:write-end p))
	  (M'::set-sink CLOSED_FD))
	(do-spawn M CLOSED_FD))))

(define (pipe:splice sink)
  (lambda (M)
    (splice M::source sink)
    (M::set-source CLOSED_FD)))

(define (pipe:write-to pathname flags mode)
  (open pathname flags mode))

;;
;; Monadic transformer support.
;;

(define (tr:do . commands)
  (let loop ((tmpfiles '()) (source  #f) (cmds commands))
    (if (null? cmds)
	(for-each remove-temporary-file tmpfiles)
	(let ((v ((car cmds) tmpfiles source)))
	  (loop (car v) (cadr v) (cdr cmds))))))

(define (tr:open pathname)
  (lambda (tmpfiles source)
    (list tmpfiles pathname)))

(define (tr:spawn input command)
  (lambda (tmpfiles source)
    (let* ((t (make-temporary-file))
	   (cmd (map (lambda (x)
		       (cond
			((equal? '**in** x) source)
			((equal? '**out** x) t)
			(else x))) command)))
      (call-popen cmd input)
      (list (cons t tmpfiles) t))))

(define (tr:write-to pathname)
  (lambda (tmpfiles source)
    (rename source pathname)
    (list tmpfiles pathname)))

(define (tr:pipe-do . commands)
  (lambda (tmpfiles source)
    (let ((t (make-temporary-file)))
      (apply pipe:do
        `(,@(if source `(,(pipe:open source (logior O_RDONLY O_BINARY))) '())
	  ,@commands
	  ,(pipe:write-to t (logior O_WRONLY O_BINARY O_CREAT) #o600)))
      (list (cons t tmpfiles) t))))

(define (tr:assert-identity reference)
  (lambda (tmpfiles source)
    (if (not (file=? source reference))
	(error "mismatch"))
    (list tmpfiles source)))

(define (tr:assert-weak-identity reference)
  (lambda (tmpfiles source)
    (if (not (text-file=? source reference))
	(error "mismatch"))
    (list tmpfiles source)))

(define (tr:call-with-content function)
  (lambda (tmpfiles source)
    (function (call-with-input-file source read-all))
    (list tmpfiles source)))
