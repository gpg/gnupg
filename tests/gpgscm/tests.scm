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

;; Reporting.
(define (echo . msg)
  (for-each (lambda (x) (display x) (display " ")) msg)
  (newline))

(define (info . msg)
  (apply echo msg)
  (flush-stdio))

(define (log . msg)
  (if (> (*verbose*) 0)
      (apply info msg)))

(define (fail . msg)
  (apply info msg)
  (exit 1))

(define (skip . msg)
  (apply info msg)
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

(define (for-each-p msg proc lst . lsts)
  (apply for-each-p' `(,msg ,proc ,(lambda (x . xs) x) ,lst ,@lsts)))

(define (for-each-p' msg proc fmt lst . lsts)
  (call-with-progress
   msg
   (lambda (progress)
     (apply for-each
	    `(,(lambda args
		 (progress (apply fmt args))
		 (apply proc args))
	      ,lst ,@lsts)))))

;; Process management.
(define CLOSED_FD -1)
(define (call-with-fds what infd outfd errfd)
  (wait-process (stringify what) (spawn-process-fd what infd outfd errfd) #t))
(define (call what)
  (call-with-fds what
		 CLOSED_FD
		 (if (< (*verbose*) 0) STDOUT_FILENO CLOSED_FD)
		 (if (< (*verbose*) 0) STDERR_FILENO CLOSED_FD)))

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
      (if (> (*verbose*) 2)
	  (info "Child" (:pid h) "returned:"
		`((command ,(stringify what))
		  (status ,result)
		  (stdout ,out)
		  (stderr ,err))))
      (list result out err))))

;; Accessor function for the results of 'call-with-io'.  ':stdout' and
;; ':stderr' can also be used.
(define :retcode car)

(define (call-check what)
  (let ((result (call-with-io what "")))
    (if (= 0 (:retcode result))
	(:stdout result)
	(throw (string-append (stringify what) " failed")
	       (:stderr result)))))

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
(define (file-exists? name)
  (call-with-input-file name (lambda (port) #t)))

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

(define (path-join . components)
  (let loop ((acc #f) (rest (filter (lambda (s)
				      (not (string=? "" s))) components)))
    (if (null? rest)
	acc
	(loop (if (string? acc)
		  (string-append acc "/" (car rest))
		  (car rest))
	      (cdr rest)))))
(assert (string=? (path-join "foo" "bar" "baz") "foo/bar/baz"))
(assert (string=? (path-join "" "bar" "baz") "bar/baz"))

;; Is PATH an absolute path?
(define (absolute-path? path)
  (or (char=? #\/ (string-ref path 0))
      (and *win32* (char=? #\\ (string-ref path 0)))
      (and *win32*
	   (char-alphabetic? (string-ref path 0))
	   (char=? #\: (string-ref path 1))
	   (or (char=? #\/ (string-ref path 2))
	       (char=? #\\ (string-ref path 2))))))

;; Make PATH absolute.
(define (canonical-path path)
  (if (absolute-path? path) path (path-join (getcwd) path)))

(define (in-srcdir . names)
  (canonical-path (apply path-join (cons (getenv "abs_top_srcdir") names))))

;; Split a list of paths.
(define (pathsep-split s)
  (string-split s *pathsep*))

;; Join a list of paths.
(define (pathsep-join paths)
  (foldr (lambda (a b) (string-append a (string *pathsep*) b))
	 (car paths)
	 (cdr paths)))

;; Try to find NAME in PATHS.  Returns the full path name on success,
;; or raises an error.
(define (path-expand name paths)
  (let loop ((path paths))
    (if (null? path)
	(throw "Could not find" name "in" paths)
	(let* ((qualified-name (path-join (car path) name))
	       (file-exists (call-with-input-file qualified-name
			      (lambda (x) #t))))
	  (if file-exists
	      qualified-name
	      (loop (cdr path)))))))

;; Expand NAME using the gpgscm load path.  Use like this:
;;   (load (with-path "library.scm"))
(define (with-path name)
  (catch name
	 (path-expand name (pathsep-split (getenv "GPGSCM_PATH")))))

(define (basename path)
  (let ((i (string-index path #\/)))
    (if (equal? i #f)
	path
	(basename (substring path (+ 1 i) (string-length path))))))

(define (basename-suffix path suffix)
  (basename
   (if (string-suffix? path suffix)
       (substring path 0 (- (string-length path) (string-length suffix)))
       path)))

(define (dirname path)
  (let ((i (string-rindex path #\/)))
    (if i (substring path 0 i) ".")))
(assert (string=? "foo/bar" (dirname "foo/bar/baz")))

;; Helper for (pipe).
(define :read-end car)
(define :write-end cadr)

;; let-like macro that manages file descriptors.
;;
;; (letfd <bindings> <body>)
;;
;; Bind all variables given in <bindings> and initialize each of them
;; to the given initial value, and close them after evaluating <body>.
(define-macro (letfd bindings . body)
  (let bind ((bindings' bindings))
    (if (null? bindings')
	`(begin ,@body)
	(let* ((binding (car bindings'))
	       (name (car binding))
	       (initializer (cadr binding)))
	  `(let ((,name ,initializer))
	     (finally (close ,name)
		      ,(bind (cdr bindings'))))))))

(define-macro (with-working-directory new-directory . expressions)
  (let ((new-dir (gensym))
	(old-dir (gensym)))
    `(let* ((,new-dir ,new-directory)
	    (,old-dir (getcwd)))
       (dynamic-wind
	   (lambda () (if ,new-dir (chdir ,new-dir)))
	   (lambda () ,@expressions)
	   (lambda () (chdir ,old-dir))))))

;; Make a temporary directory.  If arguments are given, they are
;; joined using path-join, and must end in a component ending in
;; "XXXXXX".  If no arguments are given, a suitable location and
;; generic name is used.  Returns an absolute path.
(define (mkdtemp . components)
  (canonical-path (_mkdtemp (if (null? components)
				(path-join
				 (get-temp-path)
				 (string-append "gpgscm-" (get-isotime) "-"
						(basename-suffix *scriptname* ".scm")
						"-XXXXXX"))
				(apply path-join components)))))

;; Make a temporary directory and remove it at interpreter shutdown.
;; Note that there are macros that limit the lifetime of temporary
;; directories and files to a lexical scope.  Use those if possible.
;; Otherwise this works like mkdtemp.
(define (mkdtemp-autoremove . components)
  (let ((dir (apply mkdtemp components)))
    (atexit (lambda () (unlink-recursively dir)))
    dir))

(define-macro (with-temporary-working-directory . expressions)
  (let ((tmp-sym (gensym)))
    `(let* ((,tmp-sym (mkdtemp)))
       (finally (unlink-recursively ,tmp-sym)
		(with-working-directory ,tmp-sym
					,@expressions)))))

(define (make-temporary-file . args)
  (canonical-path (path-join
		   (mkdtemp)
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
;; them after evaluating <body>.
(define-macro (lettmp bindings . body)
  (let bind ((bindings' bindings))
    (if (null? bindings')
	`(begin ,@body)
	(let ((name (car bindings'))
	      (rest (cdr bindings')))
	  `(let ((,name (make-temporary-file ,(symbol->string name))))
	     (finally (remove-temporary-file ,name)
		      ,(bind rest)))))))

(define (check-execution source transformer)
  (lettmp (sink)
	  (transformer source sink)))

(define (check-identity source transformer)
  (lettmp (sink)
	  (transformer source sink)
	  (if (not (file=? source sink))
	      (fail "mismatch"))))

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
				   (if (> (*verbose*) 0)
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
	(let* ((v ((car cmds) tmpfiles source))
	       (tmpfiles' (car v))
	       (sink (cadr v))
	       (error (caddr v)))
	  (if error
	      (begin
		(for-each remove-temporary-file tmpfiles')
		(apply throw error)))
	  (loop tmpfiles' sink (cdr cmds))))))

(define (tr:open pathname)
  (lambda (tmpfiles source)
    (list tmpfiles pathname #f)))

(define (tr:spawn input command)
  (lambda (tmpfiles source)
    (if (and (member '**in** command) (not source))
	(fail (string-append (stringify cmd) " needs an input")))
    (let* ((t (make-temporary-file))
	   (cmd (map (lambda (x)
		       (cond
			((equal? '**in** x) source)
			((equal? '**out** x) t)
			(else x))) command)))
      (catch (list (cons t tmpfiles) t *error*)
	     (call-popen cmd input)
	     (if (and (member '**out** command) (not (file-exists? t)))
		 (fail (string-append (stringify cmd)
				       " did not produce '" t "'.")))
	     (list (cons t tmpfiles) t #f)))))

(define (tr:write-to pathname)
  (lambda (tmpfiles source)
    (rename source pathname)
    (list tmpfiles pathname #f)))

(define (tr:pipe-do . commands)
  (lambda (tmpfiles source)
    (let ((t (make-temporary-file)))
      (apply pipe:do
        `(,@(if source `(,(pipe:open source (logior O_RDONLY O_BINARY))) '())
	  ,@commands
	  ,(pipe:write-to t (logior O_WRONLY O_BINARY O_CREAT) #o600)))
      (list (cons t tmpfiles) t #f))))

(define (tr:assert-identity reference)
  (lambda (tmpfiles source)
    (if (not (file=? source reference))
	(fail "mismatch"))
    (list tmpfiles source #f)))

(define (tr:assert-weak-identity reference)
  (lambda (tmpfiles source)
    (if (not (text-file=? source reference))
	(fail "mismatch"))
    (list tmpfiles source #f)))

(define (tr:call-with-content function . args)
  (lambda (tmpfiles source)
    (catch (list tmpfiles source *error*)
	   (apply function `(,(call-with-input-file source read-all) ,@args)))
    (list tmpfiles source #f)))

;;
;; Developing and debugging tests.
;;

;; Spawn an os shell.
(define (interactive-shell)
  (call-with-fds `(,(getenv "SHELL") -i) 0 1 2))

;;
;; The main test framework.
;;

(define semaphore
  (package
   (define (new n)
     (package
      (define (acquire!?)
	(if (> n 0)
	    (begin
	      (set! n (- n 1))
	      #t)
	    #f))
      (define (release!)
	(set! n (+ n 1)))))))

;; A pool of tests.
(define test-pool
  (package
   (define (new n)
     (package
      ;; A semaphore to restrict the number of spawned processes.
      (define sem (semaphore::new n))

      ;; A list of enqueued, but not yet run tests.
      (define enqueued '())

      ;; A list of running or finished processes.
      (define procs '())

      (define (add test)
	(if (test::started?)
	    (set! procs (cons test procs))
	    (if (sem::acquire!?)
		(add (test::run-async))
		(set! enqueued (cons test enqueued))))
	(current-environment))

      ;; Pop the last of the enqueued tests off the fifo queue.
      (define (pop-test!)
	(let ((i (length enqueued)))
	  (assert (> i 0))
	  (cond
	   ((= i 1)
	    (let ((test (car enqueued)))
	      (set! enqueued '())
	      test))
	   (else
	    (let* ((tail (list-tail enqueued (- i 2)))
		   (test (cadr tail)))
	      (set-cdr! tail '())
	      (assert (= (length enqueued) (- i 1)))
	      test)))))

      (define (pid->test pid)
	(let ((t (filter (lambda (x) (= pid x::pid)) procs)))
	  (if (null? t) #f (car t))))
      (define (wait)
	(if (null? enqueued)
	    ;; If no tests are enqueued, we can just block until all
	    ;; of them finished.
	    (wait' #t)
	    ;; Otherwise, we must not block, but give some tests the
	    ;; chance to finish so that we can start new ones.
	    (begin
	      (wait' #f)
	      (usleep (/ 1000000 10))
	      (wait))))
      (define (wait' hang)
	(let ((unfinished (filter (lambda (t) (not t::retcode)) procs)))
	  (if (null? unfinished)
	      (current-environment)
	      (let ((names (map (lambda (t) t::name) unfinished))
		    (pids (map (lambda (t) t::pid) unfinished))
		    (any #f))
		(for-each
		 (lambda (test retcode)
		   (unless (< retcode 0)
			   (test::set-end-time!)
			   (test:::set! 'retcode retcode)
			   (test::report)
			   (sem::release!)
			   (set! any #t)))
		 (map pid->test pids)
		 (wait-processes (map stringify names) pids hang))

		;; If some processes finished, try to start new ones.
		(let loop ()
		  (cond
		   ((not any) #f)
		   ((pair? enqueued)
		    (if (sem::acquire!?)
			(let ((test (pop-test!)))
			  (add (test::run-async))
			  (loop)))))))))
	(current-environment))
      (define (filter-tests status)
	(filter (lambda (p) (eq? status (p::status))) procs))
      (define (report)
	(define (print-tests tests message)
	  (unless (null? tests)
		  (apply echo (cons message
				    (map (lambda (t) t::name) tests)))))

	(let ((failed (filter-tests 'FAIL))
	      (xfailed (filter-tests 'XFAIL))
	      (xpassed (filter-tests 'XPASS))
	      (skipped (filter-tests 'SKIP)))
          (echo "===================")
	  (echo (length procs) "tests run,"
		(length (filter-tests 'PASS)) "succeeded,"
		(length failed) "failed,"
		(length xfailed) "failed expectedly,"
		(length xpassed) "succeeded unexpectedly,"
		(length skipped) "skipped.")
	  (print-tests failed "Failed tests:")
	  (print-tests xfailed "Expectedly failed tests:")
	  (print-tests xpassed "Unexpectedly passed tests:")
	  (print-tests skipped "Skipped tests:")
          (echo "===================")
	  (+ (length failed) (length xpassed))))

      (define (xml)
	(xx::document
	 (xx::tag 'testsuites
		  `((xmlns:xsi "http://www.w3.org/2001/XMLSchema-instance")
		    ("xsi:noNamespaceSchemaLocation"
		     "https://windyroad.com.au/dl/Open%20Source/JUnit.xsd"))
		  (map (lambda (t) (t::xml)) procs))))))))

(define (verbosity n)
  (if (= 0 n) '() (cons '--verbose (verbosity (- n 1)))))

(define (locate-test path)
  (if (absolute-path? path) path (in-srcdir path)))

;; A single test.
(define test
 (begin

  ;; Private definitions.

  (define (isotime->junit t)
    "[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    "20170418T145809"
    (string-append (substring t 0 4)
		   "-"
		   (substring t 4 6)
		   "-"
		   (substring t 6 11)
		   ":"
		   (substring t 11 13)
		   ":"
		   (substring t 13 15)))

  ;; If a tests name ends with a bang (!), it is expected to fail.
  (define (expect-failure? name)
    (string-suffix? name "!"))
  ;; Strips the bang (if any).
  (define (test-name name)
    (if (expect-failure? name)
	(substring name 0 (- (string-length name) 1))
	name))

  (package
   (define (scm setup variant name path . args)
     ;; Start the process.
     (define (spawn-scm args' in out err)
       (spawn-process-fd `(,*argv0* ,@(verbosity (*verbose*))
				    ,(locate-test (test-name path))
				    ,@(if setup (force setup) '())
				    ,@args' ,@args) in out err))
     (new variant name #f spawn-scm #f #f CLOSED_FD (expect-failure? name)))

   (define (binary setup name path . args)
     ;; Start the process.
     (define (spawn-binary args' in out err)
       (spawn-process-fd `(,(test-name path)
			   ,@(if setup (force setup) '()) ,@args' ,@args)
			 in out err))
     (new #f name #f spawn-binary #f #f CLOSED_FD (expect-failure? name)))

   (define (new variant name directory spawn pid retcode logfd expect-failure)
     (package

      ;; XXX: OO glue.
      (define self (current-environment))
      (define (:set! key value)
	(eval `(set! ,key ,value) (current-environment))
	(current-environment))

      ;; The log is written here.
      (define log-file-name #f)

      ;; Record time stamps.
      (define timestamp #f)
      (define start-time 0)
      (define end-time 0)

      (define (set-start-time!)
	(set! timestamp (isotime->junit (get-isotime)))
	(set! start-time (get-time)))
      (define (set-end-time!)
	(set! end-time (get-time)))

      ;; Has the test been started yet?
      (define (started?)
	(number? pid))

      (define (open-log-file)
	(unless log-file-name
	  (set! log-file-name (path-join
			       (getenv "objdir")
			       (if variant
				   (string-append name "." variant ".log")
				   (string-append name ".log")))))
	(catch '() (unlink log-file-name))
	(open log-file-name (logior O_RDWR O_BINARY O_CREAT) #o600))

      (define (run-sync . args)
	(set-start-time!)
	(letfd ((log (open-log-file)))
	  (with-working-directory directory
	    (let* ((p (inbound-pipe))
		   (pid' (spawn args 0 (:write-end p) (:write-end p))))
	      (close (:write-end p))
	      (splice (:read-end p) STDERR_FILENO log)
	      (close (:read-end p))
	      (set! pid pid')
	      (set! retcode (wait-process name pid' #t)))))
	(report)
	(current-environment))
      (define (run-sync-quiet . args)
	(set-start-time!)
	(with-working-directory directory
	  (set! pid (spawn args CLOSED_FD CLOSED_FD CLOSED_FD)))
	(set! retcode (wait-process name pid #t))
	(set-end-time!)
	(current-environment))
      (define (run-async . args)
	(set-start-time!)
	(let ((log (open-log-file)))
	  (with-working-directory directory
	    (set! pid (spawn args CLOSED_FD log log)))
	  (set! logfd log))
	(current-environment))
      (define (status)
	(let* ((t' (assoc retcode '((0 PASS) (77 SKIP) (99 ERROR))))
	       (t (if (not t') 'FAIL (cadr t'))))
	  (if expect-failure
	      (case t ((PASS) 'XPASS) ((FAIL) 'XFAIL) (else t))
	      t)))
      (define (status-string)
	(cadr (assoc (status) '((PASS "PASS")
			       (SKIP "SKIP")
			       (ERROR "ERROR")
			       (FAIL "FAIL")
			       (XPASS "XPASS")
			       (XFAIL "XFAIL")))))
      (define (report)
	(unless (= logfd CLOSED_FD)
		(seek logfd 0 SEEK_SET)
		(splice logfd STDERR_FILENO)
		(close logfd))
	(echo (string-append (status-string) ":")
	      (if variant
		  (string-append "<" variant ">" name)
		  name)))

      (define (xml)
	(xx::tag
	 'testsuite
	 `((name ,name)
	   (time ,(- end-time start-time))
	   (package ,(dirname name))
	   (id 0)
	   (timestamp ,timestamp)
	   (hostname "unknown")
	   (tests 1)
	   (failures ,(if (eq? FAIL (status)) 1 0))
	   (errors ,(if (eq? ERROR (status)) 1 0)))
	 (list
	  (xx::tag 'properties)
	  (xx::tag 'testcase
		   `((name ,(basename name))
		     (classname ,(string-translate (dirname name) "/" "."))
		     (time ,(- end-time start-time)))
		   `(,@(case (status)
			 ((PASS XFAIL) '())
			 ((SKIP) (list (xx::tag 'skipped)))
			 ((ERROR) (list
				   (xx::tag 'error '((message "Unknown error.")))))
			 (else
			  (list (xx::tag 'failure '((message "Unknown error."))))))))
	  (xx::tag 'system-out '()
		   (list (xx::textnode (read-all (open-input-file log-file-name)))))
	  (xx::tag 'system-err '() (list (xx::textnode "")))))))))))

;; Run the setup target to create an environment, then run all given
;; tests in parallel.
(define (run-tests-parallel tests n)
  (let loop ((pool (test-pool::new n)) (tests' tests))
    (if (null? tests')
	(let ((results (pool::wait)))
	  ((results::xml) (open-output-file "report.xml"))
	  (exit (results::report)))
	(let ((wd (mkdtemp-autoremove))
	      (test (car tests')))
	  (test:::set! 'directory wd)
	  (loop (pool::add test)
		(cdr tests'))))))

;; Run the setup target to create an environment, then run all given
;; tests in sequence.
(define (run-tests-sequential tests)
  (let loop ((pool (test-pool::new 1)) (tests' tests))
    (if (null? tests')
	(let ((results (pool::wait)))
	  ((results::xml) (open-output-file "report.xml"))
	  (exit (results::report)))
	(let ((wd (mkdtemp-autoremove))
	      (test (car tests')))
	  (test:::set! 'directory wd)
	  (loop (pool::add (test::run-sync))
		(cdr tests'))))))

;; Run tests either in sequence or in parallel, depending on the
;; number of tests and the command line flags.
(define (run-tests tests)
  (let ((parallel (flag "--parallel" *args*))
	(default-parallel-jobs 32))
    (if (and parallel (> (length tests) 1))
	(run-tests-parallel tests (if (and (pair? parallel)
					   (string->number (car parallel)))
				      (string->number (car parallel))
				      default-parallel-jobs))
	(run-tests-sequential tests))))

;; Load all tests from the given path.
(define (load-tests . path)
  (load (apply in-srcdir `(,@path "all-tests.scm")))
  all-tests)

;; Helper to create environment caches from test functions.  SETUP
;; must be a test implementing the producer side cache protocol.
;; Returns a promise containing the arguments that must be passed to a
;; test implementing the consumer side of the cache protocol.
(define (make-environment-cache setup)
  (delay (with-temporary-working-directory
	  (let ((tarball (make-temporary-file "environment-cache")))
	    (atexit (lambda () (remove-temporary-file tarball)))
	    (setup::run-sync '--create-tarball tarball)
	    (if (not (equal? 'PASS (setup::status)))
		(fail "Setup failed."))
	    `(--unpack-tarball ,tarball)))))

;; Command line flag handling.  Returns the elements following KEY in
;; ARGUMENTS up to the next argument, or #f if KEY is not in
;; ARGUMENTS.  If 'KEY=XYZ' is encountered, then the singleton list
;; containing 'XYZ' is returned.
(define (flag key arguments)
  (cond
   ((null? arguments)
    #f)
   ((string=? key (car arguments))
    (let loop ((acc '())
	       (args (cdr arguments)))
      (if (or (null? args) (string-prefix? (car args) "--"))
	  (reverse acc)
	  (loop (cons (car args) acc) (cdr args)))))
   ((string-prefix? (car arguments) (string-append key "="))
    (list (substring (car arguments)
		     (+ (string-length key) 1)
		     (string-length (car arguments)))))
   ((string=? "--" (car arguments))
    #f)
   (else
    (flag key (cdr arguments)))))
(assert (equal? (flag "--xxx" '("--yyy")) #f))
(assert (equal? (flag "--xxx" '("--xxx")) '()))
(assert (equal? (flag "--xxx" '("--xxx" "yyy")) '("yyy")))
(assert (equal? (flag "--xxx" '("--xxx=foo" "yyy")) '("foo")))
(assert (equal? (flag "--xxx" '("--xxx" "yyy" "zzz")) '("yyy" "zzz")))
(assert (equal? (flag "--xxx" '("--xxx" "yyy" "zzz" "--")) '("yyy" "zzz")))
(assert (equal? (flag "--xxx" '("--xxx" "yyy" "--" "zzz")) '("yyy")))
(assert (equal? (flag "--" '("--" "xxx" "yyy" "--" "zzz")) '("xxx" "yyy")))
