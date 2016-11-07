;; Test-suite runner.
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

(if (string=? "" (getenv "srcdir"))
    (begin
      (echo "Environment variable 'srcdir' not set.  Please point it to"
	    "tests/openpgp.")
      (exit 2)))

;; Set objdir so that the tests can locate built programs.
(setenv "objdir" (getcwd) #f)

(define test-pool
  (package
   (define (new procs)
     (package
      (define (add test)
	(new (cons test procs)))
      (define (wait)
	(let ((unfinished (filter (lambda (t) (not t::retcode)) procs)))
	  (if (null? unfinished)
	      (package)
	      (let* ((commands (map (lambda (t) t::command) unfinished))
		     (pids (map (lambda (t) t::pid) unfinished))
		     (results
		      (map (lambda (pid retcode) (list pid retcode))
			   pids
			   (wait-processes (map stringify commands) pids #t))))
		(new
		 (map (lambda (t)
			(if t::retcode
			    t
			    (t::set-retcode (cadr (assoc t::pid results)))))
		      procs))))))
      (define (passed)
	(filter (lambda (p) (= 0 p::retcode)) procs))
      (define (skipped)
	(filter (lambda (p) (= 77 p::retcode)) procs))
      (define (hard-errored)
	(filter (lambda (p) (= 99 p::retcode)) procs))
      (define (failed)
	(filter (lambda (p)
		  (not (or (= 0 p::retcode) (= 77 p::retcode)
			   (= 99 p::retcode))))
		procs))
      (define (report)
	(echo (length procs) "tests run,"
	      (length (passed)) "succeeded,"
	      (length (failed)) "failed,"
	      (length (skipped)) "skipped.")
	(length (failed)))))))

(define (verbosity n)
  (if (= 0 n) '() (cons '--verbose (verbosity (- n 1)))))

(define test
  (package
   (define (scm name . args)
     (new name #f `(,*argv0* ,@(verbosity (*verbose*)) ,@args
			     ,(in-srcdir name)) #f #f))
   (define (new name directory command pid retcode)
     (package
      (define (set-directory x)
	(new name x command pid retcode))
      (define (set-retcode x)
	(new name directory command pid x))
      (define (set-pid x)
	(new name directory command x retcode))
      (define (run-sync . args)
	(with-working-directory directory
	  (let* ((p (inbound-pipe))
		 (pid (spawn-process-fd (append command args) 0
					(:write-end p) (:write-end p))))
	    (close (:write-end p))
	    (splice (:read-end p) STDERR_FILENO)
	    (close (:read-end p))
	    (let ((t' (set-retcode (wait-process name pid #t))))
	      (t'::report)
	      t'))))
      (define (run-sync-quiet . args)
	(with-working-directory directory
	  (set-retcode
	   (wait-process
	    name (spawn-process-fd (append command args)
				   CLOSED_FD CLOSED_FD CLOSED_FD) #t))))
      (define (run-async . args)
	(with-working-directory directory
	  (set-pid (spawn-process-fd (append command args)
				     CLOSED_FD CLOSED_FD CLOSED_FD))))
      (define (status)
	(let ((t (assoc retcode '((0 "PASS") (77 "SKIP") (99 "ERROR")))))
	  (if (not t) "FAIL" (cadr t))))
      (define (report)
	(echo (string-append (status retcode) ":") name))))))

(define (run-tests-parallel setup teardown . tests)
  (lettmp (gpghome-tar)
    (setup::run-sync '--create-tarball gpghome-tar)
    (let loop ((pool (test-pool::new '())) (tests' tests))
      (if (null? tests')
	  (let ((results (pool::wait)))
	    (for-each (lambda (t)
			(let ((teardown' (teardown::set-directory
					  t::directory)))
			  (teardown'::run-sync-quiet))
			(unlink-recursively t::directory)
			(t::report)) results::procs)
	    (exit (results::report)))
	  (let* ((wd (mkdtemp))
		 (test (car tests'))
		 (test' (test::set-directory wd))
		 (setup' (setup::set-directory wd)))
	    (setup'::run-sync-quiet '--unpack-tarball gpghome-tar)
	    (loop (pool::add (test'::run-async)) (cdr tests')))))))

(define (run-tests-sequential setup teardown . tests)
  (lettmp (gpghome-tar)
    (setup::run-sync '--create-tarball gpghome-tar)
    (let loop ((pool (test-pool::new '())) (tests' tests))
      (if (null? tests')
	  (let ((results (pool::wait)))
	    (for-each (lambda (t)
			(let ((teardown' (teardown::set-directory
					  t::directory)))
			  (teardown'::run-sync-quiet))
			(unlink-recursively t::directory))
		      results::procs)
	    (exit (results::report)))
	  (let* ((wd (mkdtemp))
		 (test (car tests'))
		 (test' (test::set-directory wd))
		 (setup' (setup::set-directory wd)))
	    (setup'::run-sync-quiet '--unpack-tarball gpghome-tar)
	    (loop (pool::add (test'::run-sync)) (cdr tests')))))))

(let* ((runner (if (member "--parallel" *args*)
		   run-tests-parallel
		   run-tests-sequential))
       (tests (filter (lambda (arg) (not (string-prefix? arg "--"))) *args*)))
  (apply runner (append (list (test::scm "setup.scm") (test::scm "finish.scm"))
			(map test::scm tests))))
