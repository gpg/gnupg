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
	      (let* ((names (map (lambda (t) t::name) unfinished))
		     (pids (map (lambda (t) t::pid) unfinished))
		     (results
		      (map (lambda (pid retcode) (list pid retcode))
			   pids
			   (wait-processes (map stringify names) pids #t))))
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

(define (locate-test path)
  (if (absolute-path? path) path (in-srcdir path)))

(define test
  (package
   (define (scm path . args)
     ;; Start the process.
     (define (spawn-scm args in out err)
       (spawn-process-fd `(,*argv0* ,@(verbosity (*verbose*))
				    ,(locate-test path) ,@args) in out err))
     (new (basename path) #f spawn-scm #f #f CLOSED_FD))

   (define (binary path . args)
     ;; Start the process.
     (define (spawn-binary args in out err)
       (spawn-process-fd `(path ,@args) in out err))
     (new (basename path) #f spawn-binary #f #f CLOSED_FD))

   (define (new name directory spawn pid retcode logfd)
     (package
      (define (set-directory x)
	(new name x spawn pid retcode logfd))
      (define (set-retcode x)
	(new name directory spawn pid x logfd))
      (define (set-pid x)
	(new name directory spawn x retcode logfd))
      (define (set-logfd x)
	(new name directory spawn pid retcode x))
      (define (open-log-file)
	(let ((filename (string-append (basename name) ".log")))
	  (catch '() (unlink filename))
	  (open filename (logior O_RDWR O_BINARY O_CREAT) #o600)))
      (define (run-sync . args)
	(letfd ((log (open-log-file)))
	  (with-working-directory directory
	    (let* ((p (inbound-pipe))
		   (pid (spawn args 0 (:write-end p) (:write-end p))))
	      (close (:write-end p))
	      (splice (:read-end p) STDERR_FILENO log)
	      (close (:read-end p))
	      (let ((t' (set-retcode (wait-process name pid #t))))
		(t'::report)
		t')))))
      (define (run-sync-quiet . args)
	(with-working-directory directory
	  (set-retcode
	   (wait-process
	    name (spawn args CLOSED_FD CLOSED_FD CLOSED_FD) #t))))
      (define (run-async . args)
	(let ((log (open-log-file)))
	  (with-working-directory directory
	    (new name directory spawn
		 (spawn args CLOSED_FD log log)
		 retcode log))))
      (define (status)
	(let ((t (assoc retcode '((0 "PASS") (77 "SKIP") (99 "ERROR")))))
	  (if (not t) "FAIL" (cadr t))))
      (define (report)
	(unless (= logfd CLOSED_FD)
		(seek logfd 0 SEEK_SET)
		(splice logfd STDERR_FILENO)
		(close logfd))
	(echo (string-append (status retcode) ":") name))))))

(define (run-tests-parallel setup tests)
  (lettmp (gpghome-tar)
    (setup::run-sync '--create-tarball gpghome-tar)
    (let loop ((pool (test-pool::new '())) (tests' tests))
      (if (null? tests')
	  (let ((results (pool::wait)))
	    (for-each (lambda (t)
			(catch (echo "Removing" t::directory "failed:" *error*)
			       (unlink-recursively t::directory))
			(t::report)) (reverse results::procs))
	    (exit (results::report)))
	  (let* ((wd (mkdtemp))
		 (test (car tests'))
		 (test' (test::set-directory wd)))
	    (loop (pool::add (test'::run-async '--unpack-tarball gpghome-tar))
		  (cdr tests')))))))

(define (run-tests-sequential setup tests)
  (lettmp (gpghome-tar)
    (setup::run-sync '--create-tarball gpghome-tar)
    (let loop ((pool (test-pool::new '())) (tests' tests))
      (if (null? tests')
	  (let ((results (pool::wait)))
	    (for-each (lambda (t)
			(catch (echo "Removing" t::directory "failed:" *error*)
			       (unlink-recursively t::directory)))
		      results::procs)
	    (exit (results::report)))
	  (let* ((wd (mkdtemp))
		 (test (car tests'))
		 (test' (test::set-directory wd)))
	    (loop (pool::add (test'::run-sync '--unpack-tarball gpghome-tar))
		  (cdr tests')))))))

(let* ((runner (if (member "--parallel" *args*)
		   run-tests-parallel
		   run-tests-sequential))
       (tests (filter (lambda (arg) (not (string-prefix? arg "--"))) *args*)))
  (runner (test::scm "setup.scm") (map test::scm tests)))
