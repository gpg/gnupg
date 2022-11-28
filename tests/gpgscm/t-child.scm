;; Tests for the low-level process and IPC primitives.
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

(echo "Testing process and IPC primitives...")

(define (qualify executable)
  (string-append executable (getenv "EXEEXT")))

(define child (qualify "t-child"))

(assert (= 0 (call `(,(qualify "t-child") "return0"))))
(assert (= 1 (call `(,(qualify "t-child") "return1"))))
(assert (= 77 (call `(,(qualify "t-child") "return77"))))

(let ((r (call-with-io `(,(qualify "t-child") "return0") "")))
  (assert (= 0 (:retcode r)))
  (assert (string=? "" (:stdout r)))
  (assert (string=? "" (:stderr r))))

(let ((r (call-with-io `(,(qualify "t-child") "return1") "")))
  (assert (= 1 (:retcode r)))
  (assert (string=? "" (:stdout r)))
  (assert (string=? "" (:stderr r))))

(let ((r (call-with-io `(,(qualify "t-child") "return77") "")))
  (assert (= 77 (:retcode r)))
  (assert (string=? "" (:stdout r)))
  (assert (string=? "" (:stderr r))))

(let ((r (call-with-io `(,(qualify "t-child") "hello_stdout") "")))
  (assert (= 0 (:retcode r)))
  (assert (string=? "hello" (:stdout r)))
  (assert (string=? "" (:stderr r))))

(let ((r (call-with-io `(,(qualify "t-child") "hello_stderr") "")))
  (assert (= 0 (:retcode r)))
  (assert (string=? "" (:stdout r)))
  (assert (string=? "hello" (:stderr r))))

(let ((r (call-with-io `(,(qualify "t-child") "stdout4096") "")))
  (assert (= 0 (:retcode r)))
  (assert (= 4096 (string-length (:stdout r))))
  (assert (string=? "" (:stderr r))))

(let ((r (call-with-io `(,(qualify "t-child") "stdout8192") "")))
  (assert (= 0 (:retcode r)))
  (assert (= 8192 (string-length (:stdout r))))
  (assert (string=? "" (:stderr r))))

(let ((r (call-with-io `(,(qualify "t-child") "cat") "hellohello")))
  (assert (= 0 (:retcode r)))
  (assert (string=? "hellohello" (:stdout r)))
  (assert (string=? "" (:stderr r))))

(define (spawn what)
  (process-spawn-fd what CLOSED_FD STDOUT_FILENO STDERR_FILENO))

(let ((proc0 (spawn `(,(qualify "t-child") "return0")))
      (proc1 (spawn `(,(qualify "t-child") "return0"))))
  (assert (= (process-wait proc0 #t) 0))
  (assert (= (process-wait proc1 #t) 0)))

(let ((proc0 (spawn `(,(qualify "t-child") "return1")))
      (proc1 (spawn `(,(qualify "t-child") "return0"))))
  (assert (= (process-wait proc0 #t) 1))
  (assert (= (process-wait proc1 #t) 0)))

(let ((proc0 (spawn `(,(qualify "t-child") "return0")))
      (proc1 (spawn `(,(qualify "t-child") "return77")))
      (proc2 (spawn `(,(qualify "t-child") "return1"))))
  (assert (= (process-wait proc0 #t) 0))
  (assert (= (process-wait proc1 #t) 77))
  (assert (= (process-wait proc2 #t) 1)))

(let* ((p (pipe))
       (proc0 (process-spawn-fd
	       `(,(qualify "t-child") "hello_stdout")
	       CLOSED_FD (:write-end p) STDERR_FILENO))
       (_ (close (:write-end p)))
       (proc1 (process-spawn-fd
	       `(,(qualify "t-child") "cat")
	       (:read-end p) STDOUT_FILENO STDERR_FILENO)))
  (close (:read-end p))
  (assert (= (process-wait proc0 #t) 0))
  (assert (= (process-wait proc1 #t) 0)))
(echo " world.")

(tr:do
 (tr:pipe-do
  (pipe:spawn `(,child stdout4096))
  (pipe:spawn `(,child cat)))
 (tr:call-with-content (lambda (c)
			 (assert (= 4096 (string-length c))))))
(tr:do
 (tr:pipe-do
  (pipe:spawn `(,child stdout8192))
  (pipe:spawn `(,child cat)))
 (tr:call-with-content (lambda (c)
			 (assert (= 8192 (string-length c))))))

(echo "All good.")
