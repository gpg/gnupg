(echo "Testing process and IPC primitives...")

(define (qualify executable)
  (string-append executable (getenv "EXEEXT")))

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

(let ((r (call-with-io `(,(qualify "t-child") "cat") "hellohello")))
  (assert (= 0 (:retcode r)))
  (assert (string=? "hellohello" (:stdout r)))
  (assert (string=? "" (:stderr r))))

(define (spawn what)
  (spawn-process-fd what CLOSED_FD STDOUT_FILENO STDERR_FILENO))

(let ((pid0 (spawn `(,(qualify "t-child") "return0")))
      (pid1 (spawn `(,(qualify "t-child") "return0"))))
  (assert (equal? '(0 0)
		  (wait-processes '("child0" "child1") (list pid0 pid1) #t))))

(let ((pid0 (spawn `(,(qualify "t-child") "return1")))
      (pid1 (spawn `(,(qualify "t-child") "return0"))))
  (assert (equal? '(1 0)
		  (wait-processes '("child0" "child1") (list pid0 pid1) #t))))

(let ((pid0 (spawn `(,(qualify "t-child") "return0")))
      (pid1 (spawn `(,(qualify "t-child") "return77")))
      (pid2 (spawn `(,(qualify "t-child") "return1"))))
  (assert (equal? '(0 77 1)
		  (wait-processes '("child0" "child1" "child2")
				  (list pid0 pid1 pid2) #t))))

(let* ((p (pipe))
       (pid0 (spawn-process-fd
	       `(,(qualify "t-child") "hello_stdout")
	       CLOSED_FD (:write-end p) STDERR_FILENO))
       (_ (close (:write-end p)))
       (pid1 (spawn-process-fd
	       `(,(qualify "t-child") "cat")
	       (:read-end p) STDOUT_FILENO STDERR_FILENO)))
  (close (:read-end p))
  (assert
   (equal? '(0 0)
	   (wait-processes '("child0" "child1") (list pid0 pid1) #t))))
(echo " world.")

(echo "All good.")
