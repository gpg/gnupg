(define (prime? n)
  (define (smallest-divisor n)
    (find-divisor n 2))
  (define (find-divisor n test)
    (cond ((> (square test) n) n)
	  ((divides? test n)   test)
	  (else (find-divisor n (+ test 1)))))
  (define (divides? a b)
    (= (remainder b a) 0))
  (define (square n)
    (* n n))
  (= n (smallest-divisor n)))

(define count 0)



(define (display-prime n)
  (display n)
  (display ", ")
  (cond ((> count 8) (display "\n") (let count 0))
	(else (define count (+ count 1)))))


(define (primes n limit)
  (if (prime? n)
      (display-prime n) )
  (if (< n limit)
      (primes (+ n 1) limit)) )

(primes 3 5000)
