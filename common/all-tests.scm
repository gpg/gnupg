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

(export all-tests
 ;; XXX: Currently, the makefile parser does not understand this
 ;; Makefile.am, so we hardcode the list of tests here.
 (map (lambda (name)
	(test::binary #f
		      (path-join "common" name)
		      (path-join (getenv "objdir") "common" name)))
      (list "t-stringhelp"
	    "t-timestuff"
	    "t-convert"
	    "t-percent"
	    "t-gettime"
	    "t-sysutils"
	    "t-sexputil"
	    "t-session-env"
	    "t-openpgp-oid"
	    "t-ssh-utils"
	    "t-mapstrings"
	    "t-zb32"
	    "t-mbox-util"
	    "t-iobuf"
	    "t-strlist"
	    "t-name-value"
	    "t-ccparray"
	    "t-recsel"
	    "t-exechelp"
	    "t-exectool"
	    )))
