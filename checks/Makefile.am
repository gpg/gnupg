## Process this file with automake to create Makefile.in

TESTS = version.test mds.test \
	decrypt.test decrypt-dsa.test \
	sigs.test sigs-dsa.test \
	encrypt.test encrypt-dsa.test  \
	seat.test clearsig.test encryptp.test detach.test \
	armsigs.test armencrypt.test armencryptp.test \
	signencrypt.test signencrypt-dsa.test \
	armsignencrypt.test armdetach.test \
	armdetachm.test detachm.test genkey1024.test \
	conventional.test


TEST_FILES = pubring.asc secring.asc plain-1 plain-2 plain-3o.asc \
	     plain-1.asc plain-2.asc plain-3.asc plain-1-pgp.asc \
	     pubring.pkr.asc secring.skr.asc

DATA_FILES = data-500 data-9000 data-32000 data-80000

EXTRA_DIST = defs.inc run-gpg run-gpgm $(TESTS) $(TEST_FILES)
CLEANFILES = prepared.stamp x y z out err  $(DATA_FILES)

check: prepared.stamp

prepared.stamp: pubring.gpg secring.gpg plain-3 \
		pubring.pkr secring.skr $(DATA_FILES)
	 echo timestamp >./prepared.stamp

pubring.gpg: pubring.asc
	../g10/gpgm --yes --dearmor -o pubring.gpg pubring.asc
secring.gpg: secring.asc
	../g10/gpgm --yes --dearmor -o secring.gpg secring.asc
plain-3: plain-3o.asc
	../g10/gpgm --yes --dearmor -o plain-3 plain-3o.asc
pubring.pkr: pubring.pkr.asc
	../g10/gpgm --yes --dearmor -o pubring.pkr pubring.pkr.asc
secring.skr: secring.skr.asc
	../g10/gpgm --yes --dearmor -o secring.skr secring.skr.asc

data-500:
	../tools/mk-tdata   500 /dev/urandom >data-500
data-9000:
	../tools/mk-tdata  9000 /dev/urandom >data-9000
data-32000:
	../tools/mk-tdata 32000 /dev/urandom >data-32000
data-80000:
	../tools/mk-tdata 80000 /dev/urandom >data-80000


