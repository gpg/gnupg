## Process this file with automake to create Makefile.in

TESTS = version.test decrypt.test clearsig.test armsigs.test \
	sigs.test armencrypt.test armencryptp.test \
	encrypt.test encryptp.test signencrypt.test \
	armsignencrypt.test armdetach.test detach.test \
	armdetachm.test detachm.test genkey1024.test


TEST_FILES = pubring.asc secring.asc gnupg.asc plain-1 plain-2 plain-3o.asc \
	     plain-1.asc plain-2.asc plain-3.asc

DATA_FILES = data-500 data-9000 data-32000 data-80000

EXTRA_DIST = $(TESTS) $(TEST_FILES)
CLEANFILES = prepared.stamp x y z out err  $(DATA_FILES)

check: prepared.stamp

prepared.stamp: pubring.gpg secring.gpg gnupg.sig plain-3 $(DATA_FILES)
	@set -x; \
	echo "def" | ../g10/gpg -v --no-operation; \
	echo timestamp >./prepared.stamp

pubring.gpg: pubring.asc
	../g10/gpgm --yes --dearmor -o pubring.gpg pubring.asc
secring.gpg: secring.asc
	../g10/gpgm --yes --dearmor -o secring.gpg secring.asc
gnupg.sig: gnupg.asc
	../g10/gpgm --yes --dearmor -o gnupg.sig gnupg.asc
plain-3: plain-3o.asc
	../g10/gpgm --yes --dearmor -o plain-3 plain-3o.asc

data-500:
	head -c 500 /dev/urandom >data-500
data-9000:
	head -c 9000 /dev/urandom >data-9000
data-32000:
	head -c 32000 /dev/urandom >data-32000
data-80000:
	head -c 80000 /dev/urandom >data-80000


