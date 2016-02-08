#! /bin/bash

set -e
# set -x

if ! test -e mailing-list
then
    echo "Are you sure you are in the right directory?"
    exit 1
fi

set +e
TEMP=$(getopt \
         --longoptions verbose \
         -o v \
         -n "${0##*/}" -- "$@")
EC=$?
set -e
if test $EC != 0
then
  echo "Try \`$0 --help' for more information."
  exit 1
fi
eval set -- "$TEMP"

VERBOSE=0
while true
do
  case "$1" in
    --verbose|-v) VERBOSE=1; shift;;
    --) shift; break;;
    *) echo 'Internal error!'; exit 1;;
  esac
done

banner() {
    echo
    echo "***************"
    echo -e "$@"
    echo "***************"
}

GPG() {
    # valgrind gpg2 "$@"
    if test x"$VERBOSE" = x1
    then
        gpg2 --no-permission-warning "$@"
    else
        gpg2 --no-permission-warning "$@" 2>/dev/null
    fi
}

GPGU() {
    GNUPGHOME=`pwd`/user GPG "$@"
}

SETPASSWD() {
    keyids=$(gpg2 --no-permission-warning -K --with-keygrip --with-colons 2>/dev/null \
                    | gawk -F: '/^grp/ { print $10; }')
    if test x$KEYID != x
    then
        for keygrip in $keyids
        do
            /usr/lib/gnupg2/gpg-preset-passphrase \
                     --preset -P a "$keygrip"
        done
    fi
}

TEST()
{
    TEXT="$1"
    shift
    banner "$TEXT\n  Running: gpg2 $@"

    if GPG "$@"
    then
        :
    else
        EC=$?
        echo "FAIL! (exit code: $EC)"
        exit $EC
    fi
}

XTEST()
{
    TEXT="$1"
    shift
    banner "$TEXT\n  Running: gpg2 $@"

    if GPG "$@"
    then
        echo "UNEXPECTEDLY PASSED!"
        exit 1
    fi
}

# Be sure to clean up.
cleanup() {
  rm -f "mailing-list/subs-expected.$KEYID" "mailing-list/subs-have.$KEYID"
}
trap cleanup EXIT

CHECKLIST() {
    for x in $@
    do
        echo $x
    done | sort > "mailing-list/subs-expected.$KEYID"

    if ! cmp "mailing-list/subs-have.$KEYID" \
         "mailing-list/subs-expected.$KEYID"
    then
        echo "Current subscriber list does not match expected subscriber list!"
        diff -u "mailing-list/subs-expected.$KEYID" \
             "mailing-list/subs-have.$KEYID"
        exit 1
    fi
}

CHECKSUBS() {
    GPG --mailing-list-subs $KEYID | grep -v subscribers \
        | sort > "mailing-list/subs-have.$KEYID"

    CHECKLIST "$@"
}

export GNUPGHOME=`pwd`/mailing-list
unset KEYID

# Kill any running agent.
gpgconf --kill gpg-agent

# Rebuild the directory.
rm -rf mailing-list
mkdir mailing-list

cat >$GNUPGHOME/gpg-agent.conf <<EOF
pinentry-program /home/us/neal/work/gpg/build/pinentry/gtk+-2/pinentry-gtk-2
allow-preset-passphrase
min-passphrase-len 1
min-passphrase-nonalpha 0
EOF

cat >$GNUPGHOME/gpg.conf <<EOF
EOF

rm -rf user
cp -r mailing-list user

banner "Generating a user key (use a password of 'a')."
GPGU --batch --quick-gen-key 'Some User <some@user.org>'

UKEYID=$(GPGU -K --with-colons | gawk -F: '/^sec/ { print $5 }')
if test "x$UKEYID" = x
then
    echo "Failed to figure out the keyid of the user's primary key."
    exit 1
fi
# We need the short keyid.
UEKEYID=$(GPGU -K --with-colons | gawk -F: '/^ssb/ { print $5 }' \
                 | sed 's/^.\{8\}//')
if test "x$UKEYID" = x
then
    echo "Failed to figure out the keyid of the user's encryption key."
    exit 1
fi


# CFEFE77F (encryption subkey: 2B6E7103)
# A9316686 (95A0BEEA)
# E29FC3CC (117E1AFB)
# 5C1A4468 (94244910)
# F462B6B1 (AA45C71F)
TEST "Importing some public keys." --batch --import keys.gpg
GPGU --batch --export $UKEYID | GPG --batch --import

banner "Set the password to 'a'"
TEST "Creating mailing list." \
    --batch --quick-gen-mailing-list-key "gnupg-devel <gnupg-devel@gnupg.org>"

KEYID=$(GPG -K --with-colons | gawk -F: '/^sec/ { print $5 }')
if test "x$KEYID" = x
then
    echo "Failed to figure out the keyid of the ML's primary key."
    exit 1
fi
SETPASSWD

TEST "Adding a subscriber." --mailing-list-add-sub $KEYID CFEFE77F
CHECKSUBS 2B6E7103

XTEST "Adding the same subscriber." --mailing-list-add-sub $KEYID CFEFE77F

TEST "Adding two subscribers." --mailing-list-add-sub $KEYID A9316686 E29FC3CC
CHECKSUBS 117E1AFB 2B6E7103 95A0BEEA

TEST "Removing a subscriber." --mailing-list-rm-sub $KEYID 117E1AFB
# We need to wait a second, otherwise the key may not yet be
# recognized as expired.
sleep 1
CHECKSUBS 2B6E7103 95A0BEEA

TEST "Adding a subscriber." --mailing-list-add-sub $KEYID 5C1A4468
GPG --mailing-list-subs $KEYID | grep -v subscribers | sort > subs
CHECKSUBS 2B6E7103 94244910 95A0BEEA

TEST "Removing a subscriber." --mailing-list-rm-sub $KEYID 2B6E7103
sleep 1
CHECKSUBS 94244910 95A0BEEA

TEST "Adding a subscriber." --mailing-list-add-sub $KEYID F462B6B1
CHECKSUBS AA45C71F 94244910 95A0BEEA

TEST "Adding a subscriber." --mailing-list-add-sub $KEYID $UKEYID
CHECKSUBS AA45C71F 94244910 95A0BEEA $UEKEYID

GPG --batch --export $KEYID | GPGU --batch --import

GNUPGHOME=`pwd`/user SETPASSWD

banner "Using subscriber's key to list subscribers"
GPGU --try-secret-key $UKEYID --mailing-list-subs $KEYID \
    | grep -v subscribers | sort > mailing-list/subs-have.$KEYID
CHECKLIST AA45C71F 94244910 95A0BEEA $UEKEYID

banner "Using subscriber's key to send a message"
# Note: --list-packets uses long keyids.
echo | GPGU --trust-model=always --try-secret-key $UKEYID -r $KEYID -e \
    | GPGU --list-packets \
    | gawk '/pubkey enc packet/ { print $9 }' \
    | sed 's/^.\{8\}//' \
    | sort > mailing-list/subs-have.$KEYID
CHECKLIST AA45C71F 94244910 95A0BEEA $UEKEYID

echo "All tests passed!"

exit 0
