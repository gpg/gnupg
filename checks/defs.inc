# definitions for the check scripts

#--------------------------------
#------ constants ---------------
#--------------------------------

# Note that usrpass1 is also used in Makefile.am
usrname1="one"
usrpass1="def"
usrname2="two"
usrpass2=""
plain_files="plain-1 plain-2 plain-3"
data_files="data-500 data-9000 data-32000 data-80000"
exp_files=""
#cleanup_files="x y z"


#--------------------------------
#------ utility functions -------
#--------------------------------

fatal () {
    echo "$pgmname: fatal:" $* >&2
    exit 1;
}

error () {
    echo "$pgmname:" $* >&2
    exit 1
}

info () {
    echo "$pgmname:" $* >&2
}

chdir () {
    cd $1 || fatal "cannot cd to $1"
}

#cleanup () {
#    rm $cleanup_files 2>/dev/null || true
#    echo "#empty" >./options
#}


#add_cleanup () {
#    cleanup_files="$cleanup_files $*"
#}

run_gpg () {
    if ! eval ../g10/gpg --homedir . $* 2>err ; then
	cat err >&2
	echo "(../g10/gpg --homedir . $*) failed" >&2
	exit 1
    fi
    grep -v 'gpg: Good signature from' err || true
}

run_gpgm () {
    if ! eval ../g10/gpgm --homedir . $* ; then
	echo "(../g10/gpgm --homedir . $*) failed" >&2
	exit 1
    fi
}



set -e
pgmname=$(basename $0)
#trap cleanup SIGHUP SIGINT SIGQUIT

[ -z $srcdir ] && fatal "not called from make"

cat <<EOF  >./options
no-greeting
no-secmem-warning
batch
EOF

