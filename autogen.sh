#! /bin/sh
# autogen.sh
# Copyright (C) 2003, 2014 g10 Code GmbH
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
# This is a generic script to create the configure script and handle cross
# build environments.  It requires the presence of a autogen.rc file to
# configure it for the respective package.  It is maintained as part of
# GnuPG and source copied by other packages.
#
# Version: 2014-01-10

configure_ac="configure.ac"

cvtver () {
  awk 'NR==1 {split($NF,A,".");X=1000000*A[1]+1000*A[2]+A[3];print X;exit 0}'
}

check_version () {
    if [ $(( `("$1" --version || echo "0") | cvtver` >= $2 )) = 1 ]; then
       return 0
    fi
    echo "**Error**: "\`$1\'" not installed or too old." >&2
    echo '           Version '$3' or newer is required.' >&2
    [ -n "$4" ] && echo '           Note that this is part of '\`$4\''.' >&2
    DIE="yes"
    return 1
}

fatal () {
    echo "autogen.sh:" "$*" >&2
    DIE=yes
}

info () {
    if [ -z "${SILENT}" ]; then
      echo "autogen.sh:" "$*"
    fi
}

die_p () {
  if [ "$DIE" = "yes" ]; then
    echo "autogen.sh: Stop." >&2
    exit 1
  fi
}

replace_sysroot () {
    configure_opts=$(echo $configure_opts | sed "s#@SYSROOT@#${w32root}#g")
    extraoptions=$(echo $extraoptions | sed "s#@SYSROOT@#${w32root}#g")
}

# Allow to override the default tool names
AUTOCONF=${AUTOCONF_PREFIX}${AUTOCONF:-autoconf}${AUTOCONF_SUFFIX}
AUTOHEADER=${AUTOCONF_PREFIX}${AUTOHEADER:-autoheader}${AUTOCONF_SUFFIX}

AUTOMAKE=${AUTOMAKE_PREFIX}${AUTOMAKE:-automake}${AUTOMAKE_SUFFIX}
ACLOCAL=${AUTOMAKE_PREFIX}${ACLOCAL:-aclocal}${AUTOMAKE_SUFFIX}

GETTEXT=${GETTEXT_PREFIX}${GETTEXT:-gettext}${GETTEXT_SUFFIX}
MSGMERGE=${GETTEXT_PREFIX}${MSGMERGE:-msgmerge}${GETTEXT_SUFFIX}

DIE=no
FORCE=
SILENT=
tmp=$(dirname "$0")
tsdir=$(cd "${tmp}"; pwd)

if [ -n "${AUTOGEN_SH_SILENT}" ]; then
  SILENT=" --silent"
fi
if test x"$1" = x"--help"; then
  echo "usage: ./autogen.sh [--silent] [--force] [--build-TYPE] [ARGS]"
  exit 0
fi
if test x"$1" = x"--silent"; then
  SILENT=" --silent"
  shift
fi
if test x"$1" = x"--force"; then
  FORCE=" --force"
  shift
fi


# Reject unsafe characters in $HOME, $tsdir and cwd.  We consider spaces
# as unsafe because it is too easy to get scripts wrong in this regard.
am_lf='
'
case `pwd` in
  *[\;\\\"\#\$\&\'\`$am_lf\ \	]*)
    fatal "unsafe working directory name" ;;
esac
case $tsdir in
  *[\;\\\"\#\$\&\'\`$am_lf\ \	]*)
    fatal "unsafe source directory: \`$tsdir'" ;;
esac
case $HOME in
  *[\;\\\"\#\$\&\'\`$am_lf\ \	]*)
    fatal "unsafe home directory: \`$HOME'" ;;
esac
die_p


# List of variables sourced from autogen.rc.  The strings '@SYSROOT@' in
# these variables are replaced by the actual system root.
configure_opts=
extraoptions=
# List of optional variables sourced from autogen.rc and ~/.gnupg-autogen.rc
w32_toolprefixes=
w32_extraoptions=
w32ce_toolprefixes=
w32ce_extraoptions=
w64_toolprefixes=
w64_extraoptions=
amd64_toolprefixes=
# End list of optional variables sourced from ~/.gnupg-autogen.rc
# What follows are variables which are sourced but default to
# environment variables or lacking them hardcoded values.
#w32root=
#w32ce_root=
#w64root=
#amd64root=

# Convenience option to use certain configure options for some hosts.
myhost=""
myhostsub=""
case "$1" in
    --build-w32)
        myhost="w32"
        shift
        ;;
    --build-w32ce)
        myhost="w32"
        myhostsub="ce"
        shift
        ;;
    --build-w64)
        myhost="w32"
        myhostsub="64"
        shift
        ;;
    --build-amd64)
        myhost="amd64"
        shift
        ;;
    --build*)
        fatal "**Error**: invalid build option $1"
        shift
        ;;
    *)
        ;;
esac
die_p


# Source our configuration
if [ -f "${tsdir}/autogen.rc" ]; then
    . "${tsdir}/autogen.rc"
fi

# Source optional site specific configuration
if [ -f "$HOME/.gnupg-autogen.rc" ]; then
    info "sourcing extra definitions from $HOME/.gnupg-autogen.rc"
    . "$HOME/.gnupg-autogen.rc"
fi

# ******************
#  W32 build script
# ******************
if [ "$myhost" = "w32" ]; then
    if [ ! -f "$tsdir/build-aux/config.guess" ]; then
        fatal "$tsdir/build-aux/config.guess not found"
        exit 1
    fi
    build=`$tsdir/build-aux/config.guess`

    case $myhostsub in
        ce)
          w32root="$w32ce_root"
          [ -z "$w32root" ] && w32root="$HOME/w32ce_root"
          toolprefixes="$w32ce_toolprefixes arm-mingw32ce"
          extraoptions="$extraoptions $w32ce_extraoptions"
          ;;
        64)
          w32root="$w64root"
          [ -z "$w32root" ] && w32root="$HOME/w64root"
          toolprefixes="$w64_toolprefixes x86_64-w64-mingw32"
          extraoptions="$extraoptions $w64_extraoptions"
          ;;
        *)
          [ -z "$w32root" ] && w32root="$HOME/w32root"
          toolprefixes="$w32_toolprefixes i686-w64-mingw32 i586-mingw32msvc"
          toolprefixes="$toolprefixes i386-mingw32msvc mingw32"
          extraoptions="$extraoptions $w32_extraoptions"
          ;;
    esac
    info "Using $w32root as standard install directory"
    replace_sysroot

    # Locate the cross compiler
    crossbindir=
    for host in $toolprefixes; do
        if ${host}-gcc --version >/dev/null 2>&1 ; then
            crossbindir=/usr/${host}/bin
            conf_CC="CC=${host}-gcc"
            break;
        fi
    done
    if [ -z "$crossbindir" ]; then
        fatal "cross compiler kit not installed"
        if [ -z "$myhostsub" ]; then
          info "Under Debian GNU/Linux, you may install it using"
          info "  apt-get install mingw32 mingw32-runtime mingw32-binutils"
        fi
        die_p
    fi

    if [ -f "$tsdir/config.log" ]; then
        if ! head $tsdir/config.log | grep "$host" >/dev/null; then
            fatal "Please run a 'make distclean' first"
            die_p
        fi
    fi

    $tsdir/configure --enable-maintainer-mode ${SILENT} \
             --prefix=${w32root}  \
             --host=${host} --build=${build} \
             ${configure_opts} ${extraoptions} "$@"
    rc=$?
    exit $rc
fi
# ***** end W32 build script *******

# ***** AMD64 cross build script *******
# Used to cross-compile for AMD64 (for testing)
if [ "$myhost" = "amd64" ]; then
    shift
    if [ ! -f $tsdir/build-aux/config.guess ]; then
        echo "$tsdir/build-aux/config.guess not found" >&2
        exit 1
    fi
    build=`$tsdir/build-aux/config.guess`

    [ -z "$amd64root" ] && amd64root="$HOME/amd64root"
    info "Using $amd64root as standard install directory"
    replace_sysroot

    toolprefixes="$amd64_toolprefixes x86_64-linux-gnu amd64-linux-gnu"

    # Locate the cross compiler
    crossbindir=
    for host in $toolprefixes ; do
        if ${host}-gcc --version >/dev/null 2>&1 ; then
            crossbindir=/usr/${host}/bin
            conf_CC="CC=${host}-gcc"
            break;
        fi
    done
    if [ -z "$crossbindir" ]; then
        echo "Cross compiler kit not installed" >&2
        echo "Stop." >&2
        exit 1
    fi

    if [ -f "$tsdir/config.log" ]; then
        if ! head $tsdir/config.log | grep "$host" >/dev/null; then
            echo "Please run a 'make distclean' first" >&2
            exit 1
        fi
    fi

    $tsdir/configure --enable-maintainer-mode ${SILENT} \
             --prefix=${amd64root}  \
             --host=${host} --build=${build} \
             ${configure_opts} ${extraoptions} "$@"
    rc=$?
    exit $rc
fi
# ***** end AMD64 cross build script *******


# Grep the required versions from configure.ac
autoconf_vers=`sed -n '/^AC_PREREQ(/ {
s/^.*(\(.*\))/\1/p
q
}' ${configure_ac}`
autoconf_vers_num=`echo "$autoconf_vers" | cvtver`

automake_vers=`sed -n '/^min_automake_version=/ {
s/^.*="\(.*\)"/\1/p
q
}' ${configure_ac}`
automake_vers_num=`echo "$automake_vers" | cvtver`

if [ -d "${tsdir}/po" ]; then
  gettext_vers=`sed -n '/^AM_GNU_GETTEXT_VERSION(/ {
s/^.*\[\(.*\)])/\1/p
q
}' ${configure_ac}`
  gettext_vers_num=`echo "$gettext_vers" | cvtver`
else
  gettext_vers="n/a"
fi

if [ -z "$autoconf_vers" -o -z "$automake_vers" -o -z "$gettext_vers" ]
then
  echo "**Error**: version information not found in "\`${configure_ac}\'"." >&2
  exit 1
fi


if check_version $AUTOCONF $autoconf_vers_num $autoconf_vers ; then
    check_version $AUTOHEADER $autoconf_vers_num $autoconf_vers autoconf
fi
if check_version $AUTOMAKE $automake_vers_num $automake_vers; then
  check_version $ACLOCAL $automake_vers_num $autoconf_vers automake
fi
if [ "$gettext_vers" != "n/a" ]; then
  if check_version $GETTEXT $gettext_vers_num $gettext_vers; then
    check_version $MSGMERGE $gettext_vers_num $gettext_vers gettext
  fi
fi

if [ "$DIE" = "yes" ]; then
    cat <<EOF

Note that you may use alternative versions of the tools by setting
the corresponding environment variables; see README.GIT for details.

EOF
    die_p
fi

# Check the git setup.
if [ -d .git ]; then
  CP="cp -a"
  [ -z "${SILENT}" ] && CP="$CP -v"
  if [ -f .git/hooks/pre-commit.sample -a ! -f .git/hooks/pre-commit ] ; then
    [ -z "${SILENT}" ] && cat <<EOF
*** Activating trailing whitespace git pre-commit hook. ***
    For more information see this thread:
      http://mail.gnome.org/archives/desktop-devel-list/2009-May/msg00084html
    To deactivate this pre-commit hook again move .git/hooks/pre-commit
    and .git/hooks/pre-commit.sample out of the way.
EOF
      $CP .git/hooks/pre-commit.sample .git/hooks/pre-commit
      chmod +x  .git/hooks/pre-commit
  fi

  if [ "$gettext_vers" != "n/a" ]; then
    tmp=$(git config --get filter.cleanpo.clean)
    if [ "$tmp" != \
          "awk '/^\"POT-Creation-Date:/&&!s{s=1;next};!/^#: /{print}'" ]
    then
      info "*** Adding GIT filter.cleanpo.clean configuration."
      git config --add filter.cleanpo.clean \
        "awk '/^\"POT-Creation-Date:/&&!s{s=1;next};!/^#: /{print}'"
    fi
  fi
  if [ -f build-aux/git-hooks/commit-msg -a ! -f .git/hooks/commit-msg ] ; then
      [ -z "${SILENT}" ] && cat <<EOF
*** Activating commit log message check hook. ***
EOF
      $CP build-aux/git-hooks/commit-msg .git/hooks/commit-msg
      chmod +x  .git/hooks/commit-msg
  fi
fi

aclocal_flags="-I m4"
if [ -n "${extra_aclocal_flags}" ]; then
  aclocal_flags="${aclocal_flags} ${extra_aclocal_flags}"
fi
if [ -n "${ACLOCAL_FLAGS}" ]; then
  aclocal_flags="${aclocal_flags} ${ACLOCAL_FLAGS}"
fi
info "Running $ACLOCAL ${aclocal_flags} ..."
$ACLOCAL ${aclocal_flags}
info "Running autoheader..."
$AUTOHEADER
info "Running automake --gnu ..."
$AUTOMAKE --gnu;
info "Running autoconf${FORCE} ..."
$AUTOCONF${FORCE}

info "You may now run:${am_lf}  ${final_info}"
