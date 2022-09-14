# gpgconf.ctl.in - copied to bin during tests.
#
# This file is used to change the directories where the gpg components
# are installed.  It does not change the configuration directories.
# The file is expected in the same directory as gpgconf.  The physical
# installation directories are evaluated and no symlinks.  Blank lines
# and lines starting with pound signed are ignored.  No errors are
# printed for unknown keywords or commands.  The only defined key for
# now is "rootdir" which must be followed by one optional space, an
# equal sign, and the value for the root directory.  Environment
# variables are substituted in standard shell manner, the final value
# must start with a slash, trailing slashes are stripped.

# This file is only considered if the given envvar evaluates to true.
.enable = $GNUPG_IN_TEST_SUITE

sysconfdir = $GNUPG_BUILD_ROOT/etc
rootdir = $GNUPG_BUILD_ROOT/
