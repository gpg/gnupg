Fake Pinentries for Test Suites
===============================

If you're writing a test suite, it should use one of these pinentries
by setting the following line in $GNUPGHOME/gpg-agent.conf:

    pinentry-program /path/to/fake-pinentry.ext

Note that different fake-pinentry programs have been supplied here in
different languages, with the intent of making them available to
developers who have different languages available.

They are all licensed Creative Commons Zero (CC0-1.0-Universal, see
the COPYING.CC0 file in GnuPG's top directory), so they should be
reusable by any project.  Feel free to copy them into your own
project's test suite.

Rationale
---------

If you're implementing software that uses GnuPG, you probably want a
test suite that exercises your code, and you may have some that
involve secret key material locked with a passphrase.  However, you
don't want to require your developers to manually enter a passphrase
while tests are run, and you probably also don't want to deal with
alternate codepaths/workflows like using gpg's loopback pinentry.

The solution for this is to use a fake pinentry in your test suite,
one that simply returns a pre-selected passphrase.  In this case, all
the other code follows the same path as normal, but the user
interaction is bypassed because the fake-pinentry is used instead.

Troubleshooting
---------------

If you have any trouble with this technique, please drop a line to the
GnuPG development mailing list <gnupg-devel@gnupg.org> or open a
report on the GnuPG bug tracker at https://dev.gnupg.org/gnupg
