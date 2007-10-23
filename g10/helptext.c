/* helptext.c  - English help texts
 * Copyright (C) 1998, 1999, 2000, 2001, 2002,
 *               2004 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"
#include "ttyio.h"
#include "main.h"
#include "i18n.h"


/****************
 * These helptexts are used for the "online" help feature. We use
 * a key consisting of words and dots.	Because the lookup is only
 * done in an interactive mode on a user request (when she enters a "?"
 * as response to a prompt) we can use a simple search through the list.
 *
 * Mini glossary:
 *
 * "user ID", "trustdb", "NOTE" and "WARNING".
 */

static struct helptexts { const char *key; const char *help; } helptexts[] = {

/* begin of list */

{ "edit_ownertrust.value", N_(
"It's up to you to assign a value here; this value will never be exported\n"
"to any 3rd party.  We need it to implement the web-of-trust; it has nothing\n"
"to do with the (implicitly created) web-of-certificates."
)},

{ "edit_ownertrust.set_ultimate.okay", N_(
 "To build the Web-of-Trust, GnuPG needs to know which keys are\n"
 "ultimately trusted - those are usually the keys for which you have\n"
 "access to the secret key.  Answer \"yes\" to set this key to\n"
 "ultimately trusted\n"
)},

{ "untrusted_key.override", N_(
"If you want to use this untrusted key anyway, answer \"yes\"."
)},

{ "pklist.user_id.enter", N_(
"Enter the user ID of the addressee to whom you want to send the message."
)},

{ "keygen.algo", N_(
"Select the algorithm to use.\n"
"\n"
"DSA (aka DSS) is the Digital Signature Algorithm and can only be used\n"
"for signatures.\n"
"\n"
"Elgamal is an encrypt-only algorithm.\n"
"\n"
"RSA may be used for signatures or encryption.\n"
"\n"
"The first (primary) key must always be a key which is capable of signing."
)},


{ "keygen.algo.rsa_se", N_(
"In general it is not a good idea to use the same key for signing and\n"
"encryption.  This algorithm should only be used in certain domains.\n"
"Please consult your security expert first."
)},


{ "keygen.size", N_(
 "Enter the size of the key"
)},

{ "keygen.size.huge.okay", N_(
 "Answer \"yes\" or \"no\""
)},


{ "keygen.size.large.okay", N_(
 "Answer \"yes\" or \"no\""
)},


{ "keygen.valid", N_(
 "Enter the required value as shown in the prompt.\n"
 "It is possible to enter a ISO date (YYYY-MM-DD) but you won't\n"
 "get a good error response - instead the system tries to interpret\n"
 "the given value as an interval."
)},

{ "keygen.valid.okay", N_(
 "Answer \"yes\" or \"no\""
)},


{ "keygen.name", N_(
 "Enter the name of the key holder"
)},


{ "keygen.email", N_(
 "please enter an optional but highly suggested email address"
)},

{ "keygen.comment", N_(
 "Please enter an optional comment"
)},


{ "keygen.userid.cmd", N_(
 ""
"N  to change the name.\n"
"C  to change the comment.\n"
"E  to change the email address.\n"
"O  to continue with key generation.\n"
"Q  to to quit the key generation."
)},

{ "keygen.sub.okay", N_(
 "Answer \"yes\" (or just \"y\") if it is okay to generate the sub key."
)},

{ "sign_uid.okay", N_(
 "Answer \"yes\" or \"no\""
)},

{ "sign_uid.class", N_(
"When you sign a user ID on a key, you should first verify that the key\n"
"belongs to the person named in the user ID.  It is useful for others to\n"
"know how carefully you verified this.\n\n"
"\"0\" means you make no particular claim as to how carefully you verified the\n"
"    key.\n\n"
"\"1\" means you believe the key is owned by the person who claims to own it\n"
"    but you could not, or did not verify the key at all.  This is useful for\n"
"    a \"persona\" verification, where you sign the key of a pseudonymous user.\n\n"
"\"2\" means you did casual verification of the key.  For example, this could\n"
"    mean that you verified the key fingerprint and checked the user ID on the\n"
"    key against a photo ID.\n\n"
"\"3\" means you did extensive verification of the key.  For example, this could\n"
"    mean that you verified the key fingerprint with the owner of the key in\n"
"    person, and that you checked, by means of a hard to forge document with a\n"
"    photo ID (such as a passport) that the name of the key owner matches the\n"
"    name in the user ID on the key, and finally that you verified (by exchange\n"
"    of email) that the email address on the key belongs to the key owner.\n\n"
"Note that the examples given above for levels 2 and 3 are *only* examples.\n"
"In the end, it is up to you to decide just what \"casual\" and \"extensive\"\n"
"mean to you when you sign other keys.\n\n"
"If you don't know what the right answer is, answer \"0\"."
)},

{ "change_passwd.empty.okay", N_(
 "Answer \"yes\" or \"no\""
)},


{ "keyedit.save.okay", N_(
 "Answer \"yes\" or \"no\""
)},


{ "keyedit.cancel.okay", N_(
 "Answer \"yes\" or \"no\""
)},

{ "keyedit.sign_all.okay", N_(
 "Answer \"yes\" if you want to sign ALL the user IDs"
)},

{ "keyedit.remove.uid.okay", N_(
 "Answer \"yes\" if you really want to delete this user ID.\n"
 "All certificates are then also lost!"
)},

{ "keyedit.remove.subkey.okay", N_(
 "Answer \"yes\" if it is okay to delete the subkey"
)},


{ "keyedit.delsig.valid", N_(
 "This is a valid signature on the key; you normally don't want\n"
 "to delete this signature because it may be important to establish a\n"
 "trust connection to the key or another key certified by this key."
)},
{ "keyedit.delsig.unknown", N_(
 "This signature can't be checked because you don't have the\n"
 "corresponding key.  You should postpone its deletion until you\n"
 "know which key was used because this signing key might establish\n"
 "a trust connection through another already certified key."
)},
{ "keyedit.delsig.invalid", N_(
 "The signature is not valid.  It does make sense to remove it from\n"
 "your keyring."
)},
{ "keyedit.delsig.selfsig", N_(
 "This is a signature which binds the user ID to the key. It is\n"
 "usually not a good idea to remove such a signature.  Actually\n"
 "GnuPG might not be able to use this key anymore.  So do this\n"
 "only if this self-signature is for some reason not valid and\n"
 "a second one is available."
)},

{ "keyedit.updpref.okay", N_(
 "Change the preferences of all user IDs (or just of the selected ones)\n"
 "to the current list of preferences.  The timestamp of all affected\n"
 "self-signatures will be advanced by one second.\n"
)},


{ "passphrase.enter", N_(
 ""
"Please enter the passhrase; this is a secret sentence \n"
)},


{ "passphrase.repeat", N_(
 "Please repeat the last passphrase, so you are sure what you typed in."
)},

{ "detached_signature.filename", N_(
 "Give the name of the file to which the signature applies"
)},

/* openfile.c (overwrite_filep) */
{ "openfile.overwrite.okay", N_(
 "Answer \"yes\" if it is okay to overwrite the file"
)},

/* openfile.c (ask_outfile_name) */
{ "openfile.askoutname", N_(
 "Please enter a new filename. If you just hit RETURN the default\n"
 "file (which is shown in brackets) will be used."
)},

/* revoke.c (ask_revocation_reason) */
{ "ask_revocation_reason.code", N_(
 "You should specify a reason for the certification.  Depending on the\n"
 "context you have the ability to choose from this list:\n"
 "  \"Key has been compromised\"\n"
 "      Use this if you have a reason to believe that unauthorized persons\n"
 "      got access to your secret key.\n"
 "  \"Key is superseded\"\n"
 "      Use this if you have replaced this key with a newer one.\n"
 "  \"Key is no longer used\"\n"
 "      Use this if you have retired this key.\n"
 "  \"User ID is no longer valid\"\n"
 "      Use this to state that the user ID should not longer be used;\n"
 "      this is normally used to mark an email address invalid.\n"
)},

/* revoke.c (ask_revocation_reason) */
{ "ask_revocation_reason.text", N_(
 "If you like, you can enter a text describing why you issue this\n"
 "revocation certificate.  Please keep this text concise.\n"
 "An empty line ends the text.\n"
)},

/* end of list */
{ NULL, NULL } };


void
display_online_help( const char *keyword )
{

    tty_kill_prompt();
    if( !keyword )
	tty_printf(_("No help available") );
    else {
	const char *p;
	int i;

	for(i=0; (p=helptexts[i].key) && strcmp( p, keyword ); i++ )
	    ;
	if( !p || !*helptexts[i].help )
	    tty_printf(_("No help available for `%s'"), keyword );
	else
	    tty_printf("%s", _(helptexts[i].help) );
    }
    tty_printf("\n");
}
