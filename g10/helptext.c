/* helptext.c  - English help texts
 * Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
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

{ "revoked_key.override", N_(
"If you want to use this revoked key anyway, answer \"yes\"."
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
"DSA (aka DSS) is the digital signature algorithm which can only be used\n"
"for signatures.  This is the suggested algorithm because verification of\n"
"DSA signatures are much faster than those of ElGamal.\n"
"\n"
"ElGamal is an algorithm which can be used for signatures and encryption.\n"
"OpenPGP distinguishs between two flavors of this algorithms: an encrypt only\n"
"and a sign+encrypt; actually it is the same, but some parameters must be\n"
"selected in a special way to create a safe key for signatures: this program\n"
"does this but other OpenPGP implementations are not required to understand\n"
"the signature+encryption flavor.\n"
"\n"
"The first (primary) key must always be a key which is capable of signing;\n"
"this is the reason why the encryption only ElGamal key is not available in\n"
"this menu."
)},


{ "keygen.algo.elg_se", N_(
"Although these keys are defined in RFC2440 they are not suggested\n"
"because they are not supported by all programs and signatures created\n"
"with them are quite large and very slow to verify."
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
 "Answer \"yes\" is you want to sign ALL the user IDs"
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


{ "passphrase.enter", N_(
 ""
"Please enter the passhrase; this is a secret sentence \n"
"  Blurb, blurb,.... "
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


