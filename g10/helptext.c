/* helptext.c  - English help texts
 *	Copyright (C) 1998 Free Software Foundation, Inc.
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
 * Translators should use the key as msgid, this is to keep the msgid short
 * and to allow for easy changing of the helptexts.
 *
 * Mini glossary:
 *
 * "user ID", "trustdb", "NOTE" and "WARNING".
 */

static struct helptexts { const char *key; const char *help; } helptexts[] = {

/* begin of list */

{ N_("edit_ownertrust.value"),
"It's up to you to assign a value here; this value will never be exported\n"
"to any 3rd party.  We need it to implement the web-of-trust; it has nothing\n"
"to do with the (implicitly created) web-of-certificates."
},

{ N_("revoked_key.override"),
"If you want to use this revoked key anyway, answer \"yes\"."
},

{ N_("untrusted_key.override"),
"If you want to use this untrusted key anyway, answer \"yes\"."
},

{ N_("pklist.user_id.enter"),
"Enter the user id of the addressee to whom you want to send the message."
},

{ N_("keygen.algo"),
"Select the algorithm to use.\n"
"DSA (aka DSS) is the digital signature algorithm which can only be used\n"
"for signatures.  This is the suggested algorithm because verification of\n"
"DSA signatures are much faster than those of ElGamal.\n"
"ElGamal is a algorithm which can be used for signatures and encryption.\n"
"OpenPGP distunguishs between two flavors of this algorithms: a encrypt only\n"
"and a sign+encrypt; actually it is the same, but some parameters must be\n"
"selected in a special way to create a safe key for signatures: this program\n"
"does this but other OpenPGP implemenations are not required to understand\n"
"the signature+encryption flavor.\n"
"The first (primary) key must always be a key which is capable of signing;\n"
"this is the reason why the encryption only ElGamal key is disabled in this."
},


{ N_("keygen.algo.elg_se"),
"Although these keys are defined in RFC2440 they are not suggested\n"
"because they are not supported by all programs and signatures created\n"
"with them are quite large and very slow to verify."
},


{ N_("keygen.size"),
 "Enter the size of the key"
},

{ N_("keygen.size.huge.okay"),
 "Answer \"yes\" or \"no\""
},


{ N_("keygen.size.large.okay"),
 "Answer \"yes\" or \"no\""
},


{ N_("keygen.valid"),
 "Enter the required value"
},

{ N_("keygen.valid.okay"),
 "Answer \"yes\" or \"no\""
},


{ N_("keygen.name"),
 "Enter the name of the key holder"
},


{ N_("keygen.email"),
 "please enter an optional but highly suggested email address"
},

{ N_("keygen.comment"),
 "Please enter an optional comment"
},


{ N_("keygen.userid.cmd"),
 ""
"N  to change the name.\n"
"C  to change the comment.\n"
"E  to change the email address.\n"
"O  to continue with key generation.\n"
"Q  to to quit the key generation."
},

{ N_("keygen.sub.okay"),
 "Answer \"yes\" (or just \"y\") if it is okay to generate the sub key."
},

{ N_("sign_uid.okay"),
 "Answer \"yes\" or \"no\""
},


{ N_("change_passwd.empty.okay"),
 "Answer \"yes\" or \"no\""
},


{ N_("keyedit.cmd"),
 "Please enter \"help\" to see the list of commands."
},

{ N_("keyedit.save.okay"),
 "Answer \"yes\" or \"no\""
},


{ N_("keyedit.cancel.okay"),
 "Answer \"yes\" or \"no\""
},

{ N_("keyedit.sign_all.okay"),
 "Answer \"yes\" is you want to sign ALL the user IDs"
},

{ N_("keyedit.remove.uid.okay"),
 "Answer \"yes\" if you really want to delete this user ID.\n"
 "All certificates are then also lost!"
},

{ N_("keyedit.remove.subkey.okay"),
 "Answer \"yes\" if it is okay to delete the subkey"
},


{ N_("keyedit.delsig.valid"),
 "This is a valid signature on the key; you normally don't want\n"
 "to delete this signature may be important to establish a trust\n"
 "connection to the key or another key certified by this key."
},
{ N_("keyedit.delsig.invalid"),
 "The signature is not valid.  It does make sense to remove it from\n"
 "your keyring if it is really invalid and not just unchecked due to\n"
 "a missing public key (marked by \"sig?\")."
},
{ N_("keyedit.delsig.selfsig"),
 "This is a signature which binds the user ID to the key. It is\n"
 "usually not a good idea to remove such a signature.  Actually\n"
 "GnuPG might not be able to use this key anymore.  So do this\n"
 "only if this self-signature is for some reason not valid and\n"
 "a second one is available."
},


{ N_("passphrase.enter"),
 ""
"Please enter the passhrase; this is a secret sentence \n"
"  Blurb, blurb,.... "
},


{ N_("passphrase.repeat"),
 "Please repeat the last passphrase, so you are sure what you typed in."
},

{ N_("detached_signature.filename"),
 "Give the name fo the file to which the signature applies"
},

{ N_("openfile.overwrite.okay"),
 "Answer \"yes\" if it is okay to overwrite the file"
},

/* end of list */
{ NULL, NULL } };


void
display_online_help( const char *keyword )
{

    tty_kill_prompt();
    if( !keyword )
	tty_printf(_("No help available") );
    else {
	const char *p = _(keyword);

	if( strcmp( p, keyword ) )
	    tty_printf("%s", p );
	else {
	    int i;

	    for(i=0; (p=helptexts[i].key) && strcmp( p, keyword ); i++ )
		;
	    if( !p || !*helptexts[i].help )
		tty_printf(_("No help available for `%s'"), keyword );
	    else
		tty_printf("%s", helptexts[i].help );
	}
    }
    tty_printf("\n");
}


