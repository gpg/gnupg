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
"Enter the user id of the addresse to whom you want to send the message."
},

{ N_("keygen.algo"),
"Select the algorithm to use.\n"
"DSA (aka DSS) is the digital signature algorithm which can only be used\n"
"for signatures.  This is the suggested algorithm because verification of\n"
"DSA signatures are much faster than those of ElGamal\n"
"ElGamal is a algorithm which can be used for signatures and encryption.\n"
"OpenPGP distunguishs between two flavors of this algorithms: a encrypt only\n"
"and a sign+encrypt; actually it is the same, but some parameters must be\n"
"selected in a special way to create a safe key for signatures: this program\n"
"does this but other OpenPGP implemenations are not required to understand\n"
"the signature+encryption flavor.\n"
"The first (primary) key must always be a key which is capable of signing;\n"
"this is the reason why the ecrytion only ElGamal key is disabled in this.\n"
"You should not select the \"ElGamal in a v3 packet\", because that key is\n"
"not compatible to other OpenPGP implementations."
},

{ N_("keygen.size"),
 ""
},

{ N_("keygen.size.huge.okay"),
 ""
},


{ N_("keygen.size.large.okay"),
 ""
},


{ N_("keygen.valid"),
 ""
},

{ N_("keygen.valid.okay"),
 ""
},


{ N_("keygen.name"),
 ""
},


{ N_("keygen.email"),
 ""
},

{ N_("keygen.comment"),
 ""
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
 ""
},


{ N_("change_passwd.empty.okay"),
 ""
},


{ N_("keyedit.cmd"),
 "Please enter \"help\" to see the list of commands."
},

{ N_("keyedit.save.okay"),
 ""
},


{ N_("keyedit.cancel.okay"),
 ""
},

{ N_("keyedit.sign_all.okay"),
 ""
},

{ N_("keyedit.remove.uid.okay"),
 ""
},

{ N_("keyedit.remove.subkey.okay"),
 ""
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
 ""
},

{ N_("openfile.overwrite.okay"),
 ""
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
		tty_printf(_("No help available for '%s'"), keyword );
	    else
		tty_printf("%s", helptexts[i].help );
	}
    }
    tty_printf("\n");
}


