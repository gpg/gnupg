/* import.c
 *	Copyright (c) 1998 by Werner Koch (dd9jn)
 *
 * This file is part of G10.
 *
 * G10 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * G10 is distributed in the hope that it will be useful,
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
#include <errno.h>
#include <assert.h>

#include "options.h"
#include "packet.h"
#include "errors.h"
#include "keydb.h"
#include "memory.h"
#include "util.h"
#include "trustdb.h"


/****************
 * Import the public keys from the given filename. Input may be armored.
 * This function rejects alls keys which are not valid self signed on at
 * least one userid. Only user ids which are self signed will be imported.
 * Other signatures are not not checked.
 *
 * Actually this functtion does a merge, it works like this:
 *   FIXME: add handling for revocation certs
 *
 *  - get the keyblock
 *  - check self-signatures and remove all userids and their isgnatures
 *    without/invalid self-signatures.
 *  - reject the keyblock, if we have no valid userid.
 *  - See wether we have this key already in one of our pubrings.
 *    If not, simply add it to the default keyring.
 *  - Compare the key and the self-signatures of the new and the one in
 *    our keyring.  If they are differen something weird is going on;
 *    ask what to do.
 *  - See wether we have only non-self-signature on one user id; if not
 *    ask the user what to do.
 *  - compare the signatures: If we already have this signature, check
 *    that they compare okay, if not issue a warning and ask the user.
 *    (consider to look at the timestamp and use the newest?)
 *  - Simply add the signature.  Can't verify here because we may not have
 *    the signatures public key yet; verification is done when putting it
 *    into the trustdb, which is done automagically as soon as this pubkey
 *    is used.
 *  - Proceed with next signature.
 *
 */
int
import_pubkeys( const char *filename )
{
    log_fatal("Not yet implemented");
    return 0;
}


