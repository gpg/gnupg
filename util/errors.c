/* errors.c  -	error strings
 *	Copyright (c) 1997 by Werner Koch (dd9jn)
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
#include <stdarg.h>

#include "errors.h"

const char *
g10_errstr( int err )
{
    static char buf[50];
    const char *p;

  #define X(n,s) case G10ERR_##n : p = s; break;
    switch( err ) {
      X(GENERAL,	"General error")
      X(UNKNOWN_PACKET, "Unknown packet type")
      X(UNKNOWN_VERSION,"Unknown version")
      X(PUBKEY_ALGO    ,"Unknown pubkey algorithm")
      X(DIGEST_ALGO    ,"Unknown digest algorithm")
      X(BAD_PUBKEY     ,"Bad public key")
      X(BAD_SECKEY     ,"Bad secret key")
      X(BAD_SIGN       ,"Bad signature")
      X(CHECKSUM   ,	"Checksum error")
      X(BAD_PASS     ,	"Bad passphrase")
      X(NO_PUBKEY      ,"Public key not found")
      X(CIPHER_ALGO    ,"Unknown cipher algorithm")
      X(KEYRING_OPEN   ,"Can't open the keyring")
      X(BAD_RING       ,"Broken keyring")
      X(NO_USER_ID     ,"No such user id found")
      X(NO_SECKEY      ,"Secret key not available")
      X(WRONG_SECKEY   ,"Wrong secret key used")
      X(UNSUPPORTED    ,"Not supported")
      X(BAD_KEY        ,"Bad key")
      X(READ_FILE      ,"File read error")
      X(WRITE_FILE     ,"File write error")
      X(COMPR_ALGO     ,"Unknown compress algorithm")
      X(OPEN_FILE      ,"File open error")
      X(CREATE_FILE    ,"File create error")
      X(PASSPHRASE     ,"Invalid passphrase")
      X(NI_PUBKEY      ,"Unimplemented pubkey algorithm")
      X(NI_CIPHER      ,"Unimplemented cipher algorithm")

      default: p = buf; sprintf(buf, "Error code %d", err); break;
    }
  #undef X
    return p;
}

