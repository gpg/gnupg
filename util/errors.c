/* errors.c  -	error strings
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
#include <stdarg.h>

#include "errors.h"
#include "i18n.h"

#ifndef HAVE_STRERROR
char *
strerror( int n )
{
    extern char *sys_errlist[];
    extern int sys_nerr;
    static char buf[15];

    if( n >= 0 && n < sys_nerr )
	return sys_errlist[n];
    strcpy( buf, "Unknown error" );
    return buf;
}
#endif /* !HAVE_STRERROR */

const char *
g10_errstr( int err )
{
    static char buf[50];
    const char *p;

  #define X(n,s) case G10ERR_##n : p = s; break;
    switch( err ) {
      case -1:		p = "eof"; break;
      case 0:		p = "okay"; break;
      X(GENERAL,	N_("General error"))
      X(UNKNOWN_PACKET, N_("Unknown packet type"))
      X(UNKNOWN_VERSION,N_("Unknown version"))
      X(PUBKEY_ALGO    ,N_("Unknown pubkey algorithm"))
      X(DIGEST_ALGO    ,N_("Unknown digest algorithm"))
      X(BAD_PUBKEY     ,N_("Bad public key"))
      X(BAD_SECKEY     ,N_("Bad secret key"))
      X(BAD_SIGN       ,N_("Bad signature"))
      X(CHECKSUM   ,	N_("Checksum error"))
      X(BAD_PASS     ,	N_("Bad passphrase"))
      X(NO_PUBKEY      ,N_("Public key not found"))
      X(CIPHER_ALGO    ,N_("Unknown cipher algorithm"))
      X(KEYRING_OPEN   ,N_("Can't open the keyring"))
      X(INVALID_PACKET ,N_("Invalid packet"))
      X(INVALID_ARMOR  ,N_("Invalid armor"))
      X(NO_USER_ID     ,N_("No such user id"))
      X(NO_SECKEY      ,N_("Secret key not available"))
      X(WRONG_SECKEY   ,N_("Wrong secret key used"))
      X(UNSUPPORTED    ,N_("Not supported"))
      X(BAD_KEY        ,N_("Bad key"))
      X(READ_FILE      ,N_("File read error"))
      X(WRITE_FILE     ,N_("File write error"))
      X(COMPR_ALGO     ,N_("Unknown compress algorithm"))
      X(OPEN_FILE      ,N_("File open error"))
      X(CREATE_FILE    ,N_("File create error"))
      X(PASSPHRASE     ,N_("Invalid passphrase"))
      X(NI_PUBKEY      ,N_("Unimplemented pubkey algorithm"))
      X(NI_CIPHER      ,N_("Unimplemented cipher algorithm"))
      X(SIG_CLASS      ,N_("Unknown signature class"))
      X(TRUSTDB        ,N_("Trust database error"))
      X(BAD_MPI        ,N_("Bad MPI"))
      X(RESOURCE_LIMIT ,N_("Resource limit"))
      X(INV_KEYRING    ,N_("Invalid keyring"))
      X(BAD_CERT       ,N_("Bad certificate"))
      X(INV_USER_ID    ,N_("Malformed user id"))
      X(CLOSE_FILE     ,N_("File close error"))
      X(RENAME_FILE    ,N_("File rename error"))
      X(DELETE_FILE    ,N_("File delete error"))
      X(UNEXPECTED     ,N_("Unexpected data"))
      X(TIME_CONFLICT  ,N_("Timestamp conflict"))
      X(WR_PUBKEY_ALGO ,N_("Unusable pubkey algorithm"))
      X(FILE_EXISTS    ,N_("File exists"))
      X(WEAK_KEY       ,N_("Weak key"))
      default: p = buf; sprintf(buf, "g10err=%d", err); break;
    }
  #undef X
    return _(p);
}

