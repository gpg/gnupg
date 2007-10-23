/* errors.c  -	error strings
 *	Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
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
      X(GENERAL,	N_("general error"))
      X(UNKNOWN_PACKET, N_("unknown packet type"))
      X(UNKNOWN_VERSION,N_("unknown version"))
      X(PUBKEY_ALGO    ,N_("unknown pubkey algorithm"))
      X(DIGEST_ALGO    ,N_("unknown digest algorithm"))
      X(BAD_PUBKEY     ,N_("bad public key"))
      X(BAD_SECKEY     ,N_("bad secret key"))
      X(BAD_SIGN       ,N_("bad signature"))
      X(CHECKSUM   ,	N_("checksum error"))
      X(BAD_PASS     ,	N_("bad passphrase"))
      X(NO_PUBKEY      ,N_("public key not found"))
      X(CIPHER_ALGO    ,N_("unknown cipher algorithm"))
      X(KEYRING_OPEN   ,N_("can't open the keyring"))
      X(INVALID_PACKET ,N_("invalid packet"))
      X(INVALID_ARMOR  ,N_("invalid armor"))
      X(NO_USER_ID     ,N_("no such user id"))
      X(NO_SECKEY      ,N_("secret key not available"))
      X(WRONG_SECKEY   ,N_("wrong secret key used"))
      X(UNSUPPORTED    ,N_("not supported"))
      X(BAD_KEY        ,N_("bad key"))
      X(READ_FILE      ,N_("file read error"))
      X(WRITE_FILE     ,N_("file write error"))
      X(COMPR_ALGO     ,N_("unknown compress algorithm"))
      X(OPEN_FILE      ,N_("file open error"))
      X(CREATE_FILE    ,N_("file create error"))
      X(PASSPHRASE     ,N_("invalid passphrase"))
      X(NI_PUBKEY      ,N_("unimplemented pubkey algorithm"))
      X(NI_CIPHER      ,N_("unimplemented cipher algorithm"))
      X(SIG_CLASS      ,N_("unknown signature class"))
      X(TRUSTDB        ,N_("trust database error"))
      X(BAD_MPI        ,N_("bad MPI"))
      X(RESOURCE_LIMIT ,N_("resource limit"))
      X(INV_KEYRING    ,N_("invalid keyring"))
      X(BAD_CERT       ,N_("bad certificate"))
      X(INV_USER_ID    ,N_("malformed user id"))
      X(CLOSE_FILE     ,N_("file close error"))
      X(RENAME_FILE    ,N_("file rename error"))
      X(DELETE_FILE    ,N_("file delete error"))
      X(UNEXPECTED     ,N_("unexpected data"))
      X(TIME_CONFLICT  ,N_("timestamp conflict"))
      X(WR_PUBKEY_ALGO ,N_("unusable pubkey algorithm"))
      X(FILE_EXISTS    ,N_("file exists"))
      X(WEAK_KEY       ,N_("weak key"))
      X(INV_ARG        ,N_("invalid argument"))
      X(BAD_URI        ,N_("bad URI"))
      X(INVALID_URI    ,N_("unsupported URI"))
      X(NETWORK        ,N_("network error"))
      X(SELFTEST_FAILED,"selftest failed")
      X(NOT_ENCRYPTED  ,N_("not encrypted"))
      X(NOT_PROCESSED  ,N_("not processed"))
      /* the key cannot be used for a specific usage */
      X(UNU_PUBKEY     ,N_("unusable public key"))
      X(UNU_SECKEY     ,N_("unusable secret key"))
      X(KEYSERVER      ,N_("keyserver error"))
      X(CANCELED       ,N_("canceled"))
      X(NO_CARD        ,N_("no card"))
      X(NO_DATA        ,N_("no data"))
      default: p = buf; sprintf(buf, "g10err=%d", err); break;
    }
#undef X
    return _(p);
}
