/* cardglue.c - mainly dispatcher for card related functions.
 * Copyright (C) 2003 Free Software Foundation, Inc.
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
#ifdef ENABLE_CARD_SUPPORT
/* 
   Note, that most card related code has been taken from 1.9.x branch
   and is maintained over there if at all possible.  Thus, if you make
   changes here, please check that a similar change has been commited
   to the 1.9.x branch.
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "options.h"
#include "packet.h"
#include "errors.h"
#include "memory.h"
#include "util.h"
#include "main.h"
#include "status.h"
#include "i18n.h"

#include "cardglue.h"




/* Create a serialno/fpr string from the serial number and the secret
   key.  caller must free the returned string.  There is no error
   return. [Taken from 1.9's keyid.c]*/
char *
serialno_and_fpr_from_sk (const unsigned char *sn, size_t snlen,
                          PKT_secret_key *sk)
{
  unsigned char fpr[MAX_FINGERPRINT_LEN];
  size_t fprlen;
  char *buffer, *p;
  int i;
  
  fingerprint_from_sk (sk, fpr, &fprlen);
  buffer = p = xmalloc (snlen*2 + 1 + fprlen*2 + 1);
  for (i=0; i < snlen; i++, p+=2)
    sprintf (p, "%02X", sn[i]);
  *p++ = '/';
  for (i=0; i < fprlen; i++, p+=2)
    sprintf (p, "%02X", fpr[i]);
  *p = 0;
  return buffer;
}










#endif /*ENABLE_CARD_SUPPORT*/

