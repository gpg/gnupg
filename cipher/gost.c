/* gost.c  -  GOST encryption
 *	Copyright (C) 1998 Free Software Foundation, Inc.
 *
 * The description of GOST (and the used S-boxes) are taken from:
 *   Bruce Schneier: Applied Cryptography. John Wiley & Sons, 1996.
 *   ISBN 0-471-11709-9. .
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
#include "types.h"
#include "gost.h"

#error don't use this


void
gost_setkey( GOST_context *c, byte *key )
{
}

void
gost_setiv( GOST_context *c, byte *iv )
{
}


void
gost_encode( GOST_context *c, byte *outbuf, byte *inbuf, unsigned nblocks )
{
}


void
gost_decode( GOST_context *c, byte *outbuf, byte *inbuf, unsigned nblocks )
{
}


static void
cfbshift( byte *iv, byte *buf, unsigned count)
{
}



void
gost_encode_cfb( GOST_context *c, byte *outbuf, byte *inbuf, unsigned nbytes)
{
}


void
gost_decode_cfb( GOST_context *c, byte *outbuf, byte *inbuf, unsigned nbytes)
{
}

