/* basicdefs.h - Some definitions used at many place
 *	Copyright (C) 1999 Free Software Foundation, Inc.
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

#ifndef G10_BASICDEFS_H
#define G10_BASICDEFS_H

#include "types.h"

typedef struct {
    int algo;
    int keylen;
    byte key[32]; /* this is the largest used keylen (256 bit) */
} DEK;


struct pk_list;
struct sk_list;
typedef struct pk_list *PK_LIST;
typedef struct sk_list *SK_LIST;



#endif /* G10_BASICDEFS_H */
