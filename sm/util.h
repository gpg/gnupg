/* util.h - Utility functions for GpgSM
 *	Copyright (C) 2001 Free Software Foundation, Inc.
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

#ifndef UTIL_H
#define UTIL_H

#include <gcrypt.h> /* we need this for the memory function protos */

#include "../jnlib/logging.h"
#include "../jnlib/argparse.h"
#include "../jnlib/stringhelp.h"
#include "../jnlib/mischelp.h"
#include "../jnlib/strlist.h"
#include "../jnlib/dotlock.h"

#define xtrymalloc(a)    gcry_malloc ((a))
#define xtrycalloc(a,b)  gcry_calloc ((a),(b))
#define xtryrealloc(a,b) gcry_realloc ((a),(b))
#define xtrystrdup(a)    gcry_strdup ((a))
#define xfree(a)         gcry_free ((a))

#define xmalloc(a)       gcry_xmalloc ((a))
#define xcalloc(a,b)     gcry_xcalloc ((a),(b))
#define xrealloc(a,b)    gcry_xrealloc ((a),(b))
#define xstrdup(a)       gcry_xstrdup ((a))



#endif /*UTIL_H*/
