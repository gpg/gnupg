/* util.h - Utility functions for Gnupg
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

#ifndef GNUPG_COMMON_UTIL_H
#define GNUPG_COMMON_UTIL_H

#include <gcrypt.h> /* we need this for the memory function protos */
#include <time.h>   /* we need time_t */

/* to pass hash functions to libksba we need to cast it */
#define HASH_FNC ((void (*)(void *, const void*,size_t))gcry_md_write)

/* get all the stuff from jnlib */
#include "../jnlib/logging.h"
#include "../jnlib/argparse.h"
#include "../jnlib/stringhelp.h"
#include "../jnlib/mischelp.h"
#include "../jnlib/strlist.h"
#include "../jnlib/dotlock.h"

/* handy malloc macros  - use only them */
#define xtrymalloc(a)    gcry_malloc ((a))
#define xtrycalloc(a,b)  gcry_calloc ((a),(b))
#define xtryrealloc(a,b) gcry_realloc ((a),(b))
#define xtrystrdup(a)    gcry_strdup ((a))
#define xfree(a)         gcry_free ((a))

#define xmalloc(a)       gcry_xmalloc ((a))
#define xcalloc(a,b)     gcry_xcalloc ((a),(b))
#define xrealloc(a,b)    gcry_xrealloc ((a),(b))
#define xstrdup(a)       gcry_xstrdup ((a))

#define seterr(a)  (GNUPG_ ## a)

/*-- maperror.c --*/
int map_ksba_err (int err);
int map_gcry_err (int err);
int map_kbx_err (int err);
int map_assuan_err (int err);
int map_to_assuan_status (int rc);

/*-- gettime.c --*/
time_t gnupg_get_time (void);
void   gnupg_set_time (time_t newtime, int freeze);
int    gnupg_faked_time_p (void);


/*-- replacement functions from funcname.c --*/
#if !HAVE_VASPRINTF
#include <stdarg.h>
int vasprintf (char **result, const char *format, va_list *args);
int asprintf (char **result, const char *format, ...);
#endif

#if !HAVE_FOPENCOOKIE
typedef struct
{
  ssize_t (*read)(void*,char*,size_t);
  ssize_t (*write)(void*,const char*,size_t);
  int (*seek)(void*,off_t*,int);
  int (*close)(coid*);
} _IO_cookie_io_functions_t;
typedef _IO_cookie_io_functions_t cookie_io_functions_t;
FILE *fopencookie (void *cookie, const char *opentype,
                   cookie_io_functions_t funclist);
#endif /*!HAVE_FOPENCOOKIE*/



/*-- some macros to replace ctype ones and avoid locale problems --*/
#define spacep(p)   (*(p) == ' ' || *(p) == '\t')
#define digitp(p)   (*(p) >= '0' && *(p) <= '9')
#define hexdigitp(a) (digitp (a)                     \
                      || (*(a) >= 'A' && *(a) <= 'F')  \
                      || (*(a) >= 'a' && *(a) <= 'f'))
/* the atoi macros assume that the buffer has only valid digits */
#define atoi_1(p)   (*(p) - '0' )
#define atoi_2(p)   ((atoi_1(p) * 10) + atoi_1((p)+1))
#define atoi_4(p)   ((atoi_2(p) * 100) + atoi_2((p)+2))
#define xtoi_1(p)   (*(p) <= '9'? (*(p)- '0'): \
                     *(p) <= 'F'? (*(p)-'A'+10):(*(p)-'a'+10))
#define xtoi_2(p)   ((xtoi_1(p) * 16) + xtoi_1((p)+1))



#endif /*GNUPG_COMMON_UTIL_H*/








