/* util.h - Utility functions for Gnupg
 *	Copyright (C) 2001, 2002, 2003 Free Software Foundation, Inc.
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

#include <gcrypt.h> /* We need this for the memory function protos. */
#include <time.h>   /* We need time_t. */
#include <gpg-error.h> /* we need gpg-error_t. */

/* to pass hash functions to libksba we need to cast it */
#define HASH_FNC ((void (*)(void *, const void*,size_t))gcry_md_write)

/* get all the stuff from jnlib */
#include "../jnlib/logging.h"
#include "../jnlib/argparse.h"
#include "../jnlib/stringhelp.h"
#include "../jnlib/mischelp.h"
#include "../jnlib/strlist.h"
#include "../jnlib/dotlock.h"
#include "../jnlib/utf8conv.h"

/* handy malloc macros  - use only them */
#define xtrymalloc(a)    gcry_malloc ((a))
#define xtrycalloc(a,b)  gcry_calloc ((a),(b))
#define xtryrealloc(a,b) gcry_realloc ((a),(b))
#define xtrystrdup(a)    gcry_strdup ((a))
#define xfree(a)         gcry_free ((a))

#define xmalloc(a)       gcry_xmalloc ((a))
#define xmalloc_secure(a)  gcry_xmalloc_secure ((a))
#define xcalloc(a,b)     gcry_xcalloc ((a),(b))
#define xcalloc_secure(a,b) gcry_xcalloc_secure ((a),(b))
#define xrealloc(a,b)    gcry_xrealloc ((a),(b))
#define xstrdup(a)       gcry_xstrdup ((a))


/* A type to hold the ISO time.  Note that this this is the same as
   the the KSBA type ksba_isotime_t. */
typedef char gnupg_isotime_t[16];


/*-- maperror.c --*/
int map_kbx_err (int err);
gpg_error_t map_assuan_err (int err);
int map_to_assuan_status (int rc);

/*-- gettime.c --*/
time_t gnupg_get_time (void);
void   gnupg_get_isotime (gnupg_isotime_t timebuf);
void   gnupg_set_time (time_t newtime, int freeze);
int    gnupg_faked_time_p (void);
u32    make_timestamp (void);
u32    scan_isodatestr (const char *string);
u32    add_days_to_timestamp (u32 stamp, u16 days);
const char *strtimevalue (u32 stamp);
const char *strtimestamp (u32 stamp); /* GMT */
const char *asctimestamp (u32 stamp); /* localized */


/* Copy one iso ddate to another, this is inline so that we can do a
   sanity check. */
static inline void
gnupg_copy_time (gnupg_isotime_t d, const gnupg_isotime_t s)
{
  if (*s && (strlen (s) != 15 || s[8] != 'T'))
    BUG();
  strcpy (d, s);
}


/*-- signal.c --*/
void gnupg_init_signals (int mode, void (*fast_cleanup)(void));
void gnupg_pause_on_sigusr (int which);
void gnupg_block_all_signals (void);
void gnupg_unblock_all_signals (void);

/*-- yesno.c --*/
int answer_is_yes (const char *s);
int answer_is_yes_no_default (const char *s, int def_answer);
int answer_is_yes_no_quit (const char *s);


/*-- miscellaneous.c --*/
const char *print_fname_stdout (const char *s);
const char *print_fname_stdin (const char *s);
void print_string (FILE *fp, const byte *p, size_t n, int delim);
void print_utf8_string2 ( FILE *fp, const byte *p, size_t n, int delim);
void print_utf8_string (FILE *fp, const byte *p, size_t n);
char *make_printable_string (const byte *p, size_t n, int delim);

int is_file_compressed (const char *s, int *ret_rc);


/*-- replacement functions from funcname.c --*/
#if !HAVE_VASPRINTF
#include <stdarg.h>
int vasprintf (char **result, const char *format, va_list args);
int asprintf (char **result, const char *format, ...);
#endif



/*-- some macros to replace ctype ones and avoid locale problems --*/
#define spacep(p)   (*(p) == ' ' || *(p) == '\t')
#define digitp(p)   (*(p) >= '0' && *(p) <= '9')
#define hexdigitp(a) (digitp (a)                     \
                      || (*(a) >= 'A' && *(a) <= 'F')  \
                      || (*(a) >= 'a' && *(a) <= 'f'))
  /* Note this isn't identical to a C locale isspace() without \f and
     \v, but works for the purposes used here. */
#define ascii_isspace(a) ((a)==' ' || (a)=='\n' || (a)=='\r' || (a)=='\t')

/* the atoi macros assume that the buffer has only valid digits */
#define atoi_1(p)   (*(p) - '0' )
#define atoi_2(p)   ((atoi_1(p) * 10) + atoi_1((p)+1))
#define atoi_4(p)   ((atoi_2(p) * 100) + atoi_2((p)+2))
#define xtoi_1(p)   (*(p) <= '9'? (*(p)- '0'): \
                     *(p) <= 'F'? (*(p)-'A'+10):(*(p)-'a'+10))
#define xtoi_2(p)   ((xtoi_1(p) * 16) + xtoi_1((p)+1))



#endif /*GNUPG_COMMON_UTIL_H*/
