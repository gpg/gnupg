/* libjnlib-config.h - local configuration of the jnlib functions
 *	Copyright (C) 2000, 2001 Free Software Foundation, Inc.
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

/****************
 * This header is to be included only by the files in this directory
 * it should not be used by other modules.
 */

#ifndef LIBJNLIB_CONFIG_H
#define LIBJNLIB_CONFIG_H

#include <gcrypt.h> /* gcry_malloc & Cie. */
#include "logging.h"

#ifdef USE_SIMPLE_GETTEXT
  int set_gettext_file( const char *filename );
  const char *gettext( const char *msgid );

  #define _(a) gettext (a)
  #define N_(a) (a)

#else
#ifdef HAVE_LOCALE_H
  #include <locale.h>
#endif

#ifdef ENABLE_NLS
  #include <libintl.h>
  #define _(a) gettext (a)
  #ifdef gettext_noop
    #define N_(a) gettext_noop (a)
  #else
    #define N_(a) (a)
  #endif
#else
  #define _(a) (a)
  #define N_(a) (a)
#endif
#endif /* !USE_SIMPLE_GETTEXT */


#define jnlib_xmalloc(a)    gcry_xmalloc( (a) )
#define jnlib_xcalloc(a,b)  gcry_xcalloc( (a), (b) )
#define jnlib_xrealloc(a,n) gcry_xrealloc( (a), (n) )
#define jnlib_xstrdup(a)    gcry_xstrdup( (a) )
#define jnlib_free(a)	    gcry_free( (a) )

#define jnlib_log_debug    log_debug
#define jnlib_log_info	   log_info
#define jnlib_log_error    log_error
#define jnlib_log_fatal    log_fatal
#define jnlib_log_bug	   log_bug


#endif /*LIBJNUTIL_CONFIG_H*/
