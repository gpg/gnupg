/* libjnlib-config.h - local configuration of the jnlib functions
 *	Copyright (C) 2000, 2001, 2006 Free Software Foundation, Inc.
 *
 * This file is part of JNLIB.
 *
 * JNLIB is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 3 of
 * the License, or (at your option) any later version.
 *
 * JNLIB is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/****************
 * This header is to be included only by the files in this directory
 * it should not be used by other modules.
 */

#ifndef LIBJNLIB_CONFIG_H
#define LIBJNLIB_CONFIG_H

#include <gcrypt.h> /* gcry_malloc & Cie. */
#include "logging.h"

/* We require support for utf-8 conversion. */
#define JNLIB_NEED_UTF8CONV 1



#if !defined(JNLIB_NEED_UTF8CONV) && defined(HAVE_W32_SYSTEM)
#define JNLIB_NEED_UTF8CONV 1
#endif

/* Gettext stuff */
#ifdef USE_SIMPLE_GETTEXT
# include "w32help.h"
# define _(a) gettext (a)
# define N_(a) (a)

#else
#ifdef HAVE_LOCALE_H
#  include <locale.h>
#endif

#ifdef ENABLE_NLS
# include <libintl.h>
# define _(a) gettext (a)
# ifdef gettext_noop
# define N_(a) gettext_noop (a)
# else
# define N_(a) (a)
# endif
#else
# define _(a) (a)
# define N_(a) (a)
#endif
#endif /* !USE_SIMPLE_GETTEXT */

/* Malloc functions to be used by jnlib.  */
#define jnlib_malloc(a)     gcry_malloc( (a) )
#define jnlib_calloc(a,b)   gcry_calloc( (a), (b) )
#define jnlib_realloc(a,b)  gcry_realloc( (a), (b) )
#define jnlib_strdup(a)     gcry_strdup( (a) )
#define jnlib_xmalloc(a)    gcry_xmalloc( (a) )
#define jnlib_xcalloc(a,b)  gcry_xcalloc( (a), (b) )
#define jnlib_xrealloc(a,n) gcry_xrealloc( (a), (n) )
#define jnlib_xstrdup(a)    gcry_xstrdup( (a) )
#define jnlib_free(a)	    gcry_free( (a) )

/* Logging functions to be used by jnlib.  */
#define jnlib_log_debug    log_debug
#define jnlib_log_info	   log_info
#define jnlib_log_error    log_error
#define jnlib_log_fatal    log_fatal
#define jnlib_log_bug	   log_bug


#endif /*LIBJNUTIL_CONFIG_H*/
