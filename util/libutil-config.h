/* libutil-config.h - configuration of the libutil functions
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

/****************
 * This header is to be included only by the files in this directory
 * it should not be used by other modules.
 */

#ifndef LIBUTIL_CONFIG_H
#define LIBUTIL_CONFIG_H

#define LIBUTIL_CONFIG_OF_GNUPG 1  /* currently we need this kludge */

#include <sys/types.h>

#ifndef HAVE_BYTE_TYPEDEF
  #undef byte	    /* (this matches the test used by configure) */
  typedef unsigned char byte;
  #define HAVE_BYTE_TYPEDEF
#endif

#include "types.h"
#include "memory.h"
#include "util.h"
#include "i18n.h"

#define libutil_xmalloc(a)   m_alloc( (a) )
#define libutil_realloc(a,n) m_realloc( (a), (n) )
#define libutil_strdup(a)    m_strdup( (a) )
#define libutil_free(a)      m_free( (a) )

#define libutil_log_debug    log_debug
#define libutil_log_info     log_info
#define libutil_log_error    log_error
#define libutil_log_fatal    log_fatal
#define libutil_log_bug      log_bug


#endif /*LIBUTIL_CONFIGH*/
