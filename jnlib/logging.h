/* logging.h
 * Copyright (C) 1999, 2000, 2001, 2004, 2006 Free Software Foundation, Inc.
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

#ifndef LIBJNLIB_LOGGING_H
#define LIBJNLIB_LOGGING_H

#include <stdio.h>
#include "mischelp.h"

/* Flag values for log_set_prefix. */
#define JNLIB_LOG_WITH_PREFIX  1
#define JNLIB_LOG_WITH_TIME    2
#define JNLIB_LOG_WITH_PID     4
#define JNLIB_LOG_RUN_DETACHED 256

int  log_get_errorcount (int clear);
void log_inc_errorcount (void);
void log_set_file( const char *name );
void log_set_fd (int fd);
void log_set_get_tid_callback (unsigned long (*cb)(void));
void log_set_prefix (const char *text, unsigned int flags);
const char *log_get_prefix (unsigned int *flags);
int log_test_fd (int fd);
int  log_get_fd(void);
FILE *log_get_stream (void);

#ifdef JNLIB_GCC_M_FUNCTION
  void bug_at( const char *file, int line, const char *func ) JNLIB_GCC_A_NR;
# define BUG() bug_at( __FILE__ , __LINE__, __FUNCTION__ )
#else
  void bug_at( const char *file, int line );
# define BUG() bug_at( __FILE__ , __LINE__ )
#endif

/* To avoid mandatory inclusion of stdarg and other stuff, do it only
   if explicitly requested to do so. */
#ifdef JNLIB_NEED_LOG_LOGV
#include <stdarg.h>
enum jnlib_log_levels {
    JNLIB_LOG_BEGIN,
    JNLIB_LOG_CONT,
    JNLIB_LOG_INFO,
    JNLIB_LOG_WARN,
    JNLIB_LOG_ERROR,
    JNLIB_LOG_FATAL,
    JNLIB_LOG_BUG,
    JNLIB_LOG_DEBUG
};
void log_logv (int level, const char *fmt, va_list arg_ptr);
#endif /*JNLIB_NEED_LOG_LOGV*/


void log_bug( const char *fmt, ... )	JNLIB_GCC_A_NR_PRINTF(1,2);
void log_fatal( const char *fmt, ... )	JNLIB_GCC_A_NR_PRINTF(1,2);
void log_error( const char *fmt, ... )	JNLIB_GCC_A_PRINTF(1,2);
void log_info( const char *fmt, ... )	JNLIB_GCC_A_PRINTF(1,2);
void log_debug( const char *fmt, ... )	JNLIB_GCC_A_PRINTF(1,2);
void log_printf( const char *fmt, ... ) JNLIB_GCC_A_PRINTF(1,2);

/* Print a hexdump of BUFFER.  With TEXT passes as NULL print just the
   raw dump, with TEXT being an empty string, print a trailing
   linefeed, otherwise print an entire debug line with TEXT followed
   by the hexdump and a final LF.  */
void log_printhex (const char *text, const void *buffer, size_t length);


#endif /*LIBJNLIB_LOGGING_H*/





