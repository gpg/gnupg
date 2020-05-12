/* logging.h
 * Copyright (C) 1999, 2000, 2001, 2004, 2006,
 *               2010 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute and/or modify this
 * part of GnuPG under the terms of either
 *
 *   - the GNU Lesser General Public License as published by the Free
 *     Software Foundation; either version 3 of the License, or (at
 *     your option) any later version.
 *
 * or
 *
 *   - the GNU General Public License as published by the Free
 *     Software Foundation; either version 2 of the License, or (at
 *     your option) any later version.
 *
 * or both in parallel, as here.
 *
 * GnuPG is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copies of the GNU General Public License
 * and the GNU Lesser General Public License along with this program;
 * if not, see <https://www.gnu.org/licenses/>.
 */

#ifndef GNUPG_COMMON_LOGGING_H
#define GNUPG_COMMON_LOGGING_H

#include <stdio.h>
#include <stdarg.h>
#include <gpg-error.h>
#include "mischelp.h"
#include "w32help.h"

int  log_get_errorcount (int clear);
void log_inc_errorcount (void);
void log_set_file( const char *name );
void log_set_fd (int fd);
void log_set_socket_dir_cb (const char *(*fnc)(void));
void log_set_pid_suffix_cb (int (*cb)(unsigned long *r_value));
void log_set_prefix (const char *text, unsigned int flags);
const char *log_get_prefix (unsigned int *flags);
int log_test_fd (int fd);
int  log_get_fd(void);
estream_t log_get_stream (void);

#ifdef GPGRT_HAVE_MACRO_FUNCTION
  void bug_at (const char *file, int line, const char *func)
               GPGRT_ATTR_NORETURN;
  void _log_assert (const char *expr, const char *file, int line,
                    const char *func) GPGRT_ATTR_NORETURN;
# define BUG() bug_at( __FILE__ , __LINE__, __FUNCTION__)
# define log_assert(expr)                                       \
  ((expr)                                                       \
   ? (void) 0                                                   \
   : _log_assert (#expr, __FILE__, __LINE__, __FUNCTION__))
#else /*!GPGRT_HAVE_MACRO_FUNCTION*/
  void bug_at (const char *file, int line);
  void _log_assert (const char *expr, const char *file, int line);
# define BUG() bug_at( __FILE__ , __LINE__ )
# define log_assert(expr)                                       \
  ((expr)                                                       \
   ? (void) 0                                                   \
   : _log_assert (#expr, __FILE__, __LINE__))
#endif /*!GPGRT_HAVE_MACRO_FUNCTION*/

/* Flag values for log_set_prefix. */
#define GPGRT_LOG_WITH_PREFIX  1
#define GPGRT_LOG_WITH_TIME    2
#define GPGRT_LOG_WITH_PID     4
#define GPGRT_LOG_RUN_DETACHED 256
#define GPGRT_LOG_NO_REGISTRY  512

/* Log levels as used by log_log.  */
enum jnlib_log_levels {
    GPGRT_LOG_BEGIN,
    GPGRT_LOG_CONT,
    GPGRT_LOG_INFO,
    GPGRT_LOG_WARN,
    GPGRT_LOG_ERROR,
    GPGRT_LOG_FATAL,
    GPGRT_LOG_BUG,
    GPGRT_LOG_DEBUG
};
void log_log (int level, const char *fmt, ...) GPGRT_ATTR_PRINTF(2,3);
void log_logv (int level, const char *fmt, va_list arg_ptr);
void log_logv_with_prefix (int level, const char *prefix,
                           const char *fmt, va_list arg_ptr);
void log_string (int level, const char *string);
void log_bug (const char *fmt, ...)    GPGRT_ATTR_NR_PRINTF(1,2);
void log_fatal (const char *fmt, ...)  GPGRT_ATTR_NR_PRINTF(1,2);
void log_error (const char *fmt, ...)  GPGRT_ATTR_PRINTF(1,2);
void log_info (const char *fmt, ...)   GPGRT_ATTR_PRINTF(1,2);
void log_debug (const char *fmt, ...)  GPGRT_ATTR_PRINTF(1,2);
void log_debug_with_string (const char *string, const char *fmt,
                            ...) GPGRT_ATTR_PRINTF(2,3);
void log_printf (const char *fmt, ...) GPGRT_ATTR_PRINTF(1,2);
void log_flush (void);

/* Print a hexdump of BUFFER.  With FMT passed as NULL print just the
 * raw dump, with FMT being an empty string, print a trailing
 * linefeed, otherwise print an entire debug line with expanded FMT
 * followed by the hexdump and a final LF.  */
void log_printhex (const void *buffer, size_t length,
                   const char *fmt, ...) GPGRT_ATTR_PRINTF(3,4);

void log_clock (const char *string);


/* Some handy assertion macros which don't abort.  */

#define return_if_fail(expr) do {                        \
    if (!(expr)) {                                       \
        log_debug ("%s:%d: assertion '%s' failed\n",     \
                   __FILE__, __LINE__, #expr );          \
        return;	                                         \
    } } while (0)
#define return_null_if_fail(expr) do {                   \
    if (!(expr)) {                                       \
        log_debug ("%s:%d: assertion '%s' failed\n",     \
                   __FILE__, __LINE__, #expr );          \
        return NULL;	                                 \
    } } while (0)
#define return_val_if_fail(expr,val) do {                \
    if (!(expr)) {                                       \
        log_debug ("%s:%d: assertion '%s' failed\n",     \
                   __FILE__, __LINE__, #expr );          \
        return (val);	                                 \
    } } while (0)
#define never_reached() do {                             \
    log_debug ("%s:%d: oops - should never get here\n",  \
               __FILE__, __LINE__ );                     \
    } while (0)


#endif /*GNUPG_COMMON_LOGGING_H*/
