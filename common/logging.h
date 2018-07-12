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

/* We use the libgpg-error provided log functions.  but we need one
 * more function:  */
#ifdef GPGRT_HAVE_MACRO_FUNCTION
#  define BUG() bug_at ( __FILE__, __LINE__, __FUNCTION__)
static inline void bug_at (const char *file, int line, const char *func)
                           GPGRT_ATTR_NORETURN;
static inline void
bug_at (const char *file, int line, const char *func)
{
  gpgrt_log (GPGRT_LOGLVL_BUG, "there is a bug at %s:%d:%s\n",
             file, line, func);
  abort ();
}
#else
#  define BUG() bug_at ( __FILE__, __LINE__)
static inline void bug_at (const char *file, int line)
                           GPGRT_ATTR_NORETURN;
static inline void
bug_at (const char *file, int line)
{
  gpgrt_log (GPGRT_LOGLVL_BUG, "there is a bug at %s:%d\n", file, line);
  abort ();
}
#endif /*!GPGRT_HAVE_MACRO_FUNCTION*/



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
