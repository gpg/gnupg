/* ttyio.h
 * Copyright (C) 1998, 1999, 2000, 2001, 2003, 2006,
 *               2009 Free Software Foundation, Inc.
 *
 * This file is part of GNUPG.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of either
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
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */
#ifndef GNUPG_COMMON_TTYIO_H
#define GNUPG_COMMON_TTYIO_H

#include "util.h" /* Make sure our readline typedef is available. */


const char *tty_get_ttyname (void);
int tty_batchmode (int onoff);
#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 5 )
void tty_printf (const char *fmt, ... )
                 __attribute__ ((format (printf,1,2)));
void tty_fprintf (estream_t fp, const char *fmt, ... )
                 __attribute__ ((format (printf,2,3)));
char *tty_getf (const char *promptfmt, ... )
                 __attribute__ ((format (printf,1,2)));
#else
void tty_printf (const char *fmt, ... );
void tty_fprintf (estream_t fp, const char *fmt, ... );
char *tty_getf (const char *promptfmt, ... );
#endif
void tty_print_utf8_string (const unsigned char *p, size_t n);
void tty_print_utf8_string2 (estream_t fp,
                             const unsigned char *p, size_t n, size_t max_n);
char *tty_get (const char *prompt);
char *tty_get_hidden (const char *prompt);
void tty_kill_prompt (void);
int tty_get_answer_is_yes (const char *prompt);
int tty_no_terminal (int onoff);

#ifdef HAVE_LIBREADLINE
void tty_enable_completion (rl_completion_func_t *completer);
void tty_disable_completion (void);
#else
/* Use a macro to stub out these functions since a macro has no need
   to typedef a "rl_completion_func_t" which would be undefined
   without readline. */
#define tty_enable_completion(x)
#define tty_disable_completion()
#endif
int tty_read_history (const char *filename, int nlines);
int tty_write_history (const char *filename);
void tty_cleanup_after_signal (void);
void tty_cleanup_rl_after_signal (void);


#endif /*GNUPG_COMMON_TTYIO_H*/
