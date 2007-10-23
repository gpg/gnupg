/* ttyio.h
 * Copyright (C) 1998, 1999, 2000, 2001, 2005 Free Software Foundation, Inc.
 *
 * This file is part of GNUPG.
 *
 * GNUPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GNUPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */
#ifndef G10_TTYIO_H
#define G10_TTYIO_H

#ifdef HAVE_LIBREADLINE
#include <stdio.h>
#include <readline/readline.h>
#endif

const char *tty_get_ttyname (void);
int tty_batchmode( int onoff );
#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 5 )
 void tty_printf (const char *fmt, ... ) __attribute__ ((format (printf,1,2)));
 void tty_fprintf (FILE *fp, const char *fmt, ... )
                                __attribute__ ((format (printf,2,3)));
#else
 void tty_printf (const char *fmt, ... );
 void tty_fprintf (FILE *fp, const char *fmt, ... );
#endif
void tty_print_string( const byte *p, size_t n );
void tty_print_utf8_string( const byte *p, size_t n );
void tty_print_utf8_string2( const byte *p, size_t n, size_t max_n );
char *tty_get( const char *prompt );
char *tty_get_hidden( const char *prompt );
void tty_kill_prompt(void);
int tty_get_answer_is_yes( const char *prompt );
int tty_no_terminal(int onoff);

#ifdef HAVE_LIBREADLINE
void tty_enable_completion(rl_completion_func_t *completer);
void tty_disable_completion(void);
#else
/* Use a macro to stub out these functions since a macro has no need
   to typedef a "rl_completion_func_t" which would be undefined
   without readline. */
#define tty_enable_completion(x)
#define tty_disable_completion()
#endif

#endif /*G10_TTYIO_H*/
