/* ttyio.h
 *	Copyright (C) 1998, 1999 Free Software Foundation, Inc.
 *
 * This file is part of GNUPG.
 *
 * GNUPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */
#ifndef G10_TTYIO_H
#define G10_TTYIO_H

int tty_batchmode( int onoff );
void tty_printf( const char *fmt, ... );
void tty_print_string( byte *p, size_t n );
void tty_print_utf8_string( byte *p, size_t n );
void tty_print_utf8_string2( byte *p, size_t n, size_t max_n );
char *tty_get( const char *prompt );
char *tty_get_hidden( const char *prompt );
void tty_kill_prompt(void);
int tty_get_answer_is_yes( const char *prompt );
int tty_no_terminal(int onoff);


#endif /*G10_TTYIO_H*/
