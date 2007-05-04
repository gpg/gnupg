/* utf8conf.h
 *	Copyright (C) 2003, 2006 Free Software Foundation, Inc.
 *
 * This file is part of JNLIB.
 *
 * JNLIB is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * JNLIB is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#ifndef LIBJNLIB_UTF8CONF_H
#define LIBJNLIB_UTF8CONF_H

int set_native_charset (const char *newset);
const char *get_native_charset (void);
int is_native_utf8 (void);

char *native_to_utf8 (const char *string);
char *utf8_to_native (const char *string, size_t length, int delim);


#endif /*LIBJNLIB_UTF8CONF_H*/
