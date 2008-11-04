/* w32help.h - W32 speicif functions
 * Copyright (C) 2007  Free Software Foundation, Inc.
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

#ifndef LIBJNLIB_W32HELP_H
#define LIBJNLIB_W32HELP_H
#ifdef HAVE_W32_SYSTEM

/*-- w32-reg.c --*/
char *read_w32_registry_string (const char *root,
				const char *dir, const char *name );
int write_w32_registry_string (const char *root, const char *dir,
                               const char *name, const char *value);

#ifdef USE_SIMPLE_GETTEXT
char *bindtextdomain (const char *domainname, const char *dirname);
const char *gettext (const char *msgid );
const char *ngettext (const char *msgid1, const char *msgid2,
                      unsigned long int n);
const char *gettext_localename (void);
void gettext_select_utf8 (int value);
#endif /*USE_SIMPLE_GETTEXT*/


#endif /*HAVE_W32_SYSTEM*/
#endif /*LIBJNLIB_MISCHELP_H*/
