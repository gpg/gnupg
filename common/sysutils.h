/* sysutils.h - System utility functions for Gnupg
 *	Copyright (C) 2002 Free Software Foundation, Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA.
 */

#ifndef GNUPG_COMMON_SYSUTILS_H
#define GNUPG_COMMON_SYSUTILS_H

void trap_unaligned (void);
int  disable_core_dumps (void);
int  enable_core_dumps (void);
const unsigned char *get_session_marker (size_t *rlen);
int check_permissions (const char *path,int extension,int checkonly);
void gnupg_sleep (unsigned int seconds);

#ifdef HAVE_W32_SYSTEM

#include "../jnlib/w32help.h"

#endif /*HAVE_W32_SYSTEM*/




#endif /*GNUPG_COMMON_SYSUTILS_H*/
