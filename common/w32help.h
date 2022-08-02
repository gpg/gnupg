/* w32help.h - W32 speicif functions
 * Copyright (C) 2007  Free Software Foundation, Inc.
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

#ifndef GNUPG_COMMON_W32HELP_H
#define GNUPG_COMMON_W32HELP_H

/*-- w32-cmdline.c --*/

/* This module is also part of the Unix tests.  */
char **w32_parse_commandline (char *cmdline, int globing, int *r_argv,
                              int *r_itemsalloced);



#ifdef HAVE_W32_SYSTEM

/*-- w32-reg.c --*/
char *read_w32_registry_string (const char *root,
				const char *dir, const char *name );
char *read_w32_reg_string (const char *key, int *r_hklm_fallback);


#endif /*HAVE_W32_SYSTEM*/
#endif /*GNUPG_COMMON_MISCHELP_H*/
