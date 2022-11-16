/* common-defs.h - Private declarations for common/
 * Copyright (C) 2006 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
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

#ifndef GNUPG_COMMON_COMMON_DEFS_H
#define GNUPG_COMMON_COMMON_DEFS_H


/* Dummy replacement for getenv.  */
#ifndef HAVE_GETENV
#define getenv(a)  (NULL)
#endif


/*-- ttyio.c --*/
void tty_private_set_rl_hooks (void (*init_stream) (FILE *),
                               void (*set_completer) (rl_completion_func_t*),
                               void (*inhibit_completion) (int),
                               void (*cleanup_after_signal) (void),
                               char *(*readline_fun) (const char*),
                               void (*add_history_fun) (const char*),
                               int (*rw_history_fun)(const char *, int, int));



#endif /*GNUPG_COMMON_COMMON_DEFS_H*/
