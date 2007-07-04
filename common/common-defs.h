/* common-defs.h - Private declarations for common/
 * Copyright (C) 2006 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef GNUPG_COMMON_COMMON_DEFS_H
#define GNUPG_COMMON_COMMON_DEFS_H

/*-- ttyio.c --*/
void tty_private_set_rl_hooks (void (*init_stream) (FILE *),
                               void (*set_completer) (rl_completion_func_t*),
                               void (*inhibit_completion) (int),
                               void (*cleanup_after_signal) (void),
                               char *(*readline_fun) (const char*),
                               void (*add_history_fun) (const char*));



#endif /*GNUPG_COMMON_COMMON_DEFS_H*/
