/* sqlite.h - SQLite helper functions.
 * Copyright (C) 2015 g10 Code GmbH
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

#ifndef GNUPG_SQLITE_H
#define GNUPG_SQLITE_H

#include <sqlite3.h>

enum sqlite_arg_type
  {
    SQLITE_ARG_END = 0xdead001,
    SQLITE_ARG_INT,
    SQLITE_ARG_LONG_LONG,
    SQLITE_ARG_STRING
  };


int sqlite3_exec_printf (sqlite3 *db,
                         int (*callback)(void*,int,char**,char**), void *cookie,
                         char **errmsg,
                         const char *sql, ...);

int sqlite3_stepx (sqlite3 *db,
                   sqlite3_stmt **stmtp,
                   int (*callback) (void*,int,char**,char**),
                   void *cookie,
                   char **errmsg,
                   const char *sql, ...);

#endif
