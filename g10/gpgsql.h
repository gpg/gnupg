/* gpgsql.h - SQLite helper functions.
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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifndef GNUPG_GPGSQL_H
#define GNUPG_GPGSQL_H

#include <sqlite3.h>

enum gpgsql_arg_type
  {
    GPGSQL_ARG_END = 0xdead001,
    GPGSQL_ARG_INT,
    GPGSQL_ARG_LONG_LONG,
    GPGSQL_ARG_STRING,
    /* This takes two arguments: the blob as a void * and the length
       of the blob as a long long.  */
    GPGSQL_ARG_BLOB
  };

int gpgsql_exec_printf (sqlite3 *db,
                        int (*callback)(void*,int,char**,char**), void *cookie,
                        char **errmsg,
                        const char *sql, ...);

typedef int (*gpgsql_stepx_callback) (void *cookie,
                                      /* number of columns.  */
                                      int cols,
                                      /* columns as text.  */
                                      char **values,
                                      /* column names.  */
                                      char **names,
                                      /* The prepared statement so
                                       * that it is possible to use
                                       * something like
                                       * sqlite3_column_blob().  */
                                      sqlite3_stmt *statement);

int gpgsql_stepx (sqlite3 *db,
                  sqlite3_stmt **stmtp,
                  gpgsql_stepx_callback callback,
                  void *cookie,
                  char **errmsg,
                  const char *sql, ...);

#endif /*GNUPG_GPGSQL_H*/
