/* gpgsql.c - SQLite helper functions.
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

#include <config.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "gpg.h"
#include "../common/util.h"
#include "../common/logging.h"

#include "gpgsql.h"

/* This is a convenience function that combines sqlite3_mprintf and
   sqlite3_exec.  */
int
gpgsql_exec_printf (sqlite3 *db,
                    int (*callback)(void*,int,char**,char**), void *cookie,
                    char **errmsg,
                    const char *sql, ...)
{
  va_list ap;
  int rc;
  char *sql2;

  va_start (ap, sql);
  sql2 = sqlite3_vmprintf (sql, ap);
  va_end (ap);

#if 0
  log_debug ("tofo db: executing: '%s'\n", sql2);
#endif

  rc = sqlite3_exec (db, sql2, callback, cookie, errmsg);

  sqlite3_free (sql2);

  return rc;
}

int
gpgsql_stepx (sqlite3 *db,
              sqlite3_stmt **stmtp,
              gpgsql_stepx_callback callback,
              void *cookie,
              char **errmsg,
              const char *sql, ...)
{
  int rc;
  int err = 0;
  sqlite3_stmt *stmt = NULL;

  va_list va;
  int args;
  enum gpgsql_arg_type t;
  int i;

  int cols;
  /* Names of the columns.  We initialize this lazily to avoid the
     overhead in case the query doesn't return any results.  */
  const char **azColName = 0;
  int callback_initialized = 0;

  const char **azVals = 0;

  callback_initialized = 0;

  if (stmtp && *stmtp)
    {
      stmt = *stmtp;

      /* Make sure this statement is associated with the supplied db.  */
      log_assert (db == sqlite3_db_handle (stmt));

#if DEBUG_TOFU_CACHE
      prepares_saved ++;
#endif
    }
  else
    {
      const char *tail = NULL;

      rc = sqlite3_prepare_v2 (db, sql, -1, &stmt, &tail);
      if (rc)
        log_fatal ("failed to prepare SQL: %s", sql);

      /* We can only process a single statement.  */
      if (tail)
        {
          while (*tail == ' ' || *tail == ';' || *tail == '\n')
            tail ++;

          if (*tail)
            log_fatal
              ("sqlite3_stepx can only process a single SQL statement."
               "  Second statement starts with: '%s'\n",
               tail);
        }

      if (stmtp)
        *stmtp = stmt;
    }

#if DEBUG_TOFU_CACHE
  queries ++;
#endif

  args = sqlite3_bind_parameter_count (stmt);
  va_start (va, sql);
  if (args)
    {
      for (i = 1; i <= args; i ++)
        {
          t = va_arg (va, enum gpgsql_arg_type);
          switch (t)
            {
            case GPGSQL_ARG_INT:
              {
                int value = va_arg (va, int);
                err = sqlite3_bind_int (stmt, i, value);
                break;
              }
            case GPGSQL_ARG_LONG_LONG:
              {
                long long value = va_arg (va, long long);
                err = sqlite3_bind_int64 (stmt, i, value);
                break;
              }
            case GPGSQL_ARG_STRING:
              {
                char *text = va_arg (va, char *);
                err = sqlite3_bind_text (stmt, i, text, -1, SQLITE_STATIC);
                break;
              }
            case GPGSQL_ARG_BLOB:
              {
                char *blob = va_arg (va, void *);
                long long length = va_arg (va, long long);
                err = sqlite3_bind_blob (stmt, i, blob, length, SQLITE_STATIC);
                break;
              }
            default:
              /* Internal error.  Likely corruption.  */
              log_fatal ("Bad value for parameter type %d.\n", t);
            }

          if (err)
            {
              log_fatal ("Error binding parameter %d\n", i);
              goto out;
            }
        }

    }
  t = va_arg (va, enum gpgsql_arg_type);
  log_assert (t == GPGSQL_ARG_END);
  va_end (va);

  for (;;)
    {
      rc = sqlite3_step (stmt);

      if (rc != SQLITE_ROW)
        /* No more data (SQLITE_DONE) or an error occurred.  */
        break;

      if (! callback)
        continue;

      if (! callback_initialized)
        {
          cols = sqlite3_column_count (stmt);
          azColName = xmalloc (2 * cols * sizeof (const char *) + 1);

          for (i = 0; i < cols; i ++)
            azColName[i] = sqlite3_column_name (stmt, i);

          callback_initialized = 1;
        }

      azVals = &azColName[cols];
      for (i = 0; i < cols; i ++)
        {
          azVals[i] = sqlite3_column_text (stmt, i);
          if (! azVals[i] && sqlite3_column_type (stmt, i) != SQLITE_NULL)
            /* Out of memory.  */
            {
              err = SQLITE_NOMEM;
              break;
            }
        }

      if (callback (cookie, cols, (char **) azVals, (char **) azColName, stmt))
        /* A non-zero result means to abort.  */
        {
          err = SQLITE_ABORT;
          break;
        }
    }

 out:
  xfree (azColName);

  if (stmtp)
    rc = sqlite3_reset (stmt);
  else
    rc = sqlite3_finalize (stmt);
  if (rc == SQLITE_OK && err)
    /* Local error.  */
    {
      rc = err;
      if (errmsg)
        {
          const char *e = sqlite3_errstr (err);
          size_t l = strlen (e) + 1;
          *errmsg = sqlite3_malloc (l);
          if (! *errmsg)
            log_fatal ("Out of memory.\n");
          memcpy (*errmsg, e, l);
        }
    }
  else if (rc != SQLITE_OK && errmsg)
    /* Error reported by sqlite.  */
    {
      const char * e = sqlite3_errmsg (db);
      size_t l = strlen (e) + 1;
      *errmsg = sqlite3_malloc (l);
      if (! *errmsg)
        log_fatal ("Out of memory.\n");
      memcpy (*errmsg, e, l);
    }

  return rc;
}
