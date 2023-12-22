/* backend-sqlite.c - SQLite based backend for keyboxd
 * Copyright (C) 2019, 2020 g10 Code GmbH
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
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <sqlite3.h>
#include <npth.h>

#include "keyboxd.h"
#include "../common/i18n.h"
#include "../common/mbox-util.h"
#include "backend.h"
#include "keybox-search-desc.h"
#include "keybox-defs.h"  /* (for the openpgp parser) */



/* Our definition of the backend handle.  */
struct backend_handle_s
{
  enum database_types db_type; /* Always DB_TYPE_SQLITE.  */
  unsigned int backend_id;     /* Always the id of the backend.  */

  char filename[1];
};


/* Definition of local request data.  */
struct be_sqlite_local_s
{
  /* The statement object of the current select command.  */
  sqlite3_stmt *select_stmt;

  /* The column numbers for UIDNO and SUBKEY or 0.  */
  int select_col_uidno;
  int select_col_subkey;

  /* The search mode represented by the current select command.  */
  KeydbSearchMode select_mode;

  /* The flags active when the select was first done.  */
  unsigned int filter_opgp : 1;
  unsigned int filter_x509 : 1;

  /* Flag indicating that LASTUBID has a value.  */
  unsigned int lastubid_valid : 1;

  /* The current description index.  */
  unsigned int descidx;

  /* The select statement has been executed with success.  */
  int select_done;

  /* The last row has already been reached.  */
  int select_eof;

  /* The last UBID found by a select; only valid if LASTUBID_VALID is
   * set.  This is required to return only one blob in case a search
   * is done over the user id and the same user id occurs several
   * times in a blob.  */
  unsigned char lastubid[UBID_LEN];
};


/* The Mutex we use to protect all our SQLite calls.  */
static npth_mutex_t database_mutex = NPTH_MUTEX_INITIALIZER;
/* The one and only database handle. */
static sqlite3 *database_hd;
/* A lockfile used make sure only we are accessing the database.  */
static dotlock_t database_lock;

/* The version of our current database schema.  */
#define DATABASE_VERSION 1

/* Table definitions for the database.  */
static struct
{
  const char *sql;
  int special;
} table_definitions[] =
  {
   { "PRAGMA foreign_keys = ON" },

   /* Table to store config values:
    * Standard name value pairs:
    *   dbversion = 1
    *   created = <ISO time string>
    */
   { "CREATE TABLE IF NOT EXISTS config ("
     "name  TEXT NOT NULL UNIQUE,"
     "value TEXT NOT NULL "
     ")", 1 },

   /* The actual data; either X.509 certificates or OpenPGP
    * keyblocks.  */
   { "CREATE TABLE IF NOT EXISTS pubkey ("
     /* The 20 octet truncated primary-fpr */
     "ubid     BLOB NOT NULL PRIMARY KEY,"
     /* The type of the public key: 1 = openpgp, 2 = X.509.  */
     "type  INTEGER NOT NULL,"
     /* The Ephemeral flag as used by gpgsm. Values: 0 or 1. */
     "ephemeral INTEGER NOT NULL DEFAULT 0,"
     /* The Revoked flag as set by gpgsm. Values: 0 or 1. */
     "revoked INTEGER NOT NULL DEFAULT 0,"
     /* The OpenPGP keyblock or X.509 certificate.  */
     "keyblob BLOB NOT NULL"
     ")"  },

   /* Table with fingerprints and keyids of OpenPGP and X.509 keys.
    * It is also used for the primary key and the X.509 fingerprint
    * because we want to be able to use the keyid and keygrip.  */
   { "CREATE TABLE IF NOT EXISTS fingerprint ("
     /* The fingerprint, for OpenPGP either 20 octets or 32 octets;
      * for X.509 it is the same as the UBID.  */
     "fpr  BLOB NOT NULL PRIMARY KEY,"
     /* The long keyid as a 64 bit blob.  */
     "kid  BLOB NOT NULL,"
     /* The keygrip for this key.  */
     "keygrip BLOB NOT NULL,"
     /* 0 = primary or X.509, > 0 = subkey.  Also used as
      * order number for the keys similar to uidno.  */
     "subkey INTEGER NOT NULL,"
     /* The Unique Blob ID (possibly truncated fingerprint).  */
     "ubid BLOB NOT NULL REFERENCES pubkey"
     ")"  },

   /* Indices for the fingerprint table.  */
   { "CREATE INDEX IF NOT EXISTS fingerprintidx0 on fingerprint (ubid)"    },
   { "CREATE INDEX IF NOT EXISTS fingerprintidx1 on fingerprint (fpr)"     },
   { "CREATE INDEX IF NOT EXISTS fingerprintidx2 on fingerprint (keygrip)" },

   /* Table to allow fast access via user ids or mail addresses.  */
   { "CREATE TABLE IF NOT EXISTS userid ("
     /* The full user id - for X.509 the Subject or altSubject.  */
     "uid  TEXT NOT NULL,"
     /* The mail address if available or NULL.  */
     "addrspec TEXT,"
     /* The type of the public key: 1 = openpgp, 2 = X.509.  */
     "type  INTEGER NOT NULL,"
     /* The order number of the user id within the keyblock or
      * certificates.  For X.509 0 is reserved for the issuer, 1 the
      * subject, 2 and up the altSubjects.  For OpenPGP this starts
      * with 1 for the first user id in the keyblock.  */
     "uidno INTEGER NOT NULL,"
     /* The Unique Blob ID (possibly truncated fingerprint).  */
     "ubid BLOB NOT NULL REFERENCES pubkey"
     ")"  },

   /* Indices for the userid table.  */
   { "CREATE INDEX IF NOT EXISTS userididx0 on userid (ubid)"     },
   { "CREATE INDEX IF NOT EXISTS userididx1 on userid (uid)"      },
   { "CREATE INDEX IF NOT EXISTS userididx3 on userid (addrspec)" },

   /* Table to allow fast access via s/n + issuer DN  (X.509 only).  */
   { "CREATE TABLE IF NOT EXISTS issuer ("
     /* The hex encoded S/N.  */
     "sn TEXT NOT NULL,"
     /* The RFC2253 issuer DN.  */
     "dn TEXT NOT NULL,"
     /* The Unique Blob ID (usually the truncated fingerprint).  */
     "ubid BLOB NOT NULL REFERENCES pubkey"
     ")"  },
   { "CREATE INDEX IF NOT EXISTS issueridx1 on issuer (dn)" }

  };


/*-- prototypes --*/
static gpg_error_t get_config_value (const char *name, char **r_value);
static gpg_error_t set_config_value (const char *name, const char *value);



/* Take a lock for accessing SQLite.  */
static void
acquire_mutex (void)
{
  int res = npth_mutex_lock (&database_mutex);
  if (res)
    log_fatal ("failed to acquire database lock: %s\n",
               gpg_strerror (gpg_error_from_errno (res)));
}



/* Release a lock.  */
static void
release_mutex (void)
{
  int res = npth_mutex_unlock (&database_mutex);
  if (res)
    log_fatal ("failed to release database db lock: %s\n",
               gpg_strerror (gpg_error_from_errno (res)));
}


static void
show_sqlstr (const char *sqlstr)
{
  if (!opt.verbose)
    return;

  log_info ("(SQL: %s)\n", sqlstr);
}


static void
show_sqlstmt (sqlite3_stmt *stmt)
{
  char *p;

  if (!opt.verbose)
    return;

  p = sqlite3_expanded_sql (stmt);
  if (p)
    log_info ("(SQL: %s)\n", p);
  sqlite3_free (p);
}


static gpg_error_t
diag_prepare_err (int res, const char *sqlstr)
{
  gpg_error_t err;

  err = gpg_error (gpg_err_code_from_sqlite (res));
  show_sqlstr (sqlstr);
  log_error ("error preparing SQL statement: %s\n", sqlite3_errstr (res));
  return err;
}

static gpg_error_t
diag_bind_err (int res, sqlite3_stmt *stmt)
{
  gpg_error_t err;

  err = gpg_error (gpg_err_code_from_sqlite (res));
  show_sqlstmt (stmt);
  log_error ("error binding a value to an SQL statement: %s\n",
             sqlite3_errstr (res));
  return err;
}


static gpg_error_t
diag_step_err (int res, sqlite3_stmt *stmt)
{
  gpg_error_t err;

  err = gpg_error (gpg_err_code_from_sqlite (res));
  show_sqlstmt (stmt);
  log_error ("error executing SQL statement: %s\n", sqlite3_errstr (res));
  return err;
}


/* We store the keyid in the database as an 8 byte blob.  This
 * function converts it from the usual u32[2] array.  BUFFER is a
 * caller provided buffer of at least 8 bytes; a pointer to that
 * buffer is the return value.  */
static GPGRT_INLINE unsigned char *
kid_from_u32 (u32 *keyid, unsigned char *buffer)
{
  buffer[0] = keyid[0] >> 24;
  buffer[1] = keyid[0] >> 16;
  buffer[2] = keyid[0] >> 8;
  buffer[3] = keyid[0];
  buffer[4] = keyid[1] >> 24;
  buffer[5] = keyid[1] >> 16;
  buffer[6] = keyid[1] >> 8;
  buffer[7] = keyid[1];

  return buffer;
}


/* Run an SQL reset on STMT.  */
static gpg_error_t
run_sql_reset (sqlite3_stmt *stmt)
{
  gpg_error_t err;
  int res;

  res = sqlite3_reset (stmt);
  if (res)
    {
      err = gpg_error (gpg_err_code_from_sqlite (res));
      show_sqlstmt (stmt);
      log_error ("error executing SQL reset: %s\n", sqlite3_errstr (res));
    }
  else
    err = 0;
  return err;
}


/* Run an SQL prepare for SQLSTR and return a statement at R_STMT.  If
 * EXTRA or EXTRA2 are not NULL these parts are appended to the SQL
 * statement.  */
static gpg_error_t
run_sql_prepare (const char *sqlstr, const char *extra, const char *extra2,
                 sqlite3_stmt **r_stmt)
{
  gpg_error_t err;
  int res;
  char *buffer = NULL;

  if (extra || extra2)
    {
      buffer = strconcat (sqlstr, extra?extra:"", extra2, NULL);
      if (!buffer)
        return gpg_error_from_syserror ();
      sqlstr = buffer;
    }

  res = sqlite3_prepare_v2 (database_hd, sqlstr, -1, r_stmt, NULL);
  if (res)
    err = diag_prepare_err (res, sqlstr);
  else
    err = 0;
  xfree (buffer);
  return err;
}


/* Helper to bind a BLOB parameter to a statement.  */
static gpg_error_t
run_sql_bind_blob (sqlite3_stmt *stmt, int no,
                   const void *blob, size_t bloblen)
{
  gpg_error_t err;
  int res;

  res = sqlite3_bind_blob (stmt, no, blob, bloblen, SQLITE_TRANSIENT);
  if (res)
    err = diag_bind_err (res, stmt);
  else
    err = 0;
  return err;
}


/* Helper to bind an INTEGER parameter to a statement.  */
static gpg_error_t
run_sql_bind_int (sqlite3_stmt *stmt, int no, int value)
{
  gpg_error_t err;
  int res;

  res = sqlite3_bind_int (stmt, no, value);
  if (res)
    err = diag_bind_err (res, stmt);
  else
    err = 0;
  return err;
}


/* Helper to bind a string parameter to a statement.  VALUE is allowed
 * to be NULL to bind NULL.  */
static gpg_error_t
run_sql_bind_ntext (sqlite3_stmt *stmt, int no,
                    const char *value, size_t valuelen)
{
  gpg_error_t err;
  int res;

  res = sqlite3_bind_text (stmt, no, value, value? valuelen:0,
                           SQLITE_TRANSIENT);
  if (res)
    err = diag_bind_err (res, stmt);
  else
    err = 0;
  return err;
}


/* Helper to bind a string parameter to a statement.  VALUE is allowed
 * to be NULL to bind NULL.  */
static gpg_error_t
run_sql_bind_text (sqlite3_stmt *stmt, int no, const char *value)
{
  return run_sql_bind_ntext (stmt, no, value, value? strlen (value):0);
}


/* Helper to bind a string parameter to a statement.  VALUE is allowed
 * to be NULL to bind NULL.  A non-NULL VALUE is clamped with percent
 * signs.  */
static gpg_error_t
run_sql_bind_text_like (sqlite3_stmt *stmt, int no, const char *value)
{
  gpg_error_t err;
  int res;
  char *buf;

  if (!value)
    {
      res = sqlite3_bind_null (stmt, no);
      buf = NULL;
    }
  else
    {
      buf = xtrymalloc (strlen (value) + 2 + 1);
      if (!buf)
        return gpg_error_from_syserror ();
      *buf = '%';
      strcpy (buf+1, value);
      strcat (buf+1, "%");
      res = sqlite3_bind_text (stmt, no, buf, strlen (buf), SQLITE_TRANSIENT);
    }
  if (res)
    err = diag_bind_err (res, stmt);
  else
    err = 0;
  xfree (buf);
  return err;
}


/* Wrapper around sqlite3_step for use with simple functions.  */
static gpg_error_t
run_sql_step (sqlite3_stmt *stmt)
{
  gpg_error_t err;
  int res;

  show_sqlstmt (stmt);
  res = sqlite3_step (stmt);
  if (res != SQLITE_DONE)
    err = diag_step_err (res, stmt);
  else
    err = 0;
  return err;
}


/* Wrapper around sqlite3_step for use with select.  This version does
 * not print diags for SQLITE_DONE or SQLITE_ROW but returns them as
 * gpg error codes.  */
static gpg_error_t
run_sql_step_for_select (sqlite3_stmt *stmt)
{
  gpg_error_t err;
  int res;

  res = sqlite3_step (stmt);
  if (res == SQLITE_DONE || res == SQLITE_ROW)
    err = gpg_error (gpg_err_code_from_sqlite (res));
  else
    {
      /* SQL_OK is unexpected for a select so in this case we return
       * the OK error code by bypassing the special mapping.  */
      if (!res)
        err = gpg_error (GPG_ERR_SQL_OK);
      else
        err = gpg_error (gpg_err_code_from_sqlite (res));
      show_sqlstmt (stmt);
      log_error ("error running SQL step: %s\n", sqlite3_errstr (res));
    }
  return err;
}


/* Run the simple SQL statement in SQLSTR.  If UBID is not NULL this
 * will be bound to ?1 in SQLSTR.  This command may not be used for
 * select or other command which return rows.  */
static gpg_error_t
run_sql_statement_bind_ubid (const char *sqlstr, const unsigned char *ubid)
{
  gpg_error_t err;
  sqlite3_stmt *stmt;

  err = run_sql_prepare (sqlstr, NULL, NULL, &stmt);
  if (err)
    goto leave;
  if (ubid)
    {
      err = run_sql_bind_blob (stmt, 1, ubid, UBID_LEN);
      if (err)
        goto leave;
    }

  err = run_sql_step (stmt);
  sqlite3_finalize (stmt);
  if (err)
    goto leave;

 leave:
  return err;
}


/* Run the simple SQL statement in SQLSTR.  This command may not be used
 * for select or other command which return rows.  */
static gpg_error_t
run_sql_statement (const char *sqlstr)
{
  return run_sql_statement_bind_ubid (sqlstr, NULL);
}


static int
dblock_info_cb (dotlock_t h, void *opaque, enum dotlock_reasons reason,
                const char *format, ...)
{
  ctrl_t ctrl = opaque;
  va_list arg_ptr;
  gpg_error_t err;
  int rc = 0;
  char tmpbuf[200];

  (void)h;

  if (reason == DOTLOCK_WAITING)
    {
      if (format)
        {
          va_start (arg_ptr, format);
          gpgrt_vsnprintf (tmpbuf, sizeof tmpbuf, format, arg_ptr);
          va_end (arg_ptr);
        }
      else
        *tmpbuf = 0;
      err = kbxd_status_printf (ctrl, "NOTE", "database_open %u %s",
                                gpg_error (GPG_ERR_LOCKED), tmpbuf);
      if (err)
        {
          log_error ("sending status line failed: %s\n", gpg_strerror (err));
          rc = 1;  /* snprintf failed.  */
        }

    }
  return rc;
}

/* Create and initialize a new SQL database file if it does not
 * exists; else open it and check that all required objects are
 * available.  */
static gpg_error_t
create_or_open_database (ctrl_t ctrl, const char *filename)
{
  gpg_error_t err;
  int res;
  int idx;
  char *value;
  int dbversion;
  int setdbversion = 0;

  if (database_hd)
    return 0;  /* Already initialized.  */

  acquire_mutex ();

  /* To avoid races with other temporary instances of keyboxd trying
   * to create or update the database, we run the database with a lock
   * file held. */
  database_lock = dotlock_create (filename, DOTLOCK_PREPARE_CREATE);
  if (!database_lock)
    {
      err = gpg_error_from_syserror ();
      if (opt.verbose)
        log_info ("can't allocate dotlock handle: %s\n", gpg_strerror (err));
      goto leave;
    }
  dotlock_set_info_cb (database_lock, dblock_info_cb, ctrl);
  database_lock = dotlock_finish_create (database_lock, filename);
  if (!database_lock)
    {
      err = gpg_error_from_syserror ();
      /* A reason for this to fail is that the directory is not
       * writable. However, this whole locking stuff does not make
       * sense if this is the case. An empty non-writable directory
       * with no database is not really useful at all. */
      if (opt.verbose)
        log_info ("can't allocate lock for '%s': %s\n",
                  filename, gpg_strerror (err));
      goto leave;
    }

  if (dotlock_take (database_lock, 10000))
    {
      err = gpg_error_from_syserror ();
      /* This is something bad.  Probably a stale lockfile.  */
      log_info ("can't lock '%s': %s\n", filename, gpg_strerror (err));
      goto leave;
    }

  /* Database has not yet been opened.  Open or create it, make sure
   * the tables exist, and prepare the required statements.  We use
   * our own locking instead of the more complex serialization sqlite
   * would have to do and it avoid that we call
   * npth_unprotect/protect.  */
  res = sqlite3_open_v2 (filename,
                         &database_hd,
                         (SQLITE_OPEN_READWRITE
                          | SQLITE_OPEN_CREATE
                          | SQLITE_OPEN_NOMUTEX),
                         NULL);
  if (res)
    {
      err = gpg_error (gpg_err_code_from_sqlite (res));
      log_error ("error opening '%s': %s\n", filename, sqlite3_errstr (res));
      goto leave;
    }
  /* Enable extended error codes.  */
  sqlite3_extended_result_codes (database_hd, 1);

  /* Create the tables if needed.  */
  for (idx=0; idx < DIM(table_definitions); idx++)
    {
      err = run_sql_statement (table_definitions[idx].sql);
      if (err)
        goto leave;
      if (table_definitions[idx].special == 1)
        {
          /* Check and create dbversion etc entries.  */
          err = get_config_value ("dbversion", &value);
          if (gpg_err_code (err) == GPG_ERR_NOT_FOUND)
            {
              dbversion = 0;
              setdbversion = 1;
            }
          else if (err)
            {
              log_error ("error reading database version: %s\n",
                         gpg_strerror (err));
              err = 0;
              dbversion = 0;
            }
          else if ((dbversion = atoi (value)) < 1)
            {
              log_error ("database version %d is not valid\n", dbversion);
              dbversion = 0;
            }
          log_info ("database version: %d\n", dbversion);

          xfree (value);
          err = get_config_value ("created", &value);
          if (gpg_err_code (err) == GPG_ERR_NOT_FOUND)
            log_info ("database created: %.50s\n", "[unknown]");
          else if (err)
            log_error ("error getting database creation date: %s\n",
                       gpg_strerror (err));
          else
            log_info ("database created: %.50s\n", value);

          xfree (value);
          value = NULL;
        }
    }

  if (!opt.quiet)
    log_info (_("database '%s' created\n"), filename);

  if (setdbversion)
    {
      err = set_config_value ("dbversion", STR2(DATABASE_VERSION));
      if (!err)
        err = set_config_value ("created", isotimestamp (gnupg_get_time ()));
    }


  err = 0;

 leave:
  if (err)
    {
      log_error (_("error creating database '%s': %s\n"),
                 filename, gpg_strerror (err));
      if (dotlock_is_locked (database_lock))
        dotlock_release (database_lock);
      dotlock_destroy (database_lock);
      database_lock = NULL;
    }
  release_mutex ();
  return err;
}


/* Install a new resource and return a handle for that backend.  */
gpg_error_t
be_sqlite_add_resource (ctrl_t ctrl, backend_handle_t *r_hd,
                        const char *filename, int readonly)
{
  backend_handle_t hd;

  (void)ctrl;
  (void)readonly;  /* FIXME: implement read-only mode.  */

  *r_hd = NULL;
  hd = xtrycalloc (1, sizeof *hd + strlen (filename));
  if (!hd)
    return gpg_error_from_syserror ();
  hd->db_type = DB_TYPE_SQLITE;
  strcpy (hd->filename, filename);
  hd->backend_id = be_new_backend_id ();

  *r_hd = hd;
  return 0;
}


/* Release the backend handle HD and all its resources.  HD is not
 * valid after a call to this function.  */
void
be_sqlite_release_resource (ctrl_t ctrl, backend_handle_t hd)
{
  (void)ctrl;

  if (!hd)
    return;
  hd->db_type = DB_TYPE_NONE;

  xfree (hd);
}


/* Helper for be_find_request_part to initialize a sqlite request part.  */
gpg_error_t
be_sqlite_init_local (backend_handle_t backend_hd, db_request_part_t part)
{
  (void)backend_hd;

  part->besqlite = xtrycalloc (1, sizeof *part->besqlite);
  if (!part->besqlite)
    return gpg_error_from_syserror ();
  return 0;
}


/* Release local data of a sqlite request part.  */
void
be_sqlite_release_local (be_sqlite_local_t ctx)
{
  if (ctx->select_stmt)
    sqlite3_finalize (ctx->select_stmt);
  xfree (ctx);
}


gpg_error_t
be_sqlite_rollback (void)
{
  opt.in_transaction = 0;
  if (!opt.active_transaction)
    return 0;  /* Nothing to do.  */

  if (!database_hd)
    {
      log_error ("Warning: No database handle for global rollback\n");
      return gpg_error (GPG_ERR_INTERNAL);
    }

  opt.active_transaction = 0;
  return run_sql_statement ("rollback");
}


gpg_error_t
be_sqlite_commit (void)
{
  opt.in_transaction = 0;
  if (!opt.active_transaction)
    return 0;  /* Nothing to do.  */

  if (!database_hd)
    {
      log_error ("Warning: No database handle for global commit\n");
      return gpg_error (GPG_ERR_INTERNAL);
    }

  opt.active_transaction = 0;
  return run_sql_statement ("commit");
}


/* Return a value from the config table.  NAME most not have quotes
 * etc.  If no error is returned the caller must xfree the value
 * stored at R_VALUE.  On error NULL is stored there.  */
static gpg_error_t
get_config_value (const char *name, char **r_value)
{
  gpg_error_t err;
  sqlite3_stmt *stmt;
  char *sqlstr;
  const char *s;

  *r_value = NULL;

  sqlstr = strconcat ("SELECT value FROM config WHERE name='", name, "'", NULL);
  if (!sqlstr)
    return gpg_error_from_syserror ();

  err = run_sql_prepare (sqlstr, NULL, NULL, &stmt);
  xfree (sqlstr);
  if (err)
    return err;

  err = run_sql_step_for_select (stmt);
  if (gpg_err_code (err) == GPG_ERR_SQL_ROW)
    {
      s = sqlite3_column_text (stmt, 0);
      *r_value = xtrystrdup (s? s : "");
      if (!*r_value)
        err = gpg_error_from_syserror ();
      else
        err = 0;
    }
  else if (gpg_err_code (err) == GPG_ERR_SQL_DONE)
    err = gpg_error (GPG_ERR_NOT_FOUND);
  else
    log_assert (err);  /* We'll never see 0 here.  */

  sqlite3_finalize (stmt);

  return err;
}


/* Insert or update a value in the config table.  */
static gpg_error_t
set_config_value (const char *name, const char *value)
{
  gpg_error_t err;
  sqlite3_stmt *stmt;

  err = run_sql_prepare ("INSERT OR REPLACE INTO config(name,value)"
                         " VALUES(?1,?2)", NULL, NULL, &stmt);
  if (err)
    return err;

  err = run_sql_bind_text (stmt, 1, name);
  if (!err)
    err = run_sql_bind_text (stmt, 2, value);
  if (!err)
    err = run_sql_step (stmt);

  sqlite3_finalize (stmt);

  return err;
}


/* Run a select for the search given by (DESC,NDESC).  The data is not
 * returned but stored in the request item.  */
static gpg_error_t
run_select_statement (ctrl_t ctrl, be_sqlite_local_t ctx,
                      KEYDB_SEARCH_DESC *desc, unsigned int ndesc)
{
  gpg_error_t err = 0;
  unsigned int descidx;
  const char *extra = NULL;
  unsigned char kidbuf[8];
  const char *s;
  size_t n;


  descidx = ctx->descidx;
  if (descidx >= ndesc)
    {
      err = gpg_error (GPG_ERR_EOF);
      goto leave;
    }

  /* Check whether we can re-use the current select statement.  */
  if (!ctx->select_stmt)
    ;
  else if (ctx->select_mode != desc[descidx].mode)
    {
      sqlite3_finalize (ctx->select_stmt);
      ctx->select_stmt = NULL;
    }
  else if (ctx->filter_opgp != ctrl->filter_opgp
           || ctx->filter_x509 != ctrl->filter_x509)
    {
      /* The filter flags changed, thus we can't reuse the statement.  */
      sqlite3_finalize (ctx->select_stmt);
      ctx->select_stmt = NULL;
    }

  ctx->select_mode = desc[descidx].mode;
  ctx->filter_opgp = ctrl->filter_opgp;
  ctx->filter_x509 = ctrl->filter_x509;

  /* Prepare the select and bind the parameters.  */
  if (ctx->select_stmt)
    {
      err = run_sql_reset (ctx->select_stmt);
      if (err)
        goto leave;
    }
  else
    {
      if (ctx->filter_opgp && ctx->filter_x509)
        extra = " AND ( p.type = 1 OR p.type = 2 )";
      else if (ctx->filter_opgp && !ctx->filter_x509)
        extra = " AND p.type = 1";
      else if (!ctx->filter_opgp && ctx->filter_x509)
        extra = " AND p.type = 2";

      err = 0;
    }


  ctx->select_col_uidno = ctx->select_col_subkey = 0;
  switch (desc[descidx].mode)
    {
    case KEYDB_SEARCH_MODE_NONE:
      never_reached ();
      err = gpg_error (GPG_ERR_INTERNAL);
      break;

    case KEYDB_SEARCH_MODE_EXACT:
      ctx->select_col_uidno = 5;
      if (!ctx->select_stmt)
        err = run_sql_prepare ("SELECT p.ubid, p.type, p.ephemeral, p.revoked,"
                               " p.keyblob, u.uidno"
                               " FROM pubkey as p, userid as u"
                               " WHERE p.ubid = u.ubid AND u.uid = ?1",
                               extra, " ORDER BY p.ubid", &ctx->select_stmt);
      if (!err)
        err = run_sql_bind_text (ctx->select_stmt, 1, desc[descidx].u.name);
      break;
    case KEYDB_SEARCH_MODE_MAIL:
      ctx->select_col_uidno = 5;
      if (!ctx->select_stmt)
        err = run_sql_prepare ("SELECT p.ubid, p.type, p.ephemeral, p.revoked,"
                               " p.keyblob, u.uidno"
                               " FROM pubkey as p, userid as u"
                               " WHERE p.ubid = u.ubid AND u.addrspec = ?1",
                               extra, " ORDER BY p.ubid", &ctx->select_stmt);
      if (!err)
        {
          s = desc[descidx].u.name;
          if (s && *s == '<' && s[1])
            { /* It is common that the indicator for exact addrspec
               * search has not been removed.  We do this here.  */
              s++;
              n = strlen (s);
              if (n > 1 && s[n-1] == '>')
                n--;
            }
          else
            n = s? strlen (s):0;
          err = run_sql_bind_ntext (ctx->select_stmt, 1, s, n);
        }
      break;

    case KEYDB_SEARCH_MODE_MAILSUB:
      ctx->select_col_uidno = 5;
      if (!ctx->select_stmt)
        err = run_sql_prepare ("SELECT p.ubid, p.type, p.ephemeral, p.revoked,"
                               " p.keyblob, u.uidno"
                               " FROM pubkey as p, userid as u"
                               " WHERE p.ubid = u.ubid AND u.addrspec LIKE ?1",
                               extra, " ORDER BY p.ubid", &ctx->select_stmt);
      if (!err)
        err = run_sql_bind_text_like (ctx->select_stmt, 1,
                                      desc[descidx].u.name);
      break;

    case KEYDB_SEARCH_MODE_SUBSTR:
      ctx->select_col_uidno = 5;
      if (!ctx->select_stmt)
        err = run_sql_prepare ("SELECT p.ubid, p.type, p.ephemeral, p.revoked,"
                               " p.keyblob, u.uidno"
                               " FROM pubkey as p, userid as u"
                               " WHERE p.ubid = u.ubid AND u.uid LIKE ?1",
                               extra, " ORDER BY p.ubid", &ctx->select_stmt);
      if (!err)
        err = run_sql_bind_text_like (ctx->select_stmt, 1,
                                      desc[descidx].u.name);
      break;

    case KEYDB_SEARCH_MODE_MAILEND:
    case KEYDB_SEARCH_MODE_WORDS:
      err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
      break;

    case KEYDB_SEARCH_MODE_ISSUER:
      if (!ctx->select_stmt)
        err = run_sql_prepare ("SELECT p.ubid, p.type, p.ephemeral, p.revoked,"
                               " p.keyblob"
                               " FROM pubkey as p, issuer as i"
                               " WHERE p.ubid = i.ubid"
                               " AND i.dn = $1",
                               extra, " ORDER BY p.ubid", &ctx->select_stmt);
      if (!err)
        err = run_sql_bind_text (ctx->select_stmt, 1,
                                 desc[descidx].u.name);
      break;

    case KEYDB_SEARCH_MODE_ISSUER_SN:
      if (!desc[descidx].snhex)
        {
          /* We should never get a binary S/N here.  */
          log_debug ("%s: issuer_sn with binary s/n\n", __func__);
          err = gpg_error (GPG_ERR_INTERNAL);
        }
      else
        {
          if (!ctx->select_stmt)
            err = run_sql_prepare ("SELECT p.ubid, p.type, p.ephemeral,"
                                   " p.revoked, p.keyblob"
                                   " FROM pubkey as p, issuer as i"
                                   " WHERE p.ubid = i.ubid"
                                   " AND i.sn = $1 AND i.dn = $2",
                                   extra, " ORDER BY p.ubid",
                                   &ctx->select_stmt);
          if (!err)
            err = run_sql_bind_ntext (ctx->select_stmt, 1,
                                      desc[descidx].sn, desc[descidx].snlen);
          if (!err)
            err = run_sql_bind_text (ctx->select_stmt, 2,
                                     desc[descidx].u.name);
        }
      break;

    case KEYDB_SEARCH_MODE_SN:
      err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);  /* FIXME */
      /* if (has_sn (blob, sn_array? sn_array[n].sn : desc[n].sn, */
      /*             sn_array? sn_array[n].snlen : desc[n].snlen)) */
      /*   goto found; */
      break;

    case KEYDB_SEARCH_MODE_SUBJECT:
      ctx->select_col_uidno = 5;
      if (!ctx->select_stmt)
        err = run_sql_prepare ("SELECT p.ubid, p.type, p.ephemeral, p.revoked,"
                               " p.keyblob, u.uidno"
                               " FROM pubkey as p, userid as u"
                               " WHERE p.ubid = u.ubid"
                               " AND u.uid = $1",
                               extra, " ORDER BY p.ubid", &ctx->select_stmt);
      if (!err)
        err = run_sql_bind_text (ctx->select_stmt, 1,
                                 desc[descidx].u.name);
      break;

    case KEYDB_SEARCH_MODE_SHORT_KID:
      ctx->select_col_subkey = 5;
      if (!ctx->select_stmt)
        err = run_sql_prepare ("SELECT p.ubid, p.type, p.ephemeral,"
                               " p.revoked, p.keyblob, f.subkey"
                               " FROM pubkey as p, fingerprint as f"
                               " WHERE p.ubid = f.ubid AND"
                               " substr(f.kid,5) = ?1",
                               extra, " ORDER BY p.ubid", &ctx->select_stmt);
      if (!err)
        err = run_sql_bind_blob (ctx->select_stmt, 1,
                                 kid_from_u32 (desc[descidx].u.kid, kidbuf)+4,
                                 4);
      break;

    case KEYDB_SEARCH_MODE_LONG_KID:
      ctx->select_col_subkey = 5;
      if (!ctx->select_stmt)
        err = run_sql_prepare ("SELECT p.ubid, p.type, p.ephemeral,"
                               " p.revoked, p.keyblob, f.subkey"
                               " FROM pubkey as p, fingerprint as f"
                               " WHERE p.ubid = f.ubid AND f.kid = ?1",
                               extra, " ORDER BY p.ubid", &ctx->select_stmt);
      if (!err)
        err = run_sql_bind_blob (ctx->select_stmt, 1,
                                 kid_from_u32 (desc[descidx].u.kid, kidbuf),
                                 8);
      break;

    case KEYDB_SEARCH_MODE_FPR:
      ctx->select_col_subkey = 5;
      if (!ctx->select_stmt)
        err = run_sql_prepare ("SELECT p.ubid, p.type, p.ephemeral,"
                               " p.revoked, p.keyblob, f.subkey"
                               " FROM pubkey as p, fingerprint as f"
                               " WHERE p.ubid = f.ubid AND f.fpr = ?1",
                               extra, " ORDER BY p.ubid", &ctx->select_stmt);
      if (!err)
        err = run_sql_bind_blob (ctx->select_stmt, 1,
                                 desc[descidx].u.fpr, desc[descidx].fprlen);
      break;

    case KEYDB_SEARCH_MODE_KEYGRIP:
      ctx->select_col_subkey = 5;
      if (!ctx->select_stmt)
        err = run_sql_prepare ("SELECT p.ubid, p.type, p.ephemeral, p.revoked,"
                               " p.keyblob, f.subkey"
                               " FROM pubkey as p, fingerprint as f"
                               " WHERE p.ubid = f.ubid AND f.keygrip = ?1",
                               extra, " ORDER BY p.ubid", &ctx->select_stmt);
      if (!err)
        err = run_sql_bind_blob (ctx->select_stmt, 1,
                                 desc[descidx].u.grip, KEYGRIP_LEN);
      break;

    case KEYDB_SEARCH_MODE_UBID:
      if (!ctx->select_stmt)
        err = run_sql_prepare ("SELECT ubid, type, ephemeral, revoked, keyblob"
                               " FROM pubkey as p"
                               " WHERE ubid = ?1",
                               extra, NULL, &ctx->select_stmt);
      if (!err)
        err = run_sql_bind_blob (ctx->select_stmt, 1,
                                 desc[descidx].u.ubid, UBID_LEN);
      break;

    case KEYDB_SEARCH_MODE_FIRST:
      if (!ctx->select_stmt)
        {
          if (ctx->filter_opgp && ctx->filter_x509)
            extra = " WHERE ( p.type = 1 OR p.type = 2 ) ORDER by ubid";
          else if (ctx->filter_opgp && !ctx->filter_x509)
            extra = " WHERE p.type = 1 ORDER by ubid";
          else if (!ctx->filter_opgp && ctx->filter_x509)
            extra = " WHERE p.type = 2 ORDER by ubid";
          else
            extra = " ORDER by ubid";

          err = run_sql_prepare ("SELECT ubid, type, ephemeral, revoked,"
                                 " keyblob"
                                 " FROM pubkey as p",
                                 extra, NULL, &ctx->select_stmt);
        }
      break;

    case KEYDB_SEARCH_MODE_NEXT:
      err = gpg_error (GPG_ERR_INTERNAL);
      break;

    default:
      err = gpg_error (GPG_ERR_INV_VALUE);
      break;
    }

 leave:
  return err;
}


/* Search for the keys described by (DESC,NDESC) and return them to
 * the caller.  BACKEND_HD is the handle for this backend and REQUEST
 * is the current database request object.  */
gpg_error_t
be_sqlite_search (ctrl_t ctrl,
                  backend_handle_t backend_hd, db_request_t request,
                  KEYDB_SEARCH_DESC *desc, unsigned int ndesc)
{
  gpg_error_t err;
  db_request_part_t part;
  be_sqlite_local_t ctx;

  log_assert (backend_hd && backend_hd->db_type == DB_TYPE_SQLITE);
  log_assert (request);

  err = create_or_open_database (ctrl, backend_hd->filename);
  if (err)
    return err;

  acquire_mutex ();

  /* Find the specific request part or allocate it.  */
  err = be_find_request_part (backend_hd, request, &part);
  if (err)
    goto leave;
  ctx = part->besqlite;

  if (!desc)
    {
      /* Reset */
      ctx->select_done = 0;
      ctx->select_eof = 0;
      ctx->descidx = 0;
      ctx->lastubid_valid = 0;
      err = 0;
      goto leave;
    }

  if (ctx->select_eof)
    {
      /* Still in EOF state.  */
      err = gpg_error (GPG_ERR_EOF);
      goto leave;
    }

  /* Start a global transaction if needed.  */
  if (!opt.active_transaction && opt.in_transaction)
    {
      err = run_sql_statement ("begin transaction");
      if (err)
        goto leave;
      opt.active_transaction = 1;
    }


 again:
  if (!ctx->select_done)
    {
      /* Initial search - run the select.  */
      err = run_select_statement (ctrl, ctx, desc, ndesc);
      if (err)
        goto leave;
      ctx->select_done = 1;
    }

  show_sqlstmt (ctx->select_stmt);

  /* SQL select succeeded - get the first or next row. */
  err = run_sql_step_for_select (ctx->select_stmt);
  if (gpg_err_code (err) == GPG_ERR_SQL_ROW)
    {
      int n;
      const void *ubid, *keyblob;
      size_t keybloblen;
      enum pubkey_types pubkey_type;
      int is_ephemeral, is_revoked;
      int pk_no, uid_no;

      ubid = sqlite3_column_blob (ctx->select_stmt, 0);
      n = sqlite3_column_bytes (ctx->select_stmt, 0);
      if (!ubid || n < 0)
        {
          if (!ubid && sqlite3_errcode (database_hd) == SQLITE_NOMEM)
            err = gpg_error (gpg_err_code_from_sqlite (SQLITE_NOMEM));
          else
            err = gpg_error (GPG_ERR_DB_CORRUPTED);
          show_sqlstmt (ctx->select_stmt);
          log_error ("error in returned SQL column UBID: No column (n=%d)\n",n);
          goto leave;
        }
      if (n != UBID_LEN)
        {
          show_sqlstmt (ctx->select_stmt);
          log_error ("error in returned SQL column UBID: Bad value (n=%d)\n",n);
          err = gpg_error (GPG_ERR_INV_VALUE);
          goto leave;
        }

      if (ctx->lastubid_valid && !memcmp (ctx->lastubid, ubid, UBID_LEN))
        {
          /* The search has already returned this blob and thus we may
           * not return this again.  Consider the case that we are
           * searching for user id "foo" and a keyblock or certificate
           * has several userids with "foo" in it (or with even a full
           * mail address in it but with other extra parts).  The code
           * in gpg and gpgsm expects to see only a single block and
           * not several of them.  Whether the UIDNO makes any sense
           * in this case is questionable and we ignore that because
           * we currently are not able to return several UIDNOs.  */
          goto again;
        }
      memcpy (ctx->lastubid, ubid, UBID_LEN);
      ctx->lastubid_valid = 1;

      n = sqlite3_column_int (ctx->select_stmt, 1);
      if (!n && sqlite3_errcode (database_hd) == SQLITE_NOMEM)
        {
          err = gpg_error (gpg_err_code_from_sqlite (SQLITE_NOMEM));
          show_sqlstmt (ctx->select_stmt);
          log_error ("error in returned SQL column TYPE: %s)\n",
                     gpg_strerror (err));
          goto leave;
        }
      pubkey_type = n;

      n = sqlite3_column_int (ctx->select_stmt, 2);
      if (!n && sqlite3_errcode (database_hd) == SQLITE_NOMEM)
        {
          err = gpg_error (gpg_err_code_from_sqlite (SQLITE_NOMEM));
          show_sqlstmt (ctx->select_stmt);
          log_error ("error in returned SQL column EPHEMERAL: %s)\n",
                     gpg_strerror (err));
          goto leave;
        }
      is_ephemeral = !!n;

      n = sqlite3_column_int (ctx->select_stmt, 3);
      if (!n && sqlite3_errcode (database_hd) == SQLITE_NOMEM)
        {
          err = gpg_error (gpg_err_code_from_sqlite (SQLITE_NOMEM));
          show_sqlstmt (ctx->select_stmt);
          log_error ("error in returned SQL column REVOKED: %s)\n",
                     gpg_strerror (err));
          goto leave;
        }
      is_revoked = !!n;

      keyblob = sqlite3_column_blob (ctx->select_stmt, 4);
      n = sqlite3_column_bytes (ctx->select_stmt, 4);
      if (!keyblob || n < 0)
        {
          if (!keyblob && sqlite3_errcode (database_hd) == SQLITE_NOMEM)
            err = gpg_error (gpg_err_code_from_sqlite (SQLITE_NOMEM));
          else
            err = gpg_error (GPG_ERR_DB_CORRUPTED);
          show_sqlstmt (ctx->select_stmt);
          log_error ("error in returned SQL column KEYBLOB: %s\n",
                     gpg_strerror (err));
          goto leave;
        }
      keybloblen = n;

      if (ctx->select_col_uidno)
        {
          n = sqlite3_column_int (ctx->select_stmt, ctx->select_col_uidno);
          if (!n && sqlite3_errcode (database_hd) == SQLITE_NOMEM)
            {
              err = gpg_error (gpg_err_code_from_sqlite (SQLITE_NOMEM));
              show_sqlstmt (ctx->select_stmt);
              log_error ("error in returned SQL column UIDNO: %s)\n",
                         gpg_strerror (err));
              uid_no = 0;
            }
          else if (n < 0)
            uid_no = 0;
          else
            uid_no = n + 1;
        }
      else
        uid_no = 0;

      if (ctx->select_col_subkey)
        {
          n = sqlite3_column_int (ctx->select_stmt, ctx->select_col_subkey);
          if (!n && sqlite3_errcode (database_hd) == SQLITE_NOMEM)
            {
              err = gpg_error (gpg_err_code_from_sqlite (SQLITE_NOMEM));
              show_sqlstmt (ctx->select_stmt);
              log_error ("error in returned SQL column SUBKEY: %s)\n",
                         gpg_strerror (err));
              goto leave;
            }
          else if (n < 0)
            pk_no = 0;
          else
            pk_no = n + 1;
        }
      else
        pk_no = 0;

      err = be_return_pubkey (ctrl, keyblob, keybloblen, pubkey_type,
                              ubid, is_ephemeral, is_revoked, uid_no, pk_no);
      if (!err)
        be_cache_pubkey (ctrl, ubid, keyblob, keybloblen, pubkey_type);
    }
  else if (gpg_err_code (err) == GPG_ERR_SQL_DONE)
    {
      if (++ctx->descidx < ndesc)
        {
          ctx->select_done = 0;
          goto again;
        }
      err = gpg_error (GPG_ERR_EOF);
      ctx->select_eof = 1;
    }
  else
    {
      log_assert (err);
    }

 leave:
  release_mutex ();
  return err;
}



/* Helper for be_sqlite_store to update or insert a row in the pubkey
 * table.  */
static gpg_error_t
store_into_pubkey (enum kbxd_store_modes mode,
                   enum pubkey_types pktype, const unsigned char *ubid,
                   const void *blob, size_t bloblen)
{
  gpg_error_t err;
  const char *sqlstr;
  sqlite3_stmt *stmt = NULL;

  if (mode == KBXD_STORE_UPDATE)
    sqlstr = ("UPDATE pubkey set keyblob = ?3, type = ?2 WHERE ubid = ?1");
  else if (mode == KBXD_STORE_INSERT)
    sqlstr = ("INSERT INTO pubkey(ubid,type,keyblob) VALUES(?1,?2,?3)");
  else /* Auto */
    sqlstr = ("INSERT OR REPLACE INTO pubkey(ubid,type,keyblob)"
              " VALUES(?1,?2,?3)");
  err = run_sql_prepare (sqlstr, NULL, NULL, &stmt);
  if (err)
    goto leave;
  err = run_sql_bind_blob (stmt, 1, ubid, UBID_LEN);
  if (err)
    goto leave;
  err = run_sql_bind_int (stmt, 2, (int)pktype);
  if (err)
    goto leave;
  err = run_sql_bind_blob (stmt, 3, blob, bloblen);
  if (err)
    goto leave;

  err = run_sql_step (stmt);

 leave:
  if (stmt)
    sqlite3_finalize (stmt);
  return err;
}


/* Helper for be_sqlite_store to update or insert a row in the
 * fingerprint table.  */
static gpg_error_t
store_into_fingerprint (const unsigned char *ubid, int subkey,
                        const unsigned char *keygrip,
                        const unsigned char *kid,
                        const unsigned char *fpr, int fprlen)
{
  gpg_error_t err;
  const char *sqlstr;
  sqlite3_stmt *stmt = NULL;

  sqlstr = ("INSERT OR REPLACE INTO fingerprint(fpr,kid,keygrip,subkey,ubid)"
            " VALUES(?1,?2,?3,?4,?5)");
  err = run_sql_prepare (sqlstr, NULL, NULL, &stmt);
  if (err)
    goto leave;
  err = run_sql_bind_blob (stmt, 1, fpr, fprlen);
  if (err)
    goto leave;
  err = run_sql_bind_blob (stmt, 2, kid, 8);
  if (err)
    goto leave;
  err = run_sql_bind_blob (stmt, 3, keygrip, KEYGRIP_LEN);
  if (err)
    goto leave;
  err = run_sql_bind_int (stmt, 4, subkey);
  if (err)
    goto leave;
  err = run_sql_bind_blob (stmt, 5, ubid, UBID_LEN);
  if (err)
    goto leave;

  err = run_sql_step (stmt);

 leave:
  if (stmt)
    sqlite3_finalize (stmt);
  return err;
}


/* Helper for be_sqlite_store to update or insert a row in the userid
 * table.  If OVERRIDE_MBOX is set, that value is used instead of a
 * value extracted from UID. */
static gpg_error_t
store_into_userid (const unsigned char *ubid, enum pubkey_types pktype,
                   const char *uid, int uidno, const char *override_mbox)
{
  gpg_error_t err;
  const char *sqlstr;
  sqlite3_stmt *stmt = NULL;
  char *addrspec = NULL;

  sqlstr = ("INSERT OR REPLACE INTO userid(uid,addrspec,type,ubid,uidno)"
            " VALUES(?1,?2,?3,?4,?5)");
  err = run_sql_prepare (sqlstr, NULL, NULL, &stmt);
  if (err)
    goto leave;

  err = run_sql_bind_text (stmt, 1, uid);
  if (err)
    goto leave;

  if (override_mbox)
    err = run_sql_bind_text (stmt, 2, override_mbox);
  else
    {
      addrspec = mailbox_from_userid (uid, 0);
      err = run_sql_bind_text (stmt, 2, addrspec);
    }
  if (err)
    goto leave;

  err = run_sql_bind_int (stmt, 3, pktype);
  if (err)
    goto leave;
  err = run_sql_bind_blob (stmt, 4, ubid, UBID_LEN);
  if (err)
    goto leave;
  err = run_sql_bind_int (stmt, 5, uidno);
  if (err)
    goto leave;

  err = run_sql_step (stmt);

 leave:
  if (stmt)
    sqlite3_finalize (stmt);
  xfree (addrspec);
  return err;
}


/* Helper for be_sqlite_store to update or insert a row in the
 * issuer table.  */
static gpg_error_t
store_into_issuer (const unsigned char *ubid,
                   const char *sn, const char *issuer)
{
  gpg_error_t err;
  const char *sqlstr;
  sqlite3_stmt *stmt = NULL;
  char *addrspec = NULL;

  sqlstr = ("INSERT OR REPLACE INTO issuer(sn,dn,ubid)"
            " VALUES(?1,?2,?3)");
  err = run_sql_prepare (sqlstr, NULL, NULL, &stmt);
  if (err)
    goto leave;

  err = run_sql_bind_text (stmt, 1, sn);
  if (err)
    goto leave;
  err = run_sql_bind_text (stmt, 2, issuer);
  if (err)
    goto leave;
  err = run_sql_bind_blob (stmt, 3, ubid, UBID_LEN);
  if (err)
    goto leave;

  err = run_sql_step (stmt);

 leave:
  if (stmt)
    sqlite3_finalize (stmt);
  xfree (addrspec);
  return err;
}


/* Store (BLOB,BLOBLEN) into the database.  UBID is the UBID matching
 * that blob.  BACKEND_HD is the handle for this backend and REQUEST
 * is the current database request object.  MODE is the store
 * mode.  */
gpg_error_t
be_sqlite_store (ctrl_t ctrl, backend_handle_t backend_hd,
                 db_request_t request, enum kbxd_store_modes mode,
                 enum pubkey_types pktype, const unsigned char *ubid,
                 const void *blob, size_t bloblen)
{
  gpg_error_t err;
  db_request_part_t part;
  /* be_sqlite_local_t ctx; */
  int got_mutex = 0;
  int in_transaction = 0;
  int info_valid = 0;
  struct _keybox_openpgp_info info;
  ksba_cert_t cert = NULL;
  char *sn = NULL;
  char *dn = NULL;
  char *kludge_mbox = NULL;
  int uidno;

  (void)ctrl;

  log_assert (backend_hd && backend_hd->db_type == DB_TYPE_SQLITE);
  log_assert (request);

  /* Fixme: The code below is duplicated in be_ubid_from_blob - we
   * should have only one function and pass the passed info around
   * with the BLOB.  */

  if (be_is_x509_blob (blob, bloblen))
    {
      log_assert (pktype == PUBKEY_TYPE_X509);

      err = ksba_cert_new (&cert);
      if (err)
        goto leave;
      err = ksba_cert_init_from_mem (cert, blob, bloblen);
      if (err)
        goto leave;
    }
  else
    {
      err = _keybox_parse_openpgp (blob, bloblen, NULL, &info);
      if (err)
        {
          log_info ("error parsing OpenPGP blob: %s\n", gpg_strerror (err));
          err = gpg_error (GPG_ERR_WRONG_BLOB_TYPE);
          goto leave;
        }
      info_valid = 1;
      log_assert (pktype == PUBKEY_TYPE_OPGP);
      log_assert (info.primary.fprlen >= 20);
      log_assert (!memcmp (ubid, info.primary.fpr, UBID_LEN));
    }


  acquire_mutex ();
  got_mutex = 1;

  /* Find the specific request part or allocate it.  */
  err = be_find_request_part (backend_hd, request, &part);
  if (err)
    goto leave;
  /* ctx = part->besqlite; */

  if (!opt.active_transaction)
    {
      err = run_sql_statement ("begin transaction");
      if (err)
        goto leave;
      if (opt.in_transaction)
        opt.active_transaction = 1;
    }
  in_transaction = 1;

  err = store_into_pubkey (mode, pktype, ubid, blob, bloblen);
  if (err)
    goto leave;

  /* Delete all related rows so that we can freshly add possibly added
   * or changed user ids and subkeys.  */
  err = run_sql_statement_bind_ubid
    ("DELETE FROM fingerprint WHERE ubid = ?1", ubid);
  if (err)
    goto leave;
  err = run_sql_statement_bind_ubid
    ("DELETE FROM userid WHERE ubid = ?1", ubid);
  if (err)
    goto leave;
  if (cert)
    {
      err = run_sql_statement_bind_ubid
        ("DELETE FROM issuer WHERE ubid = ?1", ubid);
      if (err)
        goto leave;
    }

  if (cert)  /* X.509 */
    {
      unsigned char grip[KEYGRIP_LEN];
      int idx;

      err = be_get_x509_keygrip (cert, grip);
      if (err)
        goto leave;

      /* Note that for X.509 the UBID is also the fingerprint.  */
      err = store_into_fingerprint (ubid, 0, grip,
                                    ubid+12,
                                    ubid, UBID_LEN);
      if (err)
        goto leave;

      /* Now the issuer.  */
      sn = be_get_x509_serial (cert);
      if (!sn)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      dn = ksba_cert_get_issuer (cert, 0);
      if (!dn)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      err = store_into_issuer (ubid, sn, dn);
      if (err)
        goto leave;

      /* Loop over the subject and alternate subjects. */
      uidno = 0;
      for (idx=0; (xfree (dn), dn = ksba_cert_get_subject (cert, idx)); idx++)
        {
          /* In the case that the same email address is in the
           * subject DN as well as in an alternate subject name
           * we avoid printing it a second time. */
          if (kludge_mbox && !strcmp (kludge_mbox, dn))
            continue;

          err = store_into_userid (ubid, PUBKEY_TYPE_X509, dn, ++uidno, NULL);
          if (err)
            goto leave;

          if (!idx)
            {
              kludge_mbox = _keybox_x509_email_kludge (dn);
              if (kludge_mbox)
                {
                  err = store_into_userid (ubid, PUBKEY_TYPE_X509,
                                           dn, ++uidno, kludge_mbox);
                  if (err)
                    goto leave;
                }
            }
        } /* end loop over the subjects.  */
    }
  else /* OpenPGP */
    {
      struct _keybox_openpgp_key_info *kinfo;

      kinfo = &info.primary;
      err = store_into_fingerprint (ubid, 0, kinfo->grip,
                                    kinfo->keyid,
                                    kinfo->fpr, kinfo->fprlen);
      if (err)
        goto leave;

      if (info.nsubkeys)
        {
          int subkey = 1;
          for (kinfo = &info.subkeys; kinfo; kinfo = kinfo->next, subkey++)
            {
              err = store_into_fingerprint (ubid, subkey, kinfo->grip,
                                            kinfo->keyid,
                                            kinfo->fpr, kinfo->fprlen);
              if (err)
                goto leave;
            }
        }

      if (info.nuids)
        {
          struct _keybox_openpgp_uid_info *u;

          uidno = 0;
          u = &info.uids;
          do
            {
              log_assert (u->off <= bloblen);
              log_assert (u->off + u->len <= bloblen);
              {
                char *uid = xtrymalloc (u->len + 1);
                if (!uid)
                  {
                    err = gpg_error_from_syserror ();
                    goto leave;
                  }
                memcpy (uid, (const unsigned char *)blob + u->off, u->len);
                uid[u->len] = 0;
                /* Note that we ignore embedded zeros in the user id;
                 * this is what we do all over the place.  */
                err = store_into_userid (ubid, pktype, uid, ++uidno, NULL);
                xfree (uid);
              }
              if (err)
                goto leave;

              u = u->next;
            }
          while (u);
        }
    }

 leave:
  if (in_transaction && !err)
    {
      if (opt.active_transaction)
        ; /* We are in a global transaction.  */
      else
        err = run_sql_statement ("commit");
    }
  else if (in_transaction)
    {
      if (opt.active_transaction)
        ; /* We are in a global transaction.  */
      else if (run_sql_statement ("rollback"))
        log_error ("Warning: database rollback failed - should not happen!\n");
    }
  if (got_mutex)
    release_mutex ();
  if (info_valid)
    _keybox_destroy_openpgp_info (&info);
  if (cert)
    ksba_cert_release (cert);
  ksba_free (dn);
  xfree (sn);
  xfree (kludge_mbox);
  return err;
}


/* Delete the blob specified by UBID from the database.  BACKEND_HD is
 * the handle for this backend and REQUEST is the current database
 * request object.  */
gpg_error_t
be_sqlite_delete (ctrl_t ctrl, backend_handle_t backend_hd,
                  db_request_t request, const unsigned char *ubid)
{
  gpg_error_t err;
  db_request_part_t part;
  /* be_sqlite_local_t ctx; */
  sqlite3_stmt *stmt = NULL;
  int in_transaction = 0;

  (void)ctrl;

  log_assert (backend_hd && backend_hd->db_type == DB_TYPE_SQLITE);
  log_assert (request);

  acquire_mutex ();

  /* Find the specific request part or allocate it.  */
  err = be_find_request_part (backend_hd, request, &part);
  if (err)
    goto leave;
  /* ctx = part->besqlite; */

  if (!opt.active_transaction)
    {
      err = run_sql_statement ("begin transaction");
      if (err)
        goto leave;
      if (opt.in_transaction)
        opt.active_transaction = 1;
    }
  in_transaction = 1;

  err = run_sql_statement_bind_ubid
    ("DELETE from userid WHERE ubid = ?1", ubid);
  if (!err)
    err = run_sql_statement_bind_ubid
      ("DELETE from fingerprint WHERE ubid = ?1", ubid);
  if (!err)
    err = run_sql_statement_bind_ubid
      ("DELETE from issuer WHERE ubid = ?1", ubid);
  if (!err)
    err = run_sql_statement_bind_ubid
      ("DELETE from pubkey WHERE ubid = ?1", ubid);


 leave:
  if (stmt)
    sqlite3_finalize (stmt);

  if (in_transaction && !err)
    {
      if (opt.active_transaction)
        ; /* We are in a global transaction.  */
      else
        err = run_sql_statement ("commit");
    }
  else if (in_transaction)
    {
      if (opt.active_transaction)
        ; /* We are in a global transaction.  */
      else if (run_sql_statement ("rollback"))
        log_error ("Warning: database rollback failed - should not happen!\n");
    }
  release_mutex ();
  return err;
}
