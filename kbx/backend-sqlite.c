/* backend-sqlite.c - SQLite based backend for keyboxd
 * Copyright (C) 2019 g10 Code GmbH
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


/* Add replacement error codes; GPGRT provides SQL error codes from
 * version 1.37 on.  */
#if GPGRT_VERSION_NUMBER < 0x012500 /* 1.37 */

static GPGRT_INLINE gpg_error_t
gpg_err_code_from_sqlite (int sqlres)
{
  return sqlres? 1500 + (sqlres & 0xff) : 0;
}

#define GPG_ERR_SQL_OK   1500
#define GPG_ERR_SQL_ROW  1600
#define GPG_ERR_SQL_DONE 1601

#endif /*GPGRT_VERSION_NUMBER*/


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

  /* The search mode represented by the current select command.  */
  KeydbSearchMode select_mode;

  /* The select statement has been executed with success.  */
  int select_done;

  /* The last row has already been reached.  */
  int select_eof;
};


/* The Mutex we use to protect all our SQLite calls.  */
static npth_mutex_t database_mutex = NPTH_MUTEX_INITIALIZER;
/* The one and only database handle. */
static sqlite3 *database_hd;
/* A lockfile used make sure only we are accessing the database.  */
static dotlock_t database_lock;


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
     "name  TEXT NOT NULL,"
     "value TEXT NOT NULL "
     ")", 1 },

   /* The actual data; either X.509 certificates or OpenPGP
    * keyblocks.  */
   { "CREATE TABLE IF NOT EXISTS pubkey ("
     /* The 20 octet truncated primary-fpr */
     "ubid     BLOB NOT NULL PRIMARY KEY,"
     /* The type of the public key: 1 = openpgp, 2 = X.509.  */
     "type  INTEGER NOT NULL,"
     /* The OpenPGP keyblock or X.509 certificate.  */
     "keyblob BLOB NOT NULL"
     ")"  },

   /* Table with fingerprints and keyids of OpenPGP and X.509 keys.
    * It is also used for the primary key and the X.509 fingerprint
    * because we want to be able to use the keyid and keygrip.  */
   { "CREATE TABLE IF NOT EXISTS fingerprint ("
     "fpr  BLOB NOT NULL PRIMARY KEY,"
     /* The long keyid as 64 bit integer.  */
     "kid  INTEGER NOT NULL,"
     /* The keygrip for this key.  */
     "keygrip BLOB NOT NULL,"
     /* 0 = primary, > 0 = subkey.  */
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
     /* The full user id.  */
     "uid  TEXT NOT NULL,"
     /* The mail address if available or NULL.  */
     "addrspec TEXT,"
     /* The type of the public key: 1 = openpgp, 2 = X.509.  */
     "type  INTEGER NOT NULL,"
     /* The Unique Blob ID (possibly truncated fingerprint).  */
     "ubid BLOB NOT NULL REFERENCES pubkey"
     ")"  },

   /* Indices for the userid table.  */
   { "CREATE INDEX IF NOT EXISTS userididx0 on userid (ubid)"     },
   { "CREATE INDEX IF NOT EXISTS userididx1 on userid (uid)"      },
   { "CREATE INDEX IF NOT EXISTS userididx3 on userid (addrspec)" }

  };




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


/* We store the keyid in the database as an integer - this function
 * converts it from a memory buffer.  */
static GPGRT_INLINE sqlite3_int64
kid_from_mem (const unsigned char *keyid)
{
  return (  ((uint64_t)keyid[0] << 56)
          | ((uint64_t)keyid[1] << 48)
          | ((uint64_t)keyid[2] << 40)
          | ((uint64_t)keyid[3] << 32)
          | ((uint64_t)keyid[4] << 24)
          | ((uint64_t)keyid[5] << 16)
          | ((uint64_t)keyid[6] << 8)
          | ((uint64_t)keyid[7])
          );
}


/* We store the keyid in the database as an integer - this function
 * converts it from the usual u32[2] array.  */
static GPGRT_INLINE sqlite3_int64
kid_from_u32 (u32 *keyid)
{
  return (((uint64_t)keyid[0] << 32) | ((uint64_t)keyid[1]) );
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


/* Run an SQL prepare for SQLSTR and return a statement at R_STMT.  */
static gpg_error_t
run_sql_prepare (const char *sqlstr, sqlite3_stmt **r_stmt)
{
  gpg_error_t err;
  int res;

  res = sqlite3_prepare_v2 (database_hd, sqlstr, -1, r_stmt, NULL);
  if (res)
    err = diag_prepare_err (res, sqlstr);
  else
    err = 0;
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


/* Helper to bind an INTEGER64 parameter to a statement.  */
static gpg_error_t
run_sql_bind_int64 (sqlite3_stmt *stmt, int no, sqlite3_int64 value)
{
  gpg_error_t err;
  int res;

  res = sqlite3_bind_int64 (stmt, no, value);
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
  gpg_error_t err;
  int res;

  res = sqlite3_bind_text (stmt, no, value, value? strlen (value):0,
                           SQLITE_TRANSIENT);
  if (res)
    err = diag_bind_err (res, stmt);
  else
    err = 0;
  return err;
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
 * will be bound to :1 in SQLSTR.  This command may not be used for
 * select or other command which return rows.  */
static gpg_error_t
run_sql_statement_bind_ubid (const char *sqlstr, const unsigned char *ubid)
{
  gpg_error_t err;
  sqlite3_stmt *stmt;

  err = run_sql_prepare (sqlstr, &stmt);
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


/* Create and initialize a new SQL database file if it does not
 * exists; else open it and check that all required objects are
 * available.  */
static gpg_error_t
create_or_open_database (const char *filename)
{
  gpg_error_t err;
  int res;
  int idx;

  if (database_hd)
    return 0;  /* Already initialized.  */

  acquire_mutex ();

  /* To avoid races with other temporary instances of keyboxd trying
   * to create or update the database, we run the database with a lock
   * file held. */
  database_lock = dotlock_create (filename, 0);
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

  if (dotlock_take (database_lock, -1))
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
          // FIXME
        }
    }

  if (!opt.quiet)
    log_info (_("database '%s' created\n"), filename);
  err = 0;

 leave:
  if (err)
    {
      log_error (_("error creating database '%s': %s\n"),
                 filename, gpg_strerror (err));
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
  gpg_error_t err;
  backend_handle_t hd;

  (void)ctrl;
  (void)readonly;  /* FIXME: implement read-only mode.  */

  *r_hd = NULL;
  hd = xtrycalloc (1, sizeof *hd + strlen (filename));
  if (!hd)
    return gpg_error_from_syserror ();
  hd->db_type = DB_TYPE_SQLITE;
  strcpy (hd->filename, filename);

  err = create_or_open_database (filename);
  if (err)
    goto leave;

  hd->backend_id = be_new_backend_id ();

  *r_hd = hd;
  hd = NULL;

 leave:
  xfree (hd);
  return err;
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


/* Run a select for the search given by (DESC,NDESC).  The data is not
 * returned but stored in the request item.  */
static gpg_error_t
run_select_statement (be_sqlite_local_t ctx,
                      KEYDB_SEARCH_DESC *desc, unsigned int ndesc)
{
  gpg_error_t err = 0;
  unsigned int descidx;

  descidx = 0; /* Fixme: take from context.  */
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

  ctx->select_mode = desc[descidx].mode;

  /* Prepare the select and bind the parameters.  */
  if (ctx->select_stmt)
    {
      err = run_sql_reset (ctx->select_stmt);
      if (err)
        goto leave;
    }
  else
    err = 0;

  switch (desc[descidx].mode)
    {
    case KEYDB_SEARCH_MODE_NONE:
      never_reached ();
      err = gpg_error (GPG_ERR_INTERNAL);
      break;

    case KEYDB_SEARCH_MODE_EXACT:
      if (!ctx->select_stmt)
        err = run_sql_prepare ("SELECT p.ubid, p.type, p.keyblob"
                               " FROM pubkey as p, userid as u"
                               " WHERE p.ubid = u.ubid AND u.uid = ?1",
                               &ctx->select_stmt);
      if (!err)
        err = run_sql_bind_text (ctx->select_stmt, 1, desc[descidx].u.name);
      break;

    case KEYDB_SEARCH_MODE_MAIL:
      if (!ctx->select_stmt)
        err = run_sql_prepare ("SELECT p.ubid, p.type, p.keyblob"
                               " FROM pubkey as p, userid as u"
                               " WHERE p.ubid = u.ubid AND u.addrspec = ?1",
                               &ctx->select_stmt);
      if (!err)
        err = run_sql_bind_text (ctx->select_stmt, 1, desc[descidx].u.name);
      break;

    case KEYDB_SEARCH_MODE_MAILSUB:
      if (!ctx->select_stmt)
        err = run_sql_prepare ("SELECT p.ubid, p.type, p.keyblob"
                               " FROM pubkey as p, userid as u"
                               " WHERE p.ubid = u.ubid AND u.addrspec LIKE ?1",
                               &ctx->select_stmt);
      if (!err)
        err = run_sql_bind_text_like (ctx->select_stmt, 1,
                                      desc[descidx].u.name);
      break;

    case KEYDB_SEARCH_MODE_SUBSTR:
      if (!ctx->select_stmt)
        err = run_sql_prepare ("SELECT p.ubid, p.type, p.keyblob"
                               " FROM pubkey as p, userid as u"
                               " WHERE p.ubid = u.ubid AND u.uid LIKE ?1",
                               &ctx->select_stmt);
      if (!err)
        err = run_sql_bind_text_like (ctx->select_stmt, 1,
                                      desc[descidx].u.name);
      break;

    case KEYDB_SEARCH_MODE_MAILEND:
    case KEYDB_SEARCH_MODE_WORDS:
      err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
      break;

    case KEYDB_SEARCH_MODE_ISSUER:
      err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);  /* FIXME */
      /* if (has_issuer (blob, desc[n].u.name)) */
      /*   goto found; */
      break;

    case KEYDB_SEARCH_MODE_ISSUER_SN:
      err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);  /* FIXME */
      /* if (has_issuer_sn (blob, desc[n].u.name, */
      /*                    sn_array? sn_array[n].sn : desc[n].sn, */
      /*                    sn_array? sn_array[n].snlen : desc[n].snlen)) */
      /*   goto found; */
      break;
    case KEYDB_SEARCH_MODE_SN:
      err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);  /* FIXME */
      /* if (has_sn (blob, sn_array? sn_array[n].sn : desc[n].sn, */
      /*             sn_array? sn_array[n].snlen : desc[n].snlen)) */
      /*   goto found; */
      break;
    case KEYDB_SEARCH_MODE_SUBJECT:
      err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);  /* FIXME */
      /* if (has_subject (blob, desc[n].u.name)) */
      /*   goto found; */
      break;

    case KEYDB_SEARCH_MODE_SHORT_KID:
      err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);  /* FIXME */
      /* pk_no = has_short_kid (blob, desc[n].u.kid[1]); */
      /* if (pk_no) */
      /*   goto found; */
      break;

    case KEYDB_SEARCH_MODE_LONG_KID:
      if (!ctx->select_stmt)
        err = run_sql_prepare ("SELECT p.ubid, p.type, p.keyblob"
                               " FROM pubkey as p, fingerprint as f"
                               " WHERE p.ubid = f.ubid AND f.kid = ?1",
                               &ctx->select_stmt);
      if (!err)
        err = run_sql_bind_int64 (ctx->select_stmt, 1,
                                  kid_from_u32 (desc[descidx].u.kid));
      break;

    case KEYDB_SEARCH_MODE_FPR:
      if (!ctx->select_stmt)
        err = run_sql_prepare ("SELECT p.ubid, p.type, p.keyblob"
                               " FROM pubkey as p, fingerprint as f"
                               " WHERE p.ubid = f.ubid AND f.fpr = ?1",
                               &ctx->select_stmt);
      if (!err)
        err = run_sql_bind_blob (ctx->select_stmt, 1,
                                 desc[descidx].u.fpr, desc[descidx].fprlen);
      break;

    case KEYDB_SEARCH_MODE_KEYGRIP:
      if (!ctx->select_stmt)
        err = run_sql_prepare ("SELECT p.ubid, p.type, p.keyblob"
                               " FROM pubkey as p, fingerprint as f"
                               " WHERE p.ubid = f.ubid AND f.keygrip = ?1",
                               &ctx->select_stmt);
      if (!err)
        err = run_sql_bind_blob (ctx->select_stmt, 1,
                                 desc[descidx].u.grip, KEYGRIP_LEN);
      break;

    case KEYDB_SEARCH_MODE_UBID:
      if (!ctx->select_stmt)
        err = run_sql_prepare ("SELECT ubid, type, keyblob"
                               " FROM pubkey"
                               " WHERE ubid = ?1",
                               &ctx->select_stmt);
      if (!err)
        err = run_sql_bind_blob (ctx->select_stmt, 1,
                                 desc[descidx].u.ubid, UBID_LEN);
      break;

    case KEYDB_SEARCH_MODE_FIRST:
      if (!ctx->select_stmt)
        err = run_sql_prepare ("SELECT ubid, type, keyblob"
                               " FROM pubkey ORDER by ubid",
                               &ctx->select_stmt);
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
      err = 0;
      goto leave;
    }

  if (ctx->select_eof)
    {
      /* Still in EOF state.  */
      err = gpg_error (GPG_ERR_EOF);
      goto leave;
    }

  if (!ctx->select_done)
    {
      /* Initial search - run the select.  */
      err = run_select_statement (ctx, desc, ndesc);
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

      keyblob = sqlite3_column_blob (ctx->select_stmt, 2);
      n = sqlite3_column_bytes (ctx->select_stmt, 2);
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

      err = be_return_pubkey (ctrl, keyblob, keybloblen, pubkey_type, ubid);
      if (!err)
        be_cache_pubkey (ctrl, ubid, keyblob, keybloblen, pubkey_type);
    }
  else if (gpg_err_code (err) == GPG_ERR_SQL_DONE)
    {
      /* FIXME: Move on to the next description index.  */
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
    sqlstr = ("UPDATE pubkey set keyblob = :3, type = :2 WHERE ubid = :1");
  else if (mode == KBXD_STORE_INSERT)
    sqlstr = ("INSERT INTO pubkey(ubid,type,keyblob) VALUES(:1,:2,:3)");
  else /* Auto */
    sqlstr = ("INSERT OR REPLACE INTO pubkey(ubid,type,keyblob)"
              " VALUES(:1,:2,:3)");
  err = run_sql_prepare (sqlstr, &stmt);
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
                        const unsigned char *keygrip, sqlite3_int64 kid,
                        const unsigned char *fpr, int fprlen)
{
  gpg_error_t err;
  const char *sqlstr;
  sqlite3_stmt *stmt = NULL;

  sqlstr = ("INSERT OR REPLACE INTO fingerprint(fpr,kid,keygrip,subkey,ubid)"
            " VALUES(:1,:2,:3,:4,:5)");
  err = run_sql_prepare (sqlstr, &stmt);
  if (err)
    goto leave;
  err = run_sql_bind_blob (stmt, 1, fpr, fprlen);
  if (err)
    goto leave;
  err = run_sql_bind_int64 (stmt, 2, kid);
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


/* Helper for be_sqlite_store to update or insert a row in the
 * userid table.  */
static gpg_error_t
store_into_userid (const unsigned char *ubid, enum pubkey_types pktype,
                   const char *uid)
{
  gpg_error_t err;
  const char *sqlstr;
  sqlite3_stmt *stmt = NULL;
  char *addrspec = NULL;

  sqlstr = ("INSERT OR REPLACE INTO userid(uid,addrspec,type,ubid)"
            " VALUES(:1,:2,:3,:4)");
  err = run_sql_prepare (sqlstr, &stmt);
  if (err)
    goto leave;

  err = run_sql_bind_text (stmt, 1, uid);
  if (err)
    goto leave;
  addrspec = mailbox_from_userid (uid, 0);
  err = run_sql_bind_text (stmt, 2, addrspec);
  if (err)
    goto leave;
  err = run_sql_bind_int (stmt, 3, pktype);
  if (err)
    goto leave;
  err = run_sql_bind_blob (stmt, 4, ubid, UBID_LEN);
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
  struct _keybox_openpgp_key_info *kinfo;

  (void)ctrl;

  log_assert (backend_hd && backend_hd->db_type == DB_TYPE_SQLITE);
  log_assert (request);

  /* Fixme: The code below is duplicated in be_ubid_from_blob - we
   * should have only one function and pass the passed info around
   * with the BLOB.  */

  if (be_is_x509_blob (blob, bloblen))
    {
      /* The UBID is also our fingerprint.  */
      /* FIXME: Extract keygrip and KID.  */
      err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
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

  err = run_sql_statement ("begin transaction");
  if (err)
    goto leave;
  in_transaction = 1;

  err = store_into_pubkey (mode, pktype, ubid, blob, bloblen);
  if (err)
    goto leave;

  /* Delete all related rows so that we can freshly add possibly added
   * or changed user ids and subkeys.  */
  err = run_sql_statement_bind_ubid
    ("DELETE FROM fingerprint WHERE ubid = :1", ubid);
  if (err)
    goto leave;
  err = run_sql_statement_bind_ubid
    ("DELETE FROM userid WHERE ubid = :1", ubid);
  if (err)
    goto leave;

  kinfo = &info.primary;
  err = store_into_fingerprint (ubid, 0, kinfo->grip,
                                kid_from_mem (kinfo->keyid),
                                kinfo->fpr, kinfo->fprlen);
  if (err)
    goto leave;

  if (info.nsubkeys)
    {
      int subkey = 1;
      for (kinfo = &info.subkeys; kinfo; kinfo = kinfo->next, subkey++)
        {
          err = store_into_fingerprint (ubid, subkey, kinfo->grip,
                                        kid_from_mem (kinfo->keyid),
                                        kinfo->fpr, kinfo->fprlen);
          if (err)
            goto leave;
        }
    }

  if (info.nuids)
    {
      struct _keybox_openpgp_uid_info *u;

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
            /* Note that we ignore embedded zeros in the user id; this
             * is what we do all over the place.  */
            err = store_into_userid (ubid, pktype, uid);
            xfree (uid);
          }
          if (err)
            goto leave;

          u = u->next;
        }
      while (u);
    }

 leave:
  if (in_transaction && !err)
    err = run_sql_statement ("commit");
  else if (in_transaction)
    {
      if (run_sql_statement ("rollback"))
        log_error ("Warning: database rollback failed - should not happen!\n");
    }
  if (got_mutex)
    release_mutex ();
  if (info_valid)
    _keybox_destroy_openpgp_info (&info);
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

  err = run_sql_statement ("begin transaction");
  if (err)
    goto leave;
  in_transaction = 1;

  err = run_sql_statement_bind_ubid
    ("DELETE from userid WHERE ubid = :1", ubid);
  if (!err)
    err = run_sql_statement_bind_ubid
      ("DELETE from fingerprint WHERE ubid = :1", ubid);
  if (!err)
    err = run_sql_statement_bind_ubid
      ("DELETE from pubkey WHERE ubid = :1", ubid);


 leave:
  if (stmt)
    sqlite3_finalize (stmt);
  if (in_transaction && !err)
    err = run_sql_statement ("commit");
  else if (in_transaction)
    {
      if (run_sql_statement ("rollback"))
        log_error ("Warning: database rollback failed - should not happen!\n");
    }
  release_mutex ();
  return err;
}
