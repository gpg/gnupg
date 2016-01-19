/* tofu.c - TOFU trust model.
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

/* TODO:

   - Format the fingerprints nicely when printing (similar to gpg
     --list-keys)
 */

#include <config.h>
#include <stdio.h>
#include <sys/stat.h>
#include <assert.h>
#include <stdarg.h>
#include <sched.h>
#include <sqlite3.h>

#include "gpg.h"
#include "types.h"
#include "logging.h"
#include "stringhelp.h"
#include "options.h"
#include "mbox-util.h"
#include "i18n.h"
#include "ttyio.h"
#include "trustdb.h"
#include "mkdir_p.h"
#include "sqlite.h"

#include "tofu.h"


#define CONTROL_L ('L' - 'A' + 1)


#define DEBUG_TOFU_CACHE 0
#if DEBUG_TOFU_CACHE
static int prepares_saved;
static int queries;
#endif

/* The TOFU data can be saved in two different formats: either in a
   single combined database (opt.tofu_db_format == TOFU_DB_FLAT) or in
   a split file format (opt.tofu_db_format == TOFU_DB_SPLIT).  In the
   split format, there is one database per normalized email address
   (DB_EMAIL) and one per key (DB_KEY).  */
enum db_type
  {
    DB_COMBINED,
    DB_EMAIL,
    DB_KEY
  };

/* A list of open DBs.

   In the flat format, this consists of a single element with the type
   DB_COMBINED and whose name is the empty string.

   In the split format, the first element is a dummy element (DB is
   NULL) whose type is DB_COMBINED and whose name is the empty string.
   Any following elements describe either DB_EMAIL or DB_KEY DBs.  In
   theis case, NAME is either the normalized email address or the
   fingerprint.

   To initialize this data structure, call opendbs().  When you are
   done, clean it up using closedbs().  To get a handle to a database,
   use the getdb() function.  This will either return an existing
   handle or open a new DB connection, as appropriate.  */
struct db
{
  struct db *next;
  struct db **prevp;

  enum db_type type;

  sqlite3 *db;

  struct
  {
    sqlite3_stmt *savepoint_batch;
    sqlite3_stmt *savepoint_batch_commit;

    sqlite3_stmt *savepoint_inner;
    sqlite3_stmt *savepoint_inner_commit;

    sqlite3_stmt *record_binding_get_old_policy;
    sqlite3_stmt *record_binding_update;
    sqlite3_stmt *record_binding_update2;
    sqlite3_stmt *get_policy_select_policy_and_conflict;
    sqlite3_stmt *get_trust_bindings_with_this_email;
    sqlite3_stmt *get_trust_gather_other_user_ids;
    sqlite3_stmt *get_trust_gather_other_keys;
    sqlite3_stmt *register_already_seen;
    sqlite3_stmt *register_insert;
  } s;

#if DEBUG_TOFU_CACHE
  int hits;
#endif

  int batch_update;

  /* If TYPE is DB_COMBINED, this is "".  Otherwise, it is either the
     fingerprint (type == DB_KEY) or the normalized email address
     (type == DB_EMAIL).  */
  char name[1];
};

static struct db *db_cache;
static int db_cache_count;
#define DB_CACHE_ENTRIES 16

static void tofu_cache_dump (struct db *db) GPGRT_ATTR_USED;

static void
tofu_cache_dump (struct db *db)
{
  log_info ("Connection %p:\n", db);
  for (; db; db = db->next)
    log_info ("  %s: %sbatch mode\n", db->name, db->batch_update ? "" : "NOT ");
  log_info ("Cache:\n");
  for (db = db_cache; db; db = db->next)
    log_info ("  %s: %sbatch mode\n", db->name, db->batch_update ? "" : "NOT ");
}

#define STRINGIFY(s) STRINGIFY2(s)
#define STRINGIFY2(s) #s

/* The grouping parameters when collecting signature statistics.  */

/* If a message is signed a couple of hours in the future, just assume
   some clock skew.  */
#define TIME_AGO_FUTURE_IGNORE (2 * 60 * 60)
#if 0
#  define TIME_AGO_UNIT_SMALL 60
#  define TIME_AGO_MEDIUM_THRESHOLD (60 * TIME_AGO_UNIT_SMALL)
#  define TIME_AGO_UNIT_MEDIUM (60 * 60)
#  define TIME_AGO_LARGE_THRESHOLD (24 * 60 * TIME_AGO_UNIT_SMALL)
#  define TIME_AGO_UNIT_LARGE (24 * 60 * 60)
#else
#  define TIME_AGO_UNIT_SMALL (24 * 60 * 60)
#  define TIME_AGO_MEDIUM_THRESHOLD (4 * TIME_AGO_UNIT_SMALL)
#  define TIME_AGO_UNIT_MEDIUM (7 * 24 * 60 * 60)
#  define TIME_AGO_LARGE_THRESHOLD (28 * TIME_AGO_UNIT_SMALL)
#  define TIME_AGO_UNIT_LARGE (30 * 24 * 60 * 60)
#endif



const char *
tofu_policy_str (enum tofu_policy policy)
{
  switch (policy)
    {
    case TOFU_POLICY_NONE: return "none";
    case TOFU_POLICY_AUTO: return "auto";
    case TOFU_POLICY_GOOD: return "good";
    case TOFU_POLICY_UNKNOWN: return "unknown";
    case TOFU_POLICY_BAD: return "bad";
    case TOFU_POLICY_ASK: return "ask";
    default: return "???";
    }
}

/* Convert a binding policy (e.g., TOFU_POLICY_BAD) to a trust level
   (e.g., TRUST_BAD) in light of the current configuration.  */
int
tofu_policy_to_trust_level (enum tofu_policy policy)
{
  if (policy == TOFU_POLICY_AUTO)
    /* If POLICY is AUTO, fallback to OPT.TOFU_DEFAULT_POLICY.  */
    policy = opt.tofu_default_policy;

  switch (policy)
    {
    case TOFU_POLICY_AUTO:
      /* If POLICY and OPT.TOFU_DEFAULT_POLICY are both AUTO, default
	 to marginal trust.  */
      return TRUST_MARGINAL;
    case TOFU_POLICY_GOOD:
      return TRUST_FULLY;
    case TOFU_POLICY_UNKNOWN:
      return TRUST_UNKNOWN;
    case TOFU_POLICY_BAD:
      return TRUST_NEVER;
    case TOFU_POLICY_ASK:
      return TRUST_UNKNOWN;
    default:
      log_bug ("Bad value for trust policy: %d\n",
	       opt.tofu_default_policy);
      return 0;
    }
}

static int batch_update;
static time_t batch_update_started;

static gpg_error_t end_transaction (struct db *db, int only_batch);

/* Start a transaction on DB.  */
static gpg_error_t
begin_transaction (struct db *db, int only_batch)
{
  int rc;
  char *err = NULL;

  if (batch_update && batch_update_started != gnupg_get_time ())
    /* We've been in batch update mode for a while (on average, more
       than 500 ms).  To prevent starving other gpg processes, we drop
       and retake the batch lock.

       Note: if we wanted higher resolution, we could use
       npth_clock_gettime.  */
    {
      struct db *t;

      for (t = db_cache; t; t = t->next)
        if (t->batch_update)
          end_transaction (t, 1);
      for (t = db; t; t = t->next)
        if (t->batch_update)
          end_transaction (t, 1);

      batch_update_started = gnupg_get_time ();

      /* Yield to allow another process a chance to run.  */
      sched_yield ();
    }

  /* XXX: In split mode, this can end in deadlock.

     Consider: we have two gpg processes running simultaneously and
     they each want to lock DB A and B, but in different orders.  This
     will be automatically resolved by causing one of them to return
     EBUSY and aborting.

     A more intelligent approach would be to commit and retake the
     batch transaction.  This requires a list of all DBs that are
     currently in batch mode.  */

  if (batch_update && ! db->batch_update)
    {
      rc = sqlite3_stepx (db->db, &db->s.savepoint_batch,
                          NULL, NULL, &err,
                          "savepoint batch;", SQLITE_ARG_END);
      if (rc)
        {
          log_error (_("error beginning transaction on TOFU database: %s\n"),
                     err);
          print_further_info ("batch, database '%s'",
                              *db->name ? db->name : "[combined]");
          sqlite3_free (err);
          return gpg_error (GPG_ERR_GENERAL);
        }

      db->batch_update = 1;
    }

  if (only_batch)
    return 0;

  rc = sqlite3_stepx (db->db, &db->s.savepoint_inner,
                      NULL, NULL, &err,
                      "savepoint inner;", SQLITE_ARG_END);
  if (rc)
    {
      log_error (_("error beginning transaction on TOFU database: %s\n"),
                 err);
      print_further_info ("inner, database '%s'",
                          *db->name ? db->name : "[combined]");
      sqlite3_free (err);
      return gpg_error (GPG_ERR_GENERAL);
    }

  return 0;
}

/* Commit a transaction.  If ONLY_BATCH is 1, then this only ends the
   batch transaction if we have left batch mode.  If ONLY_BATCH is 2,
   this ends any open batch transaction even if we are still in batch
   mode.  */
static gpg_error_t
end_transaction (struct db *db, int only_batch)
{
  int rc;
  char *err = NULL;

  if (!db)
    return 0;  /* Shortcut to allow for easier cleanup code.  */

  if ((! batch_update || only_batch == 2) && db->batch_update)
    /* The batch transaction is still in open, but we left batch
       mode.  */
    {
      db->batch_update = 0;

      rc = sqlite3_stepx (db->db, &db->s.savepoint_batch_commit,
                          NULL, NULL, &err,
                          "release batch;", SQLITE_ARG_END);
      if (rc)
        {
          log_error (_("error committing transaction on TOFU database: %s\n"),
                     err);
          print_further_info ("batch, database '%s'",
                              *db->name ? db->name : "[combined]");
          sqlite3_free (err);
          return gpg_error (GPG_ERR_GENERAL);
        }

      /* Releasing an outer transaction releases an open inner
         transactions.  We're done.  */
      return 0;
    }

  if (only_batch)
    return 0;

  rc = sqlite3_stepx (db->db, &db->s.savepoint_inner_commit,
                      NULL, NULL, &err,
                      "release inner;", SQLITE_ARG_END);
  if (rc)
    {
      log_error (_("error committing transaction on TOFU database: %s\n"),
                 err);
      print_further_info ("inner, database '%s'",
                          *db->name ? db->name : "[combined]");
      sqlite3_free (err);
      return gpg_error (GPG_ERR_GENERAL);
    }

  return 0;
}

static gpg_error_t
rollback_transaction (struct db *db)
{
  int rc;
  char *err = NULL;

  if (!db)
    return 0;  /* Shortcut to allow for easier cleanup code.  */

  if (db->batch_update)
    /* Just undo the most recent update; don't revert any progress
       made by the batch transaction.  */
    rc = sqlite3_exec (db->db, "rollback to inner;", NULL, NULL, &err);
  else
    /* Rollback the whole she-bang.  */
    rc = sqlite3_exec (db->db, "rollback;", NULL, NULL, &err);

  if (rc)
    {
      log_error (_("error rolling back transaction on TOFU database: %s\n"),
                 err);
      print_further_info ("inner, database '%s'",
                          *db->name ? db->name : "[combined]");
      sqlite3_free (err);
      return gpg_error (GPG_ERR_GENERAL);
    }

  return 0;
}

void
tofu_begin_batch_update (void)
{
  if (! batch_update)
    batch_update_started = gnupg_get_time ();

  batch_update ++;
}

void
tofu_end_batch_update (void)
{
  assert (batch_update > 0);
  batch_update --;

  if (batch_update == 0)
    {
      struct db *db;

      for (db = db_cache; db; db = db->next)
        end_transaction (db, 1);
    }
}

/* Collect results of a select count (*) ...; style query.  Aborts if
   the argument is not a valid integer (or real of the form X.0).  */
static int
get_single_unsigned_long_cb (void *cookie, int argc, char **argv,
			     char **azColName)
{
  unsigned long int *count = cookie;
  char *tail = NULL;

  (void) azColName;

  assert (argc == 1);

  errno = 0;
  *count = strtoul (argv[0], &tail, 0);
  if (errno || ! (strcmp (tail, ".0") == 0 || *tail == '\0'))
    /* Abort.  */
    return 1;
  return 0;
}

static int
get_single_unsigned_long_cb2 (void *cookie, int argc, char **argv,
			     char **azColName, sqlite3_stmt *stmt)
{
  (void) stmt;
  return get_single_unsigned_long_cb (cookie, argc, argv, azColName);
}

/* We expect a single integer column whose name is "version".  COOKIE
   must point to an int.  This function always aborts.  On error or a
   if the version is bad, sets *VERSION to -1.  */
static int
version_check_cb (void *cookie, int argc, char **argv, char **azColName)
{
  int *version = cookie;

  if (argc != 1 || strcmp (azColName[0], "version") != 0)
    {
      *version = -1;
      return 1;
    }

  if (strcmp (argv[0], "1") == 0)
    *version = 1;
  else
    {
      log_error (_("unsupported TOFU database version: %s\n"), argv[0]);
      *version = -1;
    }

  /* Don't run again.  */
  return 1;
}


/* If the DB is new, initialize it.  Otherwise, check the DB's
   version.

   Return 0 if the database is okay and 1 otherwise.  */
static int
initdb (sqlite3 *db, enum db_type type)
{
  char *err = NULL;
  int rc;
  unsigned long int count;
  int version = -1;

  rc = sqlite3_exec (db, "begin transaction;", NULL, NULL, &err);
  if (rc)
    {
      log_error (_("error beginning transaction on TOFU database: %s\n"),
		 err);
      sqlite3_free (err);
      return 1;
    }

  /* If the DB has no tables, then assume this is a new DB that needs
     to be initialized.  */
  rc = sqlite3_exec (db,
		     "select count(*) from sqlite_master where type='table';",
		     get_single_unsigned_long_cb, &count, &err);
  if (rc)
    {
      log_error (_("error reading TOFU database: %s\n"), err);
      print_further_info ("query available tables");
      sqlite3_free (err);
      goto out;
    }
  else if (count != 0)
    /* Assume that the DB is already initialized.  Make sure the
       version is okay.  */
    {
      rc = sqlite3_exec (db, "select version from version;", version_check_cb,
			 &version, &err);
      if (rc == SQLITE_ABORT && version == 1)
	/* Happy, happy, joy, joy.  */
	{
	  sqlite3_free (err);
          rc = 0;
          goto out;
	}
      else if (rc == SQLITE_ABORT && version == -1)
	/* Unsupported version.  */
	{
	  /* An error message was already displayed.  */
	  sqlite3_free (err);
          goto out;
	}
      else if (rc)
	/* Some error.  */
	{
	  log_error (_("error determining TOFU database's version: %s\n"), err);
	  sqlite3_free (err);
          goto out;
	}
      else
        {
          /* Unexpected success.  This can only happen if there are no
             rows.  (select returned 0, but expected ABORT.)  */
	  log_error (_("error determining TOFU database's version: %s\n"),
                     gpg_strerror (GPG_ERR_NO_DATA));
          rc = 1;
          goto out;
	}
    }

  /* Create the version table.  */
  rc = sqlite3_exec (db,
		     "create table version (version INTEGER);",
		     NULL, NULL, &err);
  if (rc)
    {
      log_error (_("error initializing TOFU database: %s\n"), err);
      print_further_info ("create version");
      sqlite3_free (err);
      goto out;
    }

  /* Initialize the version table, which contains a single integer
     value.  */
  rc = sqlite3_exec (db,
		     "insert into version values (1);",
		     NULL, NULL, &err);
  if (rc)
    {
      log_error (_("error initializing TOFU database: %s\n"), err);
      print_further_info ("insert version");
      sqlite3_free (err);
      goto out;
    }

  /* The list of <fingerprint, email> bindings and auxiliary data.
   *
   *  OID is a unique ID identifying this binding (and used by the
   *    signatures table, see below).  Note: OIDs will never be
   *    reused.
   *
   *  FINGERPRINT: The key's fingerprint.
   *
   *  EMAIL: The normalized email address.
   *
   *  USER_ID: The unmodified user id from which EMAIL was extracted.
   *
   *  TIME: The time this binding was first observed.
   *
   *  POLICY: The trust policy (TOFU_POLICY_BAD, etc. as an integer).
   *
   *  CONFLICT is either NULL or a fingerprint.  Assume that we have
   *    a binding <0xdeadbeef, foo@example.com> and then we observe
   *    <0xbaddecaf, foo@example.com>.  There two bindings conflict
   *    (they have the same email address).  When we observe the
   *    latter binding, we warn the user about the conflict and ask
   *    for a policy decision about the new binding.  We also change
   *    the old binding's policy to ask if it was auto.  So that we
   *     know why this occurred, we also set conflict to 0xbaddecaf.
   */
  if (type == DB_EMAIL || type == DB_COMBINED)
    rc = sqlite3_exec_printf
      (db, NULL, NULL, &err,
       "create table bindings\n"
       " (oid INTEGER PRIMARY KEY AUTOINCREMENT,\n"
       "  fingerprint TEXT, email TEXT, user_id TEXT, time INTEGER,\n"
       "  policy BOOLEAN CHECK (policy in (%d, %d, %d, %d, %d)),\n"
       "  conflict STRING,\n"
       "  unique (fingerprint, email));\n"
       "create index bindings_fingerprint_email\n"
       " on bindings (fingerprint, email);\n"
       "create index bindings_email on bindings (email);\n",
       TOFU_POLICY_AUTO, TOFU_POLICY_GOOD, TOFU_POLICY_UNKNOWN,
       TOFU_POLICY_BAD, TOFU_POLICY_ASK);
  else
    /* In the split DB case, the fingerprint DB only contains a subset
       of the fields.  This reduces the amount of duplicated data.

       Note: since the data is split on the email address, there is no
       need to index the email column.  */
    rc = sqlite3_exec_printf
      (db, NULL, NULL, &err,
       "create table bindings\n"
       " (oid INTEGER PRIMARY KEY AUTOINCREMENT,\n"
       "  fingerprint TEXT, email TEXT, user_id,\n"
       "  unique (fingerprint, email));\n"
       "create index bindings_fingerprint\n"
       " on bindings (fingerprint);\n");
  if (rc)
    {
      log_error (_("error initializing TOFU database: %s\n"), err);
      print_further_info ("create bindings");
      sqlite3_free (err);
      goto out;
    }

  if (type != DB_KEY)
    {
      /* The signatures that we have observed.

	 BINDING refers to a record in the bindings table, which
         describes the binding (i.e., this is a foreign key that
         references bindings.oid).

	 SIG_DIGEST is the digest stored in the signature.

	 SIG_TIME is the timestamp stored in the signature.

	 ORIGIN is a free-form string that describes who fed this
         signature to GnuPG (e.g., email:claws).

	 TIME is the time this signature was registered.  */
      rc = sqlite3_exec (db,
			 "create table signatures "
			 " (binding INTEGER NOT NULL, sig_digest TEXT,"
			 "  origin TEXT, sig_time INTEGER, time INTEGER,"
			 "  primary key (binding, sig_digest, origin));",
			 NULL, NULL, &err);
      if (rc)
	{
          log_error (_("error initializing TOFU database: %s\n"), err);
          print_further_info ("create signatures");
	  sqlite3_free (err);
	  goto out;
	}
    }

 out:
  if (rc)
    {
      rc = sqlite3_exec (db, "rollback;", NULL, NULL, &err);
      if (rc)
	{
	  log_error (_("error rolling back transaction on TOFU database: %s\n"),
		     err);
	  sqlite3_free (err);
	}
      return 1;
    }
  else
    {
      rc = sqlite3_exec (db, "end transaction;", NULL, NULL, &err);
      if (rc)
	{
	  log_error (_("error committing transaction on TOFU database: %s\n"),
		     err);
	  sqlite3_free (err);
	  return 1;
	}
      return 0;
    }
}

/* Open and initialize a low-level TOFU database.  Returns NULL on
   failure.  This function should not normally be directly called to
   get a database handle.  Instead, use getdb().  */
static sqlite3 *
opendb (char *filename, enum db_type type)
{
  sqlite3 *db;
  int filename_free = 0;
  int rc;

  if (opt.tofu_db_format == TOFU_DB_FLAT)
    {
      assert (! filename);
      assert (type == DB_COMBINED);

      filename = make_filename (opt.homedir, "tofu.db", NULL);
      filename_free = 1;
    }
  else
    assert (type == DB_EMAIL || type == DB_KEY);

  assert (filename);

  rc = sqlite3_open (filename, &db);
  if (rc)
    {
      log_error (_("error opening TOFU database '%s': %s\n"),
                 filename, sqlite3_errmsg (db));
      /* Even if an error occurs, DB is guaranteed to be valid.  */
      sqlite3_close (db);
      db = NULL;
    }

  /* If a DB is locked wait up to 5 seconds for the lock to be cleared
     before failing.  */
  sqlite3_busy_timeout (db, 5 * 1000);

  if (filename_free)
    xfree (filename);

  if (db && initdb (db, type))
    {
      sqlite3_close (db);
      db = NULL;
    }

  return db;
}

struct dbs
{
  struct db *db;
};

static void
unlink_db (struct db *db)
{
  *db->prevp = db->next;
  if (db->next)
    db->next->prevp = db->prevp;
}

static void
link_db (struct db **head, struct db *db)
{
  db->next = *head;
  if (db->next)
    db->next->prevp = &db->next;
  db->prevp = head;
  *head = db;
}

/* Return a database handle.  <type, name> describes the required
   database.  If there is a cached handle in DBS, that handle is
   returned.  Otherwise, the database is opened and cached in DBS.

   NAME is the name of the DB and may not be NULL.

   TYPE must be either DB_MAIL or DB_KEY.  In the combined format, the
   combined DB is always returned.  */
static struct db *
getdb (struct dbs *dbs, const char *name, enum db_type type)
{
  struct db *t = NULL;
  char *name_sanitized = NULL;
  int count;
  char *filename = NULL;
  int need_link = 1;
  sqlite3 *sqlitedb = NULL;
  gpg_error_t rc;

  assert (dbs);
  assert (name);
  assert (type == DB_EMAIL || type == DB_KEY);

  if (opt.tofu_db_format == TOFU_DB_FLAT)
    /* When using the flat format, we only have a single DB, the
       combined DB.  */
    {
      if (dbs->db)
        {
          assert (dbs->db->type == DB_COMBINED);
          assert (! dbs->db->next);
          return dbs->db;
        }

      type = DB_COMBINED;
    }

  if (type != DB_COMBINED)
    /* Only allow alpha-numeric characters in the name.  */
    {
      int i;

      name_sanitized = xstrdup (name);
      for (i = 0; name[i]; i ++)
        {
          char c = name_sanitized[i];
          if (! (('a' <= c && c <= 'z')
                 || ('A' <= c && c <= 'Z')
                 || ('0' <= c && c <= '9')))
            name_sanitized[i] = '_';
        }
    }

  /* See if the DB is cached.  */
  for (t = dbs->db; t; t = t->next)
    if (t->type == type
        && (type == DB_COMBINED || strcmp (t->name, name_sanitized) == 0))
      {
        need_link = 0;
        goto out;
      }

  for (t = db_cache, count = 0; t; t = t->next, count ++)
    if (type == t->type
        && (type == DB_COMBINED || strcmp (t->name, name_sanitized) == 0))
      {
        unlink_db (t);
        db_cache_count --;
        goto out;
      }

  assert (db_cache_count == count);

  if (type == DB_COMBINED)
    filename = NULL;
  else
    {
      /* Open the DB.  The filename has the form:

         tofu.d/TYPE/PREFIX/NAME.db

         We use a short prefix to try to avoid having many files in a
         single directory.  */
      {
        char *type_str = type == DB_EMAIL ? "email" : "key";
        char prefix[3] = { name_sanitized[0], name_sanitized[1], 0 };
        char *name_db;

        /* Make the directory.  */
        rc = gnupg_mkdir_p (opt.homedir, "tofu.d", type_str, prefix, NULL);
        if (rc)
          {
            name_db = xstrconcat (opt.homedir, "tofu.d",
                                  type_str, prefix, NULL);
            log_error (_("can't create directory '%s': %s\n"),
                       name_db, gpg_strerror (rc));
            xfree (name_db);
            goto out;
          }

        name_db = xstrconcat (name_sanitized, ".db", NULL);
        filename = make_filename
          (opt.homedir, "tofu.d", type_str, prefix, name_db, NULL);
        xfree (name_db);
      }
    }

  sqlitedb = opendb (filename, type);
  if (! sqlitedb)
    goto out;

  t = xmalloc_clear (sizeof (struct db)
                     + (name_sanitized ? strlen (name_sanitized) : 0));
  t->type = type;
  t->db = sqlitedb;
  if (name_sanitized)
    strcpy (t->name, name_sanitized);

 out:
  if (t && need_link)
    link_db (&dbs->db, t);

#if DEBUG_TOFU_CACHE
  if (t)
    t->hits ++;
#endif

  xfree (filename);
  xfree (name_sanitized);
  return t;
}

static void
closedb (struct db *db)
{
  sqlite3_stmt **statements;

  if (opt.tofu_db_format == TOFU_DB_FLAT)
    /* If we are using the flat format, then there is only ever the
       combined DB.  */
    assert (! db->next);

  if (db->type == DB_COMBINED)
    {
      assert (opt.tofu_db_format == TOFU_DB_FLAT);
      assert (! db->name[0]);
    }
  else
    {
      assert (opt.tofu_db_format == TOFU_DB_SPLIT);
      assert (db->type != DB_COMBINED);
      assert (db->name[0]);
    }

  if (db->batch_update)
    end_transaction (db, 2);

  for (statements = (void *) &db->s;
       (void *) statements < (void *) &(&db->s)[1];
       statements ++)
    sqlite3_finalize (*statements);

  sqlite3_close (db->db);

#if DEBUG_TOFU_CACHE
  log_debug ("Freeing db.  Used %d times.\n", db->hits);
#endif

  xfree (db);
}


/* Create a new DB meta-handle.  Returns NULL on error.  */
/* FIXME: Change to return an error code for better reporting by the
   caller.  */
static struct dbs *
opendbs (void)
{
  if (opt.tofu_db_format == TOFU_DB_AUTO)
    {
      char *filename = make_filename (opt.homedir, "tofu.db", NULL);
      struct stat s;
      int have_tofu_db = 0;
      int have_tofu_d = 0;

      if (stat (filename, &s) == 0)
	{
	  have_tofu_db = 1;
	  if (DBG_TRUST)
	    log_debug ("%s exists.\n", filename);
	}
      else
	{
	  if (DBG_TRUST)
	    log_debug ("%s does not exist.\n", filename);
	}

      /* We now have tofu.d.  */
      filename[strlen (filename) - 1] = '\0';
      if (stat (filename, &s) == 0)
	{
	  have_tofu_d = 1;
	  if (DBG_TRUST)
	    log_debug ("%s exists.\n", filename);
	}
      else
	{
	  if (DBG_TRUST)
	    log_debug ("%s does not exist.\n", filename);
	}

      xfree (filename);

      if (have_tofu_db && have_tofu_d)
	{
	  log_info (_("Warning: Home directory contains both tofu.db"
                      " and tofu.d.\n"));
          log_info (_("Using split format for TOFU database\n"));
	  opt.tofu_db_format = TOFU_DB_SPLIT;
	}
      else if (have_tofu_db)
	{
	  opt.tofu_db_format = TOFU_DB_FLAT;
	  if (DBG_TRUST)
	    log_debug ("Using flat format for TOFU database.\n");
	}
      else if (have_tofu_d)
	{
	  opt.tofu_db_format = TOFU_DB_SPLIT;
	  if (DBG_TRUST)
	    log_debug ("Using split format for TOFU database.\n");
	}
      else
	{
	  opt.tofu_db_format = TOFU_DB_FLAT;
	  if (DBG_TRUST)
	    log_debug ("Using flat format for TOFU database.\n");
	}
    }

  return xmalloc_clear (sizeof (struct dbs));
}

/* Release all of the resources associated with a DB meta-handle.  */
static void
closedbs (struct dbs *dbs)
{
  if (dbs->db)
    {
      struct db *old_head = db_cache;
      struct db *db;
      int count;

      /* Find the last DB.  */
      for (db = dbs->db, count = 1; db->next; db = db->next, count ++)
        {
          /* When we leave batch mode we leave batch mode on any
             cached connections.  */
          if (! batch_update)
            assert (! db->batch_update);
        }
      if (! batch_update)
        assert (! db->batch_update);

      /* Join the two lists.  */
      db->next = db_cache;
      if (db_cache)
        db_cache->prevp = &db->next;

      /* Update the (new) first element.  */
      db_cache = dbs->db;
      dbs->db->prevp = &db_cache;

      db_cache_count += count;

      /* Make sure that we don't have too many DBs on DB_CACHE.  If
         so, free some.  */
      if (db_cache_count > DB_CACHE_ENTRIES)
        {
          /* We need to find the (DB_CACHE_ENTRIES + 1)th entry.  It
             is easy to skip the first COUNT entries since we still
             have a handle on the old head.  */
          int skip = DB_CACHE_ENTRIES - count;
          while (-- skip > 0)
            old_head = old_head->next;

          *old_head->prevp = NULL;

          while (old_head)
            {
              db = old_head->next;
              closedb (old_head);
              old_head = db;
              db_cache_count --;
            }
        }
    }

  xfree (dbs);

#if DEBUG_TOFU_CACHE
  log_debug ("Queries: %d (prepares saved: %d)\n",
             queries, prepares_saved);
#endif
}


/* Collect results of a select min (foo) ...; style query.  Aborts if
   the argument is not a valid integer (or real of the form X.0).  */
static int
get_single_long_cb (void *cookie, int argc, char **argv, char **azColName)
{
  long *count = cookie;
  char *tail = NULL;

  (void) azColName;

  assert (argc == 1);

  errno = 0;
  *count = strtol (argv[0], &tail, 0);
  if (errno || ! (strcmp (tail, ".0") == 0 || *tail == '\0'))
    /* Abort.  */
    return 1;
  return 0;
}

static int
get_single_long_cb2 (void *cookie, int argc, char **argv, char **azColName,
                     sqlite3_stmt *stmt)
{
  (void) stmt;
  return get_single_long_cb (cookie, argc, argv, azColName);
}

/* Record (or update) a trust policy about a (possibly new)
   binding.

   If SHOW_OLD is set, the binding's old policy is displayed.  */
static gpg_error_t
record_binding (struct dbs *dbs, const char *fingerprint, const char *email,
		const char *user_id, enum tofu_policy policy, int show_old)
{
  char *fingerprint_pp = format_hexfingerprint (fingerprint, NULL, 0);
  struct db *db_email = NULL, *db_key = NULL;
  gpg_error_t rc;
  char *err = NULL;
  /* policy_old needs to be a long and not an enum tofu_policy,
     because we pass it by reference to get_single_long_cb2, which
     expects a long.  */
  long policy_old = TOFU_POLICY_NONE;

  if (! (policy == TOFU_POLICY_AUTO
	 || policy == TOFU_POLICY_GOOD
	 || policy == TOFU_POLICY_UNKNOWN
	 || policy == TOFU_POLICY_BAD
	 || policy == TOFU_POLICY_ASK))
    log_bug ("%s: Bad value for policy (%d)!\n", __func__, policy);

  db_email = getdb (dbs, email, DB_EMAIL);
  if (! db_email)
    {
      rc = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }

  if (opt.tofu_db_format == TOFU_DB_SPLIT)
    /* In the split format, we need to update two DBs.  To keep them
       consistent, we start a transaction on each.  Note: this is the
       only place where we start two transaction and we always start
       transaction on the DB_KEY DB first, thus deadlock is not
       possible.  */
    {
      db_key = getdb (dbs, fingerprint, DB_KEY);
      if (! db_key)
        {
          rc = gpg_error (GPG_ERR_GENERAL);
          goto leave;
        }

      rc = begin_transaction (db_email, 0);
      if (rc)
        goto leave;

      rc = begin_transaction (db_key, 0);
      if (rc)
        goto out_revert_one;
    }
  else
    {
      rc = begin_transaction (db_email, 1);
      if (rc)
        goto leave;
    }


  if (show_old)
    /* Get the old policy.  Since this is just for informational
       purposes, there is no need to start a transaction or to die if
       there is a failure.  */
    {
      rc = sqlite3_stepx
	(db_email->db, &db_email->s.record_binding_get_old_policy,
         get_single_long_cb2, &policy_old, &err,
	 "select policy from bindings where fingerprint = ? and email = ?",
	 SQLITE_ARG_STRING, fingerprint, SQLITE_ARG_STRING, email,
         SQLITE_ARG_END);
      if (rc)
	{
	  log_debug ("TOFU: Error reading from binding database"
		     " (reading policy for <%s, %s>): %s\n",
		     fingerprint_pp, email, err);
	  sqlite3_free (err);
	}
    }

  if (DBG_TRUST)
    {
      if (policy_old != TOFU_POLICY_NONE)
	log_debug ("Changing TOFU trust policy for binding <%s, %s>"
		   " from %s to %s.\n",
		   fingerprint_pp, email,
		   tofu_policy_str (policy_old),
		   tofu_policy_str (policy));
      else
	log_debug ("Set TOFU trust policy for binding <%s, %s> to %s.\n",
		   fingerprint_pp, email,
		   tofu_policy_str (policy));
    }

  if (policy_old == policy)
    /* Nothing to do.  */
    goto out;

  rc = sqlite3_stepx
    (db_email->db, &db_email->s.record_binding_update, NULL, NULL, &err,
     "insert or replace into bindings\n"
     " (oid, fingerprint, email, user_id, time, policy)\n"
     " values (\n"
     /* If we don't explicitly reuse the OID, then SQLite will
	reallocate a new one.  We just need to search for the OID
	based on the fingerprint and email since they are unique.  */
     "  (select oid from bindings where fingerprint = ? and email = ?),\n"
     "  ?, ?, ?, strftime('%s','now'), ?);",
     SQLITE_ARG_STRING, fingerprint, SQLITE_ARG_STRING, email,
     SQLITE_ARG_STRING, fingerprint, SQLITE_ARG_STRING, email,
     SQLITE_ARG_STRING, user_id, SQLITE_ARG_INT, (int) policy,
     SQLITE_ARG_END);
  if (rc)
    {
      log_error (_("error updating TOFU database: %s\n"), err);
      print_further_info (" insert bindings <%s, %s> = %s",
                          fingerprint_pp, email, tofu_policy_str (policy));
      sqlite3_free (err);
      goto out;
    }

  if (db_key)
    /* We also need to update the key DB.  */
    {
      assert (opt.tofu_db_format == TOFU_DB_SPLIT);

      rc = sqlite3_stepx
	(db_key->db, &db_key->s.record_binding_update2, NULL, NULL, &err,
	 "insert or replace into bindings\n"
	 " (oid, fingerprint, email, user_id)\n"
	 " values (\n"
	 /* If we don't explicitly reuse the OID, then SQLite will
	    reallocate a new one.  We just need to search for the OID
	    based on the fingerprint and email since they are unique.  */
	 "  (select oid from bindings where fingerprint = ? and email = ?),\n"
	 "  ?, ?, ?);",
	 SQLITE_ARG_STRING, fingerprint, SQLITE_ARG_STRING, email,
         SQLITE_ARG_STRING, fingerprint, SQLITE_ARG_STRING, email,
         SQLITE_ARG_STRING, user_id, SQLITE_ARG_END);
      if (rc)
	{
	  log_error (_("error updating TOFU database: %s\n"), err);
          print_further_info ("insert bindings <%s, %s>",
                              fingerprint_pp, email);
	  sqlite3_free (err);
	  goto out;
	}
    }
  else
    assert (opt.tofu_db_format == TOFU_DB_FLAT);

 out:
  if (opt.tofu_db_format == TOFU_DB_SPLIT)
    /* We only need a transaction for the split format.  */
    {
      gpg_error_t rc2;

      if (rc)
        rc2 = rollback_transaction (db_key);
      else
        rc2 = end_transaction (db_key, 0);
      if (rc2)
        sqlite3_free (err);

    out_revert_one:
      if (rc)
        rc2 = rollback_transaction (db_email);
      else
        rc2 = end_transaction (db_email, 0);
      if (rc2)
        sqlite3_free (err);
    }

 leave:
  xfree (fingerprint_pp);

  return rc;
}


/* Collect the strings returned by a query in a simply string list.
   Any NULL values are converted to the empty string.

   If a result has 3 rows and each row contains two columns, then the
   results are added to the list as follows (the value is parentheses
   is the 1-based index in the final list):

     row 1, col 2 (6)
     row 1, col 1 (5)
     row 2, col 2 (4)
     row 2, col 1 (3)
     row 3, col 2 (2)
     row 3, col 1 (1)

   This is because add_to_strlist pushes the results onto the front of
   the list.  The end result is that the rows are backwards, but the
   columns are in the expected order.  */
static int
strings_collect_cb (void *cookie, int argc, char **argv, char **azColName)
{
  int i;
  strlist_t *strlist = cookie;

  (void) azColName;

  for (i = argc - 1; i >= 0; i --)
    add_to_strlist (strlist, argv[i] ? argv[i] : "");

  return 0;
}

static int
strings_collect_cb2 (void *cookie, int argc, char **argv, char **azColName,
                     sqlite3_stmt *stmt)
{
  (void) stmt;
  return strings_collect_cb (cookie, argc, argv, azColName);

}

/* Auxiliary data structure to collect statistics about
   signatures.  */
struct signature_stats
{
  struct signature_stats *next;

  /* The user-assigned policy for this binding.  */
  enum tofu_policy policy;

  /* How long ago the signature was created (rounded to a multiple of
     TIME_AGO_UNIT_SMALL, etc.).  */
  long time_ago;
  /* Number of signatures during this time.  */
  unsigned long count;

  /* The key that generated this signature.  */
  char fingerprint[1];
};

static void
signature_stats_free (struct signature_stats *stats)
{
  while (stats)
    {
      struct signature_stats *next = stats->next;
      xfree (stats);
      stats = next;
    }
}

static void
signature_stats_prepend (struct signature_stats **statsp,
			 const char *fingerprint,
			 enum tofu_policy policy,
			 long time_ago,
			 unsigned long count)
{
  struct signature_stats *stats =
    xmalloc (sizeof (*stats) + strlen (fingerprint));

  stats->next = *statsp;
  *statsp = stats;

  strcpy (stats->fingerprint, fingerprint);
  stats->policy = policy;
  stats->time_ago = time_ago;
  stats->count = count;
}


/* Process rows that contain the four columns:

     <fingerprint, policy, time ago, count>.  */
static int
signature_stats_collect_cb (void *cookie, int argc, char **argv,
			    char **azColName, sqlite3_stmt *stmt)
{
  struct signature_stats **statsp = cookie;
  char *tail;
  int i = 0;
  enum tofu_policy policy;
  long time_ago;
  unsigned long count;

  (void) azColName;
  (void) stmt;

  i ++;

  tail = NULL;
  errno = 0;
  policy = strtol (argv[i], &tail, 0);
  if (errno || ! (strcmp (tail, ".0") == 0 || *tail == '\0'))
    {
      /* Abort.  */
      log_error ("%s: Error converting %s to an integer (tail = '%s')\n",
		 __func__, argv[i], tail);
      return 1;
    }
  i ++;

  if (! argv[i])
    time_ago = 0;
  else
    {
      tail = NULL;
      errno = 0;
      time_ago = strtol (argv[i], &tail, 0);
      if (errno || ! (strcmp (tail, ".0") == 0 || *tail == '\0'))
        {
          /* Abort.  */
          log_error ("%s: Error converting %s to an integer (tail = '%s')\n",
                     __func__, argv[i], tail);
          return 1;
        }
    }
  i ++;

  /* If time_ago is NULL, then we had no messages, but we still have a
     single row, which count(*) turns into 1.  */
  if (! argv[i - 1])
    count = 0;
  else
    {
      tail = NULL;
      errno = 0;
      count = strtoul (argv[i], &tail, 0);
      if (errno || ! (strcmp (tail, ".0") == 0 || *tail == '\0'))
        {
          /* Abort.  */
          log_error ("%s: Error converting %s to an integer (tail = '%s')\n",
                     __func__, argv[i], tail);
          return 1;
        }
    }
  i ++;

  assert (argc == i);

  signature_stats_prepend (statsp, argv[0], policy, time_ago, count);

  return 0;
}

/* Convert from seconds to time units.

   Note: T should already be a multiple of TIME_AGO_UNIT_SMALL or
   TIME_AGO_UNIT_MEDIUM or TIME_AGO_UNIT_LARGE.  */
signed long
time_ago_scale (signed long t)
{
  if (t < TIME_AGO_UNIT_MEDIUM)
    return t / TIME_AGO_UNIT_SMALL;
  if (t < TIME_AGO_UNIT_LARGE)
    return t / TIME_AGO_UNIT_MEDIUM;
  return t / TIME_AGO_UNIT_LARGE;
}


/* Return the policy for the binding <FINGERPRINT, EMAIL> (email has
   already been normalized) and any conflict information in *CONFLICT
   if CONFLICT is not NULL.  Returns _tofu_GET_POLICY_ERROR if an error
   occurs.  */
static enum tofu_policy
get_policy (struct dbs *dbs, const char *fingerprint, const char *email,
	    char **conflict)
{
  struct db *db;
  int rc;
  char *err = NULL;
  strlist_t strlist = NULL;
  char *tail = NULL;
  enum tofu_policy policy = _tofu_GET_POLICY_ERROR;

  db = getdb (dbs, email, DB_EMAIL);
  if (! db)
    return _tofu_GET_POLICY_ERROR;

  /* Check if the <FINGERPRINT, EMAIL> binding is known
     (TOFU_POLICY_NONE cannot appear in the DB.  Thus, if POLICY is
     still TOFU_POLICY_NONE after executing the query, then the
     result set was empty.)  */
  rc = sqlite3_stepx (db->db, &db->s.get_policy_select_policy_and_conflict,
                      strings_collect_cb2, &strlist, &err,
                      "select policy, conflict from bindings\n"
                      " where fingerprint = ? and email = ?",
                      SQLITE_ARG_STRING, fingerprint,
                      SQLITE_ARG_STRING, email,
                      SQLITE_ARG_END);
  if (rc)
    {
      log_error (_("error reading TOFU database: %s\n"), err);
      print_further_info ("checking for existing bad bindings");
      sqlite3_free (err);
      goto out;
    }

  if (strlist_length (strlist) == 0)
    /* No results.  */
    {
      policy = TOFU_POLICY_NONE;
      goto out;
    }
  else if (strlist_length (strlist) != 2)
    /* The result has the wrong form.  */
    {
      log_error (_("error reading TOFU database: %s\n"),
                 gpg_strerror (GPG_ERR_BAD_DATA));
      print_further_info ("checking for existing bad bindings:"
                          " expected 2 results, got %d\n",
                          strlist_length (strlist));
      goto out;
    }

  /* The result has the right form.  */

  errno = 0;
  policy = strtol (strlist->d, &tail, 0);
  if (errno || *tail != '\0')
    {
      log_error (_("error reading TOFU database: %s\n"),
                 gpg_strerror (GPG_ERR_BAD_DATA));
      print_further_info ("bad value for policy: %s", strlist->d);
      goto out;
    }

  if (! (policy == TOFU_POLICY_AUTO
	 || policy == TOFU_POLICY_GOOD
	 || policy == TOFU_POLICY_UNKNOWN
	 || policy == TOFU_POLICY_BAD
	 || policy == TOFU_POLICY_ASK))
    {
      log_error (_("error reading TOFU database: %s\n"),
                 gpg_strerror (GPG_ERR_DB_CORRUPTED));
      print_further_info ("invalid value for policy (%d)", policy);
      policy = _tofu_GET_POLICY_ERROR;
      goto out;
    }


  /* If CONFLICT is set, then policy should be TOFU_POLICY_ASK.  But,
     just in case, we do the check again here and ignore the conflict
     is POLICY is not TOFU_POLICY_ASK.  */
  if (conflict)
    {
      if (policy == TOFU_POLICY_ASK && *strlist->next->d)
	*conflict = xstrdup (strlist->next->d);
      else
	*conflict = NULL;
    }

 out:
  assert (policy == _tofu_GET_POLICY_ERROR
	  || policy == TOFU_POLICY_NONE
	  || policy == TOFU_POLICY_AUTO
	  || policy == TOFU_POLICY_GOOD
	  || policy == TOFU_POLICY_UNKNOWN
	  || policy == TOFU_POLICY_BAD
	  || policy == TOFU_POLICY_ASK);

  free_strlist (strlist);

  return policy;
}

/* Return the trust level (TRUST_NEVER, etc.) for the binding
   <FINGERPRINT, EMAIL> (email is already normalized).  If no policy
   is registered, returns TOFU_POLICY_NONE.  If an error occurs,
   returns _tofu_GET_TRUST_ERROR.

   USER_ID is the unadultered user id.

   If MAY_ASK is set, then we may interact with the user.  This is
   necessary if there is a conflict or the binding's policy is
   TOFU_POLICY_ASK.  In the case of a conflict, we set the new
   conflicting binding's policy to TOFU_POLICY_ASK.  In either case,
   we return TRUST_UNDEFINED.  */
static enum tofu_policy
get_trust (struct dbs *dbs, const char *fingerprint, const char *email,
	   const char *user_id, int may_ask)
{
  char *fingerprint_pp;
  struct db *db;
  enum tofu_policy policy;
  char *conflict = NULL;
  int rc;
  char *err = NULL;
  strlist_t bindings_with_this_email = NULL;
  int bindings_with_this_email_count;
  int change_conflicting_to_ask = 0;
  int trust_level = TRUST_UNKNOWN;

  if (opt.batch)
    may_ask = 0;

  /* Make sure _tofu_GET_TRUST_ERROR isn't equal to any of the trust
     levels.  */
  assert (_tofu_GET_TRUST_ERROR != TRUST_UNKNOWN
	  && _tofu_GET_TRUST_ERROR != TRUST_EXPIRED
	  && _tofu_GET_TRUST_ERROR != TRUST_UNDEFINED
	  && _tofu_GET_TRUST_ERROR != TRUST_NEVER
	  && _tofu_GET_TRUST_ERROR != TRUST_MARGINAL
	  && _tofu_GET_TRUST_ERROR != TRUST_FULLY
	  && _tofu_GET_TRUST_ERROR != TRUST_ULTIMATE);

  db = getdb (dbs, email, DB_EMAIL);
  if (! db)
    return _tofu_GET_TRUST_ERROR;

  fingerprint_pp = format_hexfingerprint (fingerprint, NULL, 0);

  policy = get_policy (dbs, fingerprint, email, &conflict);
  if (policy == TOFU_POLICY_AUTO || policy == TOFU_POLICY_NONE)
    /* See if the key is ultimately trusted.  If so, we're done.  */
    {
      PKT_public_key *pk;
      u32 kid[2];
      char fpr_bin[MAX_FINGERPRINT_LEN+1];
      size_t fpr_bin_len;

      if (!hex2str (fingerprint, fpr_bin, sizeof fpr_bin, &fpr_bin_len))
        {
          log_error ("error converting fingerprint: %s\n",
                     gpg_strerror (gpg_error_from_syserror ()));
          return _tofu_GET_TRUST_ERROR;
        }

      /* We need to lookup the key by fingerprint again so that we can
         properly extract the keyid.  Extracting direct from the
         fingerprint works only for v4 keys and would assume that
         there is no collision in the low 64 bit.  We can't guarantee
         the latter in case the Tofu DB is used with a different
         keyring.  In any case the UTK stuff needs to be changed to
         use only fingerprints.  */
      pk = xtrycalloc (1, sizeof *pk);
      if (!pk)
         {
           log_error (_("out of core\n"));
           return _tofu_GET_TRUST_ERROR;
         }
      rc = get_pubkey_byfprint_fast (pk, fpr_bin, fpr_bin_len);
      if (rc)
        {
          log_error (_("public key %s not found: %s\n"),
                     fingerprint, gpg_strerror (rc));
          return _tofu_GET_TRUST_ERROR;
        }
      keyid_from_pk (pk, kid);
      free_public_key (pk);

      if (tdb_keyid_is_utk (kid))
        {
          if (policy == TOFU_POLICY_NONE)
            {
              if (record_binding (dbs, fingerprint, email, user_id,
                                  TOFU_POLICY_AUTO, 0) != 0)
                {
                  log_error (_("error setting TOFU binding's trust level"
                               " to %s\n"), "auto");
                  trust_level = _tofu_GET_TRUST_ERROR;
                  goto out;
                }
            }

          trust_level = TRUST_ULTIMATE;
          goto out;
        }
    }

  if (policy == TOFU_POLICY_AUTO)
    {
      policy = opt.tofu_default_policy;
      if (DBG_TRUST)
	log_debug ("TOFU: binding <%s, %s>'s policy is auto (default: %s).\n",
		   fingerprint_pp, email,
		   tofu_policy_str (opt.tofu_default_policy));
    }
  switch (policy)
    {
    case TOFU_POLICY_AUTO:
    case TOFU_POLICY_GOOD:
    case TOFU_POLICY_UNKNOWN:
    case TOFU_POLICY_BAD:
      /* The saved judgement is auto -> auto, good, unknown or bad.
	 We don't need to ask the user anything.  */
      if (DBG_TRUST)
	log_debug ("TOFU: Known binding <%s, %s>'s policy: %s\n",
		   fingerprint_pp, email, tofu_policy_str (policy));
      trust_level = tofu_policy_to_trust_level (policy);
      goto out;

    case TOFU_POLICY_ASK:
      /* We need to ask the user what to do.  Case #1 or #2 below.  */
      if (! may_ask)
	{
	  trust_level = TRUST_UNDEFINED;
	  goto out;
	}

      break;

    case TOFU_POLICY_NONE:
      /* The binding is new, we need to check for conflicts.  Case #3
	 below.  */
      break;

    case _tofu_GET_POLICY_ERROR:
      trust_level = _tofu_GET_TRUST_ERROR;
      goto out;

    default:
      log_bug ("%s: Impossible value for policy (%d)\n", __func__, policy);
    }


  /* We get here if:

       1. The saved policy is auto and the default policy is ask
          (get_policy() == TOFU_POLICY_AUTO
           && opt.tofu_default_policy == TOFU_POLICY_ASK)

       2. The saved policy is ask (either last time the user selected
          accept once or reject once or there was a conflict and this
          binding's policy was changed from auto to ask)
	  (policy == TOFU_POLICY_ASK), or,

       3. We don't have a saved policy (policy == TOFU_POLICY_NONE)
          (need to check for a conflict).
   */

  /* Look for conflicts.  This is needed in all 3 cases.

     Get the fingerprints of any bindings that share the email
     address.  Note: if the binding in question is in the DB, it will
     also be returned.  Thus, if the result set is empty, then this is
     a new binding.  */
  rc = sqlite3_stepx
    (db->db, &db->s.get_trust_bindings_with_this_email,
     strings_collect_cb2, &bindings_with_this_email, &err,
     "select distinct fingerprint from bindings where email = ?;",
     SQLITE_ARG_STRING, email, SQLITE_ARG_END);
  if (rc)
    {
      log_error (_("error reading TOFU database: %s\n"), err);
      print_further_info ("listing fingerprints");
      sqlite3_free (err);
      goto out;
    }

  bindings_with_this_email_count = strlist_length (bindings_with_this_email);
  if (bindings_with_this_email_count == 0
      && opt.tofu_default_policy != TOFU_POLICY_ASK)
    /* New binding with no conflict and a concrete default policy.

       We've never observed a binding with this email address
       (BINDINGS_WITH_THIS_EMAIL_COUNT is 0 and the above query would return
       the current binding if it were in the DB) and we have a default
       policy, which is not to ask the user.  */
    {
      /* If we've seen this binding, then we've seen this email and
	 policy couldn't possibly be TOFU_POLICY_NONE.  */
      assert (policy == TOFU_POLICY_NONE);

      if (DBG_TRUST)
	log_debug ("TOFU: New binding <%s, %s>, no conflict.\n",
		   email, fingerprint_pp);

      if (record_binding (dbs, fingerprint, email, user_id,
			  TOFU_POLICY_AUTO, 0) != 0)
	{
	  log_error (_("error setting TOFU binding's trust level to %s\n"),
		       "auto");
	  trust_level = _tofu_GET_TRUST_ERROR;
	  goto out;
	}

      trust_level = tofu_policy_to_trust_level (TOFU_POLICY_AUTO);
      goto out;
    }

  if (policy == TOFU_POLICY_NONE)
    /* This is a new binding and we have a conflict.  Mark any
       conflicting bindings that have an automatic policy as now
       requiring confirmation.  Note: we delay this until after we ask
       for confirmation so that when the current policy is printed, it
       is correct.  */
    change_conflicting_to_ask = 1;

  if (! may_ask)
    /* We can only get here in the third case (no saved policy) and if
       there is a conflict.  (If the policy was ask (cases #1 and #2)
       and we weren't allowed to ask, we'd have already exited).  */
    {
      assert (policy == TOFU_POLICY_NONE);

      if (record_binding (dbs, fingerprint, email, user_id,
			  TOFU_POLICY_ASK, 0) != 0)
	log_error (_("error setting TOFU binding's trust level to %s\n"),
		   "ask");

      trust_level = TRUST_UNDEFINED;
      goto out;
    }

  /* If we get here, we need to ask the user about the binding.  There
     are three ways we could end up here:

       - This is a new binding and there is a conflict
         (policy == TOFU_POLICY_NONE && bindings_with_this_email_count > 0),

       - This is a new binding and opt.tofu_default_policy is set to
         ask.  (policy == TOFU_POLICY_NONE && opt.tofu_default_policy ==
         TOFU_POLICY_ASK), or,

       - The policy is ask (the user deferred last time) (policy ==
         TOFU_POLICY_ASK).
   */
  {
    int is_conflict =
      ((policy == TOFU_POLICY_NONE && bindings_with_this_email_count > 0)
       || (policy == TOFU_POLICY_ASK && conflict));
    estream_t fp;
    char *binding;
    int binding_shown;
    strlist_t other_user_ids = NULL;
    struct signature_stats *stats = NULL;
    struct signature_stats *stats_iter = NULL;
    char *prompt;
    char *choices;

    fp = es_fopenmem (0, "rw,samethread");
    if (! fp)
      log_fatal ("Error creating memory stream\n");

    binding = xasprintf ("<%s, %s>", fingerprint_pp, email);
    binding_shown = 0;

    if (policy == TOFU_POLICY_NONE)
      {
	es_fprintf (fp, _("The binding %s is NOT known."), binding);
        es_fputs ("  ", fp);
	binding_shown = 1;
      }
    else if (policy == TOFU_POLICY_ASK
	     /* If there the conflict is with itself, then don't
		display this message.  */
	     && conflict && strcmp (conflict, fingerprint) != 0)
      {
        char *conflict_pp = format_hexfingerprint (conflict, NULL, 0);
	es_fprintf (fp,
		    _("The key %s raised a conflict with this binding (%s)."
                      "  Since this binding's policy was 'auto', it was "
                      "changed to 'ask'."),
		    conflict_pp, binding);
        es_fputs ("  ", fp);
        xfree (conflict_pp);
	binding_shown = 1;
      }
    /* TRANSLATORS: The %s%s is replaced by either a fingerprint and a
       blank or by two empty strings.  */
    es_fprintf (fp,
		_("Please indicate whether you believe the binding %s%s"
		  "is legitimate (the key belongs to the stated owner) "
		  "or a forgery (bad)."),
		binding_shown ? "" : binding,
		binding_shown ? "" : " ");
    es_fputs ("\n\n", fp);

    xfree (binding);

    /* Find other user ids associated with this key and whether the
       bindings are marked as good or bad.  */
    {
      struct db *db_key;

      if (opt.tofu_db_format == TOFU_DB_SPLIT)
	/* In the split format, we need to search in the fingerprint
	   DB for all the emails associated with this key, not the
	   email DB.  */
	db_key = getdb (dbs, fingerprint, DB_KEY);
      else
	db_key = db;

      if (db_key)
	{
	  rc = sqlite3_stepx
	    (db_key->db, &db_key->s.get_trust_gather_other_user_ids,
             strings_collect_cb2, &other_user_ids, &err,
             opt.tofu_db_format == TOFU_DB_SPLIT
	     ? "select user_id, email from bindings where fingerprint = ?;"
	     : "select user_id, policy from bindings where fingerprint = ?;",
	     SQLITE_ARG_STRING, fingerprint, SQLITE_ARG_END);
	  if (rc)
	    {
	      log_error (_("error gathering other user IDs: %s\n"), err);
	      sqlite3_free (err);
	      err = NULL;
	    }
	}
    }

    if (other_user_ids)
      {
	strlist_t strlist_iter;

	es_fprintf (fp, _("Known user IDs associated with this key:\n"));
	for (strlist_iter = other_user_ids;
	     strlist_iter;
	     strlist_iter = strlist_iter->next)
	  {
	    char *other_user_id = strlist_iter->d;
	    char *other_thing;
	    enum tofu_policy other_policy;

	    assert (strlist_iter->next);
	    strlist_iter = strlist_iter->next;
	    other_thing = strlist_iter->d;

	    if (opt.tofu_db_format == TOFU_DB_SPLIT)
	      other_policy = get_policy (dbs, fingerprint, other_thing, NULL);
	    else
	      other_policy = atoi (other_thing);

	    es_fprintf (fp, "  %s (", other_user_id);
	    es_fprintf (fp, _("policy: %s"), tofu_policy_str (other_policy));
	    es_fprintf (fp, ")\n");
          }
	es_fprintf (fp, "\n");

	free_strlist (other_user_ids);
      }

    /* Find other keys associated with this email address.  */
    /* XXX: When generating the statistics, do we want the time
       embedded in the signature (column 'sig_time') or the time that
       we first verified the signature (column 'time').  */
    rc = sqlite3_stepx
      (db->db, &db->s.get_trust_gather_other_keys,
       signature_stats_collect_cb, &stats, &err,
       "select fingerprint, policy, time_ago, count(*)\n"
       " from (select bindings.*,\n"
       "        case\n"
       /* From the future (but if its just a couple of hours in the
	  future don't turn it into a warning)?  Or should we use
	  small, medium or large units?  (Note: whatever we do, we
	  keep the value in seconds.  Then when we group, everything
	  that rounds to the same number of seconds is grouped.)  */
       "         when delta < -("STRINGIFY (TIME_AGO_FUTURE_IGNORE)") then -1\n"
       "         when delta < ("STRINGIFY (TIME_AGO_MEDIUM_THRESHOLD)")\n"
       "          then max(0,\n"
       "                   round(delta / ("STRINGIFY (TIME_AGO_UNIT_SMALL)"))\n"
       "               * ("STRINGIFY (TIME_AGO_UNIT_SMALL)"))\n"
       "         when delta < ("STRINGIFY (TIME_AGO_LARGE_THRESHOLD)")\n"
       "          then round(delta / ("STRINGIFY (TIME_AGO_UNIT_MEDIUM)"))\n"
       "               * ("STRINGIFY (TIME_AGO_UNIT_MEDIUM)")\n"
       "         else round(delta / ("STRINGIFY (TIME_AGO_UNIT_LARGE)"))\n"
       "              * ("STRINGIFY (TIME_AGO_UNIT_LARGE)")\n"
       "        end time_ago,\n"
       "        delta time_ago_raw\n"
       "       from bindings\n"
       "       left join\n"
       "         (select *,\n"
       "            cast(strftime('%s','now') - sig_time as real) delta\n"
       "           from signatures) ss\n"
       "        on ss.binding = bindings.oid)\n"
       " where email = ?\n"
       " group by fingerprint, time_ago\n"
       /* Make sure the current key is first.  */
       " order by fingerprint = ? asc, fingerprint desc, time_ago desc;\n",
       SQLITE_ARG_STRING, email, SQLITE_ARG_STRING, fingerprint,
       SQLITE_ARG_END);
    if (rc)
      {
	strlist_t strlist_iter;

	log_error (_("error gathering signature stats: %s\n"), err);
	sqlite3_free (err);
	err = NULL;

	es_fprintf (fp, ngettext("The email address \"%s\" is"
                                 " associated with %d key:\n",
                                 "The email address \"%s\" is"
                                 " associated with %d keys:\n",
                                 bindings_with_this_email_count),
                    email, bindings_with_this_email_count);
	for (strlist_iter = bindings_with_this_email;
	     strlist_iter;
	     strlist_iter = strlist_iter->next)
	  es_fprintf (fp, "  %s\n", strlist_iter->d);
      }
    else
      {
	char *key = NULL;

	if (! stats || strcmp (stats->fingerprint, fingerprint) != 0)
	  /* If we have already added this key to the DB, then it will
	     be first (see the above select).  Since the first key on
	     the list is not this key, we must not yet have verified
	     any messages signed by this key.  Add a dummy entry.  */
	  signature_stats_prepend (&stats, fingerprint, TOFU_POLICY_AUTO, 0, 0);

	es_fprintf
          (fp, _("Statistics for keys with the email address \"%s\":\n"),
           email);
	for (stats_iter = stats; stats_iter; stats_iter = stats_iter->next)
	  {
	    if (! key || strcmp (key, stats_iter->fingerprint) != 0)
	      {
		int this_key;
                char *key_pp;
		key = stats_iter->fingerprint;
		this_key = strcmp (key, fingerprint) == 0;
                key_pp = format_hexfingerprint (key, NULL, 0);
                es_fprintf (fp, "  %s (", key_pp);
		if (this_key)
		  es_fprintf (fp, _("this key"));
		else
		  es_fprintf (fp, _("policy: %s"),
			      tofu_policy_str (stats_iter->policy));
                es_fputs ("):\n", fp);
                xfree (key_pp);
	      }

            es_fputs ("    ", fp);
	    if (stats_iter->time_ago == -1)
	      es_fprintf (fp, ngettext("%ld message signed in the future.",
                                       "%ld messages signed in the future.",
                                       stats_iter->count), stats_iter->count);
	    else
              {
                long t_scaled = time_ago_scale (stats_iter->time_ago);

                /* TANSLATORS: This string is concatenated with one of
                 * the day/week/month strings to form one sentence.  */
                es_fprintf (fp, ngettext("%ld message signed",
                                         "%ld messages signed",
                                         stats_iter->count), stats_iter->count);
                if (!stats_iter->count)
                  es_fputs (".", fp);
                else if (stats_iter->time_ago < TIME_AGO_UNIT_MEDIUM)
                  es_fprintf (fp, ngettext(" over the past %ld day.",
                                           " over the past %ld days.",
                                           t_scaled), t_scaled);
                else if (stats_iter->time_ago < TIME_AGO_UNIT_LARGE)
                  es_fprintf (fp, ngettext(" over the past %ld week.",
                                           " over the past %ld weeks.",
                                           t_scaled), t_scaled);
                else
                  es_fprintf (fp, ngettext(" over the past %ld month.",
                                           " over the past %ld months.",
                                           t_scaled), t_scaled);
              }
            es_fputs ("\n", fp);
	  }
      }

    if (is_conflict)
      {
	/* TRANSLATORS: Please translate the text found in the source
	   file below.  We don't directly internationalize that text
	   so that we can tweak it without breaking translations.  */
	char *text = _("TOFU detected a binding conflict");
	if (strcmp (text, "TOFU detected a binding conflict") == 0)
	  /* No translation.  Use the English text.  */
	  text =
	    "Normally, there is only a single key associated with an email "
	    "address.  However, people sometimes generate a new key if "
	    "their key is too old or they think it might be compromised.  "
	    "Alternatively, a new key may indicate a man-in-the-middle "
	    "attack!  Before accepting this key, you should talk to or "
	    "call the person to make sure this new key is legitimate.";
        text = format_text (text, 0, 72, 80);
	es_fprintf (fp, "\n%s\n", text);
        xfree (text);
      }

    es_fputc ('\n', fp);

    /* Add a NUL terminator.  */
    es_fputc (0, fp);
    if (es_fclose_snatch (fp, (void **) &prompt, NULL))
      log_fatal ("error snatching memory stream\n");

    /* I think showing the large message once is sufficient.  If we
       would move it right before the cpr_get many lines will scroll
       away and the user might not realize that he merely entered a
       wrong choise (because he does not see that either).  As a small
       benefit we allow C-L to redisplay everything.  */
    tty_printf ("%s", prompt);
    while (1)
      {
	char *response;

        /* TRANSLATORS: Two letters (normally the lower and upper case
           version of the hotkey) for each of the five choices.  If
           there is only one choice in your language, repeat it.  */
        choices = _("gG" "aA" "uU" "rR" "bB");
	if (strlen (choices) != 10)
	  log_bug ("Bad TOFU conflict translation!  Please report.");

	response = cpr_get
          ("tofu.conflict",
           _("(G)ood, (A)ccept once, (U)nknown, (R)eject once, (B)ad? "));
	trim_spaces (response);
	cpr_kill_prompt ();
        if (*response == CONTROL_L)
          tty_printf ("%s", prompt);
	else if (strlen (response) == 1)
	  {
	    char *choice = strchr (choices, *response);
	    if (choice)
	      {
		int c = ((size_t) choice - (size_t) choices) / 2;

		switch (c)
		  {
		  case 0: /* Good.  */
		    policy = TOFU_POLICY_GOOD;
		    trust_level = tofu_policy_to_trust_level (policy);
		    break;
		  case 1: /* Accept once.  */
		    policy = TOFU_POLICY_ASK;
		    trust_level =
		      tofu_policy_to_trust_level (TOFU_POLICY_GOOD);
		    break;
		  case 2: /* Unknown.  */
		    policy = TOFU_POLICY_UNKNOWN;
		    trust_level = tofu_policy_to_trust_level (policy);
		    break;
		  case 3: /* Reject once.  */
		    policy = TOFU_POLICY_ASK;
		    trust_level =
		      tofu_policy_to_trust_level (TOFU_POLICY_BAD);
		    break;
		  case 4: /* Bad.  */
		    policy = TOFU_POLICY_BAD;
		    trust_level = tofu_policy_to_trust_level (policy);
		    break;
		  default:
		    log_bug ("c should be between 0 and 4 but it is %d!", c);
		  }

		if (record_binding (dbs, fingerprint, email, user_id,
				    policy, 0) != 0)
		  /* If there's an error registering the
		     binding, don't save the signature.  */
		  trust_level = _tofu_GET_TRUST_ERROR;

		break;
	      }
	  }
	xfree (response);
      }

    xfree (prompt);

    signature_stats_free (stats);
  }

 out:
  if (change_conflicting_to_ask)
    {
      if (! may_ask)
	/* If we weren't allowed to ask, also update this key as
	   conflicting with itself.  */
	rc = sqlite3_exec_printf
	  (db->db, NULL, NULL, &err,
	   "update bindings set policy = %d, conflict = %Q"
	   " where email = %Q"
	   "  and (policy = %d or (policy = %d and fingerprint = %Q));",
	   TOFU_POLICY_ASK, fingerprint, email, TOFU_POLICY_AUTO,
	   TOFU_POLICY_ASK, fingerprint);
      else
	rc = sqlite3_exec_printf
	  (db->db, NULL, NULL, &err,
	   "update bindings set policy = %d, conflict = %Q"
	   " where email = %Q and fingerprint != %Q and policy = %d;",
	   TOFU_POLICY_ASK, fingerprint, email, fingerprint, TOFU_POLICY_AUTO);
      if (rc)
	{
	  log_error (_("error changing TOFU policy: %s\n"), err);
	  sqlite3_free (err);
	  goto out;
	}
    }

  xfree (conflict);
  free_strlist (bindings_with_this_email);
  xfree (fingerprint_pp);

  return trust_level;
}


/* Return a malloced string of the form
 *    "7 months, 1 day, 5 minutes, 0 seconds"
 * The caller must free that string.
 *
 * This is actually a bad hack which may not work correctly with all
 * languages.
 */
static char *
time_ago_str (long long int t)
{
  estream_t fp;
  int years = 0;
  int months = 0;
  int days = 0;
  int hours = 0;
  int minutes = 0;
  int seconds = 0;

  /* The number of units that we've printed so far.  */
  int count = 0;
  /* The first unit that we printed (year = 0, month = 1,
     etc.).  */
  int first = -1;
  /* The current unit.  */
  int i = 0;

  char *str;

  /* It would be nice to use a macro to do this, but gettext
     works on the unpreprocessed code.  */
#define MIN_SECS (60)
#define HOUR_SECS (60 * MIN_SECS)
#define DAY_SECS (24 * HOUR_SECS)
#define MONTH_SECS (30 * DAY_SECS)
#define YEAR_SECS (365 * DAY_SECS)

  if (t > YEAR_SECS)
    {
      years = t / YEAR_SECS;
      t -= years * YEAR_SECS;
    }
  if (t > MONTH_SECS)
    {
      months = t / MONTH_SECS;
      t -= months * MONTH_SECS;
    }
  if (t > DAY_SECS)
    {
      days = t / DAY_SECS;
      t -= days * DAY_SECS;
    }
  if (t > HOUR_SECS)
    {
      hours = t / HOUR_SECS;
      t -= hours * HOUR_SECS;
    }
  if (t > MIN_SECS)
    {
      minutes = t / MIN_SECS;
      t -= minutes * MIN_SECS;
    }
  seconds = t;

#undef MIN_SECS
#undef HOUR_SECS
#undef DAY_SECS
#undef MONTH_SECS
#undef YEAR_SECS

  fp = es_fopenmem (0, "rw,samethread");
  if (! fp)
    log_fatal ("error creating memory stream: %s\n",
               gpg_strerror (gpg_error_from_syserror()));

  if (years)
    {
      es_fprintf (fp, ngettext("%d year", "%d years", years), years);
      count ++;
      first = i;
    }
  i ++;
  if ((first == -1 || i - first <= 3) && months)
    {
      if (count)
        es_fprintf (fp, ", ");
      es_fprintf (fp, ngettext("%d month", "%d months", months), months);
      count ++;
      first = i;
    }
  i ++;
  if ((first == -1 || i - first <= 3) && count < 2 && days)
    {
      if (count)
        es_fprintf (fp, ", ");
      es_fprintf (fp, ngettext("%d day", "%d days", days), days);
      count ++;
      first = i;
    }
  i ++;
  if ((first == -1 || i - first <= 3) && count < 2 && hours)
    {
      if (count)
        es_fprintf (fp, ", ");
      es_fprintf (fp, ngettext("%d hour", "%d hours", hours), hours);
      count ++;
      first = i;
    }
  i ++;
  if ((first == -1 || i - first <= 3) && count < 2 && minutes)
    {
      if (count)
        es_fprintf (fp, ", ");
      es_fprintf (fp, ngettext("%d minute", "%d minutes", minutes), minutes);
      count ++;
      first = i;
    }
  i ++;
  if ((first == -1 || i - first <= 3) && count < 2)
    {
      if (count)
        es_fprintf (fp, ", ");
      es_fprintf (fp, ngettext("%d second", "%d seconds", seconds), seconds);
    }

  es_fputc (0, fp);
  if (es_fclose_snatch (fp, (void **) &str, NULL))
    log_fatal ("error snatching memory stream\n");

  return str;
}


static void
show_statistics (struct dbs *dbs, const char *fingerprint,
		 const char *email, const char *user_id,
		 const char *sig_exclude)
{
  struct db *db;
  char *fingerprint_pp;
  int rc;
  strlist_t strlist = NULL;
  char *err = NULL;

  db = getdb (dbs, email, DB_EMAIL);
  if (! db)
    return;

  fingerprint_pp = format_hexfingerprint (fingerprint, NULL, 0);

  rc = sqlite3_exec_printf
    (db->db, strings_collect_cb, &strlist, &err,
     "select count (*), strftime('%%s','now') - min (signatures.time),\n"
     "  strftime('%%s','now') - max (signatures.time)\n"
     " from signatures\n"
     " left join bindings on signatures.binding = bindings.oid\n"
     " where fingerprint = %Q and email = %Q and sig_digest %s%s%s;",
     fingerprint, email,
     /* We want either: sig_digest != 'SIG_EXCLUDE' or sig_digest is
	not NULL.  */
     sig_exclude ? "!= '" : "is not NULL",
     sig_exclude ? sig_exclude : "",
     sig_exclude ? "'" : "");
  if (rc)
    {
      log_error (_("error reading TOFU database: %s\n"), err);
      print_further_info ("getting statistics");
      sqlite3_free (err);
      goto out;
    }

  if (! strlist)
    log_info (_("Have never verified a message signed by key %s!\n"),
              fingerprint_pp);
  else
    {
      char *tail = NULL;
      signed long messages;
      signed long first_seen_ago;
      signed long most_recent_seen_ago;

      assert (strlist_length (strlist) == 3);

      errno = 0;
      messages = strtol (strlist->d, &tail, 0);
      if (errno || *tail != '\0')
	/* Abort.  */
	{
	  log_debug ("%s:%d: Couldn't convert %s (messages) to an int: %s.\n",
		     __func__, __LINE__, strlist->d, strerror (errno));
	  messages = -1;
	}

      if (messages == 0 && *strlist->next->d == '\0')
	/* min(NULL) => NULL => "".  */
        {
          first_seen_ago = -1;
          most_recent_seen_ago = -1;
        }
      else
	{
	  errno = 0;
	  first_seen_ago = strtol (strlist->next->d, &tail, 0);
	  if (errno || *tail != '\0')
	    /* Abort.  */
	    {
	      log_debug ("%s:%d: Couldn't convert %s (first_seen) to an int: %s.\n",
			 __func__, __LINE__,
			 strlist->next->d, strerror (errno));
	      first_seen_ago = 0;
	    }

	  errno = 0;
	  most_recent_seen_ago = strtol (strlist->next->next->d, &tail, 0);
	  if (errno || *tail != '\0')
	    /* Abort.  */
	    {
	      log_debug ("%s:%d: Couldn't convert %s (most_recent_seen) to an int: %s.\n",
			 __func__, __LINE__,
			 strlist->next->next->d, strerror (errno));
	      most_recent_seen_ago = 0;
	    }
	}

      if (messages == -1 || first_seen_ago == 0)
        log_info (_("Failed to collect signature statistics"
                    " for \"%s\" (key %s)\n"),
                  user_id, fingerprint_pp);
      else
	{
	  enum tofu_policy policy = get_policy (dbs, fingerprint, email, NULL);
	  estream_t fp;
	  char *msg;

	  fp = es_fopenmem (0, "rw,samethread");
	  if (! fp)
	    log_fatal ("error creating memory stream\n");

	  if (messages == 0)
            es_fprintf (fp,
                        _("Verified 0 messages signed by \"%s\""
                          " (key: %s, policy: %s)."),
                        user_id, fingerprint_pp, tofu_policy_str (policy));
	  else
	    {
              char *first_seen_ago_str =
                time_ago_str (first_seen_ago);
              char *most_recent_seen_ago_str =
                time_ago_str (most_recent_seen_ago);

              /* TRANSLATORS: The final %s is replaced by a string like
                 "7 months, 1 day, 5 minutes, 0 seconds". */
	      es_fprintf (fp, ngettext("Verified %ld message signed by \"%s\""
                                       " (key: %s, policy: %s) in the past %s.",
                                       "Verified %ld messages signed by \"%s\""
                                       " (key: %s, policy: %s) in the past %s.",
                                       messages),
			  messages, user_id,
			  fingerprint_pp, tofu_policy_str (policy),
                          first_seen_ago_str);

              if (messages > 1)
                {
                  es_fputs ("  ", fp);
                  es_fprintf (fp,
                              _("The most recent message was verified %s ago."),
                              most_recent_seen_ago_str);
                }

              xfree (first_seen_ago_str);
              xfree (most_recent_seen_ago_str);
            }

	  es_fputc (0, fp);
	  if (es_fclose_snatch (fp, (void **) &msg, NULL))
	    log_fatal ("error snatching memory stream\n");

	  log_info ("%s\n", msg);
          xfree (msg);

	  if (policy == TOFU_POLICY_AUTO && messages < 10)
	    {
	      char *set_policy_command;
	      char *text;
              char *tmp;

	      if (messages == 0)
		log_info (_("Warning: we've have yet to see"
                            " a message signed by this key!\n"));
	      else if (messages == 1)
		log_info (_("Warning: we've only seen a"
                            " single message signed by this key!\n"));

	      set_policy_command =
		xasprintf ("gpg --tofu-policy bad \"%s\"", fingerprint);
	      /* TRANSLATORS: translate the below text.  We don't
		 directly internationalize that text so that we can
		 tweak it without breaking translations.  */
	      text = ngettext("TOFU: few signatures %d message %s",
                              "TOFU: few signatures %d messages %s", 1);
	      if (strcmp (text, "TOFU: few signatures %d message %s") == 0)
                {
                  text =
                    (messages == 1?
                     "Warning: if you think you've seen more than %d message "
                     "signed by this key, then this key might be a forgery!  "
                     "Carefully examine the email address for small variations "
                     "(e.g., additional white space).  If the key is suspect, "
                     "then use '%s' to mark it as being bad.\n"
                     :
                     "Warning: if you think you've seen more than %d messages "
                     "signed by this key, then this key might be a forgery!  "
                     "Carefully examine the email address for small variations "
                     "(e.g., additional white space).  If the key is suspect, "
                     "then use '%s' to mark it as being bad.\n");
                }

              tmp = xasprintf (text, messages, set_policy_command);
              text = format_text (tmp, 0, 72, 80);
              xfree (tmp);
	      log_info ("%s", text);
              xfree (text);
	      free (set_policy_command);
	    }
	}
    }

 out:
  free_strlist (strlist);
  xfree (fingerprint_pp);

  return;
}

/* Extract the email address from a user id and normalize it.  If the
   user id doesn't contain an email address, then we use the whole
   user_id and normalize that.  The returned string must be freed.  */
static char *
email_from_user_id (const char *user_id)
{
  char *email = mailbox_from_userid (user_id);
  if (! email)
    {
      /* Hmm, no email address was provided or we are out of core.  Just
         take the lower-case version of the whole user id.  It could be
         a hostname, for instance.  */
      email = ascii_strlwr (xstrdup (user_id));
    }

  return email;
}

/* Register the signature with the binding <fingerprint, USER_ID>.
   The fingerprint is taken from the primary key packet PK.

   SIG_DIGEST_BIN is the binary representation of the message's
   digest.  SIG_DIGEST_BIN_LEN is its length.

   SIG_TIME is the time that the signature was generated.

   ORIGIN is a free-formed string describing the origin of the
   signature.  If this was from an email and the Claws MUA was used,
   then this should be something like: "email:claws".  If this is
   NULL, the default is simply "unknown".

   If MAY_ASK is 1, then this function may interact with the user.
   This is necessary if there is a conflict or the binding's policy is
   TOFU_POLICY_ASK.

   This function returns the binding's trust level on return.  If an
   error occurs, this function returns TRUST_UNKNOWN.  */
int
tofu_register (PKT_public_key *pk, const char *user_id,
	       const byte *sig_digest_bin, int sig_digest_bin_len,
	       time_t sig_time, const char *origin, int may_ask)
{
  struct dbs *dbs;
  struct db *db;
  char *fingerprint = NULL;
  char *fingerprint_pp = NULL;
  char *email = NULL;
  char *err = NULL;
  int rc;
  int trust_level = TRUST_UNKNOWN;
  char *sig_digest;
  unsigned long c;
  int already_verified = 0;

  sig_digest = make_radix64_string (sig_digest_bin, sig_digest_bin_len);

  dbs = opendbs ();
  if (! dbs)
    {
      log_error (_("error opening TOFU database: %s\n"),
                 gpg_strerror (GPG_ERR_GENERAL));
      goto die;
    }

  fingerprint = hexfingerprint (pk, NULL, 0);
  fingerprint_pp = format_hexfingerprint (fingerprint, NULL, 0);

  if (! *user_id)
    {
      log_debug ("TOFU: user id is empty.  Can't continue.\n");
      goto die;
    }

  email = email_from_user_id (user_id);

  if (! origin)
    /* The default origin is simply "unknown".  */
    origin = "unknown";

  /* It's necessary to get the trust so that we are certain that the
     binding has been registered.  */
  trust_level = get_trust (dbs, fingerprint, email, user_id, may_ask);
  if (trust_level == _tofu_GET_TRUST_ERROR)
    /* An error.  */
    {
      trust_level = TRUST_UNKNOWN;
      goto die;
    }

  /* Save the observed signature in the DB.  */
  db = getdb (dbs, email, DB_EMAIL);
  if (! db)
    {
      log_error (_("error opening TOFU database: %s\n"),
                 gpg_strerror (GPG_ERR_GENERAL));
      goto die;
    }

  /* We do a query and then an insert.  Make sure they are atomic
     by wrapping them in a transaction.  */
  rc = begin_transaction (db, 0);
  if (rc)
    goto die;

  /* If we've already seen this signature before, then don't add
     it again.  */
  rc = sqlite3_stepx
    (db->db, &db->s.register_already_seen,
     get_single_unsigned_long_cb2, &c, &err,
     "select count (*)\n"
     " from signatures left join bindings\n"
     "  on signatures.binding = bindings.oid\n"
     " where fingerprint = ? and email = ? and sig_time = ?\n"
     "  and sig_digest = ?",
     SQLITE_ARG_STRING, fingerprint, SQLITE_ARG_STRING, email,
     SQLITE_ARG_LONG_LONG, (long long) sig_time,
     SQLITE_ARG_STRING, sig_digest,
     SQLITE_ARG_END);
  if (rc)
    {
      log_error (_("error reading TOFU database: %s\n"), err);
      print_further_info ("checking existence");
      sqlite3_free (err);
    }
  else if (c > 1)
    /* Duplicates!  This should not happen.  In particular,
       because <fingerprint, email, sig_time, sig_digest> is the
       primary key!  */
    log_debug ("SIGNATURES DB contains duplicate records"
	       " <key: %s, %s, time: 0x%lx, sig: %s, %s>."
	       "  Please report.\n",
	       fingerprint_pp, email, (unsigned long) sig_time,
	       sig_digest, origin);
  else if (c == 1)
    {
      already_verified = 1;
      if (DBG_TRUST)
	log_debug ("Already observed the signature"
		   " <key: %s, %s, time: 0x%lx, sig: %s, %s>\n",
		   fingerprint_pp, email, (unsigned long) sig_time,
		   sig_digest, origin);
    }
  else
    /* This is the first time that we've seen this signature.
       Record it.  */
    {
      if (DBG_TRUST)
	log_debug ("TOFU: Saving signature <%s, %s, %s>\n",
		   fingerprint_pp, email, sig_digest);

      assert (c == 0);

      rc = sqlite3_stepx
	(db->db, &db->s.register_insert, NULL, NULL, &err,
	 "insert into signatures\n"
	 " (binding, sig_digest, origin, sig_time, time)\n"
	 " values\n"
	 " ((select oid from bindings\n"
	 "    where fingerprint = ? and email = ?),\n"
	 "  ?, ?, ?, strftime('%s', 'now'));",
	 SQLITE_ARG_STRING, fingerprint, SQLITE_ARG_STRING, email,
         SQLITE_ARG_STRING, sig_digest, SQLITE_ARG_STRING, origin,
         SQLITE_ARG_LONG_LONG, (long long) sig_time,
         SQLITE_ARG_END);
      if (rc)
	{
	  log_error (_("error updating TOFU database: %s\n"), err);
          print_further_info ("insert signatures");
	  sqlite3_free (err);
	}
    }

  /* It only matters whether we abort or commit the transaction
     (so long as we do something) if we execute the insert.  */
  if (rc)
    rc = rollback_transaction (db);
  else
    rc = end_transaction (db, 0);
  if (rc)
    {
      sqlite3_free (err);
      goto die;
    }

 die:
  if (may_ask && trust_level != TRUST_ULTIMATE)
    /* It's only appropriate to show the statistics in an interactive
       context.  */
    show_statistics (dbs, fingerprint, email, user_id,
		     already_verified ? NULL : sig_digest);

  xfree (email);
  xfree (fingerprint_pp);
  xfree (fingerprint);
  if (dbs)
    closedbs (dbs);
  xfree (sig_digest);

  return trust_level;
}

/* Combine a trust level returned from the TOFU trust model with a
   trust level returned by the PGP trust model.  This is primarily of
   interest when the trust model is tofu+pgp (TM_TOFU_PGP).

   This function ors together the upper bits (the values not covered
   by TRUST_MASK, i.e., TRUST_FLAG_REVOKED, etc.).  */
int
tofu_wot_trust_combine (int tofu_base, int wot_base)
{
  int tofu = tofu_base & TRUST_MASK;
  int wot = wot_base & TRUST_MASK;
  int upper = (tofu_base & ~TRUST_MASK) | (wot_base & ~TRUST_MASK);

  assert (tofu == TRUST_UNKNOWN
	  || tofu == TRUST_EXPIRED
	  || tofu == TRUST_UNDEFINED
	  || tofu == TRUST_NEVER
	  || tofu == TRUST_MARGINAL
	  || tofu == TRUST_FULLY
	  || tofu == TRUST_ULTIMATE);
  assert (wot == TRUST_UNKNOWN
	  || wot == TRUST_EXPIRED
	  || wot == TRUST_UNDEFINED
	  || wot == TRUST_NEVER
	  || wot == TRUST_MARGINAL
	  || wot == TRUST_FULLY
	  || wot == TRUST_ULTIMATE);

  /* We first consider negative trust policys.  These trump positive
     trust policies.  */
  if (tofu == TRUST_NEVER || wot == TRUST_NEVER)
    /* TRUST_NEVER trumps everything else.  */
    return upper | TRUST_NEVER;
  if (tofu == TRUST_EXPIRED || wot == TRUST_EXPIRED)
    /* TRUST_EXPIRED trumps everything but TRUST_NEVER.  */
    return upper | TRUST_EXPIRED;

  /* Now we only have positive or neutral trust policies.  We take
     the max.  */
  if (tofu == TRUST_ULTIMATE || wot == TRUST_ULTIMATE)
    return upper | TRUST_ULTIMATE;
  if (tofu == TRUST_FULLY || wot == TRUST_FULLY)
    return upper | TRUST_FULLY;
  if (tofu == TRUST_MARGINAL || wot == TRUST_MARGINAL)
    return upper | TRUST_MARGINAL;
  if (tofu == TRUST_UNDEFINED || wot == TRUST_UNDEFINED)
    return upper | TRUST_UNDEFINED;
  return upper | TRUST_UNKNOWN;
}

/* Return the validity (TRUST_NEVER, etc.) of the binding
   <FINGERPRINT, USER_ID>.

   PK is the primary key packet.

   If MAY_ASK is 1 and the policy is TOFU_POLICY_ASK, then the user
   will be prompted to choose a different policy.  If MAY_ASK is 0 and
   the policy is TOFU_POLICY_ASK, then TRUST_UNKNOWN is returned.

   Returns TRUST_UNDEFINED if an error occurs.  */
int
tofu_get_validity (PKT_public_key *pk, const char *user_id,
		   int may_ask)
{
  struct dbs *dbs;
  char *fingerprint = NULL;
  char *email = NULL;
  int trust_level = TRUST_UNDEFINED;

  dbs = opendbs ();
  if (! dbs)
    {
      log_error (_("error opening TOFU database: %s\n"),
                 gpg_strerror (GPG_ERR_GENERAL));
      goto die;
    }

  fingerprint = hexfingerprint (pk, NULL, 0);

  if (! *user_id)
    {
      log_debug ("user id is empty."
                 "  Can't get TOFU validity for this binding.\n");
      goto die;
    }

  email = email_from_user_id (user_id);

  trust_level = get_trust (dbs, fingerprint, email, user_id, may_ask);
  if (trust_level == _tofu_GET_TRUST_ERROR)
    /* An error.  */
    trust_level = TRUST_UNDEFINED;

  if (may_ask && trust_level != TRUST_ULTIMATE)
    show_statistics (dbs, fingerprint, email, user_id, NULL);

 die:
  xfree (email);
  xfree (fingerprint);
  if (dbs)
    closedbs (dbs);

  return trust_level;
}

/* Set the policy for all non-revoked user ids in the keyblock KB to
   POLICY.

   If no key is available with the specified key id, then this
   function returns GPG_ERR_NO_PUBKEY.

   Returns 0 on success and an error code otherwise.  */
gpg_error_t
tofu_set_policy (kbnode_t kb, enum tofu_policy policy)
{
  struct dbs *dbs;
  PKT_public_key *pk;
  char *fingerprint = NULL;

  assert (kb->pkt->pkttype == PKT_PUBLIC_KEY);
  pk = kb->pkt->pkt.public_key;

  dbs = opendbs ();
  if (! dbs)
    {
      log_error (_("error opening TOFU database: %s\n"),
                 gpg_strerror (GPG_ERR_GENERAL));
      return gpg_error (GPG_ERR_GENERAL);
    }

  if (DBG_TRUST)
    log_debug ("Setting TOFU policy for %s to %s\n",
	       keystr (pk->keyid), tofu_policy_str (policy));
  if (! (pk->main_keyid[0] == pk->keyid[0]
	 && pk->main_keyid[1] == pk->keyid[1]))
    log_bug ("%s: Passed a subkey, but expecting a primary key.\n", __func__);

  fingerprint = hexfingerprint (pk, NULL, 0);

  for (; kb; kb = kb->next)
    {
      PKT_user_id *user_id;
      char *email;

      if (kb->pkt->pkttype != PKT_USER_ID)
	continue;

      user_id = kb->pkt->pkt.user_id;
      if (user_id->is_revoked)
	/* Skip revoked user ids.  (Don't skip expired user ids, the
	   expiry can be changed.)  */
	continue;

      email = email_from_user_id (user_id->name);

      record_binding (dbs, fingerprint, email, user_id->name, policy, 1);

      xfree (email);
    }

  xfree (fingerprint);
  closedbs (dbs);

  return 0;
}

/* Set the TOFU policy for all non-revoked user ids in the KEY with
   the key id KEYID to POLICY.

   If no key is available with the specified key id, then this
   function returns GPG_ERR_NO_PUBKEY.

   Returns 0 on success and an error code otherwise.  */
gpg_error_t
tofu_set_policy_by_keyid (u32 *keyid, enum tofu_policy policy)
{
  kbnode_t keyblock = get_pubkeyblock (keyid);
  if (! keyblock)
    return gpg_error (GPG_ERR_NO_PUBKEY);

  return tofu_set_policy (keyblock, policy);
}

/* Return the TOFU policy for the specified binding in *POLICY.  If no
   policy has been set for the binding, sets *POLICY to
   TOFU_POLICY_NONE.

   PK is a primary public key and USER_ID is a user id.

   Returns 0 on success and an error code otherwise.  */
gpg_error_t
tofu_get_policy (PKT_public_key *pk, PKT_user_id *user_id,
		 enum tofu_policy *policy)
{
  struct dbs *dbs;
  char *fingerprint;
  char *email;

  /* Make sure PK is a primary key.  */
  assert (pk->main_keyid[0] == pk->keyid[0]
	  && pk->main_keyid[1] == pk->keyid[1]);

  dbs = opendbs ();
  if (! dbs)
    {
      log_error (_("error opening TOFU database: %s\n"),
                 gpg_strerror (GPG_ERR_GENERAL));
      return gpg_error (GPG_ERR_GENERAL);
    }

  fingerprint = hexfingerprint (pk, NULL, 0);

  email = email_from_user_id (user_id->name);

  *policy = get_policy (dbs, fingerprint, email, NULL);

  xfree (email);
  xfree (fingerprint);
  closedbs (dbs);

  if (*policy == _tofu_GET_POLICY_ERROR)
    return gpg_error (GPG_ERR_GENERAL);
  return 0;
}
