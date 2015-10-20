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
#include <sqlite3.h>

#include "gpg.h"
#include "types.h"
#include "logging.h"
#include "stringhelp.h"
#include "options.h"
#include "mbox-util.h"
#include "i18n.h"
#include "trustdb.h"
#include "mkdir_p.h"

#include "tofu.h"

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

  enum db_type type;

  sqlite3 *db;

  /* If TYPE is DB_COMBINED, this is "".  Otherwise, it is either the
     fingerprint (type == DB_KEY) or the normalized email address
     (type == DB_EMAIL).  */
  char name[1];
};

/* The grouping parameters when collecting signature statistics.  */

/* If a message is signed a couple of hours in the future, just assume
   some clock skew.  */
#define TIME_AGO_FUTURE_IGNORE (2 * 60 * 60)
#if 0
#  define TIME_AGO_UNIT_SMALL 60
#  define TIME_AGO_UNIT_SMALL_NAME _("minute")
#  define TIME_AGO_UNIT_SMALL_NAME_PLURAL _("minutes")
#  define TIME_AGO_MEDIUM_THRESHOLD (60 * TIME_AGO_UNIT_SMALL)
#  define TIME_AGO_UNIT_MEDIUM (60 * 60)
#  define TIME_AGO_UNIT_MEDIUM_NAME _("hour")
#  define TIME_AGO_UNIT_MEDIUM_NAME_PLURAL _("hours")
#  define TIME_AGO_LARGE_THRESHOLD (24 * 60 * TIME_AGO_UNIT_SMALL)
#  define TIME_AGO_UNIT_LARGE (24 * 60 * 60)
#  define TIME_AGO_UNIT_LARGE_NAME _("day")
#  define TIME_AGO_UNIT_LARGE_NAME_PLURAL _("days")
#else
#  define TIME_AGO_UNIT_SMALL (24 * 60 * 60)
#  define TIME_AGO_UNIT_SMALL_NAME _("day")
#  define TIME_AGO_UNIT_SMALL_NAME_PLURAL _("days")
#  define TIME_AGO_MEDIUM_THRESHOLD (4 * TIME_AGO_UNIT_SMALL)
#  define TIME_AGO_UNIT_MEDIUM (7 * 24 * 60 * 60)
#  define TIME_AGO_UNIT_MEDIUM_NAME _("week")
#  define TIME_AGO_UNIT_MEDIUM_NAME_PLURAL _("weeks")
#  define TIME_AGO_LARGE_THRESHOLD (28 * TIME_AGO_UNIT_SMALL)
#  define TIME_AGO_UNIT_LARGE (30 * 24 * 60 * 60)
#  define TIME_AGO_UNIT_LARGE_NAME _("month")
#  define TIME_AGO_UNIT_LARGE_NAME_PLURAL _("months")
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

/* This is a convenience function that combines sqlite3_mprintf and
   sqlite3_exec.  */
static int
sqlite3_exec_printf (sqlite3 *db,
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
      log_error (_("unsupported TOFU DB version: %s\n"), argv[0]);
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

  /* If the DB has no tables, then assume this is a new DB that needs
     to be initialized.  */
  rc = sqlite3_exec (db,
		     "select count(*) from sqlite_master where type='table';",
		     get_single_unsigned_long_cb, &count, &err);
  if (rc)
    {
      log_error (_("error querying TOFU DB's available tables: %s\n"),
		 err);
      sqlite3_free (err);
      return 1;
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
	  return 0;
	}
      else if (rc == SQLITE_ABORT && version == -1)
	/* Unsupported version.  */
	{
	  /* An error message was already displayed.  */
	  sqlite3_free (err);
	  return 1;
	}
      else if (rc)
	/* Some error.  */
	{
	  log_error (_("error determining TOFU DB's version: %s\n"), err);
	  sqlite3_free (err);
	  return 1;
	}
      else
	/* Unexpected success.  This can only happen if there are no
	   rows.  */
	{
	  log_error (_("error determining TOFU DB's version: %s\n"),
		     "select returned 0, but expected ABORT");
	  return 1;
	}
    }

  rc = sqlite3_exec (db, "begin transaction;", NULL, NULL, &err);
  if (rc)
    {
      log_error (_("error beginning transaction on TOFU database: %s\n"),
		 err);
      sqlite3_free (err);
      return 1;
    }

  /* Create the version table.  */
  rc = sqlite3_exec (db,
		     "create table version (version INTEGER);",
		     NULL, NULL, &err);
  if (rc)
    {
      log_error (_("error initializing TOFU database (%s): %s\n"),
		 "version", err);
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
      log_error (_("error initializing TOFU database (%s): %s\n"),
		 "version, init", err);
      sqlite3_free (err);
      goto out;
    }

  /* The list of <fingerprint, email> bindings and auxiliary data.

       OID is a unique ID identifying this binding (and used by the
         signatures table, see below).  Note: OIDs will never be
         reused.

       FINGERPRINT: The key's fingerprint.

       EMAIL: The normalized email address.

       USER_ID: The unmodified user id from which EMAIL was extracted.

       TIME: The time this binding was first observed.

       POLICY: The trust policy (-1, 0, 1, or 2; see the
         documentation for TOFU_POLICY_BAD, etc. above).

       CONFLICT is either NULL or a fingerprint.  Assume that we have
         a binding <0xdeadbeef, foo@example.com> and then we observe
         <0xbaddecaf, foo@example.com>.  There two bindings conflict
         (they have the same email address).  When we observe the
         latter binding, we warn the user about the conflict and ask
         for a policy decision about the new binding.  We also change
         the old binding's policy to ask if it was auto.  So that we
         know why this occured, we also set conflict to 0xbaddecaf.
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
      log_error (_("error initializing TOFU database (%s): %s\n"),
		 "bindings", err);
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
	  log_error (_("error initializing TOFU database (%s): %s\n"),
		     "signatures", err);
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
	  log_error (_("error aborting transaction on TOFU DB: %s\n"),
		     err);
	  sqlite3_free (err);
	}
      return 1;
    }
  else
    {
      rc = sqlite3_exec (db, "commit transaction;", NULL, NULL, &err);
      if (rc)
	{
	  log_error (_("error committing transaction on TOFU DB: %s\n"),
		     err);
	  sqlite3_free (err);
	  return 1;
	}
      return 0;
    }
}

static sqlite3 *combined_db;

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

      if (combined_db)
	return combined_db;

      filename = make_filename (opt.homedir, "tofu.db", NULL);
      filename_free = 1;
    }
  else
    assert (type == DB_EMAIL || type == DB_KEY);

  assert (filename);

  rc = sqlite3_open (filename, &db);
  if (rc)
    {
      log_error (_("can't open TOFU DB ('%s'): %s\n"),
		 filename, sqlite3_errmsg (db));
      /* Even if an error occurs, DB is guaranteed to be valid.  */
      sqlite3_close (db);
      db = NULL;
    }

  if (filename_free)
    xfree (filename);

  if (db && initdb (db, type))
    {
      sqlite3_close (db);
      db = NULL;
    }

  if (opt.tofu_db_format == TOFU_DB_FLAT)
    combined_db = db;

  return db;
}

/* Return a database handle.  <type, name> describes the required
   database.  If there is a cached handle in DBS, that handle is
   returned.  Otherwise, the database is opened and cached in DBS.

   NAME is the name of the DB and may not be NULL.

   TYPE must be either DB_MAIL or DB_KEY.  In the combined format, the
   combined DB is always returned.  */
static sqlite3 *
getdb (struct db *dbs, const char *name, enum db_type type)
{
  struct db *t = NULL;
  sqlite3 *sqlitedb = NULL;
  char *name_sanitized = NULL;
  char *filename = NULL;
  int i;

  assert (name);
  assert (type == DB_EMAIL || type == DB_KEY);

  assert (dbs);
  /* The first entry is always for the combined DB.  */
  assert (dbs->type == DB_COMBINED);
  assert (! dbs->name[0]);

  if (opt.tofu_db_format == TOFU_DB_FLAT)
    /* When using the flat format, we only have a single combined
       DB.  */
    {
      assert (dbs->db);
      assert (! dbs->next);
      return dbs->db;
    }
  else
    /* When using the split format the first entry on the DB list is a
       dummy entry.  */
    assert (! dbs->db);

  /* We have the split format.  */

  /* Only allow alpha-numeric characters in the filename.  */
  name_sanitized = xstrdup (name);
  for (i = 0; name[i]; i ++)
    {
      char c = name_sanitized[i];
      if (! (('a' <= c && c <= 'z')
	     || ('A' <= c && c <= 'Z')
	     || ('0' <= c && c <= '9')))
	name_sanitized[i] = '_';
    }

  /* See if the DB is cached.  */
  for (t = dbs->next; t; t = t->next)
    if (type == t->type && strcmp (t->name, name_sanitized) == 0)
      goto out;

  /* Open the DB.  The filename has the form:

       tofu.d/TYPE/PREFIX/NAME.db

     We use a short prefix to try to avoid having many files in a
     single directory.  */
  {
    char *type_str = type == DB_EMAIL ? "email" : "key";
    char prefix[3] = { name_sanitized[0], name_sanitized[1], 0 };
    char *name_db;

    /* Make the directory.  */
    if (gnupg_mkdir_p (opt.homedir, "tofu.d", type_str, prefix, NULL) != 0)
      {
	log_error (_("unable to create directory %s/%s/%s/%s"),
		   opt.homedir, "tofu.d", type_str, prefix);
        goto out;
      }

    name_db = xstrconcat (name_sanitized, ".db", NULL);
    filename = make_filename
      (opt.homedir, "tofu.d", type_str, prefix, name_db, NULL);
    xfree (name_db);
  }

  sqlitedb = opendb (filename, type);
  if (! sqlitedb)
    goto out;

  t = xmalloc (sizeof (struct db) + strlen (name_sanitized));
  t->type = type;
  t->db = sqlitedb;
  strcpy (t->name, name_sanitized);

  /* Insert it immediately after the first element.  */
  t->next = dbs->next;
  dbs->next = t;

 out:
  xfree (filename);
  xfree (name_sanitized);

  if (! t)
    return NULL;
  return t->db;
}


/* Create a new DB meta-handle.  Returns NULL on error.  */
static struct db *
opendbs (void)
{
  sqlite3 *db = NULL;
  struct db *dbs;

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
	  log_info (_("Warning: Home directory contains both tofu.db and tofu.d.  Using split format for TOFU DB.\n"));
	  opt.tofu_db_format = TOFU_DB_SPLIT;
	}
      else if (have_tofu_db)
	{
	  opt.tofu_db_format = TOFU_DB_FLAT;
	  if (DBG_TRUST)
	    log_debug ("Using flat format for TOFU DB.\n");
	}
      else if (have_tofu_d)
	{
	  opt.tofu_db_format = TOFU_DB_SPLIT;
	  if (DBG_TRUST)
	    log_debug ("Using split format for TOFU DB.\n");
	}
      else
	{
	  opt.tofu_db_format = TOFU_DB_SPLIT;
	  if (DBG_TRUST)
	    log_debug ("Using split format for TOFU DB.\n");
	}
    }

  if (opt.tofu_db_format == TOFU_DB_FLAT)
    {
      db = opendb (NULL, DB_COMBINED);
      if (! db)
	return NULL;
    }
  else
    {
      /* Create a dummy entry so that we have a handle.  */
    }

  dbs = xmalloc_clear (sizeof (*dbs));
  dbs->db = db;
  dbs->type = DB_COMBINED;

  return dbs;
}

/* Release all of the resources associated with a DB meta-handle.  */
static void
closedbs (struct db *dbs)
{
  struct db *db;
  struct db *n;

  /* The first entry is always the combined DB.  */
  assert (dbs->type == DB_COMBINED);
  if (opt.tofu_db_format == TOFU_DB_FLAT)
    {
      /* If we are using the flat format, then there is only ever the
	 combined DB.  */
      assert (! dbs->next);
      assert (dbs->db);
      assert (dbs->db == combined_db);
    }
  else
    /* In the split format, the combined record is just a place holder
       so that we have a stable handle.  */
    assert (! dbs->db);

  for (db = dbs; db; db = n)
    {
      n = db->next;

      if (combined_db && db->db == combined_db)
	{
	  assert (opt.tofu_db_format == TOFU_DB_FLAT);
	  assert (dbs == db);
	  assert (db->type == DB_COMBINED);
	  assert (! db->name[0]);
	}
      else if (db->db)
	/* Not the dummy entry.  */
	{
	  if (dbs == db)
	    /* The first entry.  */
	    {
	      assert (opt.tofu_db_format == TOFU_DB_FLAT);
	      assert (db->type == DB_COMBINED);
	      assert (! db->name[0]);
	    }
	  else
	    /* Not the first entry.  */
	    {
	      assert (opt.tofu_db_format == TOFU_DB_SPLIT);
	      assert (db->type != DB_COMBINED);
	      assert (db->name[0]);
	    }

	  sqlite3_close (db->db);
	}
      else
	/* The dummy entry.  */
	{
	  assert (opt.tofu_db_format == TOFU_DB_SPLIT);
	  assert (dbs == db);
	  assert (db->type == DB_COMBINED);
	  assert (! db->name[0]);
	}

      xfree (db);
    }
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


/* Record (or update) a trust policy about a (possibly new)
   binding.

   If SHOW_OLD is set, the binding's old policy is displayed.  */
static gpg_error_t
record_binding (struct db *dbs, const char *fingerprint, const char *email,
		const char *user_id, enum tofu_policy policy, int show_old)
{
  sqlite3 *db_email = NULL, *db_key = NULL;
  int rc;
  char *err = NULL;
  enum tofu_policy policy_old = TOFU_POLICY_NONE;

  if (! (policy == TOFU_POLICY_AUTO
	 || policy == TOFU_POLICY_GOOD
	 || policy == TOFU_POLICY_UNKNOWN
	 || policy == TOFU_POLICY_BAD
	 || policy == TOFU_POLICY_ASK))
    log_bug ("%s: Bad value for policy (%d)!\n", __func__, policy);

  db_email = getdb (dbs, email, DB_EMAIL);
  if (! db_email)
    return gpg_error (GPG_ERR_GENERAL);

  if (opt.tofu_db_format == TOFU_DB_SPLIT)
    /* In the split format, we need to update two DBs.  To keep them
       consistent, we start a transaction on each.  Note: this is the
       only place where we start two transaction and we always start
       transaction on the DB_KEY DB first, thus deadlock is not
       possible.  */
    {
      db_key = getdb (dbs, fingerprint, DB_KEY);
      if (! db_key)
	return gpg_error (GPG_ERR_GENERAL);

      rc = sqlite3_exec (db_email, "begin transaction;", NULL, NULL, &err);
      if (rc)
	{
	  log_error (_("error beginning transaction on TOFU %s database: %s\n"),
		     "email", err);
	  sqlite3_free (err);
	  return gpg_error (GPG_ERR_GENERAL);
	}

      rc = sqlite3_exec (db_key, "begin transaction;", NULL, NULL, &err);
      if (rc)
	{
	  log_error (_("error beginning transaction on TOFU %s database: %s\n"),
		     "key", err);
	  sqlite3_free (err);
	  goto out_revert_one;
	}
    }

  if (show_old)
    /* Get the old policy.  Since this is just for informational
       purposes, there is no need to start a transaction or to die if
       there is a failure.  */
    {
      rc = sqlite3_exec_printf
	(db_email, get_single_long_cb, &policy_old, &err,
	 "select policy from bindings where fingerprint = %Q and email = %Q",
	 fingerprint, email);
      if (rc)
	{
	  log_debug ("TOFU: Error reading from binding database"
		     " (reading policy for <%s, %s>): %s\n",
		     fingerprint, email, err);
	  sqlite3_free (err);
	}
    }

  if (DBG_TRUST)
    {
      if (policy_old != TOFU_POLICY_NONE)
	log_debug ("Changing TOFU trust policy for binding <%s, %s>"
		   " from %s to %s.\n",
		   fingerprint, email,
		   tofu_policy_str (policy_old),
		   tofu_policy_str (policy));
      else
	log_debug ("Set TOFU trust policy for binding <%s, %s> to %s.\n",
		   fingerprint, email,
		   tofu_policy_str (policy));
    }

  if (policy_old == policy)
    /* Nothing to do.  */
    goto out;

  rc = sqlite3_exec_printf
    (db_email, NULL, NULL, &err,
     "insert or replace into bindings\n"
     " (oid, fingerprint, email, user_id, time, policy)\n"
     " values (\n"
     /* If we don't explicitly reuse the OID, then SQLite will
	reallocate a new one.  We just need to search for the OID
	based on the fingerprint and email since they are unique.  */
     "  (select oid from bindings where fingerprint = %Q and email = %Q),\n"
     "  %Q, %Q, %Q, strftime('%%s','now'), %d);",
     fingerprint, email, fingerprint, email, user_id, policy);
  if (rc)
    {
      log_error (_("error updating TOFU binding database"
		   " (inserting <%s, %s> = %s): %s\n"),
		 fingerprint, email, tofu_policy_str (policy),
		 err);
      sqlite3_free (err);
      goto out;
    }

  if (db_key)
    /* We also need to update the key DB.  */
    {
      assert (opt.tofu_db_format == TOFU_DB_SPLIT);

      rc = sqlite3_exec_printf
	(db_key, NULL, NULL, &err,
	 "insert or replace into bindings\n"
	 " (oid, fingerprint, email, user_id)\n"
	 " values (\n"
	 /* If we don't explicitly reuse the OID, then SQLite will
	    reallocate a new one.  We just need to search for the OID
	    based on the fingerprint and email since they are unique.  */
	 "  (select oid from bindings where fingerprint = %Q and email = %Q),\n"
	 "  %Q, %Q, %Q);",
	 fingerprint, email, fingerprint, email, user_id);
      if (rc)
	{
	  log_error (_("error updating TOFU binding database"
		       " (inserting <%s, %s>): %s\n"),
		     fingerprint, email, err);
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
      int rc2;

      rc2 = sqlite3_exec_printf (db_key, NULL, NULL, &err,
				 rc ? "rollback;" : "end transaction;");
      if (rc2)
	{
	  log_error (_("error ending transaction on TOFU database: %s\n"),
		     err);
	  sqlite3_free (err);
	}

    out_revert_one:
      rc2 = sqlite3_exec_printf (db_email, NULL, NULL, &err,
				 rc ? "rollback;" : "end transaction;");
      if (rc2)
	{
	  log_error (_("error ending transaction on TOFU database: %s\n"),
		     err);
	  sqlite3_free (err);
	}
    }

  if (rc)
    return gpg_error (GPG_ERR_GENERAL);
  return 0;
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
			    char **azColName)
{
  struct signature_stats **statsp = cookie;
  char *tail;
  int i = 0;
  enum tofu_policy policy;
  long time_ago;
  unsigned long count;

  (void) azColName;

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

/* Return the appropriate unit (respecting whether it is plural or
   singular).  */
const char *
time_ago_unit (signed long t)
{
  signed long t_scaled = time_ago_scale (t);

  if (t < TIME_AGO_UNIT_MEDIUM)
    {
      if (t_scaled == 1)
	return TIME_AGO_UNIT_SMALL_NAME;
      return TIME_AGO_UNIT_SMALL_NAME_PLURAL;
    }
  if (t < TIME_AGO_UNIT_LARGE)
    {
      if (t_scaled == 1)
	return TIME_AGO_UNIT_MEDIUM_NAME;
      return TIME_AGO_UNIT_MEDIUM_NAME_PLURAL;
    }
  if (t_scaled == 1)
    return TIME_AGO_UNIT_LARGE_NAME;
  return TIME_AGO_UNIT_LARGE_NAME_PLURAL;
}


/* Return the policy for the binding <FINGERPRINT, EMAIL> (email has
   already been normalized) and any conflict information in *CONFLICT
   if CONFLICT is not NULL.  Returns _tofu_GET_POLICY_ERROR if an error
   occurs.  */
static enum tofu_policy
get_policy (struct db *dbs, const char *fingerprint, const char *email,
	    char **conflict)
{
  sqlite3 *db;
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
  rc = sqlite3_exec_printf
    (db, strings_collect_cb, &strlist, &err,
     "select policy, conflict from bindings\n"
     " where fingerprint = %Q and email = %Q",
     fingerprint, email);
  if (rc)
    {
      log_error (_("error reading from TOFU database"
		   " (checking for existing bad bindings): %s\n"),
		 err);
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
      log_error (_("error reading from TOFU database"
		   " (checking for existing bad bindings):"
		   " expected 2 results, got %d\n"),
		 strlist_length (strlist));
      goto out;
    }

  /* The result has the right form.  */

  errno = 0;
  policy = strtol (strlist->d, &tail, 0);
  if (errno || *tail != '\0')
    {
      log_error (_("error reading from TOFU database: bad value for policy: %s\n"),
		 strlist->d);
      goto out;
    }

  if (! (policy == TOFU_POLICY_AUTO
	 || policy == TOFU_POLICY_GOOD
	 || policy == TOFU_POLICY_UNKNOWN
	 || policy == TOFU_POLICY_BAD
	 || policy == TOFU_POLICY_ASK))
    {
      log_error (_("TOFU DB is corrupted.  Invalid value for policy (%d).\n"),
		 policy);
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
get_trust (struct db *dbs, const char *fingerprint, const char *email,
	   const char *user_id, int may_ask)
{
  sqlite3 *db;
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

  policy = get_policy (dbs, fingerprint, email, &conflict);
  if (policy == TOFU_POLICY_AUTO)
    {
      policy = opt.tofu_default_policy;
      if (DBG_TRUST)
	log_debug ("TOFU: binding <%s, %s>'s policy is auto (default: %s).\n",
		   fingerprint, email,
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
		   fingerprint, email, tofu_policy_str (policy));
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

  /* Look for conflicts.  This is need in all 3 cases.

     Get the fingerprints of any bindings that share the email
     address.  Note: if the binding in question is in the DB, it will
     also be returned.  Thus, if the result set is empty, then this is
     a new binding.  */
  rc = sqlite3_exec_printf
    (db, strings_collect_cb, &bindings_with_this_email, &err,
     "select distinct fingerprint from bindings where email = %Q;",
     email);
  if (rc)
    {
      log_error (_("error reading from TOFU database"
		   " (listing fingerprints): %s\n"),
		 err);
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
		   email, fingerprint);

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

    binding = xasprintf ("<%s, %s>", fingerprint, email);
    binding_shown = 0;

    if (policy == TOFU_POLICY_NONE)
      {
	es_fprintf (fp, _("The binding %s is NOT known.  "), binding);
	binding_shown = 1;
      }
    else if (policy == TOFU_POLICY_ASK
	     /* If there the conflict is with itself, then don't
		display this message.  */
	     && conflict && strcmp (conflict, fingerprint) != 0)
      {
	es_fprintf (fp,
		    _("The key %s raised a conflict with this binding.  Since"
                      " this binding's policy was 'auto', it was changed to "
                      "'ask'.  "),
		    conflict);
	binding_shown = 1;
      }
    es_fprintf (fp,
		_("Please indicate whether you believe the binding %s%s"
		  "is legitimate (the key belongs to the stated owner) "
		  "or a forgery (bad).\n\n"),
		binding_shown ? "" : binding,
		binding_shown ? "" : " ");

    xfree (binding);

    /* Find other user ids associated with this key and whether the
       bindings are marked as good or bad.  */
    {
      sqlite3 *db_key;

      if (opt.tofu_db_format == TOFU_DB_SPLIT)
	/* In the split format, we need to search in the fingerprint
	   DB for all the emails associated with this key, not the
	   email DB.  */
	db_key = getdb (dbs, fingerprint, DB_KEY);
      else
	db_key = db;

      if (db_key)
	{
	  rc = sqlite3_exec_printf
	    (db_key, strings_collect_cb, &other_user_ids, &err,
	     "select user_id, %s from bindings where fingerprint = %Q;",
	     opt.tofu_db_format == TOFU_DB_SPLIT ? "email" : "policy",
	     fingerprint);
	  if (rc)
	    {
	      log_error (_("error gathering other user ids: %s.\n"), err);
	      sqlite3_free (err);
	      err = NULL;
	    }
	}
    }

    if (other_user_ids)
      {
	strlist_t strlist_iter;

	es_fprintf (fp, _("Known user ids associated with this key:\n"));
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

	    es_fprintf (fp, _("  %s (policy: %s)\n"),
			other_user_id,
			tofu_policy_str (other_policy));
	  }
	es_fprintf (fp, "\n");

	free_strlist (other_user_ids);
      }

    /* Find other keys associated with this email address.  */
    /* XXX: When generating the statistics, do we want the time
       embedded in the signature (column 'sig_time') or the time that
       we first verified the signature (column 'time').  */
    rc = sqlite3_exec_printf
      (db, signature_stats_collect_cb, &stats, &err,
       "select fingerprint, policy, time_ago, count(*)\n"
       " from (select bindings.*,\n"
       "        case\n"
       /* From the future (but if its just a couple of hours in the
	  future don't turn it into a warning)?  Or should we use
	  small, medium or large units?  (Note: whatever we do, we
	  keep the value in seconds.  Then when we group, everything
	  that rounds to the same number of seconds is grouped.)  */
       "         when delta < -%d then -1\n"
       "         when delta < %d then max(0, round(delta / %d) * %d)\n"
       "         when delta < %d then round(delta / %d) * %d\n"
       "         else round(delta / %d) * %d\n"
       "        end time_ago,\n"
       "        delta time_ago_raw\n"
       "       from bindings\n"
       "       left join\n"
       "         (select *,\n"
       "            cast(strftime('%%s','now') - sig_time as real) delta\n"
       "           from signatures) ss\n"
       "        on ss.binding = bindings.oid)\n"
       " where email = %Q\n"
       " group by fingerprint, time_ago\n"
       /* Make sure the current key is first.  */
       " order by fingerprint = %Q asc, fingerprint desc, time_ago desc;\n",
       TIME_AGO_FUTURE_IGNORE,
       TIME_AGO_MEDIUM_THRESHOLD, TIME_AGO_UNIT_SMALL, TIME_AGO_UNIT_SMALL,
       TIME_AGO_LARGE_THRESHOLD, TIME_AGO_UNIT_MEDIUM, TIME_AGO_UNIT_MEDIUM,
       TIME_AGO_UNIT_LARGE, TIME_AGO_UNIT_LARGE,
       email, fingerprint);
    if (rc)
      {
	strlist_t strlist_iter;

	log_error (_("error gathering signature stats: %s.\n"),
		   err);
	sqlite3_free (err);
	err = NULL;

	es_fprintf
	  (fp, _("The email address (%s) is associated with %d keys:\n"),
	   email, bindings_with_this_email_count);
	for (strlist_iter = bindings_with_this_email;
	     strlist_iter;
	     strlist_iter = strlist_iter->next)
	  es_fprintf (fp, _("  %s\n"), strlist_iter->d);
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

	es_fprintf (fp, _("Statistics for keys with the email '%s':\n"),
		    email);
	for (stats_iter = stats; stats_iter; stats_iter = stats_iter->next)
	  {
	    if (! key || strcmp (key, stats_iter->fingerprint) != 0)
	      {
		int this_key;
		key = stats_iter->fingerprint;
		this_key = strcmp (key, fingerprint) == 0;
		if (this_key)
		  es_fprintf (fp, _("  %s (this key):"), key);
		else
		  es_fprintf (fp, _("  %s (policy: %s):"),
			      key, tofu_policy_str (stats_iter->policy));
		es_fprintf (fp, "\n");
	      }

	    if (stats_iter->time_ago == -1)
	      es_fprintf (fp, _("    %ld %s signed in the future.\n"),
			  stats_iter->count,
			  stats_iter->count == 1
			  ? _("message") : _("messages"));
	    else if (stats_iter->count == 0)
	      es_fprintf (fp, _("    0 signed messages.\n"));
	    else
	      es_fprintf (fp, _("    %ld %s signed over the past %ld %s.\n"),
			  stats_iter->count,
			  stats_iter->count == 1
			  ? _("message") : _("messages"),
			  time_ago_scale (stats_iter->time_ago),
			  time_ago_unit (stats_iter->time_ago));
	  }
      }

    if (is_conflict)
      {
	/* TRANSLATORS: translate the below text.  We don't directly
	   internationalize that text so that we can tweak it without
	   breaking translations.  */
	char *text = _("TOFU detected a binding conflict");
	if (strcmp (text, "TOFU detected a binding conflict") == 0)
	  /* No translation.  Use the English text.  */
	  text =
	    "Normally, there is only a single key associated with an email "
	    "address.  However, people sometimes generate a new key if "
	    "their key is too old or they think it might be compromised.  "
	    "Alternatively, a new key may indicate a man-in-the-middle"
	    "attack!  Before accepting this key, you should talk to or "
	    "call the person to make sure this new key is legitimate.";
	es_fprintf (fp, "\n%s\n", text);
      }

    es_fputc ('\n', fp);
    /* TRANSLATORS: Two letters (normally the lower and upper case
       version of the hotkey) for each of the five choices.  If there
       is only one choice in your language, repeat it.  */
    choices = _("gG" "aA" "uU" "rR" "bB");
    es_fprintf (fp, _("(G)ood/(A)ccept once/(U)nknown/(R)eject once/(B)ad? "));

    /* Add a NUL terminator.  */
    es_fputc (0, fp);
    if (es_fclose_snatch (fp, (void **) &prompt, NULL))
      log_fatal ("error snatching memory stream\n");

    while (1)
      {
	char *response;

	if (strlen (choices) != 10)
	  log_bug ("Bad TOFU conflict translation!  Please report.");

	response = cpr_get ("tofu conflict", prompt);
	trim_spaces (response);
	cpr_kill_prompt ();
	if (strlen (response) == 1)
	  {
	    char *choice = strchr (choices, *response);
	    if (choice)
	      {
		int c = ((size_t) choice - (size_t) choices) / 2;
		assert (0 <= c && c <= 4);

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
	  (db, NULL, NULL, &err,
	   "update bindings set policy = %d, conflict = %Q"
	   " where email = %Q"
	   "  and (policy = %d or (policy = %d and fingerprint = %Q));",
	   TOFU_POLICY_ASK, fingerprint, email, TOFU_POLICY_AUTO,
	   TOFU_POLICY_ASK, fingerprint);
      else
	rc = sqlite3_exec_printf
	  (db, NULL, NULL, &err,
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

  return trust_level;
}

static void
show_statistics (struct db *dbs, const char *fingerprint,
		 const char *email, const char *user_id,
		 const char *sig_exclude)
{
  sqlite3 *db;
  int rc;
  strlist_t strlist = NULL;
  char *err = NULL;

  db = getdb (dbs, email, DB_EMAIL);
  if (! db)
    return;

  rc = sqlite3_exec_printf
    (db, strings_collect_cb, &strlist, &err,
     "select count (*), strftime('%%s','now') - min (signatures.time)\n"
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
      log_error (_("error reading from TOFU database"
		   " (getting statistics): %s\n"),
		 err);
      sqlite3_free (err);
      goto out;
    }

  if (! strlist)
    log_info (_("Have never verified a message signed by key %s!\n"),
	      fingerprint);
  else
    {
      char *tail = NULL;
      signed long messages;
      signed long first_seen_ago;

      assert (strlist_length (strlist) == 2);

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
	first_seen_ago = -1;
      else
	{
	  errno = 0;
	  first_seen_ago = strtol (strlist->next->d, &tail, 0);
	  if (errno || *tail != '\0')
	    /* Abort.  */
	    {
	      log_debug ("%s:%d: Cound't convert %s (first_seen) to an int: %s.\n",
			 __func__, __LINE__,
			 strlist->next->d, strerror (errno));
	      first_seen_ago = 0;
	    }
	}

      if (messages == -1 || first_seen_ago == 0)
	log_info (_("Failed to collect signature statistics for \"%s\" (key %s)\n"),
		  user_id, fingerprint);
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
			  " (key: %s, policy %s)."),
			user_id, fingerprint, tofu_policy_str (policy));
	  else
	    {
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

	      es_fprintf (fp,
			  _("Verified %ld messages signed by \"%s\""
			    " (key: %s, policy: %s) in the past "),
			  messages, user_id,
			  fingerprint, tofu_policy_str (policy));

	      /* It would be nice to use a macro to do this, but gettext
		 works on the unpreprocessed code.  */
#define MIN_SECS (60)
#define HOUR_SECS (60 * MIN_SECS)
#define DAY_SECS (24 * HOUR_SECS)
#define MONTH_SECS (30 * DAY_SECS)
#define YEAR_SECS (365 * DAY_SECS)

	      if (first_seen_ago > YEAR_SECS)
		{
		  years = first_seen_ago / YEAR_SECS;
		  first_seen_ago -= years * YEAR_SECS;
		}
	      if (first_seen_ago > MONTH_SECS)
		{
		  months = first_seen_ago / MONTH_SECS;
		  first_seen_ago -= months * MONTH_SECS;
		}
	      if (first_seen_ago > DAY_SECS)
		{
		  days = first_seen_ago / DAY_SECS;
		  first_seen_ago -= days * DAY_SECS;
		}
	      if (first_seen_ago > HOUR_SECS)
		{
		  hours = first_seen_ago / HOUR_SECS;
		  first_seen_ago -= hours * HOUR_SECS;
		}
	      if (first_seen_ago > MIN_SECS)
		{
		  minutes = first_seen_ago / MIN_SECS;
		  first_seen_ago -= minutes * MIN_SECS;
		}
	      seconds = first_seen_ago;

#undef MIN_SECS
#undef HOUR_SECS
#undef DAY_SECS
#undef MONTH_SECS
#undef YEAR_SECS

	      if (years)
		{
		  if (years > 1)
		    es_fprintf (fp, _("%d years"), years);
		  else
		    es_fprintf (fp, _("%d year"), years);
		  count ++;
		  first = i;
		}
	      i ++;
	      if ((first == -1 || i - first <= 3) && months)
		{
		  if (count)
		    es_fprintf (fp, _(", "));

		  if (months > 1)
		    es_fprintf (fp, _("%d months"), months);
		  else
		    es_fprintf (fp, _("%d month"), months);
		  count ++;
		  first = i;
		}
	      i ++;
	      if ((first == -1 || i - first <= 3) && count < 2 && days)
		{
		  if (count)
		    es_fprintf (fp, _(", "));

		  if (days > 1)
		    es_fprintf (fp, _("%d days"), days);
		  else
		    es_fprintf (fp, _("%d day"), days);
		  count ++;
		  first = i;
		}
	      i ++;
	      if ((first == -1 || i - first <= 3) && count < 2 && hours)
		{
		  if (count)
		    es_fprintf (fp, _(", "));

		  if (hours > 1)
		    es_fprintf (fp, _("%d hours"), hours);
		  else
		    es_fprintf (fp, _("%d hour"), hours);
		  count ++;
		  first = i;
		}
	      i ++;
	      if ((first == -1 || i - first <= 3) && count < 2 && minutes)
		{
		  if (count)
		    es_fprintf (fp, _(", "));

		  if (minutes > 1)
		    es_fprintf (fp, _("%d minutes"), minutes);
		  else
		    es_fprintf (fp, _("%d minute"), minutes);
		  count ++;
		  first = i;
		}
	      i ++;
	      if ((first == -1 || i - first <= 3) && count < 2)
		{
		  if (count)
		    es_fprintf (fp, _(", "));

		  if (seconds > 1)
		    es_fprintf (fp, _("%d seconds"), seconds);
		  else
		    es_fprintf (fp, _("%d second"), seconds);
		}

	      es_fprintf (fp, _("."));
	    }

	  es_fputc (0, fp);
	  if (es_fclose_snatch (fp, (void **) &msg, NULL))
	    log_fatal ("error snatching memory stream\n");

	  log_info ("%s\n", msg);

	  if (policy == TOFU_POLICY_AUTO && messages < 10)
	    {
	      char *set_policy_command;
	      const char *text;

	      if (messages == 0)
		log_info (_("Warning: we've have yet to see a message signed by this key!\n"));
	      else if (messages == 1)
		log_info (_("Warning: we've only seen a single message signed by this key!\n"));

	      set_policy_command =
		xasprintf ("gpg --tofu-policy bad \"%s\"", fingerprint);
	      /* TRANSLATORS: translate the below text.  We don't
		 directly internationalize that text so that we can
		 tweak it without breaking translations.  */
	      text = _("TOFU: few signatures %s");
	      if (strcmp (text, "TOFU: few signatures %d %s %s") == 0)
		text =
		  "Warning: if you think you've seen more than %d %s "
		  "signed by this key, then this key might be a forgery!  "
		  "Carefully examine the email address for small variations "
		  "(e.g., additional white space).  If the key is suspect, "
		  "then use '%s' to mark it as being bad.\n";
	      log_info (text,
			messages, messages == 1 ? _("message") : _("message"),
			set_policy_command);
	      free (set_policy_command);
	    }
	}
    }

 out:
  free_strlist (strlist);

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
    /* Hmm, no email address was provided.  Just take the lower-case
       version of the whole user id.  It could be a hostname, for
       instance.  */
    email = ascii_strlwr (xstrdup (user_id));

  return email;
}

/* Pretty print a MAX_FINGERPRINT_LEN-byte binary fingerprint into a
   malloc'd string.  */
static char *
fingerprint_pp (const byte *fingerprint_bin)
{
  char fingerprint[MAX_FINGERPRINT_LEN * 2 + 1];
  char *fingerprint_pretty;
  int space = (/* The characters and the NUL.  */
	       sizeof (fingerprint)
	       /* After every fourth character, we add a space (except
		  the last).  */
	       + (sizeof (fingerprint) - 1) / 4 - 1
	       /* Half way through we add a second space.  */
	       + 1);
  int i;
  int j;

  bin2hex (fingerprint_bin, MAX_FINGERPRINT_LEN, fingerprint);

  fingerprint_pretty = xmalloc (space);

  for (i = 0, j = 0; i < MAX_FINGERPRINT_LEN * 2; i ++)
    {
      if (i && i % 4 == 0)
	fingerprint_pretty[j ++] = ' ';
      if (i == MAX_FINGERPRINT_LEN * 2 / 2)
	fingerprint_pretty[j ++] = ' ';

      fingerprint_pretty[j ++] = fingerprint[i];
    }
  fingerprint_pretty[j ++] = 0;
  assert (j == space);

  return fingerprint_pretty;
}

/* Register the signature with the binding <FINGERPRINT_BIN, USER_ID>.
   FINGERPRINT must be MAX_FINGERPRINT_LEN bytes long.

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
tofu_register (const byte *fingerprint_bin, const char *user_id,
	       const byte *sig_digest_bin, int sig_digest_bin_len,
	       time_t sig_time, const char *origin, int may_ask)
{
  struct db *dbs;
  sqlite3 *db;
  char *fingerprint = NULL;
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
      log_error (_("error opening TOFU DB.\n"));
      goto die;
    }

  fingerprint = fingerprint_pp (fingerprint_bin);

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
      log_error (_("error opening TOFU DB.\n"));
      goto die;
    }

  /* We do a query and then an insert.  Make sure they are atomic
     by wrapping them in a transaction.  */
  rc = sqlite3_exec (db, "begin transaction;", NULL, NULL, &err);
  if (rc)
    {
      log_error (_("error beginning transaction on TOFU database: %s\n"), err);
      sqlite3_free (err);
      goto die;
    }

  /* If we've already seen this signature before, then don't add
     it again.  */
  rc = sqlite3_exec_printf
    (db, get_single_unsigned_long_cb, &c, &err,
     "select count (*)\n"
     " from signatures left join bindings\n"
     "  on signatures.binding = bindings.oid\n"
     " where fingerprint = %Q and email = %Q and sig_time = 0x%lx\n"
     "  and sig_digest = %Q",
     fingerprint, email, (unsigned long) sig_time, sig_digest);
  if (rc)
    {
      log_error (_("error reading from signatures database"
		   " (checking existence): %s\n"),
		 err);
      sqlite3_free (err);
    }
  else if (c > 1)
    /* Duplicates!  This should not happen.  In particular,
       because <fingerprint, email, sig_time, sig_digest> is the
       primary key!  */
    log_debug ("SIGNATURES DB contains duplicate records"
	       " <key: %s, %s, time: 0x%lx, sig: %s, %s>."
	       "  Please report.\n",
	       fingerprint, email, (unsigned long) sig_time,
	       sig_digest, origin);
  else if (c == 1)
    {
      already_verified = 1;
      if (DBG_TRUST)
	log_debug ("Already observed the signature"
		   " <key: %s, %s, time: 0x%lx, sig: %s, %s>\n",
		   fingerprint, email, (unsigned long) sig_time,
		   sig_digest, origin);
    }
  else
    /* This is the first time that we've seen this signature.
       Record it.  */
    {
      if (DBG_TRUST)
	log_debug ("TOFU: Saving signature <%s, %s, %s>\n",
		   fingerprint, email, sig_digest);

      assert (c == 0);

      rc = sqlite3_exec_printf
	(db, NULL, NULL, &err,
	 "insert into signatures\n"
	 " (binding, sig_digest, origin, sig_time, time)\n"
	 " values\n"
	 " ((select oid from bindings\n"
	 "    where fingerprint = %Q and email = %Q),\n"
	 "  %Q, %Q, 0x%lx, strftime('%%s', 'now'));",
	 fingerprint, email, sig_digest, origin, (unsigned long) sig_time);
      if (rc)
	{
	  log_error (_("error updating TOFU DB"
		       " (inserting into signatures table): %s\n"),
		     err);
	  sqlite3_free (err);
	}
    }

  /* It only matters whether we abort or commit the transaction
     (so long as we do something) if we execute the insert.  */
  if (rc)
    rc = sqlite3_exec (db, "rollback;", NULL, NULL, &err);
  else
    rc = sqlite3_exec (db, "commit transaction;", NULL, NULL, &err);
  if (rc)
    {
      log_error (_("error ending transaction on TOFU database: %s\n"), err);
      sqlite3_free (err);
      goto die;
    }

 die:
  if (may_ask)
    /* It's only appropriate to show the statistics in an interactive
       context.  */
    show_statistics (dbs, fingerprint, email, user_id,
		     already_verified ? NULL : sig_digest);

  xfree (email);
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

   FINGERPRINT must be a MAX_FINGERPRINT_LEN-byte fingerprint.

   If MAY_ASK is 1 and the policy is TOFU_POLICY_ASK, then the user
   will be prompted to choose a different policy.  If MAY_ASK is 0 and
   the policy is TOFU_POLICY_ASK, then TRUST_UNKNOWN is returned.

   Returns TRUST_UNDEFINED if an error occurs.  */
int
tofu_get_validity (const byte *fingerprint_bin, const char *user_id,
		   int may_ask)
{
  struct db *dbs;
  char *fingerprint = NULL;
  char *email = NULL;
  int trust_level = TRUST_UNDEFINED;

  dbs = opendbs ();
  if (! dbs)
    {
      log_error (_("error opening TOFU DB.\n"));
      goto die;
    }

  fingerprint = fingerprint_pp (fingerprint_bin);

  if (! *user_id)
    {
      log_debug ("user id is empty.  Can't get TOFU validity for this binding.\n");
      goto die;
    }

  email = email_from_user_id (user_id);

  trust_level = get_trust (dbs, fingerprint, email, user_id, may_ask);
  if (trust_level == _tofu_GET_TRUST_ERROR)
    /* An error.  */
    trust_level = TRUST_UNDEFINED;

  if (may_ask)
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
  struct db *dbs;
  PKT_public_key *pk;
  char fingerprint_bin[MAX_FINGERPRINT_LEN];
  size_t fingerprint_bin_len = sizeof (fingerprint_bin);
  char *fingerprint = NULL;

  assert (kb->pkt->pkttype == PKT_PUBLIC_KEY);
  pk = kb->pkt->pkt.public_key;

  dbs = opendbs ();
  if (! dbs)
    {
      log_error (_("error opening TOFU DB.\n"));
      return gpg_error (GPG_ERR_GENERAL);
    }

  if (DBG_TRUST)
    log_debug ("Setting TOFU policy for %s to %s\n",
	       keystr (pk->keyid), tofu_policy_str (policy));
  if (! (pk->main_keyid[0] == pk->keyid[0]
	 && pk->main_keyid[1] == pk->keyid[1]))
    log_bug ("%s: Passed a subkey, but expecting a primary key.\n", __func__);

  fingerprint_from_pk (pk, fingerprint_bin, &fingerprint_bin_len);
  assert (fingerprint_bin_len == sizeof (fingerprint_bin));

  fingerprint = fingerprint_pp (fingerprint_bin);

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
  struct db *dbs;
  char fingerprint_bin[MAX_FINGERPRINT_LEN];
  size_t fingerprint_bin_len = sizeof (fingerprint_bin);
  char *fingerprint;
  char *email;

  /* Make sure PK is a primary key.  */
  assert (pk->main_keyid[0] == pk->keyid[0]
	  && pk->main_keyid[1] == pk->keyid[1]);

  dbs = opendbs ();
  if (! dbs)
    {
      log_error (_("error opening TOFU DB.\n"));
      return gpg_error (GPG_ERR_GENERAL);
    }

  fingerprint_from_pk (pk, fingerprint_bin, &fingerprint_bin_len);
  assert (fingerprint_bin_len == sizeof (fingerprint_bin));

  fingerprint = fingerprint_pp (fingerprint_bin);

  email = email_from_user_id (user_id->name);

  *policy = get_policy (dbs, fingerprint, email, NULL);

  xfree (email);
  xfree (fingerprint);
  closedbs (dbs);

  if (*policy == _tofu_GET_POLICY_ERROR)
    return gpg_error (GPG_ERR_GENERAL);
  return 0;
}
