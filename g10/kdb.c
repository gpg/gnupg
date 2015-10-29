#include <config.h>
#include <assert.h>
#include <sqlite3.h>

#include "gpg.h"
#include "util.h"
#include "logging.h"
#include "i18n.h"
#include "mbox-util.h"
#include "sqlite.h"

#include "kdb.h"

#if 0
#  define DEBUG(fmt, ...)                                        \
  do {                                                           \
    log_debug("%s:%d: "fmt, __func__, __LINE__, ##__VA_ARGS__);  \
  } while (0)
#else
#  define DEBUG(fmt, ...) do {} while (0)
#endif


struct kdb_resource
{
  struct kdb_resource *next;
  int read_only;
  sqlite3 *db;

  long long int key;
  char *kb;
  int kb_len;
  u32 *sigstatus;

  char fname[1];
};
typedef struct kdb_resource *KDB_RESOURCE;
typedef struct kdb_resource const * CONST_KDB_RESOURCE;

/* All registered resources.  */
static KDB_RESOURCE kdb_resources;

struct key
{
  unsigned long int key;
  char *kb;
  size_t kb_len;
  u32 *sigstatus;
};

struct keydb_handle {
  KDB_RESOURCE resource;
  /* Current key.  */
  long long int key;
  int eof;

  struct key *full_scan;

  struct {
    long long int key;
    int pk_no;
    int uid_no;
  } found, saved_found;
};

static void
hdr_cache_clear (KDB_RESOURCE resource)
{
  xfree (resource->kb);
  resource->kb = NULL;

  xfree (resource->sigstatus);
  resource->sigstatus = NULL;

  resource->key = -1;
}

static void
hd_cache_clear (KDB_HANDLE hd)
{
  int i;
  if (! hd->full_scan)
    return;

  for (i = 0; hd->full_scan[i].key != -1; i ++)
    {
      xfree (hd->full_scan[i].kb);
      xfree (hd->full_scan[i].sigstatus);
    }
  xfree (hd->full_scan);
  hd->full_scan = NULL;
}

/* RESOURCE is a value returned by a previous call to
   kdb_register_file in *RESOURCEP.  */
KDB_HANDLE
kdb_new (void *resource)
{
  KDB_RESOURCE r;
  KDB_HANDLE hd;

  /* Assert that the resource was indeed previously registered.  */
  for (r = kdb_resources; r; r = r->next)
    if (r == resource)
      break;
  assert (r);

  hd = xmalloc_clear (sizeof (*hd));
  hd->resource = resource;
  hd->key = -1;
  return hd;
}


/* Collect a series of integers from a query.  Aborts if the argument
   is not a valid integer (or real of the form X.0).  COOKIE points to
   an array of unsigned long ints, which has enough space for ARGC
   values.  */
static int
get_unsigned_longs_cb (void *cookie, int argc, char **argv, char **azColName)
{
  unsigned long int *values = cookie;
  int i;
  char *tail = NULL;

  (void) azColName;

  for (i = 0; i < argc; i ++)
    {
      if (! argv[i])
        values[i] = 0;
      else
        {
          errno = 0;
          values[i] = strtoul (argv[i], &tail, 0);
          if (errno || ! (strcmp (tail, ".0") == 0 || *tail == '\0'))
            /* Abort.  */
            return 1;
        }
    }

  return 0;
}

static int
get_unsigned_longs_cb2 (void *cookie, int argc, char **argv, char **azColName,
                        sqlite3_stmt *stmt)
{
  (void) stmt;
  return get_unsigned_longs_cb (cookie, argc, argv, azColName);
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
      log_error (_("unsupported kdb version: %s\n"), argv[0]);
      *version = -1;
    }

  /* Don't run again.  */
  return 1;
}

/* Register a new file.  If the file has already been registered then
   returns NULL otherwise returns */
gpg_error_t
kdb_register_file (const char *fname, int read_only, void **resourcep)
{
  KDB_RESOURCE resource;
  int rc;
  sqlite3 *db = NULL;
  char *err;
  unsigned long int count;
  int need_init = 1;

  for (resource = kdb_resources; resource; resource = resource->next)
    if (same_file_p (resource->fname, fname))
      {
        if (resourcep)
          *resourcep = resource;
        if (read_only)
          resource->read_only = 1;
        return 0;
      }

  rc = sqlite3_open_v2 (fname, &db,
                        read_only
                        ? SQLITE_OPEN_READONLY
                        : (SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE),
                        NULL);
  if (rc)
    {
      log_error ("Failed to open the key db '%s': %s\n",
                 fname, sqlite3_errstr (rc));
      return rc;
    }

  /* If the DB has no tables, then assume this is a new DB that needs
     to be initialized.  */
  rc = sqlite3_exec (db,
		     "select count(*) from sqlite_master where type='table';",
		     get_unsigned_longs_cb, &count, &err);
  if (rc)
    {
      log_error (_("error querying kdb's available tables: %s\n"),
		 err);
      sqlite3_free (err);
      goto out;
    }
  else if (count != 0)
    /* Assume that the DB is already initialized.  Make sure the
       version is okay.  */
    {
      int version = -1;
      rc = sqlite3_exec (db, "select version from version;", version_check_cb,
			 &version, &err);
      if (rc == SQLITE_ABORT && version == 1)
	/* Happy, happy, joy, joy.  */
	{
	  sqlite3_free (err);
          rc = 0;
          need_init = 0;
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
	  log_error (_("error determining kdb's version: %s\n"), err);
	  sqlite3_free (err);
          goto out;
	}
      else
	/* Unexpected success.  This can only happen if there are no
	   rows.  */
	{
	  log_error (_("error determining kdb's version: %s\n"),
		     "select returned 0, but expected ABORT");
          rc = 1;
          goto out;
	}
    }

  if (need_init)
    {
      /* Create the version table.  */
      rc = sqlite3_exec (db,
                         "create table version (version INTEGER);",
                         NULL, NULL, &err);
      if (rc)
        {
          log_error (_("error initializing kdb database (%s): %s\n"),
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
          log_error (_("error initializing kdb database (%s): %s\n"),
                     "version, init", err);
          sqlite3_free (err);
          goto out;
        }

      /* We have 3 tables:

         primaries - the list of all primary keys and the key block.

         keys - the list of all keys and subkeys.

         user ids - the list of all user ids.  */

      rc = sqlite3_exec
        (db,
         /* Enable foreign key constraints.  */
         "pragma foreign_keys = on;\n"
         "create table primaries\n"
         " (oid INTEGER PRIMARY KEY AUTOINCREMENT,\n"
         "  fingerprint_rev TEXT COLLATE NOCASE, keyblock BLOB,\n"
         "  sigstatus TEXT);\n"
         "create index primaries_fingerprint on primaries\n"
         " (fingerprint_rev COLLATE NOCASE);\n"
         "\n"
         "create table keys\n"
         " (primary_key INTEGER, fingerprint_rev TEXT COLLATE NOCASE,\n"
         "  pk_no INTEGER,\n"
         "  unique (primary_key, pk_no),\n"
         "  foreign key (primary_key) references primaries(oid));\n"
         "create index keys_fingerprint_primary_key_pk_no on keys\n"
         " (fingerprint_rev COLLATE NOCASE, primary_key, pk_no);\n"
         "create index keys_primary_key_pk_no on keys (primary_key, pk_no);\n"
         "\n"
         /* XXX: Is COLLATE NOCASE reasonable?  */
         "create table uids\n"
         " (primary_key INTEGER, uid TEXT COLLATE NOCASE,\n"
         "  email TEXT COLLATE NOCASE, uid_no INTEGER,\n"
         "  unique (primary_key, uid_no),\n"
         "  foreign key (primary_key) references primaries(oid));\n"
         "create index uids_ordered on uids (primary_key, uid_no);\n"
         /* In most cases, we search for a substring (like
            '%foo@bar.com%'.  This can't exploit an index so the
            following indices mostly represent overhead.  */
#if 0
         "create index uids_uid_ordered on uids\n"
         " (uid COLLATE NOCASE, primary_key, uid_no);\n"
         "create index uids_email_ordered on uids\n"
         " (email COLLATE NOCASE, primary_key, uid_no);\n"
#endif
         ,
         NULL, NULL, &err);
      if (rc)
        {
          log_error (_("error initializing kdb database: %s\n"), err);
          sqlite3_free (err);
          goto out;
        }
    }

  resource = xmalloc_clear (sizeof *resource + strlen (fname));
  strcpy (resource->fname, fname);
  resource->read_only = read_only;
  resource->db = db;
  resource->next = kdb_resources;
  kdb_resources = resource;

  if (resourcep)
    *resourcep = resource;

 out:
  if (rc)
    {
      if (resourcep)
        *resourcep = NULL;

      sqlite3_close (db);
      return gpg_error (GPG_ERR_GENERAL);
    }

  return 0;
}

int
kdb_is_writable (void *token)
{
  KDB_RESOURCE resource = token;
  if (resource->read_only)
    return 0;
  return 1;
}

/* Release the handle.  */
void
kdb_release (KDB_HANDLE hd)
{
  KDB_RESOURCE r;

  if (! hd)
    return;

  /* Check for double frees.  */
  assert (hd->resource);
  for (r = kdb_resources; r; r = r->next)
    if (r == hd->resource)
      break;
  assert (r);

  hd_cache_clear (hd);

  hd->resource = NULL;

  xfree (hd);
}

void
kdb_push_found_state (KDB_HANDLE hd)
{
  hd->saved_found = hd->found;
  hd->found.key = -1;
}

void
kdb_pop_found_state (KDB_HANDLE hd)
{
  hd->found = hd->saved_found;
  hd->saved_found.key = -1;
}

const char *
kdb_get_resource_name (KDB_HANDLE hd)
{
  if (!hd || !hd->resource)
    return NULL;
  return hd->resource->fname;
}

/* If YES is 1, lock the DB.  Otherwise, unlock it.  Returns an error
   code if locking failed.  */
int
kdb_lock (KDB_HANDLE hd, int yes)
{
  int rc;
  char *err;

  if (yes)
    /* Lock.  */
    {
      rc = sqlite3_exec (hd->resource->db, "savepoint lock;",
                         NULL, NULL, &err);
      if (rc)
        {
          log_error (_("error beginning transaction on KDB database: %s\n"),
                     err);
          sqlite3_free (err);
          return 1;
        }

      return 0;
    }
  else
    /* Unlock.  */
    {
      rc = sqlite3_exec (hd->resource->db, "release lock;", NULL, NULL, &err);
      if (rc)
        {
          log_error (_("error ending transaction on KDB database: %s\n"),
                     err);
          sqlite3_free (err);
          return 1;
        }

      return 0;
    }
}

static u32 *
sigstatus_parse (const char *sigstatus_str)
{
  int entries;
  int i;
  u32 *sigstatus;
  char *tail;

  /* Count the number of values (= # of semicolons plus 1).  */
  entries = 1;
  for (i = 0; i < strlen (sigstatus_str); i ++)
    if (sigstatus_str[i] == ';')
      entries ++;

  /* The first entry is the number of entries.  */
  sigstatus = xmalloc (sizeof (sigstatus[0]) * (1 + entries));
  sigstatus[0] = entries;

  for (i = 0; i < entries; i ++)
    {
      errno = 0;
      sigstatus[i + 1] = strtoul (sigstatus_str, &tail, 0);
      if (errno || ! ((i < entries - 1 && *tail == ';')
                      || (i == entries - 1 && *tail == '\0')))
        /* Abort.  */
        {
          log_info ("%s: Failed to parse %s\n", __func__, sigstatus_str);
          return NULL;
        }

      sigstatus_str = tail;
      if (i < entries - 1)
        {
          assert (*tail == ';');
          sigstatus_str ++;
        }
      else
        assert (*tail == '\0');
    }

  return sigstatus;
}

static int keyblock_cached;
static int keyblock_cache_hit;
static int keyblock_cache_miss;

/* The caller needs to make sure that hd->resource->key is updated!  */
static int
keyblock_cb (void *cookie, int cols, char **values, char **names,
             sqlite3_stmt *stmt)
{
  KDB_HANDLE hd = cookie;

  (void) cols;
  (void) values;
  (void) names;

  assert (cols == 2);
  assert (strcmp (names[0], "keyblock") == 0);
  assert (strcmp (names[1], "sigstatus") == 0);

  xfree (hd->resource->kb);
  hd->resource->kb_len = sqlite3_column_bytes (stmt, 0);
  hd->resource->kb = xmalloc (hd->resource->kb_len);
  memcpy (hd->resource->kb, sqlite3_column_blob (stmt, 0),
          hd->resource->kb_len);
  hd->resource->sigstatus = sigstatus_parse (values[1]);

  keyblock_cached ++;

  /* Abort to indicate success.  */
  return 1;
}

int
kdb_get_keyblock (KDB_HANDLE hd, iobuf_t *iobuf,
                  int *pk_no, int *uid_no, u32 **sigstatus)
{
  int rc;
  char *err;
  sqlite3_stmt *stmt = NULL;

  if (pk_no)
    *pk_no = 0;
  if (uid_no)
    *uid_no = 0;
  if (sigstatus)
    *sigstatus = NULL;

  if (hd->found.key == -1)
    /* Got nothing.  */
    return gpg_error (GPG_ERR_EOF);

  DEBUG ("getting keyblock for key #%lld\n", hd->found.key);

  if (keyblock_cache_hit || keyblock_cache_miss)
    DEBUG ("keyblock cache: %d fills, %d hits (%d%%), %d misses\n",
           keyblock_cached, keyblock_cache_hit,
           (keyblock_cache_hit * 100)
           / (keyblock_cache_hit + keyblock_cache_miss),
           keyblock_cache_miss);

  if (hd->resource->kb && hd->resource->key == hd->found.key)
    {
      DEBUG("read keyblock from cache.\n");
      keyblock_cache_hit ++;
      *iobuf = iobuf_temp_with_content (hd->resource->kb, hd->resource->kb_len);
      if (hd->resource->sigstatus)
        {
          size_t s = (sizeof (hd->resource->sigstatus[0])
                      * (1 + hd->resource->sigstatus[0]));
          *sigstatus = xmalloc (s);
          memcpy (*sigstatus, hd->resource->sigstatus, s);
        }
      return 0;
    }
  else
    keyblock_cache_miss ++;

  rc = sqlite3_stepx
    (hd->resource->db,
     &stmt, keyblock_cb, hd, &err,
     "select keyblock, sigstatus from primaries where oid = ?",
     SQLITE_ARG_LONG_LONG, hd->found.key, SQLITE_ARG_END);
  if (rc == SQLITE_ABORT)
    /* Success.  */
    {
      assert (hd->resource->kb);
      hd->resource->key = hd->found.key;
      *iobuf = iobuf_temp_with_content (hd->resource->kb, hd->resource->kb_len);

      rc = 0;
      if (uid_no)
        *uid_no = hd->found.uid_no;
      if (pk_no)
        *pk_no = hd->found.pk_no;
      if (sigstatus && hd->resource->sigstatus)
        {
          size_t s = (sizeof (hd->resource->sigstatus[0])
                      * (1 + hd->resource->sigstatus[0]));
          *sigstatus = xmalloc (s);
          memcpy (*sigstatus, hd->resource->sigstatus, s);
        }
    }
  else if (! rc)
    /* If we don't get an abort, then we didn't find the record.  */
    rc = gpg_error (GPG_ERR_NOT_FOUND);
  else
    {
      log_error (_("reading keyblock from keydb DB: %s\n"), err);
      sqlite3_free (err);
      rc = gpg_error (GPG_ERR_GENERAL);
    }

  sqlite3_finalize (stmt);
  return rc;
}

int
kdb_update_keyblock (KDB_HANDLE hd, kbnode_t kb,
                     const void *image, size_t imagelen)
{
  (void) hd;
  (void) kb;
  (void) image;
  (void) imagelen;

  log_fatal ("Implement %s.", __func__);
}

static char *
strrev (char *str)
{
  int i;
  int l = strlen (str);

  for (i = 0; i < l / 2; i ++)
    {
      char t = str[i];
      str[i] = str[l - 1 - i];
      str[l - 1 - i] = t;
    }

  return str;
}

static char *
fingerprint_ascii_rev (char *fingerprint_bin, int len)
{
  char *fingerprint = xmalloc (2 * len + 1);
  bin2hex (fingerprint_bin, len, fingerprint);
  return strrev (fingerprint);
}

gpg_error_t
kdb_insert_keyblock (KDB_HANDLE hd, kbnode_t root,
                     const void *image, size_t imagelen, u32 *sigstatus)
{
  PKT_public_key *mainpk = root->pkt->pkt.public_key;
  char fingerprint_bin[MAX_FINGERPRINT_LEN];
  size_t fingerprint_bin_len = sizeof (fingerprint_bin);
  char *fingerprint_rev = NULL;

  char *sigstatus_str = NULL;

  int rc;
  char *err;

  sqlite3_stmt *uid_stmt = NULL;
  sqlite3_stmt *key_stmt = NULL;

  long long oid;
  int uid_no;
  int pk_no;
  kbnode_t k;

  if (!hd)
    return gpg_error (GPG_ERR_INV_VALUE);

  hdr_cache_clear (hd->resource);
  hd_cache_clear (hd);

  /* XXX: If we have a search result (hd->found), are we supposed to
     replace it even if it isn't for the same key?  */
  /* See if we are replacing or adding this record to the
     database.  */
  fingerprint_from_pk (mainpk, fingerprint_bin, &fingerprint_bin_len);
  assert (fingerprint_bin_len == sizeof (fingerprint_bin));
  fingerprint_rev =
    fingerprint_ascii_rev (fingerprint_bin, fingerprint_bin_len);

  if (sigstatus)
    {
      int i;
      char *p;
      p = sigstatus_str = xmalloc ((10 + 1) * sigstatus[0]);
      for (i = 0; i < sigstatus[0]; i ++)
        {
          p += sprintf (p, "%d", sigstatus[i + 1]);
          if (i != sigstatus[0] - 1)
            *p ++ = ';';
        }
    }

  oid = -1;
  rc = sqlite3_stepx
    (hd->resource->db, NULL, get_unsigned_longs_cb2, &oid, &err,
     "select oid from primaries where fingerprint_rev = ?;",
     SQLITE_ARG_STRING, fingerprint_rev, SQLITE_ARG_END);
  if (rc)
    {
      log_error (_("looking up key in keydb DB: %s\n"), err);
      sqlite3_free (err);
      return gpg_error (GPG_ERR_GENERAL);
    }

  if (oid != -1)
    /* This key is already in the DB.  Replace it.  */
    {
      DEBUG ("%s already in DB (oid = %lld), updating.\n",
             fingerprint_rev, oid);

      hdr_cache_clear (hd->resource);

      rc = sqlite3_exec_printf
        (hd->resource->db, NULL, NULL, &err,
         "delete from primaries where oid = %lld;"
         "delete from keys where primary_key = %lld;"
         "delete from uids where primary_key = %lld;",
         oid, oid, oid);
      if (rc)
        {
          log_error (_("updating key in keydb DB: %s\n"), err);
          sqlite3_free (err);
          return gpg_error (GPG_ERR_GENERAL);
        }

      /* Reuse the oid.  So that any extant search won't return the
         new record.  */
      rc = sqlite3_stepx
        (hd->resource->db, NULL, NULL, NULL, &err,
         "insert into primaries (oid, fingerprint_rev, keyblock, sigstatus)\n"
         " values (?, ?, ?, ?);",
         SQLITE_ARG_LONG_LONG, oid,
         SQLITE_ARG_STRING, fingerprint_rev,
         SQLITE_ARG_BLOB, image, (long long) imagelen,
         SQLITE_ARG_STRING, sigstatus_str,
         SQLITE_ARG_END);
    }
  else
    {
      DEBUG ("New keyblock for %s.\n", fingerprint_rev);
      rc = sqlite3_stepx
        (hd->resource->db, NULL, NULL, NULL, &err,
         "insert into primaries (fingerprint_rev, keyblock, sigstatus)\n"
         " values (?, ?, ?);",
         SQLITE_ARG_STRING, fingerprint_rev,
         SQLITE_ARG_BLOB, image, (long long) imagelen,
         SQLITE_ARG_STRING, sigstatus_str,
         SQLITE_ARG_END);
    }

  xfree (sigstatus_str);
  xfree (fingerprint_rev);
  fingerprint_rev = NULL;

  if (rc)
    {
      log_error (_("inserting %s record into keydb DB: %s\n"),
                 "primary key", err);
      sqlite3_free (err);
      return gpg_error (GPG_ERR_GENERAL);
    }

  oid = sqlite3_last_insert_rowid (hd->resource->db);

  uid_no = 0;
  pk_no = 0;
  for (k = root; k; k = k->next)
    {
      if (k->pkt->pkttype == PKT_USER_ID)
        {
          PKT_user_id *uid = k->pkt->pkt.user_id;
          const char *user_id = uid->name;
          char *email = mailbox_from_userid (user_id);

          uid_no ++;

          rc = sqlite3_stepx
            (hd->resource->db, &uid_stmt, NULL, NULL, &err,
             "insert into uids (primary_key, uid, email, uid_no)"
             " values (?, ?, ?, ?);",
             SQLITE_ARG_LONG_LONG, oid,
             SQLITE_ARG_STRING, user_id, SQLITE_ARG_STRING, email,
             SQLITE_ARG_INT, uid_no,
             SQLITE_ARG_END);
          xfree (email);
          if (rc)
            {
              log_error (_("inserting %s record into keydb DB: %s\n"),
                         "uid", err);
              sqlite3_free (err);
              return gpg_error (GPG_ERR_GENERAL);
            }
        }
      else if (k->pkt->pkttype == PKT_PUBLIC_KEY
               || k->pkt->pkttype == PKT_PUBLIC_SUBKEY)
        {
          PKT_public_key *pk = k->pkt->pkt.public_key;

          pk_no ++;

          fingerprint_from_pk (pk, fingerprint_bin, &fingerprint_bin_len);
          assert (fingerprint_bin_len == sizeof (fingerprint_bin));
          fingerprint_rev = fingerprint_ascii_rev (fingerprint_bin,
                                                   fingerprint_bin_len);

          rc = sqlite3_stepx
            (hd->resource->db, &key_stmt, NULL, NULL, &err,
             "insert into keys (primary_key, fingerprint_rev, pk_no)"
             " values (?, ?, ?);",
             SQLITE_ARG_LONG_LONG, oid,
             SQLITE_ARG_STRING, fingerprint_rev,
             SQLITE_ARG_INT, pk_no,
             SQLITE_ARG_END);

          xfree (fingerprint_rev);
          fingerprint_rev = NULL;

          if (rc)
            {
              log_error (_("inserting %s record into keydb DB: %s\n"),
                         "key", err);
              sqlite3_free (err);
              return gpg_error (GPG_ERR_GENERAL);
            }
        }
    }

  sqlite3_finalize (uid_stmt);
  sqlite3_finalize (key_stmt);

  return 0;
}

int
kdb_delete (KDB_HANDLE hd)
{
  int rc;
  char *err;

  if (!hd)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (hd->found.key == -1)
    /* No search result.  */
    return gpg_error (GPG_ERR_NOTHING_FOUND);

  hdr_cache_clear (hd->resource);
  hd_cache_clear (hd);

  rc = sqlite3_exec_printf
    (hd->resource->db, NULL, NULL, &err,
     "delete from keys where primary = %d;\n"
     "delete from uids where primary = %d;\n"
     "delete from primaries where oid = %d;\n",
     hd->found.key, hd->found.key, hd->found.key);
  if (rc)
    {
      log_error (_("error deleting key from kdb database: %s\n"), err);
      sqlite3_free (err);
      rc = gpg_error (GPG_ERR_GENERAL);
    }

  return rc;
}

int
kdb_search_reset (KDB_HANDLE hd)
{
  hd->key = -1;
  hd->eof = 0;

  hd->found.key = -1;

  return 0;
}

struct key_array
{
  long int count;
  long int size;
  struct key *keys;
};

static int
get_keyblock_array_cb (void *cookie, int argc, char **argv,
                       char **azColName, sqlite3_stmt *stmt)
{
  struct key_array *a = cookie;
  struct key *entry;
  size_t len = sqlite3_column_bytes (stmt, 0);
  char *tail;

  assert (argc == 3);

  (void) azColName;

  assert (a->count < a->size);
  entry = &a->keys[a->count ++];

  entry->kb_len = len;
  entry->kb = xmalloc (len);
  memcpy (entry->kb, sqlite3_column_blob (stmt, 0), len);

  entry->sigstatus = sigstatus_parse (argv[1]);

  errno = 0;
  entry->key = strtoul (argv[2], &tail, 0);
  if (errno || ! (strcmp (tail, ".0") == 0 || *tail == '\0'))
    /* Abort.  */
    return 1;

  return 0;
}

static int
kdb_search_cb (void *cookie, int argc, char **argv, char **azColName,
               sqlite3_stmt *stmt)
{
  KDB_HANDLE hd = cookie;
  int i = 0;
  unsigned long int values[argc];
  int got_keyblock = 0;

  /* Get the keyblock.  */
  if (argc >= 2
      && strcmp (azColName[0], "keyblock") == 0
      && strcmp (azColName[1], "sigstatus") == 0)
    {
      /* When we do: select keyblock, min(oid) and we don't have any
         results, then keyblock will be NULL.  */
      if (argv[0])
        {
          keyblock_cb (hd, 2, argv, azColName, stmt);
          got_keyblock = 1;
        }
      i = 2;
    }

  get_unsigned_longs_cb (&values[i], argc - i, &argv[i], &azColName[i]);
  hd->found.uid_no = hd->found.pk_no = 0;
  for (; i < argc; i ++)
    if (strcmp (azColName[i], "oid") == 0)
      {
        hd->key = hd->found.key = values[i];
        if (got_keyblock)
          hd->resource->key = hd->key;
      }
    else if (strcmp (azColName[i], "uid_no") == 0)
      hd->found.uid_no = values[i];
    else if (strcmp (azColName[i], "pk_no") == 0)
      hd->found.pk_no = values[i];
    else
      log_bug ("%s: Bad column name: %s\n", __func__, azColName[i]);

  /* Abort.  */
  return 1;
}


int
kdb_search (KDB_HANDLE hd, KEYDB_SEARCH_DESC *desc,
            size_t ndesc, size_t *descindex)
{
  int n;
  char *where_uid = NULL;
  char *where_key = NULL;
  char *text;
  int anyskip = 0;
  int rc = 0;
  char *err = NULL;
  char *sql = NULL;

  hd->found.key = -1;

  /* If we are doing a scan, just get the next record.  */
  for (n = 0; n < ndesc; n ++)
    {
      if (desc[n].mode == KEYDB_SEARCH_MODE_FIRST)
        {
          struct key_array a;
          a.count = 0;

          hd_cache_clear (hd);

          rc = sqlite3_exec
            (hd->resource->db, "select count(*) from primaries",
             get_unsigned_longs_cb, &a.size, &err);
          if (rc)
            {
              log_fatal ("error scan primaries table: %s\n", err);
              sqlite3_free (err);
            }

          if (a.size == 0)
            {
              hd->eof = 1;
              goto out;
            }

          hd->full_scan = a.keys = xmalloc (sizeof (*a.keys) * (a.size + 1));
          a.keys[a.size].key = -1;

          rc = sqlite3_stepx
            (hd->resource->db, NULL,
             get_keyblock_array_cb, &a, &err,
             "select keyblock, sigstatus, oid from primaries order by oid",
             SQLITE_ARG_END);
          if (rc)
            {
              log_fatal ("error listing primary table: %s\n", err);
              sqlite3_free (err);
            }

          assert (a.count == a.size);

          hd->key = hd->found.key = hd->full_scan[0].key;
          goto out;
        }
      else if (desc[n].mode == KEYDB_SEARCH_MODE_NEXT)
        {
          if (hd->full_scan)
            {
              int i;
              for (i = 0; hd->full_scan[i].key != -1; i ++)
                if (hd->full_scan[i].key == hd->key)
                  break;

              if (hd->full_scan[i].key == -1)
                log_bug ("Didn't find current key (%lld) in full_scan!\n",
                         hd->key);
              else if (hd->full_scan[i + 1].key == -1)
                hd->eof = 1;
              else
                hd->key = hd->found.key = hd->full_scan[i + 1].key;

              goto out;
            }

          rc = sqlite3_stepx
            (hd->resource->db, NULL, kdb_search_cb, hd, &err,
             "select keyblock, sigstatus, oid from primaries\n"
             " where oid > ? order by oid limit 1",
             SQLITE_ARG_LONG_LONG, hd->key, SQLITE_ARG_END);

          if ((rc == SQLITE_ABORT && hd->found.key == -1)
              || (rc == 0 && hd->found.key == -1))
            /* EOF.  */
            {
              hd->eof = 1;
              rc = 0;
            }
          else if (rc == SQLITE_ABORT)
            /* Success.  */
            rc = 0;
          else if (rc)
            {
              log_fatal ("error getting next record: %s\n", err);
              sqlite3_free (err);
            }
          else
            log_bug ("Impossible: rc == 0 && hd->found.key != -1!\n");

          goto out;
        }
      else
        continue;
    }

  hd_cache_clear (hd);

  if (hd->eof)
    /* We're at the end of the file.  There is nothing else to get.  */
    return gpg_error (GPG_ERR_EOF);

#define ADD_TERM(thing, op, fmt, ...) do {              \
    char *t = sqlite3_mprintf                           \
      ("%s%s("fmt")",                                   \
       thing ? thing : "", thing ? "\n "op" " : "",     \
       ##__VA_ARGS__);                                  \
    sqlite3_free (thing);                               \
    thing = t;                                          \
  } while (0)
#define O(thing, fmt, ...) ADD_TERM(thing, "OR", fmt, ##__VA_ARGS__)
#define A(thing, fmt, ...) ADD_TERM(thing, "AND", fmt, ##__VA_ARGS__)

  if (descindex)
    log_fatal ("Implement descindex\n");

  for (n = 0; n < ndesc; n ++)
    {
      KEYDB_SEARCH_DESC *d = &desc[n];

      switch (d->mode)
        {
        case KEYDB_SEARCH_MODE_EXACT:
          O(where_uid, "uids.uid = %Q", desc[n].u.name);
          break;

        case KEYDB_SEARCH_MODE_SUBSTR:
        case KEYDB_SEARCH_MODE_MAIL:
        case KEYDB_SEARCH_MODE_MAILSUB:
        case KEYDB_SEARCH_MODE_MAILEND:
          {
            char *escaped = xmalloc (1 + 2 * strlen (d->u.name) + 1 + 1);
            int i, j = 0;

            if (d->mode == KEYDB_SEARCH_MODE_SUBSTR
                || d->mode == KEYDB_SEARCH_MODE_MAILSUB
                || d->mode == KEYDB_SEARCH_MODE_MAILEND)
              escaped[j ++] = '%';

            for (i = 0; i < strlen (d->u.name); i ++)
              {
                if (d->u.name[i] == '%' || d->u.name[i] == '_'
                    || d->u.name[i] == '\'' || d->u.name[i] == '\\')
                  escaped[j ++] = '\\';
                escaped[j ++] = d->u.name[i];
              }

            if (d->mode == KEYDB_SEARCH_MODE_SUBSTR
                || d->mode == KEYDB_SEARCH_MODE_MAILSUB)
              escaped[j ++] = '%';

            escaped[j] = 0;

            O(where_uid, "uids.%s like %Q",
              d->mode == KEYDB_SEARCH_MODE_SUBSTR ? "uid" : "email",
              escaped);
          }
          break;


        case KEYDB_SEARCH_MODE_WORDS:
          log_fatal ("Implement me!\n");
          break;


        case KEYDB_SEARCH_MODE_SHORT_KID:
          text = xmalloc (8 + 1);
          snprintf (text, 9, "%08lX", (ulong) d->u.kid[1]);
          O(where_key, "keys.fingerprint_rev like '%s%%'", strrev (text));
          xfree (text);
          break;

        case KEYDB_SEARCH_MODE_LONG_KID:
          text = xmalloc (8 * 2 + 1);
          snprintf (text, 8 * 2 + 1, "%08lX%08lX",
                    (ulong) d->u.kid[0], (ulong) d->u.kid[1]);
          O(where_key, "keys.fingerprint_rev like '%s%%'", strrev (text));
          xfree (text);
          break;

        case KEYDB_SEARCH_MODE_FPR16:
          if (d->mode == KEYDB_SEARCH_MODE_FPR16)
            text = bin2hex (d->u.fpr, 16, NULL);
          /* Fall through.  */

        case KEYDB_SEARCH_MODE_FPR20:
        case KEYDB_SEARCH_MODE_FPR:
          if (d->mode == KEYDB_SEARCH_MODE_FPR20
              || d->mode == KEYDB_SEARCH_MODE_FPR)
            text = bin2hex (d->u.fpr, 20, NULL);

          strrev (text);
          O(where_key, "keys.fingerprint_rev = '%s'", text);
          xfree (text);
          break;

        case KEYDB_SEARCH_MODE_FIRST:
        case KEYDB_SEARCH_MODE_NEXT:
          /* Already handled above.  */
          break;

        default:
          break;
        }

      if (d->skipfnc)
        anyskip = 1;
    }

  if (anyskip)
    log_fatal ("Implement anyskip.");

  DEBUG ("uid: %s\n", where_uid);
  DEBUG ("key: %s\n", where_key);

  assert (where_uid || where_key);
  if (where_uid && where_key)
    sql = sqlite3_mprintf
      ("select keyblock, sigstatus,\n"
       "  keys.primary_key oid, keys.pk_no, uids.uid_no\n"
       " from primaries\n"
       " left join keys on primaries.oid = keys.primary_key\n"
       " left join uids on primaries.oid = uids.primary_key\n"
       " where %s%lld and (%s and %s)\n"
       " order by keys.primary_key, keys.pk_no, uids.uid_no\n"
       " limit 1\n",
       hd->key == -1 ? "" : "keys.primary_key > ", hd->key,
       where_uid, where_key);
  else if (where_key)
    sql = sqlite3_mprintf
      ("select primary_key oid, pk_no\n"
       " from keys\n"
       " where %s%lld and (%s)\n"
       " order by primary_key, pk_no\n"
       " limit 1;\n",
       hd->key == -1 ? "" : "primary_key > ", hd->key, where_key);
  else
    sql = sqlite3_mprintf
      ("select primary_key oid, uid_no\n"
       " from uids\n"
       " where %s%lld and (%s)\n"
       " order by primary_key, uid_no\n"
       " limit 1;\n",
       hd->key == -1 ? "" : "primary_key > ", hd->key, where_uid);
  DEBUG ("Running '%s'\n", sql);
  rc = sqlite3_stepx (hd->resource->db, NULL, kdb_search_cb, hd, &err,
                      sql, SQLITE_ARG_END);
  if (rc == SQLITE_ABORT)
    /* Success.  */
    rc = 0;
  else if (rc)
    {
      log_fatal ("error search DB: %s\n", err);
      sqlite3_free (err);
      goto out;
    }
  else
    /* EOF.  */
    {
      assert (hd->found.key == -1);
      hd->eof = 1;
    }

 out:
  sqlite3_free (sql);
  sqlite3_free (where_uid);
  sqlite3_free (where_key);

  if (rc)
    {
      DEBUG ("Search result: Error.\n");
      return gpg_error (GPG_ERR_GENERAL);
    }
  if (hd->eof)
    {
      DEBUG ("Search result: ENOENT.\n");
      return gpg_error (GPG_ERR_EOF);
    }

  DEBUG ("Search result: key #%lld.\n", hd->key);

  return 0;
}
