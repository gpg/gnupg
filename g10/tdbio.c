/* tdbio.c - trust database I/O operations
 * Copyright (C) 1998-2002, 2012 Free Software Foundation, Inc.
 * Copyright (C) 1998-2015 Werner Koch
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "gpg.h"
#include "../common/status.h"
#include "../common/iobuf.h"
#include "../common/util.h"
#include "options.h"
#include "main.h"
#include "../common/i18n.h"
#include "trustdb.h"
#include "tdbio.h"

#if defined(HAVE_DOSISH_SYSTEM) && !defined(ftruncate)
#define ftruncate chsize
#endif

#if defined(HAVE_DOSISH_SYSTEM) || defined(__CYGWIN__)
#define MY_O_BINARY  O_BINARY
#else
#define MY_O_BINARY  0
#endif

/* We use ERRNO despite that the cegcc provided open/read/write
   functions don't set ERRNO - at least show that ERRNO does not make
   sense.  */
#ifdef HAVE_W32CE_SYSTEM
#undef strerror
#define strerror(a) ("[errno not available]")
#endif

/*
 * Yes, this is a very simple implementation. We should really
 * use a page aligned buffer and read complete pages.
 * To implement a simple trannsaction system, this is sufficient.
 */
typedef struct cache_ctrl_struct *CACHE_CTRL;
struct cache_ctrl_struct
{
  CACHE_CTRL next;
  struct {
    unsigned used:1;
    unsigned dirty:1;
  } flags;
  ulong recno;
  char data[TRUST_RECORD_LEN];
};

/* Size of the cache.  The SOFT value is the general one.  While in a
   transaction this may not be sufficient and thus we may increase it
   then up to the HARD limit.  */
#define MAX_CACHE_ENTRIES_SOFT	200
#define MAX_CACHE_ENTRIES_HARD	10000


/* The cache is controlled by these variables.  */
static CACHE_CTRL cache_list;
static int cache_entries;
static int cache_is_dirty;


/* An object to pass information to cmp_krec_fpr. */
struct cmp_krec_fpr_struct
{
  int pubkey_algo;
  const char *fpr;
  int fprlen;
};

/* An object used to pass information to cmp_[s]dir. */
struct cmp_xdir_struct
{
  int pubkey_algo;
  u32 keyid[2];
};


/* The name of the trustdb file.  */
static char *db_name;

/* The handle for locking the trustdb file and a flag to record
   whether a lock has been taken.  */
static dotlock_t lockhandle;
static int is_locked;

/* The file descriptor of the trustdb.  */
static int  db_fd = -1;

/* A flag indicating that a transaction is active.  */
static int in_transaction;



static void open_db (void);
static void create_hashtable (ctrl_t ctrl, TRUSTREC *vr, int type);



/*
 * Take a lock on the trustdb file name.  I a lock file can't be
 * created the function terminates the process.  Excvept for a
 * different return code the function does nothing if the lock has
 * already been taken.
 *
 * Returns: True if lock already exists, False if the lock has
 *          actually been taken.
 */
static int
take_write_lock (void)
{
  if (!lockhandle)
    lockhandle = dotlock_create (db_name, 0);
  if (!lockhandle)
    log_fatal ( _("can't create lock for '%s'\n"), db_name );

  if (!is_locked)
    {
      if (dotlock_take (lockhandle, -1) )
        log_fatal ( _("can't lock '%s'\n"), db_name );
      else
        is_locked = 1;
      return 0;
    }
  else
    return 1;
}


/*
 * Release a lock from the trustdb file unless the global option
 * --lock-once has been used.
 */
static void
release_write_lock (void)
{
  if (!opt.lock_once)
    if (!dotlock_release (lockhandle))
      is_locked = 0;
}

/*************************************
 ************* record cache **********
 *************************************/

/*
 * Get the data from the record cache and return a pointer into that
 * cache.  Caller should copy the returned data.  NULL is returned on
 * a cache miss.
 */
static const char *
get_record_from_cache (ulong recno)
{
  CACHE_CTRL r;

  for (r = cache_list; r; r = r->next)
    {
      if (r->flags.used && r->recno == recno)
        return r->data;
    }
  return NULL;
}


/*
 * Write a cached item back to the trustdb file.
 *
 * Returns: 0 on success or an error code.
 */
static int
write_cache_item (CACHE_CTRL r)
{
  gpg_error_t err;
  int n;

  if (lseek (db_fd, r->recno * TRUST_RECORD_LEN, SEEK_SET) == -1)
    {
      err = gpg_error_from_syserror ();
      log_error (_("trustdb rec %lu: lseek failed: %s\n"),
                 r->recno, strerror (errno));
      return err;
    }
  n = write (db_fd, r->data, TRUST_RECORD_LEN);
  if (n != TRUST_RECORD_LEN)
    {
      err = gpg_error_from_syserror ();
      log_error (_("trustdb rec %lu: write failed (n=%d): %s\n"),
                 r->recno, n, strerror (errno) );
      return err;
    }
  r->flags.dirty = 0;
  return 0;
}


/*
 * Put data into the cache.  This function may flush
 * some cache entries if the cache is filled up.
 *
 * Returns: 0 on success or an error code.
 */
static int
put_record_into_cache (ulong recno, const char *data)
{
  CACHE_CTRL r, unused;
  int dirty_count = 0;
  int clean_count = 0;

  /* See whether we already cached this one.  */
  for (unused = NULL, r = cache_list; r; r = r->next)
    {
      if (!r->flags.used)
        {
          if (!unused)
            unused = r;
	}
      else if (r->recno == recno)
        {
          if (!r->flags.dirty)
            {
              /* Hmmm: should we use a copy and compare? */
              if (memcmp (r->data, data, TRUST_RECORD_LEN))
                {
                  r->flags.dirty = 1;
                  cache_is_dirty = 1;
		}
	    }
          memcpy (r->data, data, TRUST_RECORD_LEN);
          return 0;
	}
      if (r->flags.used)
        {
          if (r->flags.dirty)
            dirty_count++;
          else
            clean_count++;
	}
    }

  /* Not in the cache: add a new entry. */
  if (unused)
    {
      /* Reuse this entry. */
      r = unused;
      r->flags.used = 1;
      r->recno = recno;
      memcpy (r->data, data, TRUST_RECORD_LEN);
      r->flags.dirty = 1;
      cache_is_dirty = 1;
      cache_entries++;
      return 0;
    }

  /* See whether we reached the limit. */
  if (cache_entries < MAX_CACHE_ENTRIES_SOFT)
    {
      /* No: Put into cache.  */
      r = xmalloc (sizeof *r);
      r->flags.used = 1;
      r->recno = recno;
      memcpy (r->data, data, TRUST_RECORD_LEN);
      r->flags.dirty = 1;
      r->next = cache_list;
      cache_list = r;
      cache_is_dirty = 1;
      cache_entries++;
      return 0;
    }

  /* Cache is full: discard some clean entries.  */
  if (clean_count)
    {
      int n;

      /* We discard a third of the clean entries.  */
      n = clean_count / 3;
      if (!n)
        n = 1;

      for (unused = NULL, r = cache_list; r; r = r->next)
        {
          if (r->flags.used && !r->flags.dirty)
            {
              if (!unused)
                unused = r;
              r->flags.used = 0;
              cache_entries--;
              if (!--n)
                break;
	    }
	}

      /* Now put into the cache.  */
      log_assert (unused);
      r = unused;
      r->flags.used = 1;
      r->recno = recno;
      memcpy (r->data, data, TRUST_RECORD_LEN);
      r->flags.dirty = 1;
      cache_is_dirty = 1;
      cache_entries++;
      return 0;
    }

  /* No clean entries: We have to flush some dirty entries.  */
  if (in_transaction)
    {
      /* But we can't do this while in a transaction.  Thus we
       * increase the cache size instead.  */
      if (cache_entries < MAX_CACHE_ENTRIES_HARD)
        {
          if (opt.debug && !(cache_entries % 100))
            log_debug ("increasing tdbio cache size\n");
          r = xmalloc (sizeof *r);
          r->flags.used = 1;
          r->recno = recno;
          memcpy (r->data, data, TRUST_RECORD_LEN);
          r->flags.dirty = 1;
          r->next = cache_list;
          cache_list = r;
          cache_is_dirty = 1;
          cache_entries++;
          return 0;
	}
      /* Hard limit for the cache size reached.  */
      log_info (_("trustdb transaction too large\n"));
      return GPG_ERR_RESOURCE_LIMIT;
    }

  if (dirty_count)
    {
      int n;

      /* Discard some dirty entries. */
      n = dirty_count / 5;
      if (!n)
        n = 1;

      take_write_lock ();
      for (unused = NULL, r = cache_list; r; r = r->next)
        {
          if (r->flags.used && r->flags.dirty)
            {
              int rc;

              rc = write_cache_item (r);
              if (rc)
                return rc;
              if (!unused)
                unused = r;
              r->flags.used = 0;
              cache_entries--;
              if (!--n)
                break;
	    }
	}
      release_write_lock ();

      /* Now put into the cache.  */
      log_assert (unused);
      r = unused;
      r->flags.used = 1;
      r->recno = recno;
      memcpy (r->data, data, TRUST_RECORD_LEN);
      r->flags.dirty = 1;
      cache_is_dirty = 1;
      cache_entries++;
      return 0;
    }

  /* We should never reach this.  */
  BUG();
}


/* Return true if the cache is dirty.  */
int
tdbio_is_dirty()
{
  return cache_is_dirty;
}


/*
 * Flush the cache.  This cannot be used while in a transaction.
 */
int
tdbio_sync()
{
    CACHE_CTRL r;
    int did_lock = 0;

    if( db_fd == -1 )
	open_db();
    if( in_transaction )
	log_bug("tdbio: syncing while in transaction\n");

    if( !cache_is_dirty )
	return 0;

    if (!take_write_lock ())
        did_lock = 1;

    for( r = cache_list; r; r = r->next ) {
	if( r->flags.used && r->flags.dirty ) {
	    int rc = write_cache_item( r );
	    if( rc )
		return rc;
	}
    }
    cache_is_dirty = 0;
    if (did_lock)
        release_write_lock ();

    return 0;
}


#if 0  /* Not yet used.  */
/*
 * Simple transactions system:
 * Everything between begin_transaction and end/cancel_transaction
 * is not immediately written but at the time of end_transaction.
 *
 * NOTE: The transaction code is disabled in the 1.2 branch, as it is
 * not yet used.
 */
int
tdbio_begin_transaction ()  /* Not yet used.  */
{
  int rc;

  if (in_transaction)
    log_bug ("tdbio: nested transactions\n");
  /* Flush everything out. */
  rc = tdbio_sync();
  if (rc)
    return rc;
  in_transaction = 1;
  return 0;
}

int
tdbio_end_transaction ()  /* Not yet used.  */
{
  int rc;

  if (!in_transaction)
    log_bug ("tdbio: no active transaction\n");
  take_write_lock ();
  gnupg_block_all_signals ();
  in_transaction = 0;
  rc = tdbio_sync();
  gnupg_unblock_all_signals();
  release_write_lock ();
  return rc;
}

int
tdbio_cancel_transaction () /* Not yet used.  */
{
  CACHE_CTRL r;

  if (!in_transaction)
    log_bug ("tdbio: no active transaction\n");

  /* Remove all dirty marked entries, so that the original ones are
   * read back the next time.  */
  if (cache_is_dirty)
    {
      for (r = cache_list; r; r = r->next)
        {
          if (r->flags.used && r->flags.dirty)
            {
              r->flags.used = 0;
              cache_entries--;
	    }
	}
      cache_is_dirty = 0;
    }

  in_transaction = 0;
  return 0;
}
#endif  /* Not yet used.  */



/********************************************************
 **************** cached I/O functions ******************
 ********************************************************/

/* The cleanup handler for this module.  */
static void
cleanup (void)
{
  if (is_locked)
    {
      if (!dotlock_release (lockhandle))
        is_locked = 0;
    }
}


/*
 * Update an existing trustdb record.  The caller must call
 * tdbio_sync.
 *
 * Returns: 0 on success or an error code.
 */
int
tdbio_update_version_record (ctrl_t ctrl)
{
  TRUSTREC rec;
  int rc;

  memset (&rec, 0, sizeof rec);

  rc = tdbio_read_record (0, &rec, RECTYPE_VER);
  if (!rc)
    {
      rec.r.ver.created     = make_timestamp();
      rec.r.ver.marginals   = opt.marginals_needed;
      rec.r.ver.completes   = opt.completes_needed;
      rec.r.ver.cert_depth  = opt.max_cert_depth;
      rec.r.ver.trust_model = opt.trust_model;
      rec.r.ver.min_cert_level = opt.min_cert_level;
      rc = tdbio_write_record (ctrl, &rec);
    }

  return rc;
}


/*
 * Create and write the trustdb version record.
 *
 * Returns: 0 on success or an error code.
 */
static int
create_version_record (ctrl_t ctrl)
{
  TRUSTREC rec;
  int rc;

  memset (&rec, 0, sizeof rec);
  rec.r.ver.version     = 3;
  rec.r.ver.created     = make_timestamp ();
  rec.r.ver.marginals   = opt.marginals_needed;
  rec.r.ver.completes   = opt.completes_needed;
  rec.r.ver.cert_depth  = opt.max_cert_depth;
  if (opt.trust_model == TM_PGP || opt.trust_model == TM_CLASSIC)
    rec.r.ver.trust_model = opt.trust_model;
  else
    rec.r.ver.trust_model = TM_PGP;
  rec.r.ver.min_cert_level = opt.min_cert_level;
  rec.rectype = RECTYPE_VER;
  rec.recnum = 0;
  rc = tdbio_write_record (ctrl, &rec);

  if (!rc)
    tdbio_sync ();

  if (!rc)
    create_hashtable (ctrl, &rec, 0);

  return rc;
}


/*
 * Set the file name for the trustdb to NEW_DBNAME and if CREATE is
 * true create that file.  If NEW_DBNAME is NULL a default name is
 * used, if the it does not contain a path component separator ('/')
 * the global GnuPG home directory is used.
 *
 * Returns: 0 on success or an error code.
 *
 * On the first call this function registers an atexit handler.
 *
 */
int
tdbio_set_dbname (ctrl_t ctrl, const char *new_dbname,
                  int create, int *r_nofile)
{
  char *fname, *p;
  struct stat statbuf;
  static int initialized = 0;
  int save_slash;

  if (!initialized)
    {
      atexit (cleanup);
      initialized = 1;
    }

  *r_nofile = 0;

  if (!new_dbname)
    {
      fname = make_filename (gnupg_homedir (),
                             "trustdb" EXTSEP_S GPGEXT_GPG, NULL);
    }
  else if (*new_dbname != DIRSEP_C )
    {
      if (strchr (new_dbname, DIRSEP_C))
        fname = make_filename (new_dbname, NULL);
      else
        fname = make_filename (gnupg_homedir (), new_dbname, NULL);
    }
  else
    {
      fname = xstrdup (new_dbname);
    }

  xfree (db_name);
  db_name = fname;

  /* Quick check for (likely) case where there already is a
   * trustdb.gpg.  This check is not required in theory, but it helps
   * in practice avoiding costly operations of preparing and taking
   * the lock.  */
  if (!stat (fname, &statbuf) && statbuf.st_size > 0)
    {
      /* OK, we have the valid trustdb.gpg already.  */
      return 0;
    }
  else if (!create)
    {
      *r_nofile = 1;
      return 0;
    }

  /* Here comes: No valid trustdb.gpg AND CREATE==1 */

  /*
   * Make sure the directory exists.  This should be done before
   * acquiring the lock, which assumes the existence of the directory.
   */
  p = strrchr (fname, DIRSEP_C);
#if HAVE_W32_SYSTEM
  {
    /* Windows may either have a slash or a backslash.  Take
       care of it.  */
    char *pp = strrchr (fname, '/');
    if (!p || pp > p)
      p = pp;
  }
#endif /*HAVE_W32_SYSTEM*/
  log_assert (p);
  save_slash = *p;
  *p = 0;
  if (access (fname, F_OK))
    {
      try_make_homedir (fname);
      if (access (fname, F_OK))
        log_fatal (_("%s: directory does not exist!\n"), fname);
    }
  *p = save_slash;

  take_write_lock ();

  if (access (fname, R_OK) || stat (fname, &statbuf) || statbuf.st_size == 0)
    {
      FILE *fp;
      TRUSTREC rec;
      int rc;
      mode_t oldmask;

#ifdef HAVE_W32CE_SYSTEM
      /* We know how the cegcc implementation of access works ;-). */
      if (GetLastError () == ERROR_FILE_NOT_FOUND)
        gpg_err_set_errno (ENOENT);
      else
        gpg_err_set_errno (EIO);
#endif /*HAVE_W32CE_SYSTEM*/
      if (errno && errno != ENOENT)
        log_fatal ( _("can't access '%s': %s\n"), fname, strerror (errno));

      oldmask = umask (077);
      if (is_secured_filename (fname))
        {
          fp = NULL;
          gpg_err_set_errno (EPERM);
        }
      else
        fp = fopen (fname, "wb");
      umask(oldmask);
      if (!fp)
        log_fatal (_("can't create '%s': %s\n"), fname, strerror (errno));
      fclose (fp);

      db_fd = open (db_name, O_RDWR | MY_O_BINARY);
      if (db_fd == -1)
        log_fatal (_("can't open '%s': %s\n"), db_name, strerror (errno));

      rc = create_version_record (ctrl);
      if (rc)
        log_fatal (_("%s: failed to create version record: %s"),
                   fname, gpg_strerror (rc));

      /* Read again to check that we are okay. */
      if (tdbio_read_record (0, &rec, RECTYPE_VER))
        log_fatal (_("%s: invalid trustdb created\n"), db_name);

      if (!opt.quiet)
        log_info (_("%s: trustdb created\n"), db_name);
    }

  release_write_lock ();
  return 0;
}


/*
 * Return the full name of the trustdb.
 */
const char *
tdbio_get_dbname ()
{
  return db_name;
}


/*
 * Open the trustdb.  This may only be called if it has not yet been
 * opened and after a successful call to tdbio_set_dbname.  On return
 * the trustdb handle (DB_FD) is guaranteed to be open.
 */
static void
open_db ()
{
  TRUSTREC rec;

  log_assert( db_fd == -1 );

#ifdef HAVE_W32CE_SYSTEM
  {
    DWORD prevrc = 0;
    wchar_t *wname = utf8_to_wchar (db_name);
    if (wname)
      {
        db_fd = (int)CreateFile (wname, GENERIC_READ|GENERIC_WRITE,
                                 FILE_SHARE_READ|FILE_SHARE_WRITE, NULL,
                                 OPEN_EXISTING, 0, NULL);
        xfree (wname);
      }
    if (db_fd == -1)
      log_fatal ("can't open '%s': %d, %d\n", db_name,
                 (int)prevrc, (int)GetLastError ());
  }
#else /*!HAVE_W32CE_SYSTEM*/
  db_fd = open (db_name, O_RDWR | MY_O_BINARY );
  if (db_fd == -1 && (errno == EACCES
#ifdef EROFS
                      || errno == EROFS
#endif
                      )
      ) {
      /* Take care of read-only trustdbs.  */
      db_fd = open (db_name, O_RDONLY | MY_O_BINARY );
      if (db_fd != -1 && !opt.quiet)
          log_info (_("Note: trustdb not writable\n"));
  }
  if ( db_fd == -1 )
    log_fatal( _("can't open '%s': %s\n"), db_name, strerror(errno) );
#endif /*!HAVE_W32CE_SYSTEM*/
  register_secured_file (db_name);

  /* Read the version record. */
  if (tdbio_read_record (0, &rec, RECTYPE_VER ) )
    log_fatal( _("%s: invalid trustdb\n"), db_name );
}


/*
 * Append a new empty hashtable to the trustdb.  TYPE gives the type
 * of the hash table.  The only defined type is 0 for a trust hash.
 * On return the hashtable has been created, written, the version
 * record update, and the data flushed to the disk.  On a fatal error
 * the function terminates the process.
 */
static void
create_hashtable (ctrl_t ctrl, TRUSTREC *vr, int type)
{
  TRUSTREC rec;
  off_t offset;
  ulong recnum;
  int i, n, rc;

  offset = lseek (db_fd, 0, SEEK_END);
  if (offset == -1)
    log_fatal ("trustdb: lseek to end failed: %s\n", strerror(errno));
  recnum = offset / TRUST_RECORD_LEN;
  log_assert (recnum); /* This is will never be the first record. */

  if (!type)
    vr->r.ver.trusthashtbl = recnum;

  /* Now write the records making up the hash table. */
  n = (256+ITEMS_PER_HTBL_RECORD-1) / ITEMS_PER_HTBL_RECORD;
  for (i=0; i < n; i++, recnum++)
    {
      memset (&rec, 0, sizeof rec);
      rec.rectype = RECTYPE_HTBL;
      rec.recnum = recnum;
      rc = tdbio_write_record (ctrl, &rec);
      if (rc)
        log_fatal (_("%s: failed to create hashtable: %s\n"),
                   db_name, gpg_strerror (rc));
    }
  /* Update the version record and flush. */
  rc = tdbio_write_record (ctrl, vr);
  if (!rc)
    rc = tdbio_sync ();
  if (rc)
    log_fatal (_("%s: error updating version record: %s\n"),
               db_name, gpg_strerror (rc));
}


/*
 * Check whether open trustdb matches the global trust options given
 * for this process.  On a read problem the process is terminated.
 *
 * Return: 1 for yes, 0 for no.
 */
int
tdbio_db_matches_options()
{
  static int yes_no = -1;

  if (yes_no == -1)
    {
      TRUSTREC vr;
      int rc;

      rc = tdbio_read_record (0, &vr, RECTYPE_VER);
      if( rc )
	log_fatal( _("%s: error reading version record: %s\n"),
		   db_name, gpg_strerror (rc) );

      yes_no = vr.r.ver.marginals == opt.marginals_needed
	&& vr.r.ver.completes == opt.completes_needed
	&& vr.r.ver.cert_depth == opt.max_cert_depth
	&& vr.r.ver.trust_model == opt.trust_model
	&& vr.r.ver.min_cert_level == opt.min_cert_level;
    }

  return yes_no;
}


/*
 * Read and return the trust model identifier from the trustdb.  On a
 * read problem the process is terminated.
 */
byte
tdbio_read_model (void)
{
  TRUSTREC vr;
  int rc;

  rc = tdbio_read_record (0, &vr, RECTYPE_VER );
  if (rc)
    log_fatal (_("%s: error reading version record: %s\n"),
	       db_name, gpg_strerror (rc) );
  return vr.r.ver.trust_model;
}


/*
 * Read and return the nextstamp value from the trustdb.  On a read
 * problem the process is terminated.
 */
ulong
tdbio_read_nextcheck ()
{
  TRUSTREC vr;
  int rc;

  rc = tdbio_read_record (0, &vr, RECTYPE_VER);
  if (rc)
    log_fatal (_("%s: error reading version record: %s\n"),
               db_name, gpg_strerror (rc));
  return vr.r.ver.nextcheck;
}


/*
 * Write the STAMP nextstamp timestamp to the trustdb.  On a read or
 * write problem the process is terminated.
 *
 * Return: True if the stamp actually changed.
 */
int
tdbio_write_nextcheck (ctrl_t ctrl, ulong stamp)
{
  TRUSTREC vr;
  int rc;

  rc = tdbio_read_record (0, &vr, RECTYPE_VER);
  if (rc)
    log_fatal (_("%s: error reading version record: %s\n"),
               db_name, gpg_strerror (rc));

  if (vr.r.ver.nextcheck == stamp)
    return 0;

  vr.r.ver.nextcheck = stamp;
  rc = tdbio_write_record (ctrl, &vr);
  if (rc)
    log_fatal (_("%s: error writing version record: %s\n"),
               db_name, gpg_strerror (rc));
  return 1;
}



/*
 * Return the record number of the trusthash table or create one if it
 * does not yet exist.  On a read or write problem the process is
 * terminated.
 *
 * Return: record number
 */
static ulong
get_trusthashrec(void)
{
  static ulong trusthashtbl; /* Record number of the trust hashtable.  */

  if (!trusthashtbl)
    {
      TRUSTREC vr;
      int rc;

      rc = tdbio_read_record (0, &vr, RECTYPE_VER );
      if (rc)
        log_fatal (_("%s: error reading version record: %s\n"),
                   db_name, gpg_strerror (rc) );

      trusthashtbl = vr.r.ver.trusthashtbl;
    }

  return trusthashtbl;
}



/*
 * Update a hashtable in the trustdb.  TABLE gives the start of the
 * table, KEY and KEYLEN are the key, NEWRECNUM is the record number
 * to insert into the table.
 *
 * Return: 0 on success or an error code.
 */
static int
upd_hashtable (ctrl_t ctrl, ulong table, byte *key, int keylen, ulong newrecnum)
{
  TRUSTREC lastrec, rec;
  ulong hashrec, item;
  int msb;
  int level = 0;
  int rc, i;

  hashrec = table;
 next_level:
  msb = key[level];
  hashrec += msb / ITEMS_PER_HTBL_RECORD;
  rc = tdbio_read_record (hashrec, &rec, RECTYPE_HTBL);
  if (rc)
    {
      log_error ("upd_hashtable: read failed: %s\n", gpg_strerror (rc));
      return rc;
    }

  item = rec.r.htbl.item[msb % ITEMS_PER_HTBL_RECORD];
  if (!item)  /* Insert a new item into the hash table.  */
    {
      rec.r.htbl.item[msb % ITEMS_PER_HTBL_RECORD] = newrecnum;
      rc = tdbio_write_record (ctrl, &rec);
      if (rc)
        {
          log_error ("upd_hashtable: write htbl failed: %s\n",
                     gpg_strerror (rc));
          return rc;
	}
    }
  else if (item != newrecnum) /* Must do an update.  */
    {
      lastrec = rec;
      rc = tdbio_read_record (item, &rec, 0);
      if (rc)
        {
          log_error ("upd_hashtable: read item failed: %s\n",
                     gpg_strerror (rc));
          return rc;
	}

      if (rec.rectype == RECTYPE_HTBL)
        {
          hashrec = item;
          level++;
          if (level >= keylen)
            {
              log_error ("hashtable has invalid indirections.\n");
              return GPG_ERR_TRUSTDB;
	    }
          goto next_level;
	}
      else if (rec.rectype == RECTYPE_HLST) /* Extend the list.  */
        {
          /* Check whether the key is already in this list. */
          for (;;)
            {
              for (i=0; i < ITEMS_PER_HLST_RECORD; i++)
                {
                  if (rec.r.hlst.rnum[i] == newrecnum)
                    {
                      return 0; /* Okay, already in the list.  */
		    }
		}
              if (rec.r.hlst.next)
                {
                  rc = tdbio_read_record (rec.r.hlst.next, &rec, RECTYPE_HLST);
                  if (rc)
                    {
                      log_error ("upd_hashtable: read hlst failed: %s\n",
                                 gpg_strerror (rc) );
                      return rc;
		    }
		}
              else
                break; /* key is not in the list */
	    }

          /* Find the next free entry and put it in.  */
          for (;;)
            {
              for (i=0; i < ITEMS_PER_HLST_RECORD; i++)
                {
                  if (!rec.r.hlst.rnum[i])
                    {
                      /* Empty slot found.  */
                      rec.r.hlst.rnum[i] = newrecnum;
                      rc = tdbio_write_record (ctrl, &rec);
                      if (rc)
                        log_error ("upd_hashtable: write hlst failed: %s\n",
                                   gpg_strerror (rc));
                      return rc; /* Done.  */
		    }
		}

              if (rec.r.hlst.next)
                {
                  /* read the next reord of the list.  */
                  rc = tdbio_read_record (rec.r.hlst.next, &rec, RECTYPE_HLST);
                  if (rc)
                    {
                      log_error ("upd_hashtable: read hlst failed: %s\n",
                                 gpg_strerror (rc));
                      return rc;
		    }
		}
              else
                {
                  /* Append a new record to the list.  */
                  rec.r.hlst.next = item = tdbio_new_recnum (ctrl);
                  rc = tdbio_write_record (ctrl, &rec);
                  if (rc)
                    {
                      log_error ("upd_hashtable: write hlst failed: %s\n",
                                 gpg_strerror (rc));
                      return rc;
		    }
                  memset (&rec, 0, sizeof rec);
                  rec.rectype = RECTYPE_HLST;
                  rec.recnum = item;
                  rec.r.hlst.rnum[0] = newrecnum;
                  rc = tdbio_write_record (ctrl, &rec);
                  if (rc)
                    log_error ("upd_hashtable: write ext hlst failed: %s\n",
                               gpg_strerror (rc));
                  return rc; /* Done.  */
		}
	    } /* end loop over list slots */

	}
      else if (rec.rectype == RECTYPE_TRUST) /* Insert a list record.  */
        {
          if (rec.recnum == newrecnum)
            {
              return 0;
            }
          item = rec.recnum; /* Save number of key record.  */
          memset (&rec, 0, sizeof rec);
          rec.rectype = RECTYPE_HLST;
          rec.recnum = tdbio_new_recnum (ctrl);
          rec.r.hlst.rnum[0] = item;	    /* Old key record */
          rec.r.hlst.rnum[1] = newrecnum; /* and new key record */
          rc = tdbio_write_record (ctrl, &rec);
          if (rc)
            {
              log_error( "upd_hashtable: write new hlst failed: %s\n",
                           gpg_strerror (rc) );
              return rc;
            }
          /* Update the hashtable record.  */
          lastrec.r.htbl.item[msb % ITEMS_PER_HTBL_RECORD] = rec.recnum;
          rc = tdbio_write_record (ctrl, &lastrec);
          if (rc)
            log_error ("upd_hashtable: update htbl failed: %s\n",
                       gpg_strerror (rc));
          return rc; /* Ready.  */
        }
      else
        {
          log_error ("hashtbl %lu: %lu/%d points to an invalid record %lu\n",
                     table, hashrec, (msb % ITEMS_PER_HTBL_RECORD), item);
          if (opt.verbose > 1)
            list_trustdb (ctrl, es_stderr, NULL);
          return GPG_ERR_TRUSTDB;
	}
    }

  return 0;
}


/*
 * Drop an entry from a hashtable.  TABLE gives the start of the
 * table, KEY and KEYLEN are the key.
 *
 * Return: 0 on success or an error code.
 */
static int
drop_from_hashtable (ctrl_t ctrl, ulong table,
                     byte *key, int keylen, ulong recnum)
{
  TRUSTREC rec;
  ulong hashrec, item;
  int msb;
  int level = 0;
  int rc, i;

  hashrec = table;
 next_level:
  msb = key[level];
  hashrec += msb / ITEMS_PER_HTBL_RECORD;
  rc = tdbio_read_record (hashrec, &rec, RECTYPE_HTBL );
  if (rc)
    {
      log_error ("drop_from_hashtable: read failed: %s\n", gpg_strerror (rc));
      return rc;
    }

  item = rec.r.htbl.item[msb % ITEMS_PER_HTBL_RECORD];
  if (!item)
    return 0;   /* Not found - forget about it.  */

  if (item == recnum) /* Table points direct to the record.  */
    {
      rec.r.htbl.item[msb % ITEMS_PER_HTBL_RECORD] = 0;
      rc = tdbio_write_record (ctrl, &rec);
      if (rc)
        log_error ("drop_from_hashtable: write htbl failed: %s\n",
                   gpg_strerror (rc));
      return rc;
    }

  rc = tdbio_read_record (item, &rec, 0);
  if (rc)
    {
      log_error ("drop_from_hashtable: read item failed: %s\n",
                 gpg_strerror (rc));
      return rc;
    }

  if (rec.rectype == RECTYPE_HTBL)
    {
      hashrec = item;
      level++;
      if (level >= keylen)
        {
          log_error ("hashtable has invalid indirections.\n");
          return GPG_ERR_TRUSTDB;
	}
      goto next_level;
    }

  if (rec.rectype == RECTYPE_HLST)
    {
      for (;;)
        {
          for (i=0; i < ITEMS_PER_HLST_RECORD; i++)
            {
              if (rec.r.hlst.rnum[i] == recnum)
                {
                  rec.r.hlst.rnum[i] = 0; /* Mark as free.  */
                  rc = tdbio_write_record (ctrl, &rec);
                  if (rc)
                    log_error("drop_from_hashtable: write htbl failed: %s\n",
                              gpg_strerror (rc));
                  return rc;
		}
	    }
          if (rec.r.hlst.next)
            {
              rc = tdbio_read_record (rec.r.hlst.next, &rec, RECTYPE_HLST);
              if (rc)
                {
                  log_error ("drop_from_hashtable: read hlst failed: %s\n",
                             gpg_strerror (rc));
                  return rc;
		}
	    }
          else
            return 0; /* Key not in table.  */
	}
    }

  log_error ("hashtbl %lu: %lu/%d points to wrong record %lu\n",
             table, hashrec, (msb % ITEMS_PER_HTBL_RECORD), item);
  return GPG_ERR_TRUSTDB;
}



/*
 * Lookup a record via the hashtable TABLE by (KEY,KEYLEN) and return
 * the result in REC.  The return value of CMP() should be True if the
 * record is the desired one.
 *
 * Return: 0 if found, GPG_ERR_NOT_FOUND, or another error code.
 */
static gpg_error_t
lookup_hashtable (ulong table, const byte *key, size_t keylen,
		  int (*cmpfnc)(const void*, const TRUSTREC *),
                  const void *cmpdata, TRUSTREC *rec )
{
  int rc;
  ulong hashrec, item;
  int msb;
  int level = 0;

  hashrec = table;
 next_level:
  msb = key[level];
  hashrec += msb / ITEMS_PER_HTBL_RECORD;
  rc = tdbio_read_record (hashrec, rec, RECTYPE_HTBL);
  if (rc)
    {
      log_error("lookup_hashtable failed: %s\n", gpg_strerror (rc) );
      return rc;
    }

  item = rec->r.htbl.item[msb % ITEMS_PER_HTBL_RECORD];
  if (!item)
    return gpg_error (GPG_ERR_NOT_FOUND);

  rc = tdbio_read_record (item, rec, 0);
  if (rc)
    {
      log_error( "hashtable read failed: %s\n", gpg_strerror (rc) );
      return rc;
    }
  if (rec->rectype == RECTYPE_HTBL)
    {
      hashrec = item;
      level++;
      if (level >= keylen)
        {
          log_error ("hashtable has invalid indirections\n");
          return GPG_ERR_TRUSTDB;
	}
      goto next_level;
    }
  else if (rec->rectype == RECTYPE_HLST)
    {
      for (;;)
        {
          int i;

          for (i=0; i < ITEMS_PER_HLST_RECORD; i++)
            {
              if (rec->r.hlst.rnum[i])
                {
                  TRUSTREC tmp;

                  rc = tdbio_read_record (rec->r.hlst.rnum[i], &tmp, 0);
                  if (rc)
                    {
                      log_error ("lookup_hashtable: read item failed: %s\n",
                                 gpg_strerror (rc));
                      return rc;
		    }
                  if ((*cmpfnc)(cmpdata, &tmp))
                    {
                      *rec = tmp;
                      return 0;
		    }
		}
	    }
          if (rec->r.hlst.next)
            {
              rc = tdbio_read_record (rec->r.hlst.next, rec, RECTYPE_HLST);
              if (rc)
                {
                  log_error ("lookup_hashtable: read hlst failed: %s\n",
                             gpg_strerror (rc) );
                  return rc;
		}
	    }
          else
            return gpg_error (GPG_ERR_NOT_FOUND);
	}
    }

  if ((*cmpfnc)(cmpdata, rec))
    return 0; /* really found */

  return gpg_error (GPG_ERR_NOT_FOUND); /* no: not found */
}


/*
 * Update the trust hash table TR or create the table if it does not
 * exist.
 *
 * Return: 0 on success or an error code.
 */
static int
update_trusthashtbl (ctrl_t ctrl, TRUSTREC *tr)
{
  return upd_hashtable (ctrl, get_trusthashrec (),
                        tr->r.trust.fingerprint, 20, tr->recnum);
}


/*
 * Dump the trustdb record REC to stream FP.
 */
void
tdbio_dump_record (TRUSTREC *rec, estream_t fp)
{
  int i;
  ulong rnum = rec->recnum;

  es_fprintf (fp, "rec %5lu, ", rnum);

  switch (rec->rectype)
    {
    case 0:
      es_fprintf (fp, "blank\n");
      break;

    case RECTYPE_VER:
      es_fprintf (fp,
         "version, td=%lu, f=%lu, m/c/d=%d/%d/%d tm=%d mcl=%d nc=%lu (%s)\n",
                  rec->r.ver.trusthashtbl,
                  rec->r.ver.firstfree,
                  rec->r.ver.marginals,
                  rec->r.ver.completes,
                  rec->r.ver.cert_depth,
                  rec->r.ver.trust_model,
                  rec->r.ver.min_cert_level,
                  rec->r.ver.nextcheck,
                  strtimestamp(rec->r.ver.nextcheck)
                  );
      break;

    case RECTYPE_FREE:
      es_fprintf (fp, "free, next=%lu\n", rec->r.free.next);
      break;

    case RECTYPE_HTBL:
      es_fprintf (fp, "htbl,");
      for (i=0; i < ITEMS_PER_HTBL_RECORD; i++)
        es_fprintf (fp, " %lu", rec->r.htbl.item[i]);
      es_putc ('\n', fp);
      break;

    case RECTYPE_HLST:
      es_fprintf (fp, "hlst, next=%lu,", rec->r.hlst.next);
      for (i=0; i < ITEMS_PER_HLST_RECORD; i++)
        es_fprintf (fp, " %lu", rec->r.hlst.rnum[i]);
      es_putc ('\n', fp);
      break;

    case RECTYPE_TRUST:
      es_fprintf (fp, "trust ");
      for (i=0; i < 20; i++)
        es_fprintf (fp, "%02X", rec->r.trust.fingerprint[i]);
      es_fprintf (fp, ", ot=%d, d=%d, vl=%lu\n", rec->r.trust.ownertrust,
                  rec->r.trust.depth, rec->r.trust.validlist);
      break;

    case RECTYPE_VALID:
      es_fprintf (fp, "valid ");
      for (i=0; i < 20; i++)
        es_fprintf(fp, "%02X", rec->r.valid.namehash[i]);
      es_fprintf (fp, ", v=%d, next=%lu\n", rec->r.valid.validity,
                  rec->r.valid.next);
      break;

    default:
      es_fprintf (fp, "unknown type %d\n", rec->rectype );
      break;
    }
}


/*
 * Read the record with number RECNUM into the structure REC.  If
 * EXPECTED is not 0 reading any other record type will return an
 * error.
 *
 * Return: 0 on success, -1 on EOF, or an error code.
 */
int
tdbio_read_record (ulong recnum, TRUSTREC *rec, int expected)
{
  byte readbuf[TRUST_RECORD_LEN];
  const byte *buf, *p;
  gpg_error_t err = 0;
  int n, i;

  if (db_fd == -1)
    open_db ();

  buf = get_record_from_cache( recnum );
  if (!buf)
    {
      if (lseek (db_fd, recnum * TRUST_RECORD_LEN, SEEK_SET) == -1)
        {
          err = gpg_error_from_syserror ();
          log_error (_("trustdb: lseek failed: %s\n"), strerror (errno));
          return err;
	}
      n = read (db_fd, readbuf, TRUST_RECORD_LEN);
      if (!n)
        {
          return -1; /* eof */
	}
      else if (n != TRUST_RECORD_LEN)
        {
          err = gpg_error_from_syserror ();
          log_error (_("trustdb: read failed (n=%d): %s\n"),
                     n, strerror(errno));
          return err;
	}
      buf = readbuf;
    }
  rec->recnum = recnum;
  rec->dirty = 0;
  p = buf;
  rec->rectype = *p++;
  if (expected && rec->rectype != expected)
    {
      log_error ("%lu: read expected rec type %d, got %d\n",
                 recnum, expected, rec->rectype);
      return gpg_error (GPG_ERR_TRUSTDB);
    }
  p++;    /* Skip reserved byte.  */
  switch (rec->rectype)
    {
    case 0:  /* unused (free) record */
      break;

    case RECTYPE_VER: /* version record */
      if (memcmp(buf+1, GPGEXT_GPG, 3))
        {
          log_error (_("%s: not a trustdb file\n"), db_name );
          err = gpg_error (GPG_ERR_TRUSTDB);
        }
      else
        {
          p += 2; /* skip "gpg" */
          rec->r.ver.version  = *p++;
          rec->r.ver.marginals = *p++;
          rec->r.ver.completes = *p++;
          rec->r.ver.cert_depth = *p++;
          rec->r.ver.trust_model = *p++;
          rec->r.ver.min_cert_level = *p++;
          p += 2;
          rec->r.ver.created  = buf32_to_ulong(p);
          p += 4;
          rec->r.ver.nextcheck = buf32_to_ulong(p);
          p += 4;
          p += 4;
          p += 4;
          rec->r.ver.firstfree = buf32_to_ulong(p);
          p += 4;
          p += 4;
          rec->r.ver.trusthashtbl = buf32_to_ulong(p);
          if (recnum)
            {
              log_error( _("%s: version record with recnum %lu\n"), db_name,
                         (ulong)recnum );
              err = gpg_error (GPG_ERR_TRUSTDB);
            }
          else if (rec->r.ver.version != 3)
            {
              log_error( _("%s: invalid file version %d\n"), db_name,
                         rec->r.ver.version );
              err = gpg_error (GPG_ERR_TRUSTDB);
            }
        }
      break;

    case RECTYPE_FREE:
      rec->r.free.next  = buf32_to_ulong(p);
      break;

    case RECTYPE_HTBL:
      for (i=0; i < ITEMS_PER_HTBL_RECORD; i++)
        {
          rec->r.htbl.item[i] = buf32_to_ulong(p);
          p += 4;
	}
      break;

    case RECTYPE_HLST:
      rec->r.hlst.next = buf32_to_ulong(p);
      p += 4;
      for (i=0; i < ITEMS_PER_HLST_RECORD; i++)
        {
          rec->r.hlst.rnum[i] = buf32_to_ulong(p);
          p += 4;
	}
      break;

    case RECTYPE_TRUST:
      memcpy (rec->r.trust.fingerprint, p, 20);
      p+=20;
      rec->r.trust.ownertrust = *p++;
      rec->r.trust.depth = *p++;
      rec->r.trust.min_ownertrust = *p++;
      p++;
      rec->r.trust.validlist = buf32_to_ulong(p);
      break;

    case RECTYPE_VALID:
      memcpy (rec->r.valid.namehash, p, 20);
      p+=20;
      rec->r.valid.validity = *p++;
      rec->r.valid.next = buf32_to_ulong(p);
      p += 4;
      rec->r.valid.full_count = *p++;
      rec->r.valid.marginal_count = *p++;
      break;

    default:
      log_error ("%s: invalid record type %d at recnum %lu\n",
                 db_name, rec->rectype, (ulong)recnum);
      err = gpg_error (GPG_ERR_TRUSTDB);
      break;
    }

  return err;
}


/*
 * Write the record from the struct REC.
 *
 * Return: 0 on success or an error code.
 */
int
tdbio_write_record (ctrl_t ctrl, TRUSTREC *rec)
{
  byte buf[TRUST_RECORD_LEN];
  byte *p;
  int rc = 0;
  int i;
  ulong recnum = rec->recnum;

  if (db_fd == -1)
    open_db ();

  memset (buf, 0, TRUST_RECORD_LEN);
  p = buf;
  *p++ = rec->rectype; p++;

  switch (rec->rectype)
    {
    case 0:  /* unused record */
      break;

    case RECTYPE_VER: /* version record */
      if (recnum)
        BUG ();
      memcpy(p-1, GPGEXT_GPG, 3 ); p += 2;
      *p++ = rec->r.ver.version;
      *p++ = rec->r.ver.marginals;
      *p++ = rec->r.ver.completes;
      *p++ = rec->r.ver.cert_depth;
      *p++ = rec->r.ver.trust_model;
      *p++ = rec->r.ver.min_cert_level;
      p += 2;
      ulongtobuf(p, rec->r.ver.created); p += 4;
      ulongtobuf(p, rec->r.ver.nextcheck); p += 4;
      p += 4;
      p += 4;
      ulongtobuf(p, rec->r.ver.firstfree ); p += 4;
      p += 4;
      ulongtobuf(p, rec->r.ver.trusthashtbl ); p += 4;
      break;

    case RECTYPE_FREE:
      ulongtobuf(p, rec->r.free.next); p += 4;
      break;

    case RECTYPE_HTBL:
      for (i=0; i < ITEMS_PER_HTBL_RECORD; i++)
        {
          ulongtobuf( p, rec->r.htbl.item[i]); p += 4;
        }
      break;

    case RECTYPE_HLST:
      ulongtobuf( p, rec->r.hlst.next); p += 4;
      for (i=0; i < ITEMS_PER_HLST_RECORD; i++ )
        {
          ulongtobuf( p, rec->r.hlst.rnum[i]); p += 4;
	}
      break;

    case RECTYPE_TRUST:
      memcpy (p, rec->r.trust.fingerprint, 20); p += 20;
      *p++ = rec->r.trust.ownertrust;
      *p++ = rec->r.trust.depth;
      *p++ = rec->r.trust.min_ownertrust;
      p++;
      ulongtobuf( p, rec->r.trust.validlist); p += 4;
      break;

    case RECTYPE_VALID:
      memcpy (p, rec->r.valid.namehash, 20); p += 20;
      *p++ = rec->r.valid.validity;
      ulongtobuf( p, rec->r.valid.next); p += 4;
      *p++ = rec->r.valid.full_count;
      *p++ = rec->r.valid.marginal_count;
      break;

    default:
      BUG();
    }

  rc = put_record_into_cache (recnum, buf);
  if (rc)
    ;
  else if (rec->rectype == RECTYPE_TRUST)
    rc = update_trusthashtbl (ctrl, rec);

  return rc;
}


/*
 * Delete the record at record number RECNUm from the trustdb.
 *
 * Return: 0 on success or an error code.
 */
int
tdbio_delete_record (ctrl_t ctrl, ulong recnum)
{
  TRUSTREC vr, rec;
  int rc;

  /* Must read the record fist, so we can drop it from the hash tables */
  rc = tdbio_read_record (recnum, &rec, 0);
  if (rc)
    ;
  else if (rec.rectype == RECTYPE_TRUST)
    {
      rc = drop_from_hashtable (ctrl, get_trusthashrec(),
                                rec.r.trust.fingerprint, 20, rec.recnum);
    }

  if (rc)
    return rc;

  /* Now we can change it to a free record.  */
  rc = tdbio_read_record (0, &vr, RECTYPE_VER);
  if (rc)
    log_fatal (_("%s: error reading version record: %s\n"),
               db_name, gpg_strerror (rc));

  rec.recnum = recnum;
  rec.rectype = RECTYPE_FREE;
  rec.r.free.next = vr.r.ver.firstfree;
  vr.r.ver.firstfree = recnum;
  rc = tdbio_write_record (ctrl, &rec);
  if (!rc)
    rc = tdbio_write_record (ctrl, &vr);

  return rc;
}


/*
 * Create a new record and return its record number.
 */
ulong
tdbio_new_recnum (ctrl_t ctrl)
{
  off_t offset;
  ulong recnum;
  TRUSTREC vr, rec;
  int rc;

  /* Look for unused records.  */
  rc = tdbio_read_record (0, &vr, RECTYPE_VER);
  if (rc)
    log_fatal( _("%s: error reading version record: %s\n"),
               db_name, gpg_strerror (rc));
  if (vr.r.ver.firstfree)
    {
      recnum = vr.r.ver.firstfree;
      rc = tdbio_read_record (recnum, &rec, RECTYPE_FREE);
      if (rc)
        {
          log_error (_("%s: error reading free record: %s\n"),
                     db_name,  gpg_strerror (rc));
          return rc;
	}
      /* Update dir record.  */
      vr.r.ver.firstfree = rec.r.free.next;
      rc = tdbio_write_record (ctrl, &vr);
      if (rc)
        {
          log_error (_("%s: error writing dir record: %s\n"),
                     db_name, gpg_strerror (rc));
          return rc;
	}
      /* Zero out the new record.  */
      memset (&rec, 0, sizeof rec);
      rec.rectype = 0; /* Mark as unused record (actually already done
                          my the memset).  */
      rec.recnum = recnum;
      rc = tdbio_write_record (ctrl, &rec);
      if (rc)
        log_fatal (_("%s: failed to zero a record: %s\n"),
                   db_name, gpg_strerror (rc));
    }
  else /* Not found - append a new record.  */
    {
      offset = lseek (db_fd, 0, SEEK_END);
      if (offset == (off_t)(-1))
        log_fatal ("trustdb: lseek to end failed: %s\n", strerror (errno));
      recnum = offset / TRUST_RECORD_LEN;
      log_assert (recnum); /* this is will never be the first record */
      /* We must write a record, so that the next call to this
       * function returns another recnum.  */
      memset (&rec, 0, sizeof rec);
      rec.rectype = 0; /* unused record */
      rec.recnum = recnum;
      rc = 0;
      if (lseek( db_fd, recnum * TRUST_RECORD_LEN, SEEK_SET) == -1)
        {
          rc = gpg_error_from_syserror ();
          log_error (_("trustdb rec %lu: lseek failed: %s\n"),
                     recnum, strerror (errno));
	}
      else
        {
          int n;

          n = write (db_fd, &rec, TRUST_RECORD_LEN);
          if (n != TRUST_RECORD_LEN)
            {
              rc = gpg_error_from_syserror ();
              log_error (_("trustdb rec %lu: write failed (n=%d): %s\n"),
                         recnum, n, strerror (errno));
	    }
	}

      if (rc)
        log_fatal (_("%s: failed to append a record: %s\n"),
                   db_name,	gpg_strerror (rc));
    }

  return recnum ;
}



/* Helper function for tdbio_search_trust_byfpr.  */
static int
cmp_trec_fpr ( const void *fpr, const TRUSTREC *rec )
{
  return (rec->rectype == RECTYPE_TRUST
          && !memcmp (rec->r.trust.fingerprint, fpr, 20));
}


/*
 * Given a 20 byte FINGERPRINT search its trust record and return
 * that at REC.
 *
 * Return: 0 if found, GPG_ERR_NOT_FOUND, or another error code.
 */
gpg_error_t
tdbio_search_trust_byfpr (const byte *fingerprint, TRUSTREC *rec)
{
  int rc;

  /* Locate the trust record using the hash table */
  rc = lookup_hashtable (get_trusthashrec(), fingerprint, 20,
                         cmp_trec_fpr, fingerprint, rec );
  return rc;
}


/*
 * Given a primary public key object PK search its trust record and
 * return that at REC.
 *
 * Return: 0 if found, GPG_ERR_NOT_FOUND, or another error code.
 */
gpg_error_t
tdbio_search_trust_bypk (PKT_public_key *pk, TRUSTREC *rec)
{
  byte fingerprint[MAX_FINGERPRINT_LEN];
  size_t fingerlen;

  fingerprint_from_pk( pk, fingerprint, &fingerlen );
  for (; fingerlen < 20; fingerlen++)
    fingerprint[fingerlen] = 0;
  return tdbio_search_trust_byfpr (fingerprint, rec);
}


/*
 * Terminate the process with a message about a corrupted trustdb.
 */
void
tdbio_invalid (void)
{
  log_error (_("Error: The trustdb is corrupted.\n"));
  how_to_fix_the_trustdb ();
  g10_exit (2);
}
