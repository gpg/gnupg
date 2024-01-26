/* keydb.c - key database dispatcher
 * Copyright (C) 2001-2013 Free Software Foundation, Inc.
 * Copyright (C) 2001-2015 Werner Koch
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
#include <unistd.h>

#include "gpg.h"
#include "../common/util.h"
#include "../common/sysutils.h"
#include "options.h"
#include "main.h" /*try_make_homedir ()*/
#include "packet.h"
#include "keyring.h"
#include "../kbx/keybox.h"
#include "keydb.h"
#include "../common/i18n.h"
#include "../common/comopt.h"

#include "keydb-private.h"  /* For struct keydb_handle_s */

static int active_handles;


static struct resource_item all_resources[MAX_KEYDB_RESOURCES];
static int used_resources;

/* A pointer used to check for the primary key database by comparing
   to the struct resource_item's TOKEN.  */
static void *primary_keydb;

/* Whether we have successfully registered any resource.  */
static int any_registered;

/* Looking up keys is expensive.  To hide the cost, we cache whether
   keys exist in the key database.  Then, if we know a key does not
   exist, we don't have to spend time looking it up.  This
   particularly helps the --list-sigs and --check-sigs commands.

   The cache stores the results in a hash using separate chaining.
   Concretely: we use the LSB of the keyid to index the hash table and
   each bucket consists of a linked list of entries.  An entry
   consists of the 64-bit key id.  If a key id is not in the cache,
   then we don't know whether it is in the DB or not.

   To simplify the cache consistency protocol, we simply flush the
   whole cache whenever a key is inserted or updated.  */

#define KID_NOT_FOUND_CACHE_BUCKETS 256
static struct kid_not_found_cache_bucket *
  kid_not_found_cache[KID_NOT_FOUND_CACHE_BUCKETS];

struct kid_not_found_cache_bucket
{
  struct kid_not_found_cache_bucket *next;
  u32 kid[2];
};

struct
{
  unsigned int count;   /* The current number of entries in the hash table.  */
  unsigned int peak;    /* The peak of COUNT.  */
  unsigned int flushes; /* The number of flushes.  */
} kid_not_found_stats;

struct
{
  unsigned int handles; /* Number of handles created.  */
  unsigned int locks;   /* Number of locks taken.  */
  unsigned int parse_keyblocks; /* Number of parse_keyblock_image calls.  */
  unsigned int get_keyblocks;   /* Number of keydb_get_keyblock calls.    */
  unsigned int build_keyblocks; /* Number of build_keyblock_image calls.  */
  unsigned int update_keyblocks;/* Number of update_keyblock calls.       */
  unsigned int insert_keyblocks;/* Number of update_keyblock calls.       */
  unsigned int delete_keyblocks;/* Number of delete_keyblock calls.       */
  unsigned int search_resets;   /* Number of keydb_search_reset calls.    */
  unsigned int found;           /* Number of successful keydb_search calls. */
  unsigned int found_cached;    /* Ditto but from the cache.              */
  unsigned int notfound;        /* Number of failed keydb_search calls.   */
  unsigned int notfound_cached; /* Ditto but from the cache.              */
} keydb_stats;


static int lock_all (KEYDB_HANDLE hd);
static void unlock_all (KEYDB_HANDLE hd);


/* Check whether the keyid KID is in key id is definitely not in the
   database.

   Returns:

     0 - Indeterminate: the key id is not in the cache; we don't know
         whether the key is in the database or not.  If you want a
         definitive answer, you'll need to perform a lookup.

     1 - There is definitely no key with this key id in the database.
         We searched for a key with this key id previously, but we
         didn't find it in the database.  */
static int
kid_not_found_p (u32 *kid)
{
  struct kid_not_found_cache_bucket *k;

  for (k = kid_not_found_cache[kid[0] % KID_NOT_FOUND_CACHE_BUCKETS]; k; k = k->next)
    if (k->kid[0] == kid[0] && k->kid[1] == kid[1])
      {
        if (DBG_CACHE)
          log_debug ("keydb: kid_not_found_p (%08lx%08lx) => not in DB\n",
                     (ulong)kid[0], (ulong)kid[1]);
        return 1;
      }

  if (DBG_CACHE)
    log_debug ("keydb: kid_not_found_p (%08lx%08lx) => indeterminate\n",
               (ulong)kid[0], (ulong)kid[1]);
  return 0;
}


/* Insert the keyid KID into the kid_not_found_cache.  FOUND is whether
   the key is in the key database or not.

   Note this function does not check whether the key id is already in
   the cache.  As such, kid_not_found_p() should be called first.  */
static void
kid_not_found_insert (u32 *kid)
{
  struct kid_not_found_cache_bucket *k;

  if (DBG_CACHE)
    log_debug ("keydb: kid_not_found_insert (%08lx%08lx)\n",
               (ulong)kid[0], (ulong)kid[1]);
  k = xmalloc (sizeof *k);
  k->kid[0] = kid[0];
  k->kid[1] = kid[1];
  k->next = kid_not_found_cache[kid[0] % KID_NOT_FOUND_CACHE_BUCKETS];
  kid_not_found_cache[kid[0] % KID_NOT_FOUND_CACHE_BUCKETS] = k;
  kid_not_found_stats.count++;
}


/* Flush the kid not found cache.  */
static void
kid_not_found_flush (void)
{
  struct kid_not_found_cache_bucket *k, *knext;
  int i;

  if (DBG_CACHE)
    log_debug ("keydb: kid_not_found_flush\n");

  if (!kid_not_found_stats.count)
    return;

  for (i=0; i < DIM(kid_not_found_cache); i++)
    {
      for (k = kid_not_found_cache[i]; k; k = knext)
        {
          knext = k->next;
          xfree (k);
        }
      kid_not_found_cache[i] = NULL;
    }
  if (kid_not_found_stats.count > kid_not_found_stats.peak)
    kid_not_found_stats.peak = kid_not_found_stats.count;
  kid_not_found_stats.count = 0;
  kid_not_found_stats.flushes++;
}


static void
keyblock_cache_clear (struct keydb_handle_s *hd)
{
  hd->keyblock_cache.state = KEYBLOCK_CACHE_EMPTY;
  iobuf_close (hd->keyblock_cache.iobuf);
  hd->keyblock_cache.iobuf = NULL;
  hd->keyblock_cache.resource = -1;
  hd->keyblock_cache.offset = -1;
}


/* Handle the creation of a keyring or a keybox if it does not yet
   exist.  Take into account that other processes might have the
   keyring/keybox already locked.  This lock check does not work if
   the directory itself is not yet available.  If IS_BOX is true the
   filename is expected to refer to a keybox.  If FORCE_CREATE is true
   the keyring or keybox will be created.

   Return 0 if it is okay to access the specified file.  */
static gpg_error_t
maybe_create_keyring_or_box (char *filename, int is_box, int force_create)
{
  gpg_err_code_t ec;
  dotlock_t lockhd = NULL;
  IOBUF iobuf;
  int rc;
  mode_t oldmask;
  char *last_slash_in_filename;
  char *bak_fname = NULL;
  char *tmp_fname = NULL;
  int save_slash;

  /* A quick test whether the filename already exists. */
  if (!gnupg_access (filename, F_OK))
    return !gnupg_access (filename, R_OK)? 0 : gpg_error (GPG_ERR_EACCES);

  /* If we don't want to create a new file at all, there is no need to
     go any further - bail out right here.  */
  if (!force_create)
    return gpg_error (GPG_ERR_ENOENT);

  /* First of all we try to create the home directory.  Note, that we
     don't do any locking here because any sane application of gpg
     would create the home directory by itself and not rely on gpg's
     tricky auto-creation which is anyway only done for certain home
     directory name pattern. */
  last_slash_in_filename = strrchr (filename, DIRSEP_C);
#if HAVE_W32_SYSTEM
  {
    /* Windows may either have a slash or a backslash.  Take care of it.  */
    char *p = strrchr (filename, '/');
    if (!last_slash_in_filename || p > last_slash_in_filename)
      last_slash_in_filename = p;
  }
#endif /*HAVE_W32_SYSTEM*/
  if (!last_slash_in_filename)
    return gpg_error (GPG_ERR_ENOENT);  /* No slash at all - should
                                           not happen though.  */
  save_slash = *last_slash_in_filename;
  *last_slash_in_filename = 0;
  if (gnupg_access(filename, F_OK))
    {
      static int tried;

      if (!tried)
        {
          tried = 1;
          try_make_homedir (filename);
        }
      if ((ec = gnupg_access (filename, F_OK)))
        {
          rc = gpg_error (ec);
          *last_slash_in_filename = save_slash;
          goto leave;
        }

      *last_slash_in_filename = save_slash;

      if (!opt.use_keyboxd
          && !parse_comopt (GNUPG_MODULE_NAME_GPG, 0)
          && comopt.use_keyboxd)
        {
          /* The above try_make_homedir created a new default hoemdir
           * and also wrote a new common.conf.  Thus we now see that
           * use-keyboxd has been set.  Let's set this option and
           * return a dedicated error code.  */
          opt.use_keyboxd = comopt.use_keyboxd;
          rc = gpg_error (GPG_ERR_TRUE);
          goto leave;
        }
    }
  else
    *last_slash_in_filename = save_slash;

  /* To avoid races with other instances of gpg trying to create or
     update the keyring (it is removed during an update for a short
     time), we do the next stuff in a locked state. */
  lockhd = dotlock_create (filename, 0);
  if (!lockhd)
    {
      rc = gpg_error_from_syserror ();
      /* A reason for this to fail is that the directory is not
         writable. However, this whole locking stuff does not make
         sense if this is the case. An empty non-writable directory
         with no keyring is not really useful at all. */
      if (opt.verbose)
        log_info ("can't allocate lock for '%s': %s\n",
                  filename, gpg_strerror (rc));

      if (!force_create)
        return gpg_error (GPG_ERR_ENOENT);  /* Won't happen.  */
      else
        return rc;
    }

  if ( dotlock_take (lockhd, -1) )
    {
      rc = gpg_error_from_syserror ();
      /* This is something bad.  Probably a stale lockfile.  */
      log_info ("can't lock '%s': %s\n", filename, gpg_strerror (rc));
      goto leave;
    }

  /* Now the real test while we are locked. */

  /* Gpg either uses pubring.gpg or pubring.kbx and thus different
   * lock files.  Now, when one gpg process is updating a pubring.gpg
   * and thus holding the corresponding lock, a second gpg process may
   * get to here at the time between the two rename operation used by
   * the first process to update pubring.gpg.  The lock taken above
   * may not protect the second process if it tries to create a
   * pubring.kbx file which would be protected by a different lock
   * file.
   *
   * We can detect this case by checking that the two temporary files
   * used by the update code exist at the same time.  In that case we
   * do not create a new file but act as if FORCE_CREATE has not been
   * given.  Obviously there is a race between our two checks but the
   * worst thing is that we won't create a new file, which is better
   * than to accidentally creating one.  */
  rc = keybox_tmp_names (filename, is_box, &bak_fname, &tmp_fname);
  if (rc)
    goto leave;

  if (!gnupg_access (filename, F_OK))
    {
      rc = 0;  /* Okay, we may access the file now.  */
      goto leave;
    }
  if (!gnupg_access (bak_fname, F_OK) && !gnupg_access (tmp_fname, F_OK))
    {
      /* Very likely another process is updating a pubring.gpg and we
         should not create a pubring.kbx.  */
      rc = gpg_error (GPG_ERR_ENOENT);
      goto leave;
    }


  /* The file does not yet exist, create it now. */
  oldmask = umask (077);
  if (is_secured_filename (filename))
    {
      iobuf = NULL;
      gpg_err_set_errno (EPERM);
    }
  else
    iobuf = iobuf_create (filename, 0);
  umask (oldmask);
  if (!iobuf)
    {
      rc = gpg_error_from_syserror ();
      if (is_box)
        log_error (_("error creating keybox '%s': %s\n"),
                   filename, gpg_strerror (rc));
      else
        log_error (_("error creating keyring '%s': %s\n"),
                   filename, gpg_strerror (rc));
      goto leave;
    }

  iobuf_close (iobuf);
  /* Must invalidate that ugly cache */
  iobuf_ioctl (NULL, IOBUF_IOCTL_INVALIDATE_CACHE, 0, filename);

  /* Make sure that at least one record is in a new keybox file, so
     that the detection magic will work the next time it is used.  */
  if (is_box)
    {
      estream_t fp = es_fopen (filename, "wb");
      if (!fp)
        rc = gpg_error_from_syserror ();
      else
        {
          rc = _keybox_write_header_blob (fp, 1);
          es_fclose (fp);
        }
      if (rc)
        {
          if (is_box)
            log_error (_("error creating keybox '%s': %s\n"),
                       filename, gpg_strerror (rc));
          else
            log_error (_("error creating keyring '%s': %s\n"),
                       filename, gpg_strerror (rc));
          goto leave;
        }
    }

  if (!opt.quiet)
    {
      if (is_box)
        log_info (_("keybox '%s' created\n"), filename);
      else
        log_info (_("keyring '%s' created\n"), filename);
    }

  rc = 0;

 leave:
  if (lockhd)
    {
      dotlock_release (lockhd);
      dotlock_destroy (lockhd);
    }
  xfree (bak_fname);
  xfree (tmp_fname);
  return rc;
}


/* Helper for keydb_add_resource.  Opens FILENAME to figure out the
   resource type.

   Returns the specified file's likely type.  If the file does not
   exist, returns KEYDB_RESOURCE_TYPE_NONE and sets *R_FOUND to 0.
   Otherwise, tries to figure out the file's type.  This is either
   KEYDB_RESOURCE_TYPE_KEYBOX, KEYDB_RESOURCE_TYPE_KEYRING or
   KEYDB_RESOURCE_TYPE_KEYNONE.  If the file is a keybox and it has
   the OpenPGP flag set, then R_OPENPGP is also set.  */
static KeydbResourceType
rt_from_file (const char *filename, int *r_found, int *r_openpgp)
{
  u32 magic;
  unsigned char verbuf[4];
  estream_t fp;
  KeydbResourceType rt = KEYDB_RESOURCE_TYPE_NONE;

  *r_found = *r_openpgp = 0;
  fp = es_fopen (filename, "rb");
  if (fp)
    {
      *r_found = 1;

      if (es_fread (&magic, 4, 1, fp) == 1 )
        {
          if (magic == 0x13579ace || magic == 0xce9a5713)
            ; /* GDBM magic - not anymore supported. */
          else if (es_fread (&verbuf, 4, 1, fp) == 1
                   && verbuf[0] == 1
                   && es_fread (&magic, 4, 1, fp) == 1
                   && !memcmp (&magic, "KBXf", 4))
            {
              if ((verbuf[3] & 0x02))
                *r_openpgp = 1;
              rt = KEYDB_RESOURCE_TYPE_KEYBOX;
            }
          else
            rt = KEYDB_RESOURCE_TYPE_KEYRING;
        }
      else /* Maybe empty: assume keyring. */
        rt = KEYDB_RESOURCE_TYPE_KEYRING;

      es_fclose (fp);
    }

  return rt;
}

char *
keydb_search_desc_dump (struct keydb_search_desc *desc)
{
  char b[MAX_FORMATTED_FINGERPRINT_LEN + 1];
  char fpr[2 * MAX_FINGERPRINT_LEN + 1];

#if MAX_FINGERPRINT_LEN < UBID_LEN || MAX_FINGERPRINT_LEN < KEYGRIP_LEN
#error MAX_FINGERPRINT_LEN is shorter than KEYGRIP or UBID length.
#endif

  switch (desc->mode)
    {
    case KEYDB_SEARCH_MODE_EXACT:
      return xasprintf ("EXACT: '%s'", desc->u.name);
    case KEYDB_SEARCH_MODE_SUBSTR:
      return xasprintf ("SUBSTR: '%s'", desc->u.name);
    case KEYDB_SEARCH_MODE_MAIL:
      return xasprintf ("MAIL: '%s'", desc->u.name);
    case KEYDB_SEARCH_MODE_MAILSUB:
      return xasprintf ("MAILSUB: '%s'", desc->u.name);
    case KEYDB_SEARCH_MODE_MAILEND:
      return xasprintf ("MAILEND: '%s'", desc->u.name);
    case KEYDB_SEARCH_MODE_WORDS:
      return xasprintf ("WORDS: '%s'", desc->u.name);
    case KEYDB_SEARCH_MODE_SHORT_KID:
      return xasprintf ("SHORT_KID: '%s'",
                        format_keyid (desc->u.kid, KF_SHORT, b, sizeof (b)));
    case KEYDB_SEARCH_MODE_LONG_KID:
      return xasprintf ("LONG_KID: '%s'",
                        format_keyid (desc->u.kid, KF_LONG, b, sizeof (b)));
    case KEYDB_SEARCH_MODE_FPR:
      bin2hex (desc->u.fpr, desc->fprlen, fpr);
      return xasprintf ("FPR%02d: '%s'", desc->fprlen,
                        format_hexfingerprint (fpr, b, sizeof (b)));
    case KEYDB_SEARCH_MODE_ISSUER:
      return xasprintf ("ISSUER: '%s'", desc->u.name);
    case KEYDB_SEARCH_MODE_ISSUER_SN:
      return xasprintf ("ISSUER_SN: '#%.*s/%s'",
                        (int)desc->snlen,desc->sn, desc->u.name);
    case KEYDB_SEARCH_MODE_SN:
      return xasprintf ("SN: '%.*s'",
                        (int)desc->snlen, desc->sn);
    case KEYDB_SEARCH_MODE_SUBJECT:
      return xasprintf ("SUBJECT: '%s'", desc->u.name);
    case KEYDB_SEARCH_MODE_KEYGRIP:
      bin2hex (desc[0].u.grip, KEYGRIP_LEN, fpr);
      return xasprintf ("KEYGRIP: %s", fpr);
    case KEYDB_SEARCH_MODE_UBID:
      bin2hex (desc[0].u.ubid, UBID_LEN, fpr);
      return xasprintf ("UBID: %s", fpr);
    case KEYDB_SEARCH_MODE_FIRST:
      return xasprintf ("FIRST");
    case KEYDB_SEARCH_MODE_NEXT:
      return xasprintf ("NEXT");
    default:
      return xasprintf ("Bad search mode (%d)", desc->mode);
    }
}



/* Register a resource (keyring or keybox).  The first keyring or
 * keybox that is added using this function is created if it does not
 * already exist and the KEYDB_RESOURCE_FLAG_READONLY is not set.
 *
 * FLAGS are a combination of the KEYDB_RESOURCE_FLAG_* constants.
 *
 * URL must have the following form:
 *
 *   gnupg-ring:filename  = plain keyring
 *   gnupg-kbx:filename   = keybox file
 *   filename             = check file's type (create as a plain keyring)
 *
 * Note: on systems with drive letters (Windows) invalid URLs (i.e.,
 * those with an unrecognized part before the ':' such as "c:\...")
 * will silently be treated as bare filenames.  On other systems, such
 * URLs will cause this function to return GPG_ERR_GENERAL.
 *
 * If KEYDB_RESOURCE_FLAG_DEFAULT is set, the resource is a keyring
 * and the file ends in ".gpg", then this function also checks if a
 * file with the same name, but the extension ".kbx" exists, is a
 * keybox and the OpenPGP flag is set.  If so, this function opens
 * that resource instead.
 *
 * If the file is not found, KEYDB_RESOURCE_FLAG_GPGVDEF is set and
 * the URL ends in ".kbx", then this function will try opening the
 * same URL, but with the extension ".gpg".  If that file is a keybox
 * with the OpenPGP flag set or it is a keyring, then we use that
 * instead.
 *
 * If the file is not found, KEYDB_RESOURCE_FLAG_DEFAULT is set, the
 * file should be created and the file's extension is ".gpg" then we
 * replace the extension with ".kbx".
 *
 * If the KEYDB_RESOURCE_FLAG_PRIMARY is set and the resource is a
 * keyring (not a keybox), then this resource is considered the
 * primary resource.  This is used by keydb_locate_writable().  If
 * another primary keyring is set, then that keyring is considered the
 * primary.
 *
 * If KEYDB_RESOURCE_FLAG_READONLY is set and the resource is a
 * keyring (not a keybox), then the keyring is marked as read only and
 * operations just as keyring_insert_keyblock will return
 * GPG_ERR_ACCESS.
 */
gpg_error_t
keydb_add_resource (const char *url, unsigned int flags)
{
  /* The file named by the URL (i.e., without the prototype).  */
  const char *resname = url;

  char *filename = NULL;
  int create;
  int read_only = !!(flags&KEYDB_RESOURCE_FLAG_READONLY);
  int is_default = !!(flags&KEYDB_RESOURCE_FLAG_DEFAULT);
  int is_gpgvdef = !!(flags&KEYDB_RESOURCE_FLAG_GPGVDEF);
  gpg_error_t err = 0;
  KeydbResourceType rt = KEYDB_RESOURCE_TYPE_NONE;
  void *token;

  /* Create the resource if it is the first registered one.  */
  create = (!read_only && !any_registered);

  if (strlen (resname) > 11 && !strncmp( resname, "gnupg-ring:", 11) )
    {
      rt = KEYDB_RESOURCE_TYPE_KEYRING;
      resname += 11;
    }
  else if (strlen (resname) > 10 && !strncmp (resname, "gnupg-kbx:", 10) )
    {
      rt = KEYDB_RESOURCE_TYPE_KEYBOX;
      resname += 10;
    }
#if !defined(HAVE_DRIVE_LETTERS) && !defined(__riscos__)
  else if (strchr (resname, ':'))
    {
      log_error ("invalid key resource URL '%s'\n", url );
      err = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }
#endif /* !HAVE_DRIVE_LETTERS && !__riscos__ */

  if (*resname != DIRSEP_C
#ifdef HAVE_W32_SYSTEM
      && *resname != '/'  /* Fixme: does not handle drive letters.  */
#endif
        )
    {
      /* Do tilde expansion etc. */
      if (strchr (resname, DIRSEP_C)
#ifdef HAVE_W32_SYSTEM
          || strchr (resname, '/')  /* Windows also accepts this.  */
#endif
          )
        filename = make_filename (resname, NULL);
      else
        filename = make_filename (gnupg_homedir (), resname, NULL);
    }
  else
    filename = xstrdup (resname);

  /* See whether we can determine the filetype.  */
  if (rt == KEYDB_RESOURCE_TYPE_NONE)
    {
      int found, openpgp_flag;
      int pass = 0;
      size_t filenamelen;

    check_again:
      filenamelen = strlen (filename);
      rt = rt_from_file (filename, &found, &openpgp_flag);
      if (found)
        {
          /* The file exists and we have the resource type in RT.

             Now let us check whether in addition to the "pubring.gpg"
             a "pubring.kbx with openpgp keys exists.  This is so that
             GPG 2.1 will use an existing "pubring.kbx" by default iff
             that file has been created or used by 2.1.  This check is
             needed because after creation or use of the kbx file with
             2.1 an older version of gpg may have created a new
             pubring.gpg for its own use.  */
          if (!pass && is_default && rt == KEYDB_RESOURCE_TYPE_KEYRING
              && filenamelen > 4 && !strcmp (filename+filenamelen-4, ".gpg"))
            {
              strcpy (filename+filenamelen-4, ".kbx");
              if ((rt_from_file (filename, &found, &openpgp_flag)
                   == KEYDB_RESOURCE_TYPE_KEYBOX) && found && openpgp_flag)
                rt = KEYDB_RESOURCE_TYPE_KEYBOX;
              else /* Restore filename */
                strcpy (filename+filenamelen-4, ".gpg");
            }
	}
      else if (!pass && is_gpgvdef
               && filenamelen > 4 && !strcmp (filename+filenamelen-4, ".kbx"))
        {
          /* Not found but gpgv's default "trustedkeys.kbx" file has
             been requested.  We did not found it so now check whether
             a "trustedkeys.gpg" file exists and use that instead.  */
          KeydbResourceType rttmp;

          strcpy (filename+filenamelen-4, ".gpg");
          rttmp = rt_from_file (filename, &found, &openpgp_flag);
          if (found
              && ((rttmp == KEYDB_RESOURCE_TYPE_KEYBOX && openpgp_flag)
                  || (rttmp == KEYDB_RESOURCE_TYPE_KEYRING)))
            rt = rttmp;
          else /* Restore filename */
            strcpy (filename+filenamelen-4, ".kbx");
        }
      else if (!pass
               && is_default && create
               && filenamelen > 4 && !strcmp (filename+filenamelen-4, ".gpg"))
        {
          /* The file does not exist, the default resource has been
             requested, the file shall be created, and the file has a
             ".gpg" suffix.  Change the suffix to ".kbx" and try once
             more.  This way we achieve that we open an existing
             ".gpg" keyring, but create a new keybox file with an
             ".kbx" suffix.  */
          strcpy (filename+filenamelen-4, ".kbx");
          pass++;
          goto check_again;
        }
      else /* No file yet: create keybox. */
        rt = KEYDB_RESOURCE_TYPE_KEYBOX;
    }

  switch (rt)
    {
    case KEYDB_RESOURCE_TYPE_NONE:
      log_error ("unknown type of key resource '%s'\n", url );
      err = gpg_error (GPG_ERR_GENERAL);
      goto leave;

    case KEYDB_RESOURCE_TYPE_KEYRING:
      err = maybe_create_keyring_or_box (filename, 0, create);
      if (err)
        goto leave;

      if (keyring_register_filename (filename, read_only, &token))
        {
          if (used_resources >= MAX_KEYDB_RESOURCES)
            err = gpg_error (GPG_ERR_RESOURCE_LIMIT);
          else
            {
              if ((flags & KEYDB_RESOURCE_FLAG_PRIMARY))
                primary_keydb = token;
              all_resources[used_resources].type = rt;
              all_resources[used_resources].u.kr = NULL; /* Not used here */
              all_resources[used_resources].token = token;
              used_resources++;
            }
        }
      else
        {
          /* This keyring was already registered, so ignore it.
             However, we can still mark it as primary even if it was
             already registered.  */
          if ((flags & KEYDB_RESOURCE_FLAG_PRIMARY))
            primary_keydb = token;
        }
      break;

    case KEYDB_RESOURCE_TYPE_KEYBOX:
      {
        err = maybe_create_keyring_or_box (filename, 1, create);
        if (err)
          goto leave;

        err = keybox_register_file (filename, 0, &token);
        if (!err)
          {
            if (used_resources >= MAX_KEYDB_RESOURCES)
              err = gpg_error (GPG_ERR_RESOURCE_LIMIT);
            else
              {
                if ((flags & KEYDB_RESOURCE_FLAG_PRIMARY))
                  primary_keydb = token;
                all_resources[used_resources].type = rt;
                all_resources[used_resources].u.kb = NULL; /* Not used here */
                all_resources[used_resources].token = token;

                if (!(flags & KEYDB_RESOURCE_FLAG_READONLY))
                  {
                    KEYBOX_HANDLE kbxhd;

                    /* Do a compress run if needed and no other user is
                     * currently using the keybox. */
                    kbxhd = keybox_new_openpgp (token, 0);
                    if (kbxhd)
                      {
                        if (!keybox_lock (kbxhd, 1, 0))
                          {
                            keybox_compress (kbxhd);
                            keybox_lock (kbxhd, 0, 0);
                          }

                        keybox_release (kbxhd);
                      }
                  }
                used_resources++;
              }
          }
        else if (gpg_err_code (err) == GPG_ERR_EEXIST)
          {
            /* Already registered.  We will mark it as the primary key
               if requested.  */
            if ((flags & KEYDB_RESOURCE_FLAG_PRIMARY))
              primary_keydb = token;
          }
      }
      break;

      default:
	log_error ("resource type of '%s' not supported\n", url);
	err = gpg_error (GPG_ERR_GENERAL);
	goto leave;
    }

  /* fixme: check directory permissions and print a warning */

 leave:
  if (err)
    {
      if (gpg_err_code (err) != GPG_ERR_TRUE)
        {
          log_error (_("keyblock resource '%s': %s\n"),
                     filename, gpg_strerror (err));
          write_status_error ("add_keyblock_resource", err);
        }
    }
  else
    any_registered = 1;
  xfree (filename);
  return err;
}


void
keydb_dump_stats (void)
{
  log_info ("keydb: handles=%u locks=%u parse=%u get=%u\n",
            keydb_stats.handles,
            keydb_stats.locks,
            keydb_stats.parse_keyblocks,
            keydb_stats.get_keyblocks);
  log_info ("       build=%u update=%u insert=%u delete=%u\n",
            keydb_stats.build_keyblocks,
            keydb_stats.update_keyblocks,
            keydb_stats.insert_keyblocks,
            keydb_stats.delete_keyblocks);
  log_info ("       reset=%u found=%u not=%u cache=%u not=%u\n",
            keydb_stats.search_resets,
            keydb_stats.found,
            keydb_stats.notfound,
            keydb_stats.found_cached,
            keydb_stats.notfound_cached);
  log_info ("kid_not_found_cache: count=%u peak=%u flushes=%u\n",
            kid_not_found_stats.count,
            kid_not_found_stats.peak,
            kid_not_found_stats.flushes);
}


/* keydb_new diverts to here in non-keyboxd mode.  HD is just the
 * calloced structure with the handle type initialized.  */
gpg_error_t
internal_keydb_init (KEYDB_HANDLE hd)
{
  gpg_error_t err = 0;
  int i, j;
  int die = 0;
  int reterrno;

  log_assert (!hd->use_keyboxd);
  hd->found = -1;
  hd->saved_found = -1;
  hd->is_reset = 1;

  log_assert (used_resources <= MAX_KEYDB_RESOURCES);
  for (i=j=0; ! die && i < used_resources; i++)
    {
      switch (all_resources[i].type)
        {
        case KEYDB_RESOURCE_TYPE_NONE: /* ignore */
          break;
        case KEYDB_RESOURCE_TYPE_KEYRING:
          hd->active[j].type   = all_resources[i].type;
          hd->active[j].token  = all_resources[i].token;
          hd->active[j].u.kr = keyring_new (all_resources[i].token);
          if (!hd->active[j].u.kr)
            {
              reterrno = errno;
              die = 1;
            }
          j++;
          break;
        case KEYDB_RESOURCE_TYPE_KEYBOX:
          hd->active[j].type   = all_resources[i].type;
          hd->active[j].token  = all_resources[i].token;
          hd->active[j].u.kb   = keybox_new_openpgp (all_resources[i].token, 0);
          if (!hd->active[j].u.kb)
            {
              reterrno = errno;
              die = 1;
            }
          j++;
          break;
        }
    }
  hd->used = j;

  active_handles++;
  keydb_stats.handles++;

  if (die)
    err = gpg_error_from_errno (reterrno);

   return err;
}


/* Free all non-keyboxd resources owned by the database handle.
 * keydb_release diverts to here.  */
void
internal_keydb_deinit (KEYDB_HANDLE hd)
{
  int i;

  log_assert (!hd->use_keyboxd);

  log_assert (active_handles > 0);
  active_handles--;

  hd->keep_lock = 0;
  unlock_all (hd);
  for (i=0; i < hd->used; i++)
    {
      switch (hd->active[i].type)
        {
        case KEYDB_RESOURCE_TYPE_NONE:
          break;
        case KEYDB_RESOURCE_TYPE_KEYRING:
          keyring_release (hd->active[i].u.kr);
          break;
        case KEYDB_RESOURCE_TYPE_KEYBOX:
          keybox_release (hd->active[i].u.kb);
          break;
        }
    }

  keyblock_cache_clear (hd);
}


/* Take a lock on the files immediately and not only during insert or
 * update.  This lock is released with keydb_release.  */
gpg_error_t
internal_keydb_lock (KEYDB_HANDLE hd)
{
  gpg_error_t err;

  log_assert (!hd->use_keyboxd);

  err = lock_all (hd);
  if (!err)
    hd->keep_lock = 1;

  return err;
}


/* Set a flag on the handle to suppress use of cached results.  This
 * is required for updating a keyring and for key listings.  Fixme:
 * Using a new parameter for keydb_new might be a better solution.  */
void
keydb_disable_caching (KEYDB_HANDLE hd)
{
  if (hd && !hd->use_keyboxd)
    hd->no_caching = 1;
}


/* Return the file name of the resource in which the current search
 * result was found or, if there is no search result, the filename of
 * the current resource (i.e., the resource that the file position
 * points to).  Note: the filename is not necessarily the URL used to
 * open it!
 *
 * This function only returns NULL if no handle is specified, in all
 * other error cases an empty string is returned.  */
const char *
keydb_get_resource_name (KEYDB_HANDLE hd)
{
  int idx;
  const char *s = NULL;

  if (!hd)
    return NULL;

  if (hd->use_keyboxd)
    return "[keyboxd]";

  if ( hd->found >= 0 && hd->found < hd->used)
    idx = hd->found;
  else if ( hd->current >= 0 && hd->current < hd->used)
    idx = hd->current;
  else
    idx = 0;

  switch (hd->active[idx].type)
    {
    case KEYDB_RESOURCE_TYPE_NONE:
      s = NULL;
      break;
    case KEYDB_RESOURCE_TYPE_KEYRING:
      s = keyring_get_resource_name (hd->active[idx].u.kr);
      break;
    case KEYDB_RESOURCE_TYPE_KEYBOX:
      s = keybox_get_resource_name (hd->active[idx].u.kb);
      break;
    }

  return s? s: "";
}



static int
lock_all (KEYDB_HANDLE hd)
{
  int i, rc = 0;

  /* Fixme: This locking scheme may lead to a deadlock if the resources
     are not added in the same order by all processes.  We are
     currently only allowing one resource so it is not a problem.
     [Oops: Who claimed the latter]

     To fix this we need to use a lock file to protect lock_all.  */

  for (i=0; !rc && i < hd->used; i++)
    {
      switch (hd->active[i].type)
        {
        case KEYDB_RESOURCE_TYPE_NONE:
          break;
        case KEYDB_RESOURCE_TYPE_KEYRING:
          rc = keyring_lock (hd->active[i].u.kr, 1);
          break;
        case KEYDB_RESOURCE_TYPE_KEYBOX:
          rc = keybox_lock (hd->active[i].u.kb, 1, -1);
          break;
        }
    }

  if (rc)
    {
      /* Revert the already taken locks.  */
      for (i--; i >= 0; i--)
        {
          switch (hd->active[i].type)
            {
            case KEYDB_RESOURCE_TYPE_NONE:
              break;
            case KEYDB_RESOURCE_TYPE_KEYRING:
              keyring_lock (hd->active[i].u.kr, 0);
              break;
            case KEYDB_RESOURCE_TYPE_KEYBOX:
              keybox_lock (hd->active[i].u.kb, 0, 0);
              break;
            }
        }
    }
  else
    {
      hd->locked = 1;
      keydb_stats.locks++;
    }

  return rc;
}


static void
unlock_all (KEYDB_HANDLE hd)
{
  int i;

  if (!hd->locked || hd->keep_lock)
    return;

  for (i=hd->used-1; i >= 0; i--)
    {
      switch (hd->active[i].type)
        {
        case KEYDB_RESOURCE_TYPE_NONE:
          break;
        case KEYDB_RESOURCE_TYPE_KEYRING:
          keyring_lock (hd->active[i].u.kr, 0);
          break;
        case KEYDB_RESOURCE_TYPE_KEYBOX:
          keybox_lock (hd->active[i].u.kb, 0, 0);
          break;
        }
    }
  hd->locked = 0;
}



/* Save the last found state and invalidate the current selection
 * (i.e., the entry selected by keydb_search() is invalidated and
 * something like keydb_get_keyblock() will return an error).  This
 * does not change the file position.  This makes it possible to do
 * something like:
 *
 *   keydb_search (hd, ...);  // Result 1.
 *   keydb_push_found_state (hd);
 *     keydb_search_reset (hd);
 *     keydb_search (hd, ...);  // Result 2.
 *   keydb_pop_found_state (hd);
 *   keydb_get_keyblock (hd, ...);  // -> Result 1.
 *
 * Note: it is only possible to save a single save state at a time.
 * In other words, the save stack only has room for a single
 * instance of the state.  */
/* FIXME(keyboxd): This function is used only at one place - see how
 * we can avoid it.  */
void
keydb_push_found_state (KEYDB_HANDLE hd)
{
  if (!hd)
    return;

  if (hd->found < 0 || hd->found >= hd->used)
    {
      hd->saved_found = -1;
      return;
    }

  switch (hd->active[hd->found].type)
    {
    case KEYDB_RESOURCE_TYPE_NONE:
      break;
    case KEYDB_RESOURCE_TYPE_KEYRING:
      keyring_push_found_state (hd->active[hd->found].u.kr);
      break;
    case KEYDB_RESOURCE_TYPE_KEYBOX:
      keybox_push_found_state (hd->active[hd->found].u.kb);
      break;
    }

  hd->saved_found = hd->found;
  hd->found = -1;
}


/* Restore the previous save state.  If the saved state is NULL or
   invalid, this is a NOP.  */
/* FIXME(keyboxd): This function is used only at one place - see how
 * we can avoid it.  */
void
keydb_pop_found_state (KEYDB_HANDLE hd)
{
  if (!hd)
    return;

  hd->found = hd->saved_found;
  hd->saved_found = -1;
  if (hd->found < 0 || hd->found >= hd->used)
    return;

  switch (hd->active[hd->found].type)
    {
    case KEYDB_RESOURCE_TYPE_NONE:
      break;
    case KEYDB_RESOURCE_TYPE_KEYRING:
      keyring_pop_found_state (hd->active[hd->found].u.kr);
      break;
    case KEYDB_RESOURCE_TYPE_KEYBOX:
      keybox_pop_found_state (hd->active[hd->found].u.kb);
      break;
    }
}



/* Parse the keyblock in IOBUF and return at R_KEYBLOCK.  */
gpg_error_t
keydb_parse_keyblock (iobuf_t iobuf, int pk_no, int uid_no,
                      kbnode_t *r_keyblock)
{
  gpg_error_t err;
  struct parse_packet_ctx_s parsectx;
  PACKET *pkt;
  kbnode_t keyblock = NULL;
  kbnode_t node, *tail;
  int in_cert, save_mode;
  int pk_count, uid_count;

  *r_keyblock = NULL;

  pkt = xtrymalloc (sizeof *pkt);
  if (!pkt)
    return gpg_error_from_syserror ();
  init_packet (pkt);
  init_parse_packet (&parsectx, iobuf);
  save_mode = set_packet_list_mode (0);
  in_cert = 0;
  tail = NULL;
  pk_count = uid_count = 0;
  while ((err = parse_packet (&parsectx, pkt)) != -1)
    {
      if (gpg_err_code (err) == GPG_ERR_UNKNOWN_PACKET)
        {
          free_packet (pkt, &parsectx);
          init_packet (pkt);
          continue;
	}
      if (err)
        {
          es_fflush (es_stdout);
          log_error ("parse_keyblock_image: read error: %s\n",
                     gpg_strerror (err));
          if (gpg_err_code (err) == GPG_ERR_INV_PACKET)
            {
              free_packet (pkt, &parsectx);
              init_packet (pkt);
              continue;
            }
          err = gpg_error (GPG_ERR_INV_KEYRING);
          break;
        }

      /* Filter allowed packets.  */
      switch (pkt->pkttype)
        {
        case PKT_PUBLIC_KEY:
        case PKT_PUBLIC_SUBKEY:
        case PKT_SECRET_KEY:
        case PKT_SECRET_SUBKEY:
        case PKT_USER_ID:
        case PKT_ATTRIBUTE:
        case PKT_SIGNATURE:
        case PKT_RING_TRUST:
          break; /* Allowed per RFC.  */

        default:
          log_info ("skipped packet of type %d in keybox\n", (int)pkt->pkttype);
          free_packet(pkt, &parsectx);
          init_packet(pkt);
          continue;
        }

      /* Other sanity checks.  */
      if (!in_cert && pkt->pkttype != PKT_PUBLIC_KEY)
        {
          log_error ("parse_keyblock_image: first packet in a keybox blob "
                     "is not a public key packet\n");
          err = gpg_error (GPG_ERR_INV_KEYRING);
          break;
        }
      if (in_cert && (pkt->pkttype == PKT_PUBLIC_KEY
                      || pkt->pkttype == PKT_SECRET_KEY))
        {
          log_error ("parse_keyblock_image: "
                     "multiple keyblocks in a keybox blob\n");
          err = gpg_error (GPG_ERR_INV_KEYRING);
          break;
        }
      in_cert = 1;

      node = new_kbnode (pkt);

      switch (pkt->pkttype)
        {
        case PKT_PUBLIC_KEY:
        case PKT_PUBLIC_SUBKEY:
        case PKT_SECRET_KEY:
        case PKT_SECRET_SUBKEY:
          if (++pk_count == pk_no)
            node->flag |= 1;
          break;

        case PKT_USER_ID:
          if (++uid_count == uid_no)
            node->flag |= 2;
          break;

        default:
          break;
        }

      if (!keyblock)
        keyblock = node;
      else
        *tail = node;
      tail = &node->next;
      pkt = xtrymalloc (sizeof *pkt);
      if (!pkt)
        {
          err = gpg_error_from_syserror ();
          break;
        }
      init_packet (pkt);
    }
  set_packet_list_mode (save_mode);

  if (err == -1 && keyblock)
    err = 0; /* Got the entire keyblock.  */

  if (err)
    release_kbnode (keyblock);
  else
    {
      *r_keyblock = keyblock;
      keydb_stats.parse_keyblocks++;
    }
  free_packet (pkt, &parsectx);
  deinit_parse_packet (&parsectx);
  xfree (pkt);
  return err;
}


/* Return the keyblock last found by keydb_search() in *RET_KB.
 * keydb_get_keyblock divert to here in the non-keyboxd mode.
 *
 * On success, the function returns 0 and the caller must free *RET_KB
 * using release_kbnode().  Otherwise, the function returns an error
 * code.
 *
 * The returned keyblock has the kbnode flag bit 0 set for the node
 * with the public key used to locate the keyblock or flag bit 1 set
 * for the user ID node.  */
gpg_error_t
internal_keydb_get_keyblock (KEYDB_HANDLE hd, KBNODE *ret_kb)
{
  gpg_error_t err = 0;

  log_assert (!hd->use_keyboxd);

  if (hd->keyblock_cache.state == KEYBLOCK_CACHE_FILLED)
    {
      err = iobuf_seek (hd->keyblock_cache.iobuf, 0);
      if (err)
	{
	  log_error ("keydb_get_keyblock: failed to rewind iobuf for cache\n");
	  keyblock_cache_clear (hd);
	}
      else
	{
	  err = keydb_parse_keyblock (hd->keyblock_cache.iobuf,
				      hd->keyblock_cache.pk_no,
				      hd->keyblock_cache.uid_no,
				      ret_kb);
	  if (err)
	    keyblock_cache_clear (hd);
	  if (DBG_CLOCK)
	    log_clock ("%s leave (cached mode)", __func__);
	  return err;
	}
    }

  if (hd->found < 0 || hd->found >= hd->used)
    return gpg_error (GPG_ERR_VALUE_NOT_FOUND);

  switch (hd->active[hd->found].type)
    {
    case KEYDB_RESOURCE_TYPE_NONE:
      err = gpg_error (GPG_ERR_GENERAL); /* oops */
      break;
    case KEYDB_RESOURCE_TYPE_KEYRING:
      err = keyring_get_keyblock (hd->active[hd->found].u.kr, ret_kb);
      break;
    case KEYDB_RESOURCE_TYPE_KEYBOX:
      {
        iobuf_t iobuf;
        int pk_no, uid_no;

        err = keybox_get_keyblock (hd->active[hd->found].u.kb,
                                   &iobuf, &pk_no, &uid_no);
        if (!err)
          {
            err = keydb_parse_keyblock (iobuf, pk_no, uid_no, ret_kb);
            if (!err && hd->keyblock_cache.state == KEYBLOCK_CACHE_PREPARED)
              {
                hd->keyblock_cache.state     = KEYBLOCK_CACHE_FILLED;
                hd->keyblock_cache.iobuf     = iobuf;
                hd->keyblock_cache.pk_no     = pk_no;
                hd->keyblock_cache.uid_no    = uid_no;
              }
            else
              {
                iobuf_close (iobuf);
              }
          }
      }
      break;
    }

  if (hd->keyblock_cache.state != KEYBLOCK_CACHE_FILLED)
    keyblock_cache_clear (hd);

  if (!err)
    keydb_stats.get_keyblocks++;

  return err;
}


/* Update the keyblock KB (i.e., extract the fingerprint and find the
 * corresponding keyblock in the keyring).
 * keydb_update_keyblock diverts to here in the non-keyboxd mode.
 *
 * This doesn't do anything if --dry-run was specified.
 *
 * Returns 0 on success.  Otherwise, it returns an error code.  Note:
 * if there isn't a keyblock in the keyring corresponding to KB, then
 * this function returns GPG_ERR_VALUE_NOT_FOUND.
 *
 * This function selects the matching record and modifies the current
 * file position to point to the record just after the selected entry.
 * Thus, if you do a subsequent search using HD, you should first do a
 * keydb_search_reset.  Further, if the selected record is important,
 * you should use keydb_push_found_state and keydb_pop_found_state to
 * save and restore it.  */
gpg_error_t
internal_keydb_update_keyblock (ctrl_t ctrl, KEYDB_HANDLE hd, kbnode_t kb)
{
  gpg_error_t err;
  PKT_public_key *pk;
  KEYDB_SEARCH_DESC desc;
  size_t len;

  log_assert (!hd->use_keyboxd);
  pk = kb->pkt->pkt.public_key;

  kid_not_found_flush ();
  keyblock_cache_clear (hd);

  if (opt.dry_run)
    return 0;

  err = lock_all (hd);
  if (err)
    return err;

#ifdef USE_TOFU
  tofu_notice_key_changed (ctrl, kb);
#endif

  memset (&desc, 0, sizeof (desc));
  fingerprint_from_pk (pk, desc.u.fpr, &len);
  if (len == 20 || len == 32)
    {
      desc.mode = KEYDB_SEARCH_MODE_FPR;
      desc.fprlen = len;
    }
  else
    log_bug ("%s: Unsupported key length: %zu\n", __func__, len);

  keydb_search_reset (hd);
  err = keydb_search (hd, &desc, 1, NULL);
  if (err)
    return gpg_error (GPG_ERR_VALUE_NOT_FOUND);
  log_assert (hd->found >= 0 && hd->found < hd->used);

  switch (hd->active[hd->found].type)
    {
    case KEYDB_RESOURCE_TYPE_NONE:
      err = gpg_error (GPG_ERR_GENERAL); /* oops */
      break;
    case KEYDB_RESOURCE_TYPE_KEYRING:
      err = keyring_update_keyblock (hd->active[hd->found].u.kr, kb);
      break;
    case KEYDB_RESOURCE_TYPE_KEYBOX:
      {
        iobuf_t iobuf;

        err = build_keyblock_image (kb, &iobuf);
        if (!err)
          {
            keydb_stats.build_keyblocks++;
            err = keybox_update_keyblock (hd->active[hd->found].u.kb,
                                          iobuf_get_temp_buffer (iobuf),
                                          iobuf_get_temp_length (iobuf));
            iobuf_close (iobuf);
          }
      }
      break;
    }

  unlock_all (hd);
  if (!err)
    keydb_stats.update_keyblocks++;
  return err;
}


/* Insert a keyblock into one of the underlying keyrings or keyboxes.
 * keydb_insert_keyblock diverts to here in the non-keyboxd mode.
 *
 * Be default, the keyring / keybox from which the last search result
 * came is used.  If there was no previous search result (or
 * keydb_search_reset was called), then the keyring / keybox where the
 * next search would start is used (i.e., the current file position).
 *
 * Note: this doesn't do anything if --dry-run was specified.
 *
 * Returns 0 on success.  Otherwise, it returns an error code.  */
gpg_error_t
internal_keydb_insert_keyblock (KEYDB_HANDLE hd, kbnode_t kb)
{
  gpg_error_t err;
  int idx;

  log_assert (!hd->use_keyboxd);

  kid_not_found_flush ();
  keyblock_cache_clear (hd);

  if (opt.dry_run)
    return 0;

  if (hd->found >= 0 && hd->found < hd->used)
    idx = hd->found;
  else if (hd->current >= 0 && hd->current < hd->used)
    idx = hd->current;
  else
    return gpg_error (GPG_ERR_GENERAL);

  err = lock_all (hd);
  if (err)
    return err;

  switch (hd->active[idx].type)
    {
    case KEYDB_RESOURCE_TYPE_NONE:
      err = gpg_error (GPG_ERR_GENERAL); /* oops */
      break;
    case KEYDB_RESOURCE_TYPE_KEYRING:
      err = keyring_insert_keyblock (hd->active[idx].u.kr, kb);
      break;
    case KEYDB_RESOURCE_TYPE_KEYBOX:
      { /* We need to turn our kbnode_t list of packets into a proper
           keyblock first.  This is required by the OpenPGP key parser
           included in the keybox code.  Eventually we can change this
           kludge to have the caller pass the image.  */
        iobuf_t iobuf;

        err = build_keyblock_image (kb, &iobuf);
        if (!err)
          {
            keydb_stats.build_keyblocks++;
            err = keybox_insert_keyblock (hd->active[idx].u.kb,
                                          iobuf_get_temp_buffer (iobuf),
                                          iobuf_get_temp_length (iobuf));
            iobuf_close (iobuf);
          }
      }
      break;
    }

  unlock_all (hd);
  if (!err)
    keydb_stats.insert_keyblocks++;
  return err;
}


/* Delete the currently selected keyblock.  If you haven't done a
 * search yet on this database handle (or called keydb_search_reset),
 * then this will return an error.
 *
 * Returns 0 on success or an error code, if an error occurs.  */
gpg_error_t
internal_keydb_delete_keyblock (KEYDB_HANDLE hd)
{
  gpg_error_t rc;

  log_assert (!hd->use_keyboxd);

  kid_not_found_flush ();
  keyblock_cache_clear (hd);

  if (hd->found < 0 || hd->found >= hd->used)
    return gpg_error (GPG_ERR_VALUE_NOT_FOUND);

  if (opt.dry_run)
    return 0;

  rc = lock_all (hd);
  if (rc)
    return rc;

  switch (hd->active[hd->found].type)
    {
    case KEYDB_RESOURCE_TYPE_NONE:
      rc = gpg_error (GPG_ERR_GENERAL);
      break;
    case KEYDB_RESOURCE_TYPE_KEYRING:
      rc = keyring_delete_keyblock (hd->active[hd->found].u.kr);
      break;
    case KEYDB_RESOURCE_TYPE_KEYBOX:
      rc = keybox_delete (hd->active[hd->found].u.kb);
      break;
    }

  unlock_all (hd);
  if (!rc)
    keydb_stats.delete_keyblocks++;
  return rc;
}



/* A database may consists of multiple keyrings / key boxes.  This
 * sets the "file position" to the start of the first keyring / key
 * box that is writable (i.e., doesn't have the read-only flag set).
 *
 * This first tries the primary keyring (the last keyring (not
 * keybox!) added using keydb_add_resource() and with
 * KEYDB_RESOURCE_FLAG_PRIMARY set).  If that is not writable, then it
 * tries the keyrings / keyboxes in the order in which they were
 * added.  */
gpg_error_t
keydb_locate_writable (KEYDB_HANDLE hd)
{
  gpg_error_t rc;

  if (!hd)
    return GPG_ERR_INV_ARG;

  if (hd->use_keyboxd)
    return 0;  /* No need for this here.  */

  rc = keydb_search_reset (hd); /* this does reset hd->current */
  if (rc)
    return rc;

  /* If we have a primary set, try that one first */
  if (primary_keydb)
    {
      for ( ; hd->current >= 0 && hd->current < hd->used; hd->current++)
	{
	  if(hd->active[hd->current].token == primary_keydb)
	    {
	      if(keyring_is_writable (hd->active[hd->current].token))
		return 0;
	      else
		break;
	    }
	}

      rc = keydb_search_reset (hd); /* this does reset hd->current */
      if (rc)
	return rc;
    }

  for ( ; hd->current >= 0 && hd->current < hd->used; hd->current++)
    {
      switch (hd->active[hd->current].type)
        {
        case KEYDB_RESOURCE_TYPE_NONE:
          BUG();
          break;
        case KEYDB_RESOURCE_TYPE_KEYRING:
          if (keyring_is_writable (hd->active[hd->current].token))
            return 0; /* found (hd->current is set to it) */
          break;
        case KEYDB_RESOURCE_TYPE_KEYBOX:
          if (keybox_is_writable (hd->active[hd->current].token))
            return 0; /* found (hd->current is set to it) */
          break;
        }
    }

  return gpg_error (GPG_ERR_NOT_FOUND);
}


/* Rebuild the on-disk caches of all key resources.  */
void
keydb_rebuild_caches (ctrl_t ctrl, int noisy)
{
  int i, rc;

  if (opt.use_keyboxd)
    return;  /* No need for this here.  */

  for (i=0; i < used_resources; i++)
    {
      if (!keyring_is_writable (all_resources[i].token))
        continue;
      switch (all_resources[i].type)
        {
        case KEYDB_RESOURCE_TYPE_NONE: /* ignore */
          break;
        case KEYDB_RESOURCE_TYPE_KEYRING:
          rc = keyring_rebuild_cache (ctrl, all_resources[i].token,noisy);
          if (rc)
            log_error (_("failed to rebuild keyring cache: %s\n"),
                       gpg_strerror (rc));
          break;
        case KEYDB_RESOURCE_TYPE_KEYBOX:
          /* N/A.  */
          break;
        }
    }
}


/* Return the number of skipped blocks (because they were too large to
   read from a keybox) since the last search reset.  */
unsigned long
keydb_get_skipped_counter (KEYDB_HANDLE hd)
{
  /*FIXME(keyboxd): Do we need this?  */
  return hd && !hd->use_keyboxd? hd->skipped_long_blobs : 0;
}


/* Clears the current search result and resets the handle's position
 * so that the next search starts at the beginning of the database
 * (the start of the first resource).
 * keydb_search_reset diverts to here in the non-keyboxd mode.
 *
 * Returns 0 on success and an error code if an error occurred.
 * (Currently, this function always returns 0 if HD is valid.)  */
gpg_error_t
internal_keydb_search_reset (KEYDB_HANDLE hd)
{
  gpg_error_t rc = 0;
  int i;

  log_assert (!hd->use_keyboxd);

  keyblock_cache_clear (hd);

  hd->skipped_long_blobs = 0;
  hd->current = 0;
  hd->found = -1;
  /* Now reset all resources.  */
  for (i=0; !rc && i < hd->used; i++)
    {
      switch (hd->active[i].type)
        {
        case KEYDB_RESOURCE_TYPE_NONE:
          break;
        case KEYDB_RESOURCE_TYPE_KEYRING:
          rc = keyring_search_reset (hd->active[i].u.kr);
          break;
        case KEYDB_RESOURCE_TYPE_KEYBOX:
          rc = keybox_search_reset (hd->active[i].u.kb);
          break;
        }
    }
  hd->is_reset = 1;
  if (!rc)
    keydb_stats.search_resets++;
  return rc;
}


/* Search the database for keys matching the search description.  If
 * the DB contains any legacy keys, these are silently ignored.
 * keydb_search diverts to here in the non-keyboxd mode.
 *
 * DESC is an array of search terms with NDESC entries.  The search
 * terms are or'd together.  That is, the next entry in the DB that
 * matches any of the descriptions will be returned.
 *
 * Note: this function resumes searching where the last search left
 * off (i.e., at the current file position).  If you want to search
 * from the start of the database, then you need to first call
 * keydb_search_reset().
 *
 * If no key matches the search description, returns
 * GPG_ERR_NOT_FOUND.  If there was a match, returns 0.  If an error
 * occurred, returns an error code.
 *
 * The returned key is considered to be selected and the raw data can,
 * for instance, be returned by calling keydb_get_keyblock().  */
gpg_error_t
internal_keydb_search (KEYDB_HANDLE hd, KEYDB_SEARCH_DESC *desc,
                       size_t ndesc, size_t *descindex)
{
  gpg_error_t rc;
  int was_reset = hd->is_reset;
  /* If an entry is already in the cache, then don't add it again.  */
  int already_in_cache = 0;
  int fprlen;

  log_assert (!hd->use_keyboxd);

  if (!any_registered)
    {
      write_status_error ("keydb_search", gpg_error (GPG_ERR_KEYRING_OPEN));
      return gpg_error (GPG_ERR_NOT_FOUND);
    }

  if (ndesc == 1 && desc[0].mode == KEYDB_SEARCH_MODE_LONG_KID
      && (already_in_cache = kid_not_found_p (desc[0].u.kid)) == 1 )
    {
      if (DBG_CLOCK)
        log_clock ("%s leave (not found, cached)", __func__);
      keydb_stats.notfound_cached++;
      return gpg_error (GPG_ERR_NOT_FOUND);
    }

  /* NB: If one of the exact search modes below is used in a loop to
     walk over all keys (with the same fingerprint) the caching must
     have been disabled for the handle.  */
  if (desc[0].mode == KEYDB_SEARCH_MODE_FPR)
    fprlen = desc[0].fprlen;
  else
    fprlen = 0;

  if (!hd->no_caching
      && ndesc == 1
      && fprlen
      && hd->keyblock_cache.state == KEYBLOCK_CACHE_FILLED
      && hd->keyblock_cache.fprlen == fprlen
      && !memcmp (hd->keyblock_cache.fpr, desc[0].u.fpr, fprlen)
      /* Make sure the current file position occurs before the cached
         result to avoid an infinite loop.  */
      && (hd->current < hd->keyblock_cache.resource
          || (hd->current == hd->keyblock_cache.resource
              && (keybox_offset (hd->active[hd->current].u.kb)
                  <= hd->keyblock_cache.offset))))
    {
      /* (DESCINDEX is already set).  */
      if (DBG_CLOCK)
        log_clock ("%s leave (cached)", __func__);

      hd->current = hd->keyblock_cache.resource;
      /* HD->KEYBLOCK_CACHE.OFFSET is the last byte in the record.
         Seek just beyond that.  */
      keybox_seek (hd->active[hd->current].u.kb, hd->keyblock_cache.offset + 1);
      keydb_stats.found_cached++;
      return 0;
    }

  rc = -1;
  while ((rc == -1 || gpg_err_code (rc) == GPG_ERR_EOF)
         && hd->current >= 0 && hd->current < hd->used)
    {
      if (DBG_LOOKUP)
        log_debug ("%s: searching %s (resource %d of %d)\n",
                   __func__,
                   hd->active[hd->current].type == KEYDB_RESOURCE_TYPE_KEYRING
                   ? "keyring"
                   : (hd->active[hd->current].type == KEYDB_RESOURCE_TYPE_KEYBOX
                      ? "keybox" : "unknown type"),
                   hd->current, hd->used);

       switch (hd->active[hd->current].type)
        {
        case KEYDB_RESOURCE_TYPE_NONE:
          BUG(); /* we should never see it here */
          break;
        case KEYDB_RESOURCE_TYPE_KEYRING:
          rc = keyring_search (hd->active[hd->current].u.kr, desc,
                               ndesc, descindex, 1);
          break;
        case KEYDB_RESOURCE_TYPE_KEYBOX:
          do
            rc = keybox_search (hd->active[hd->current].u.kb, desc,
                                ndesc, KEYBOX_BLOBTYPE_PGP,
                                descindex, &hd->skipped_long_blobs);
          while (rc == GPG_ERR_LEGACY_KEY);
          break;
        }

      if (DBG_LOOKUP)
        log_debug ("%s: searched %s (resource %d of %d) => %s\n",
                   __func__,
                   hd->active[hd->current].type == KEYDB_RESOURCE_TYPE_KEYRING
                   ? "keyring"
                   : (hd->active[hd->current].type == KEYDB_RESOURCE_TYPE_KEYBOX
                      ? "keybox" : "unknown type"),
                   hd->current, hd->used,
                   rc == -1 ? "EOF" : gpg_strerror (rc));

      if (rc == -1 || gpg_err_code (rc) == GPG_ERR_EOF)
        {
          /* EOF -> switch to next resource */
          hd->current++;
        }
      else if (!rc)
        hd->found = hd->current;
    }
  hd->is_reset = 0;

  rc = ((rc == -1 || gpg_err_code (rc) == GPG_ERR_EOF)
        ? gpg_error (GPG_ERR_NOT_FOUND)
        : rc);

  keyblock_cache_clear (hd);
  if (!hd->no_caching
      && !rc
      && ndesc == 1
      && fprlen
      && hd->active[hd->current].type == KEYDB_RESOURCE_TYPE_KEYBOX)
    {
      hd->keyblock_cache.state = KEYBLOCK_CACHE_PREPARED;
      hd->keyblock_cache.resource = hd->current;
      /* The current offset is at the start of the next record.  Since
         a record is at least 1 byte, we just use offset - 1, which is
         within the record.  */
      hd->keyblock_cache.offset
        = keybox_offset (hd->active[hd->current].u.kb) - 1;
      memcpy (hd->keyblock_cache.fpr, desc[0].u.fpr, fprlen);
      hd->keyblock_cache.fprlen = fprlen;
    }

  if (gpg_err_code (rc) == GPG_ERR_NOT_FOUND
      && ndesc == 1
      && desc[0].mode == KEYDB_SEARCH_MODE_LONG_KID
      && was_reset
      && !already_in_cache)
    kid_not_found_insert (desc[0].u.kid);

  if (!rc)
    keydb_stats.found++;
  else
    keydb_stats.notfound++;
  return rc;
}


/* Return the first non-legacy key in the database.
 *
 * If you want the very first key in the database, you can directly
 * call keydb_search with the search description
 *  KEYDB_SEARCH_MODE_FIRST.  */
gpg_error_t
keydb_search_first (KEYDB_HANDLE hd)
{
  gpg_error_t err;
  KEYDB_SEARCH_DESC desc;

  err = keydb_search_reset (hd);
  if (err)
    return err;

  memset (&desc, 0, sizeof desc);
  desc.mode = KEYDB_SEARCH_MODE_FIRST;
  return keydb_search (hd, &desc, 1, NULL);
}


/* Return the next key (not the next matching key!).
 *
 * Unlike calling keydb_search with KEYDB_SEARCH_MODE_NEXT, this
 * function silently skips legacy keys.  */
gpg_error_t
keydb_search_next (KEYDB_HANDLE hd)
{
  KEYDB_SEARCH_DESC desc;

  memset (&desc, 0, sizeof desc);
  desc.mode = KEYDB_SEARCH_MODE_NEXT;
  return keydb_search (hd, &desc, 1, NULL);
}


/* This is a convenience function for searching for keys with a long
 * key id.
 *
 * Note: this function resumes searching where the last search left
 * off.  If you want to search the whole database, then you need to
 * first call keydb_search_reset().  */
gpg_error_t
keydb_search_kid (KEYDB_HANDLE hd, u32 *kid)
{
  KEYDB_SEARCH_DESC desc;

  memset (&desc, 0, sizeof desc);
  desc.mode = KEYDB_SEARCH_MODE_LONG_KID;
  desc.u.kid[0] = kid[0];
  desc.u.kid[1] = kid[1];
  return keydb_search (hd, &desc, 1, NULL);
}


/* This is a convenience function for searching for keys with a long
 * (20 byte) fingerprint.
 *
 * Note: this function resumes searching where the last search left
 * off.  If you want to search the whole database, then you need to
 * first call keydb_search_reset().  */
gpg_error_t
keydb_search_fpr (KEYDB_HANDLE hd, const byte *fpr, size_t fprlen)
{
  KEYDB_SEARCH_DESC desc;

  memset (&desc, 0, sizeof desc);
  desc.mode = KEYDB_SEARCH_MODE_FPR;
  memcpy (desc.u.fpr, fpr, fprlen);
  desc.fprlen = fprlen;
  return keydb_search (hd, &desc, 1, NULL);
}
