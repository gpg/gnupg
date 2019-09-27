/* keydb.c - key database dispatcher
 * Copyright (C) 2001, 2003, 2004 Free Software Foundation, Inc.
 * Copyright (C) 2014 g10 Code GmbH
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

#include "gpgsm.h"
#include "../kbx/keybox.h"
#include "keydb.h"
#include "../common/i18n.h"

static int active_handles;

typedef enum {
    KEYDB_RESOURCE_TYPE_NONE = 0,
    KEYDB_RESOURCE_TYPE_KEYBOX
} KeydbResourceType;
#define MAX_KEYDB_RESOURCES 20

struct resource_item {
  KeydbResourceType type;
  union {
    KEYBOX_HANDLE kr;
  } u;
  void *token;
};

static struct resource_item all_resources[MAX_KEYDB_RESOURCES];
static int used_resources;

/* Whether we have successfully registered any resource.  */
static int any_registered;


struct keydb_handle {

  /* If this flag is set the resources is locked.  */
  int locked;

  /* If this flag is set a lock will only be released by
   * keydb_release.  */
  int keep_lock;

  int found;
  int saved_found;
  int current;
  int is_ephemeral;
  int used; /* items in active */
  struct resource_item active[MAX_KEYDB_RESOURCES];
};


static int lock_all (KEYDB_HANDLE hd);
static void unlock_all (KEYDB_HANDLE hd);


static void
try_make_homedir (const char *fname)
{
  const char *defhome = standard_homedir ();

  /* Create the directory only if the supplied directory name is the
     same as the default one.  This way we avoid to create arbitrary
     directories when a non-default home directory is used.  To cope
     with HOME, we do compare only the suffix if we see that the
     default homedir does start with a tilde.  */
  if ( opt.dry_run || opt.no_homedir_creation )
    return;

  if (
#ifdef HAVE_W32_SYSTEM
      ( !compare_filenames (fname, defhome) )
#else
      ( *defhome == '~'
        && (strlen(fname) >= strlen (defhome+1)
            && !strcmp(fname+strlen(fname)-strlen(defhome+1), defhome+1 ) ))
      || (*defhome != '~'  && !compare_filenames( fname, defhome ) )
#endif
      )
    {
      if (gnupg_mkdir (fname, "-rwx"))
        log_info (_("can't create directory '%s': %s\n"),
                  fname, strerror(errno) );
      else if (!opt.quiet )
        log_info (_("directory '%s' created\n"), fname);
    }
}


/* Handle the creation of a keybox if it does not yet exist.  Take
   into account that other processes might have the keybox already
   locked.  This lock check does not work if the directory itself is
   not yet available.  If R_CREATED is not NULL it will be set to true
   if the function created a new keybox.  */
static gpg_error_t
maybe_create_keybox (char *filename, int force, int *r_created)
{
  dotlock_t lockhd = NULL;
  FILE *fp;
  int rc;
  mode_t oldmask;
  char *last_slash_in_filename;
  int save_slash;

  if (r_created)
    *r_created = 0;

  /* A quick test whether the filename already exists. */
  if (!access (filename, F_OK))
    return !access (filename, R_OK)? 0 : gpg_error (GPG_ERR_EACCES);

  /* If we don't want to create a new file at all, there is no need to
     go any further - bail out right here.  */
  if (!force)
    return gpg_error (GPG_ERR_ENOENT);

  /* First of all we try to create the home directory.  Note, that we
     don't do any locking here because any sane application of gpg
     would create the home directory by itself and not rely on gpg's
     tricky auto-creation which is anyway only done for some home
     directory name patterns. */
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
  if (access(filename, F_OK))
    {
      static int tried;

      if (!tried)
        {
          tried = 1;
          try_make_homedir (filename);
        }
      if (access (filename, F_OK))
        {
          rc = gpg_error_from_syserror ();
          *last_slash_in_filename = save_slash;
          goto leave;
        }
    }
  *last_slash_in_filename = save_slash;

  /* To avoid races with other instances of gpg trying to create or
     update the keybox (it is removed during an update for a short
     time), we do the next stuff in a locked state. */
  lockhd = dotlock_create (filename, 0);
  if (!lockhd)
    {
      /* A reason for this to fail is that the directory is not
         writable. However, this whole locking stuff does not make
         sense if this is the case. An empty non-writable directory
         with no keyring is not really useful at all. */
      if (opt.verbose)
        log_info ("can't allocate lock for '%s'\n", filename );

      if (!force)
        return gpg_error (GPG_ERR_ENOENT);
      else
        return gpg_error (GPG_ERR_GENERAL);
    }

  if ( dotlock_take (lockhd, -1) )
    {
      /* This is something bad.  Probably a stale lockfile.  */
      log_info ("can't lock '%s'\n", filename);
      rc = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }

  /* Now the real test while we are locked. */
  if (!access(filename, F_OK))
    {
      rc = 0;  /* Okay, we may access the file now.  */
      goto leave;
    }

  /* The file does not yet exist, create it now. */
  oldmask = umask (077);
  fp = fopen (filename, "wb");
  if (!fp)
    {
      rc = gpg_error_from_syserror ();
      umask (oldmask);
      log_error (_("error creating keybox '%s': %s\n"),
                 filename, gpg_strerror (rc));
      goto leave;
    }
  umask (oldmask);

  /* Make sure that at least one record is in a new keybox file, so
     that the detection magic for OpenPGP keyboxes works the next time
     it is used.  */
  rc = _keybox_write_header_blob (fp, NULL, 0);
  if (rc)
    {
      fclose (fp);
      log_error (_("error creating keybox '%s': %s\n"),
                 filename, gpg_strerror (rc));
      goto leave;
    }

  if (!opt.quiet)
    log_info (_("keybox '%s' created\n"), filename);
  if (r_created)
    *r_created = 1;

  fclose (fp);
  rc = 0;

 leave:
  if (lockhd)
    {
      dotlock_release (lockhd);
      dotlock_destroy (lockhd);
    }
  return rc;
}


/*
 * Register a resource (which currently may only be a keybox file).
 * The first keybox which is added by this function is created if it
 * does not exist.  If AUTO_CREATED is not NULL it will be set to true
 * if the function has created a new keybox.
 */
gpg_error_t
keydb_add_resource (ctrl_t ctrl, const char *url, int force, int *auto_created)
{
  const char *resname = url;
  char *filename = NULL;
  gpg_error_t err = 0;
  KeydbResourceType rt = KEYDB_RESOURCE_TYPE_NONE;

  if (auto_created)
    *auto_created = 0;

  /* Do we have an URL?
     gnupg-kbx:filename := this is a plain keybox
     filename := See what it is, but create as plain keybox.
  */
  if (strlen (resname) > 10)
    {
      if (!strncmp (resname, "gnupg-kbx:", 10) )
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
    }

  if (*resname != DIRSEP_C )
    { /* do tilde expansion etc */
      if (strchr(resname, DIRSEP_C) )
        filename = make_filename (resname, NULL);
      else
        filename = make_filename (gnupg_homedir (), resname, NULL);
    }
  else
    filename = xstrdup (resname);

  if (!force)
    force = !any_registered;

  /* see whether we can determine the filetype */
  if (rt == KEYDB_RESOURCE_TYPE_NONE)
    {
      FILE *fp = fopen( filename, "rb" );

      if (fp)
        {
          u32 magic;

          /* FIXME: check for the keybox magic */
          if (fread (&magic, 4, 1, fp) == 1 )
            {
              if (magic == 0x13579ace || magic == 0xce9a5713)
                ; /* GDBM magic - no more support */
              else
                rt = KEYDB_RESOURCE_TYPE_KEYBOX;
            }
          else /* maybe empty: assume keybox */
            rt = KEYDB_RESOURCE_TYPE_KEYBOX;
          fclose (fp);
        }
      else /* no file yet: create keybox */
        rt = KEYDB_RESOURCE_TYPE_KEYBOX;
    }

  switch (rt)
    {
    case KEYDB_RESOURCE_TYPE_NONE:
      log_error ("unknown type of key resource '%s'\n", url );
      err = gpg_error (GPG_ERR_GENERAL);
      goto leave;

    case KEYDB_RESOURCE_TYPE_KEYBOX:
      err = maybe_create_keybox (filename, force, auto_created);
      if (err)
        goto leave;
      /* Now register the file */
      {
        void *token;

        err = keybox_register_file (filename, 0, &token);
        if (gpg_err_code (err) == GPG_ERR_EEXIST)
          ; /* Already registered - ignore.  */
        else if (err)
          ; /* Other error.  */
        else if (used_resources >= MAX_KEYDB_RESOURCES)
          err = gpg_error (GPG_ERR_RESOURCE_LIMIT);
        else
          {
            KEYBOX_HANDLE kbxhd;

            all_resources[used_resources].type = rt;
            all_resources[used_resources].u.kr = NULL; /* Not used here */
            all_resources[used_resources].token = token;

            /* Do a compress run if needed and the keybox is not locked. */
            kbxhd = keybox_new_x509 (token, 0);
            if (kbxhd)
              {
                if (!keybox_lock (kbxhd, 1, 0))
                  {
                    keybox_compress (kbxhd);
                    keybox_lock (kbxhd, 0, 0);
                  }

                keybox_release (kbxhd);
              }

            used_resources++;
          }
      }
      break;

    default:
      log_error ("resource type of '%s' not supported\n", url);
      err = gpg_error (GPG_ERR_NOT_SUPPORTED);
      goto leave;
    }

  /* fixme: check directory permissions and print a warning */

 leave:
  if (err)
    {
      log_error ("keyblock resource '%s': %s\n", filename, gpg_strerror (err));
      gpgsm_status_with_error (ctrl, STATUS_ERROR,
                               "add_keyblock_resource", err);
    }
  else
    any_registered = 1;
  xfree (filename);
  return err;
}


KEYDB_HANDLE
keydb_new (void)
{
  KEYDB_HANDLE hd;
  int i, j;

  if (DBG_CLOCK)
    log_clock ("%s: enter\n", __func__);

  hd = xcalloc (1, sizeof *hd);
  hd->found = -1;
  hd->saved_found = -1;

  log_assert (used_resources <= MAX_KEYDB_RESOURCES);
  for (i=j=0; i < used_resources; i++)
    {
      switch (all_resources[i].type)
        {
        case KEYDB_RESOURCE_TYPE_NONE: /* ignore */
          break;
        case KEYDB_RESOURCE_TYPE_KEYBOX:
          hd->active[j].type   = all_resources[i].type;
          hd->active[j].token  = all_resources[i].token;
          hd->active[j].u.kr = keybox_new_x509 (all_resources[i].token, 0);
          if (!hd->active[j].u.kr)
            {
              xfree (hd);
              return NULL; /* fixme: release all previously allocated handles*/
            }
          j++;
          break;
        }
    }
  hd->used = j;

  active_handles++;
  if (DBG_CLOCK)
    log_clock ("%s: leave (hd=%p)\n", __func__, hd);
  return hd;
}

void
keydb_release (KEYDB_HANDLE hd)
{
  int i;

  if (!hd)
    return;

  if (DBG_CLOCK)
    log_clock ("%s: enter (hd=%p)\n", __func__, hd);

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
        case KEYDB_RESOURCE_TYPE_KEYBOX:
          keybox_release (hd->active[i].u.kr);
          break;
        }
    }

  xfree (hd);
  if (DBG_CLOCK)
    log_clock ("%s: leave\n", __func__);
}


/* Return the name of the current resource.  This is function first
   looks for the last found found, then for the current search
   position, and last returns the first available resource.  The
   returned string is only valid as long as the handle exists.  This
   function does only return NULL if no handle is specified, in all
   other error cases an empty string is returned.  */
const char *
keydb_get_resource_name (KEYDB_HANDLE hd)
{
  int idx;
  const char *s = NULL;

  if (!hd)
    return NULL;

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
    case KEYDB_RESOURCE_TYPE_KEYBOX:
      s = keybox_get_resource_name (hd->active[idx].u.kr);
      break;
    }

  return s? s: "";
}

/* Switch the handle into ephemeral mode and return the original value. */
int
keydb_set_ephemeral (KEYDB_HANDLE hd, int yes)
{
  int i;

  if (!hd)
    return 0;

  yes = !!yes;
  if (hd->is_ephemeral != yes)
    {
      for (i=0; i < hd->used; i++)
        {
          switch (hd->active[i].type)
            {
            case KEYDB_RESOURCE_TYPE_NONE:
              break;
            case KEYDB_RESOURCE_TYPE_KEYBOX:
              keybox_set_ephemeral (hd->active[i].u.kr, yes);
              break;
            }
        }
    }

  i = hd->is_ephemeral;
  hd->is_ephemeral = yes;
  return i;
}


/* If the keyring has not yet been locked, lock it now.  This
 * operation is required before any update operation; it is optional
 * for an insert operation.  The lock is kept until a keydb_release so
 * that internal unlock_all calls have no effect.  */
gpg_error_t
keydb_lock (KEYDB_HANDLE hd)
{
  gpg_error_t err;

  if (!hd)
    return gpg_error (GPG_ERR_INV_HANDLE);

  if (DBG_CLOCK)
    log_clock ("%s: enter (hd=%p)\n", __func__, hd);
  err = lock_all (hd);
  if (!err)
    hd->keep_lock = 1;

  if (DBG_CLOCK)
    log_clock ("%s: leave (err=%s)\n", __func__, gpg_strerror (err));
  return err;
}



static int
lock_all (KEYDB_HANDLE hd)
{
  int i, rc = 0;

  /* Fixme: This locking scheme may lead to deadlock if the resources
     are not added in the same order by all processes.  We are
     currently only allowing one resource so it is not a problem. */
  for (i=0; i < hd->used; i++)
    {
      switch (hd->active[i].type)
        {
        case KEYDB_RESOURCE_TYPE_NONE:
          break;
        case KEYDB_RESOURCE_TYPE_KEYBOX:
          rc = keybox_lock (hd->active[i].u.kr, 1, -1);
          break;
        }
      if (rc)
        break;
    }

    if (rc)
      {
        /* Revert the already set locks.  */
        for (i--; i >= 0; i--)
          {
            switch (hd->active[i].type)
              {
              case KEYDB_RESOURCE_TYPE_NONE:
                break;
              case KEYDB_RESOURCE_TYPE_KEYBOX:
                keybox_lock (hd->active[i].u.kr, 0, 0);
                break;
              }
          }
      }
    else
      hd->locked = 1;

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
        case KEYDB_RESOURCE_TYPE_KEYBOX:
          keybox_lock (hd->active[i].u.kr, 0, 0);
          break;
        }
    }
  hd->locked = 0;
}



/* Push the last found state if any.  */
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
    case KEYDB_RESOURCE_TYPE_KEYBOX:
      keybox_push_found_state (hd->active[hd->found].u.kr);
      break;
    }

  hd->saved_found = hd->found;
  hd->found = -1;
  if (DBG_CLOCK)
    log_clock ("%s: done (hd=%p)\n", __func__, hd);
}


/* Pop the last found state.  */
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
    case KEYDB_RESOURCE_TYPE_KEYBOX:
      keybox_pop_found_state (hd->active[hd->found].u.kr);
      break;
    }
  if (DBG_CLOCK)
    log_clock ("%s: done (hd=%p)\n", __func__, hd);
}



/*
  Return the last found object.  Caller must free it.  The returned
  keyblock has the kbode flag bit 0 set for the node with the public
  key used to locate the keyblock or flag bit 1 set for the user ID
  node.  */
int
keydb_get_cert (KEYDB_HANDLE hd, ksba_cert_t *r_cert)
{
  int rc = 0;

  if (!hd)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (DBG_CLOCK)
    log_clock ("%s: enter (hd=%p)\n", __func__, hd);

  if ( hd->found < 0 || hd->found >= hd->used)
    {
      rc = -1; /* nothing found */
      goto leave;
    }

  rc = GPG_ERR_BUG;
  switch (hd->active[hd->found].type)
    {
    case KEYDB_RESOURCE_TYPE_NONE:
      rc = gpg_error (GPG_ERR_GENERAL); /* oops */
      break;
    case KEYDB_RESOURCE_TYPE_KEYBOX:
      rc = keybox_get_cert (hd->active[hd->found].u.kr, r_cert);
      break;
    }

 leave:
  if (DBG_CLOCK)
    log_clock ("%s: leave (rc=%d)\n", __func__, rc);
  return rc;
}


/* Return a flag of the last found object. WHICH is the flag requested;
   it should be one of the KEYBOX_FLAG_ values.  If the operation is
   successful, the flag value will be stored at the address given by
   VALUE.  Return 0 on success or an error code. */
gpg_error_t
keydb_get_flags (KEYDB_HANDLE hd, int which, int idx, unsigned int *value)
{
  gpg_error_t err;

  if (!hd)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (DBG_CLOCK)
    log_clock ("%s: enter (hd=%p)\n", __func__, hd);

  if ( hd->found < 0 || hd->found >= hd->used)
    {
      err = gpg_error (GPG_ERR_NOTHING_FOUND);
      goto leave;
    }

  err = gpg_error (GPG_ERR_BUG);
  switch (hd->active[hd->found].type)
    {
    case KEYDB_RESOURCE_TYPE_NONE:
      err = gpg_error (GPG_ERR_GENERAL); /* oops */
      break;
    case KEYDB_RESOURCE_TYPE_KEYBOX:
      err = keybox_get_flags (hd->active[hd->found].u.kr, which, idx, value);
      break;
    }

 leave:
  if (DBG_CLOCK)
    log_clock ("%s: leave (err=%s)\n", __func__, gpg_strerror (err));
  return err;
}


/* Set a flag of the last found object. WHICH is the flag to be set; it
   should be one of the KEYBOX_FLAG_ values.  If the operation is
   successful, the flag value will be stored in the keybox.  Note,
   that some flag values can't be updated and thus may return an
   error, some other flag values may be masked out before an update.
   Returns 0 on success or an error code. */
gpg_error_t
keydb_set_flags (KEYDB_HANDLE hd, int which, int idx, unsigned int value)
{
  gpg_error_t err = 0;

  if (!hd)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (DBG_CLOCK)
    log_clock ("%s: enter (hd=%p)\n", __func__, hd);

  if ( hd->found < 0 || hd->found >= hd->used)
    {
      err = gpg_error (GPG_ERR_NOTHING_FOUND);
      goto leave;
    }

  if (!hd->locked)
    {
      err = gpg_error (GPG_ERR_NOT_LOCKED);
      goto leave;
    }

  switch (hd->active[hd->found].type)
    {
    case KEYDB_RESOURCE_TYPE_NONE:
      err = gpg_error (GPG_ERR_GENERAL); /* oops */
      break;
    case KEYDB_RESOURCE_TYPE_KEYBOX:
      err = keybox_set_flags (hd->active[hd->found].u.kr, which, idx, value);
      break;
    }

 leave:
  if (DBG_CLOCK)
    log_clock ("%s: leave (err=%s)\n", __func__, gpg_strerror (err));
  return err;
}

/*
 * Insert a new Certificate into one of the resources.
 */
gpg_error_t
keydb_insert_cert (KEYDB_HANDLE hd, ksba_cert_t cert)
{
  gpg_error_t err;
  int idx;
  unsigned char digest[20];

  if (!hd)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (opt.dry_run)
    return 0;

  if (DBG_CLOCK)
    log_clock ("%s: enter (hd=%p)\n", __func__, hd);

  if ( hd->found >= 0 && hd->found < hd->used)
    idx = hd->found;
  else if ( hd->current >= 0 && hd->current < hd->used)
    idx = hd->current;
  else
    {
      err = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }

  if (!hd->locked)
    {
      err = gpg_error (GPG_ERR_NOT_LOCKED);
      goto leave;
    }

  gpgsm_get_fingerprint (cert, GCRY_MD_SHA1, digest, NULL); /* kludge*/

  err = gpg_error (GPG_ERR_BUG);
  switch (hd->active[idx].type)
    {
    case KEYDB_RESOURCE_TYPE_NONE:
      err = gpg_error (GPG_ERR_GENERAL);
      break;
    case KEYDB_RESOURCE_TYPE_KEYBOX:
      err = keybox_insert_cert (hd->active[idx].u.kr, cert, digest);
      break;
    }

  unlock_all (hd);

 leave:
  if (DBG_CLOCK)
    log_clock ("%s: leave (err=%s)\n", __func__, gpg_strerror (err));
  return err;
}



/* Update the current keyblock with KB.  */
/* Note: This function is currently not called.  */
gpg_error_t
keydb_update_cert (KEYDB_HANDLE hd, ksba_cert_t cert)
{
  gpg_error_t err;
  unsigned char digest[20];

  if (!hd)
    return gpg_error (GPG_ERR_INV_VALUE);

  if ( hd->found < 0 || hd->found >= hd->used)
    return gpg_error (GPG_ERR_NOT_FOUND);

  if (opt.dry_run)
    return 0;

  if (DBG_CLOCK)
    log_clock ("%s: enter (hd=%p)\n", __func__, hd);

  err = lock_all (hd);
  if (err)
    goto leave;

  gpgsm_get_fingerprint (cert, GCRY_MD_SHA1, digest, NULL); /* kludge*/

  err = gpg_error (GPG_ERR_BUG);
  switch (hd->active[hd->found].type)
    {
    case KEYDB_RESOURCE_TYPE_NONE:
      err = gpg_error (GPG_ERR_GENERAL); /* oops */
      break;
    case KEYDB_RESOURCE_TYPE_KEYBOX:
      err = keybox_update_cert (hd->active[hd->found].u.kr, cert, digest);
      break;
    }

  unlock_all (hd);
 leave:
  if (DBG_CLOCK)
    log_clock ("%s: leave (err=%s)\n", __func__, gpg_strerror (err));
  return err;
}


/*
 * The current keyblock or cert will be deleted.
 */
gpg_error_t
keydb_delete (KEYDB_HANDLE hd)
{
  gpg_error_t err;

  if (!hd)
    return gpg_error (GPG_ERR_INV_VALUE);

  if ( hd->found < 0 || hd->found >= hd->used)
    return gpg_error (GPG_ERR_NOT_FOUND);

  if (opt.dry_run)
    return 0;

  if (DBG_CLOCK)
    log_clock ("%s: enter (hd=%p)\n", __func__, hd);

  if (!hd->locked)
    {
      err = gpg_error (GPG_ERR_NOT_LOCKED);
      goto leave;
    }

  err = gpg_error (GPG_ERR_BUG);
  switch (hd->active[hd->found].type)
    {
    case KEYDB_RESOURCE_TYPE_NONE:
      err = gpg_error (GPG_ERR_GENERAL);
      break;
    case KEYDB_RESOURCE_TYPE_KEYBOX:
      err = keybox_delete (hd->active[hd->found].u.kr);
      break;
    }

  unlock_all (hd);

 leave:
  if (DBG_CLOCK)
    log_clock ("%s: leave (err=%s)\n", __func__, gpg_strerror (err));
  return err;
}



/*
 * Locate the default writable key resource, so that the next
 * operation (which is only relevant for inserts) will be done on this
 * resource.
 */
int
keydb_locate_writable (KEYDB_HANDLE hd, const char *reserved)
{
  int rc;

  (void)reserved;

  if (!hd)
    return gpg_error (GPG_ERR_INV_VALUE);

  rc = keydb_search_reset (hd); /* this does reset hd->current */
  if (rc)
    return rc;

  for ( ; hd->current >= 0 && hd->current < hd->used; hd->current++)
    {
      switch (hd->active[hd->current].type)
        {
        case KEYDB_RESOURCE_TYPE_NONE:
          BUG();
          break;
        case KEYDB_RESOURCE_TYPE_KEYBOX:
          if (keybox_is_writable (hd->active[hd->current].token))
            return 0; /* found (hd->current is set to it) */
          break;
        }
    }

  return -1;
}

/*
 * Rebuild the caches of all key resources.
 */
void
keydb_rebuild_caches (void)
{
  int i;

  for (i=0; i < used_resources; i++)
    {
      switch (all_resources[i].type)
        {
        case KEYDB_RESOURCE_TYPE_NONE: /* ignore */
          break;
        case KEYDB_RESOURCE_TYPE_KEYBOX:
/*            rc = keybox_rebuild_cache (all_resources[i].token); */
/*            if (rc) */
/*              log_error (_("failed to rebuild keybox cache: %s\n"), */
/*                         g10_errstr (rc)); */
          break;
        }
    }
}



/*
 * Start the next search on this handle right at the beginning
 */
gpg_error_t
keydb_search_reset (KEYDB_HANDLE hd)
{
  gpg_error_t err = 0;
  int i;

  if (!hd)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (DBG_CLOCK)
    log_clock ("%s: enter (hd=%p)\n", __func__, hd);

  hd->current = 0;
  hd->found = -1;
  /* and reset all resources */
  for (i=0; !err && i < hd->used; i++)
    {
      switch (hd->active[i].type)
        {
        case KEYDB_RESOURCE_TYPE_NONE:
          break;
        case KEYDB_RESOURCE_TYPE_KEYBOX:
          err = keybox_search_reset (hd->active[i].u.kr);
          break;
        }
    }

  if (DBG_CLOCK)
    log_clock ("%s: leave (err=%s)\n", __func__, gpg_strerror (err));
  return err;
}


char *
keydb_search_desc_dump (struct keydb_search_desc *desc)
{
  char *fpr;
  char *result;

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
      return xasprintf ("SHORT_KID: '%08lX'", (ulong)desc->u.kid[1]);
    case KEYDB_SEARCH_MODE_LONG_KID:
      return xasprintf ("LONG_KID: '%08lX%08lX'",
                        (ulong)desc->u.kid[0], (ulong)desc->u.kid[1]);
    case KEYDB_SEARCH_MODE_FPR:
      fpr = bin2hexcolon (desc->u.fpr, desc->fprlen, NULL);
      result = xasprintf ("FPR%02d: '%s'", desc->fprlen, fpr);
      xfree (fpr);
      return result;
    case KEYDB_SEARCH_MODE_ISSUER:
      return xasprintf ("ISSUER: '%s'", desc->u.name);
    case KEYDB_SEARCH_MODE_ISSUER_SN:
      return xasprintf ("ISSUER_SN: '%*s'",
                        (int) (desc->snlen == -1
                               ? strlen (desc->sn) : desc->snlen),
                        desc->sn);
    case KEYDB_SEARCH_MODE_SN:
      return xasprintf ("SN: '%*s'",
                        (int) (desc->snlen == -1
                               ? strlen (desc->sn) : desc->snlen),
                        desc->sn);
    case KEYDB_SEARCH_MODE_SUBJECT:
      return xasprintf ("SUBJECT: '%s'", desc->u.name);
    case KEYDB_SEARCH_MODE_KEYGRIP:
      return xasprintf ("KEYGRIP: %s", desc->u.grip);
    case KEYDB_SEARCH_MODE_FIRST:
      return xasprintf ("FIRST");
    case KEYDB_SEARCH_MODE_NEXT:
      return xasprintf ("NEXT");
    default:
      return xasprintf ("Bad search mode (%d)", desc->mode);
    }
}


/*
 * Search through all keydb resources, starting at the current position,
 * for a keyblock which contains one of the keys described in the DESC array.
 */
int
keydb_search (ctrl_t ctrl, KEYDB_HANDLE hd,
              KEYDB_SEARCH_DESC *desc, size_t ndesc)
{
  int rc = -1;
  unsigned long skipped;
  int i;

  if (!hd)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!any_registered)
    {
      gpgsm_status_with_error (ctrl, STATUS_ERROR, "keydb_search",
                               gpg_error (GPG_ERR_KEYRING_OPEN));
      return gpg_error (GPG_ERR_NOT_FOUND);
    }

  if (DBG_CLOCK)
    log_clock ("%s: enter (hd=%p)\n", __func__, hd);

  if (DBG_LOOKUP)
    {
      log_debug ("%s: %zd search description(s):\n", __func__, ndesc);
      for (i = 0; i < ndesc; i ++)
        {
          char *t = keydb_search_desc_dump (&desc[i]);
          log_debug ("%s:   %d: %s\n", __func__, i, t);
          xfree (t);
        }
    }

  while ((rc == -1 || gpg_err_code (rc) == GPG_ERR_EOF)
         && hd->current >= 0 && hd->current < hd->used)
    {
      switch (hd->active[hd->current].type)
        {
        case KEYDB_RESOURCE_TYPE_NONE:
          BUG(); /* we should never see it here */
          break;
        case KEYDB_RESOURCE_TYPE_KEYBOX:
          rc = keybox_search (hd->active[hd->current].u.kr, desc, ndesc,
                              KEYBOX_BLOBTYPE_X509,
                              NULL, &skipped);
          break;
        }

      if (DBG_LOOKUP)
        log_debug ("%s: searched %s (resource %d of %d) => %s\n",
                   __func__,
                   hd->active[hd->current].type == KEYDB_RESOURCE_TYPE_KEYBOX
                      ? "keybox" : "unknown type",
                   hd->current, hd->used,
                   rc == -1 ? "EOF" : gpg_strerror (rc));

      if (rc == -1 || gpg_err_code (rc) == GPG_ERR_EOF)
        { /* EOF -> switch to next resource */
          hd->current++;
        }
      else if (!rc)
        hd->found = hd->current;
    }


  if (DBG_CLOCK)
    log_clock ("%s: leave (rc=%d)\n", __func__, rc);
  return rc;
}


int
keydb_search_first (ctrl_t ctrl, KEYDB_HANDLE hd)
{
  KEYDB_SEARCH_DESC desc;

  memset (&desc, 0, sizeof desc);
  desc.mode = KEYDB_SEARCH_MODE_FIRST;
  return keydb_search (ctrl, hd, &desc, 1);
}

int
keydb_search_next (ctrl_t ctrl, KEYDB_HANDLE hd)
{
  KEYDB_SEARCH_DESC desc;

  memset (&desc, 0, sizeof desc);
  desc.mode = KEYDB_SEARCH_MODE_NEXT;
  return keydb_search (ctrl, hd, &desc, 1);
}

int
keydb_search_kid (ctrl_t ctrl, KEYDB_HANDLE hd, u32 *kid)
{
  KEYDB_SEARCH_DESC desc;

  (void)kid;

  memset (&desc, 0, sizeof desc);
  desc.mode = KEYDB_SEARCH_MODE_LONG_KID;
  desc.u.kid[0] = kid[0];
  desc.u.kid[1] = kid[1];
  return keydb_search (ctrl, hd, &desc, 1);
}

int
keydb_search_fpr (ctrl_t ctrl, KEYDB_HANDLE hd, const byte *fpr)
{
  KEYDB_SEARCH_DESC desc;

  memset (&desc, 0, sizeof desc);
  desc.mode = KEYDB_SEARCH_MODE_FPR;
  memcpy (desc.u.fpr, fpr, 20);
  desc.fprlen = 20;
  return keydb_search (ctrl, hd, &desc, 1);
}

int
keydb_search_issuer (ctrl_t ctrl, KEYDB_HANDLE hd, const char *issuer)
{
  KEYDB_SEARCH_DESC desc;
  int rc;

  memset (&desc, 0, sizeof desc);
  desc.mode = KEYDB_SEARCH_MODE_ISSUER;
  desc.u.name = issuer;
  rc = keydb_search (ctrl, hd, &desc, 1);
  return rc;
}

int
keydb_search_issuer_sn (ctrl_t ctrl, KEYDB_HANDLE hd,
                        const char *issuer, ksba_const_sexp_t serial)
{
  KEYDB_SEARCH_DESC desc;
  int rc;
  const unsigned char *s;

  memset (&desc, 0, sizeof desc);
  desc.mode = KEYDB_SEARCH_MODE_ISSUER_SN;
  s = serial;
  if (*s !='(')
    return gpg_error (GPG_ERR_INV_VALUE);
  s++;
  for (desc.snlen = 0; digitp (s); s++)
    desc.snlen = 10*desc.snlen + atoi_1 (s);
  if (*s !=':')
    return gpg_error (GPG_ERR_INV_VALUE);
  desc.sn = s+1;
  desc.u.name = issuer;
  rc = keydb_search (ctrl, hd, &desc, 1);
  return rc;
}

int
keydb_search_subject (ctrl_t ctrl, KEYDB_HANDLE hd, const char *name)
{
  KEYDB_SEARCH_DESC desc;
  int rc;

  memset (&desc, 0, sizeof desc);
  desc.mode = KEYDB_SEARCH_MODE_SUBJECT;
  desc.u.name = name;
  rc = keydb_search (ctrl, hd, &desc, 1);
  return rc;
}



/* Store the certificate in the key DB but make sure that it does not
   already exists.  We do this simply by comparing the fingerprint.
   If EXISTED is not NULL it will be set to true if the certificate
   was already in the DB. */
int
keydb_store_cert (ctrl_t ctrl, ksba_cert_t cert, int ephemeral, int *existed)
{
  KEYDB_HANDLE kh;
  int rc;
  unsigned char fpr[20];

  if (existed)
    *existed = 0;

  if (!gpgsm_get_fingerprint (cert, 0, fpr, NULL))
    {
      log_error (_("failed to get the fingerprint\n"));
      return gpg_error (GPG_ERR_GENERAL);
    }

  kh = keydb_new ();
  if (!kh)
    {
      log_error (_("failed to allocate keyDB handle\n"));
      return gpg_error (GPG_ERR_ENOMEM);;
    }

  /* Set the ephemeral flag so that the search looks at all
     records.  */
  keydb_set_ephemeral (kh, 1);

  rc = lock_all (kh);
  if (rc)
    return rc;

  rc = keydb_search_fpr (ctrl, kh, fpr);
  if (rc != -1)
    {
      keydb_release (kh);
      if (!rc)
        {
          if (existed)
            *existed = 1;
          if (!ephemeral)
            {
              /* Remove ephemeral flags from existing certificate to "store"
                 it permanently. */
              rc = keydb_set_cert_flags (ctrl, cert, 1, KEYBOX_FLAG_BLOB, 0,
                                         KEYBOX_FLAG_BLOB_EPHEMERAL, 0);
              if (rc)
                {
                  log_error ("clearing ephemeral flag failed: %s\n",
                             gpg_strerror (rc));
                  return rc;
                }
            }
          return 0; /* okay */
        }
      log_error (_("problem looking for existing certificate: %s\n"),
                 gpg_strerror (rc));
      return rc;
    }

  /* Reset the ephemeral flag if not requested.  */
  if (!ephemeral)
    keydb_set_ephemeral (kh, 0);

  rc = keydb_locate_writable (kh, 0);
  if (rc)
    {
      log_error (_("error finding writable keyDB: %s\n"), gpg_strerror (rc));
      keydb_release (kh);
      return rc;
    }

  rc = keydb_insert_cert (kh, cert);
  if (rc)
    {
      log_error (_("error storing certificate: %s\n"), gpg_strerror (rc));
      keydb_release (kh);
      return rc;
    }
  keydb_release (kh);
  return 0;
}


/* This is basically keydb_set_flags but it implements a complete
   transaction by locating the certificate in the DB and updating the
   flags. */
gpg_error_t
keydb_set_cert_flags (ctrl_t ctrl, ksba_cert_t cert, int ephemeral,
                      int which, int idx,
                      unsigned int mask, unsigned int value)
{
  KEYDB_HANDLE kh;
  gpg_error_t err;
  unsigned char fpr[20];
  unsigned int old_value;

  if (!gpgsm_get_fingerprint (cert, 0, fpr, NULL))
    {
      log_error (_("failed to get the fingerprint\n"));
      return gpg_error (GPG_ERR_GENERAL);
    }

  kh = keydb_new ();
  if (!kh)
    {
      log_error (_("failed to allocate keyDB handle\n"));
      return gpg_error (GPG_ERR_ENOMEM);;
    }

  if (ephemeral)
    keydb_set_ephemeral (kh, 1);

  err = keydb_lock (kh);
  if (err)
    {
      log_error (_("error locking keybox: %s\n"), gpg_strerror (err));
      keydb_release (kh);
      return err;
    }

  err = keydb_search_fpr (ctrl, kh, fpr);
  if (err)
    {
      if (err == -1)
        err = gpg_error (GPG_ERR_NOT_FOUND);
      else
        log_error (_("problem re-searching certificate: %s\n"),
                   gpg_strerror (err));
      keydb_release (kh);
      return err;
    }

  err = keydb_get_flags (kh, which, idx, &old_value);
  if (err)
    {
      log_error (_("error getting stored flags: %s\n"), gpg_strerror (err));
      keydb_release (kh);
      return err;
    }

  value = ((old_value & ~mask) | (value & mask));

  if (value != old_value)
    {
      err = keydb_set_flags (kh, which, idx, value);
      if (err)
        {
          log_error (_("error storing flags: %s\n"), gpg_strerror (err));
          keydb_release (kh);
          return err;
        }
    }

  keydb_release (kh);
  return 0;
}


/* Reset all the certificate flags we have stored with the certificates
   for performance reasons. */
void
keydb_clear_some_cert_flags (ctrl_t ctrl, strlist_t names)
{
  gpg_error_t err;
  KEYDB_HANDLE hd = NULL;
  KEYDB_SEARCH_DESC *desc = NULL;
  int ndesc;
  strlist_t sl;
  int rc=0;
  unsigned int old_value, value;

  (void)ctrl;

  hd = keydb_new ();
  if (!hd)
    {
      log_error ("keydb_new failed\n");
      goto leave;
    }

  if (!names)
    ndesc = 1;
  else
    {
      for (sl=names, ndesc=0; sl; sl = sl->next, ndesc++)
        ;
    }

  desc = xtrycalloc (ndesc, sizeof *desc);
  if (!ndesc)
    {
      log_error ("allocating memory failed: %s\n",
                 gpg_strerror (out_of_core ()));
      goto leave;
    }

  if (!names)
    desc[0].mode = KEYDB_SEARCH_MODE_FIRST;
  else
    {
      for (ndesc=0, sl=names; sl; sl = sl->next)
        {
          rc = classify_user_id (sl->d, desc+ndesc, 0);
          if (rc)
            log_error ("key '%s' not found: %s\n", sl->d, gpg_strerror (rc));
          else
            ndesc++;
        }
    }

  err = keydb_lock (hd);
  if (err)
    {
      log_error (_("error locking keybox: %s\n"), gpg_strerror (err));
      goto leave;
    }

  while (!(rc = keydb_search (ctrl, hd, desc, ndesc)))
    {
      if (!names)
        desc[0].mode = KEYDB_SEARCH_MODE_NEXT;

      err = keydb_get_flags (hd, KEYBOX_FLAG_VALIDITY, 0, &old_value);
      if (err)
        {
          log_error (_("error getting stored flags: %s\n"),
                     gpg_strerror (err));
          goto leave;
        }

      value = (old_value & ~VALIDITY_REVOKED);
      if (value != old_value)
        {
          err = keydb_set_flags (hd, KEYBOX_FLAG_VALIDITY, 0, value);
          if (err)
            {
              log_error (_("error storing flags: %s\n"), gpg_strerror (err));
              goto leave;
            }
        }
    }
  if (rc && rc != -1)
    log_error ("keydb_search failed: %s\n", gpg_strerror (rc));

 leave:
  xfree (desc);
  keydb_release (hd);
}
